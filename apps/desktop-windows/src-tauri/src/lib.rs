use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blackspace_core::MlsIdentityV1;
use blackspace_protocol::{
    AckRequestV1, AckResponseV1, ClaimEnrollmentParcelResponseV1, ClaimKeyPackageResponseV1,
    CreateDepositCapabilityRequestV1, CreateDepositCapabilityResponseV1, DepositAcceptedV1,
    DepositTargetV1, EnvelopeV1, ListDevicesResponseV1, MailboxProvisionRequestV1,
    MailboxProvisionResponseV1, MlsStateResponseV1, ParkEnrollmentParcelRequestV1,
    ParkEnrollmentParcelResponseV1, ProblemV1, PublishKeyPackagesRequestV1,
    PublishKeyPackagesResponseV1, PullRequestV1, PullResponseV1, PutMlsStateRequestV1,
    PutMlsStateResponseV1, RecoverMailboxRequestV1, RecoverMailboxResponseV1,
    RegisterDeviceRequestV1, RotateReadCapabilityRequestV1, RotateReadCapabilityResponseV1,
    ServerInfoV1,
};
use blackspace_tor::{
    parse_bootstrap_progress, parse_control_port_file, parse_socks_listener,
    validate_v3_onion_origin,
};
use rand::{Rng, distr::Alphanumeric};
use reqwest::{Client, Method, Proxy, redirect::Policy};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_shell::{
    ShellExt,
    process::{CommandChild, CommandEvent},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

mod native_vault;
use native_vault::NativeVault;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum TorPhase {
    Starting,
    Bootstrapping,
    Ready,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Serialize)]
struct TorStatus {
    phase: TorPhase,
    bootstrap_percent: u8,
    message: String,
}

struct TorRuntime {
    status: TorStatus,
    socks_address: Option<String>,
    child: Option<CommandChild>,
}

struct TorManager {
    runtime: Mutex<TorRuntime>,
    /// One connection pool and SOCKS isolation identity per canonical onion
    /// destination. This never crosses destinations or survives a Tor restart.
    destination_clients: Mutex<HashMap<String, Client>>,
}

#[derive(Default)]
struct NativeCore {
    identity: Mutex<Option<MlsIdentityV1>>,
}

#[derive(Serialize)]
struct NativeIdentityPublic {
    identity_public_key: String,
    key_packages: Vec<String>,
}

#[derive(Serialize)]
struct NativePutMlsStateResponse {
    conflict: bool,
    version: Option<i64>,
}

#[derive(Serialize)]
struct NativeConversationBootstrap {
    group_id: String,
    welcome: String,
    first_message: String,
}

#[tauri::command]
async fn initialize_core_identity(
    core: State<'_, NativeCore>,
) -> Result<NativeIdentityPublic, String> {
    let identity = blackspace_core::generate_mls_identity(blackspace_core::KEY_PACKAGE_TARGET)
        .map_err(|error| error.to_string())?;
    let output = NativeIdentityPublic {
        identity_public_key: identity.identity.signing_public_key.clone(),
        key_packages: identity
            .key_packages
            .iter()
            .map(|value| URL_SAFE_NO_PAD.encode(value))
            .collect(),
    };
    *core.identity.lock().await = Some(identity);
    Ok(output)
}

#[tauri::command]
async fn core_start_conversation(
    core: State<'_, NativeCore>,
    recipient_identity: String,
    recipient_key_package: String,
    first_payload: String,
) -> Result<NativeConversationBootstrap, String> {
    let mut state = core.identity.lock().await;
    let identity = state
        .as_mut()
        .ok_or_else(|| "The native identity is locked.".to_string())?;
    let bootstrap = blackspace_core::start_mls_conversation(
        identity,
        &recipient_identity,
        &URL_SAFE_NO_PAD
            .decode(recipient_key_package)
            .map_err(|_| "Invalid key package.".to_string())?,
        &URL_SAFE_NO_PAD
            .decode(first_payload)
            .map_err(|_| "Invalid application payload.".to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(NativeConversationBootstrap {
        group_id: URL_SAFE_NO_PAD.encode(bootstrap.group_id),
        welcome: URL_SAFE_NO_PAD.encode(bootstrap.welcome),
        first_message: URL_SAFE_NO_PAD.encode(bootstrap.first_message),
    })
}

impl TorManager {
    fn new() -> Self {
        Self {
            runtime: Mutex::new(TorRuntime {
                status: TorStatus {
                    phase: TorPhase::Stopped,
                    bootstrap_percent: 0,
                    message: "Tor has not started.".to_string(),
                },
                socks_address: None,
                child: None,
            }),
            destination_clients: Mutex::new(HashMap::new()),
        }
    }

    async fn status(&self) -> TorStatus {
        self.runtime.lock().await.status.clone()
    }

    async fn ready_socks(&self) -> Result<String, String> {
        // UI polling can begin while the managed sidecar is still bootstrapping.
        // Wait for that bounded startup window while continuing to fail closed:
        // no request is ever attempted without a ready SOCKS listener.
        for _ in 0..60 {
            let runtime = self.runtime.lock().await;
            if matches!(runtime.status.phase, TorPhase::Ready) {
                return runtime
                    .socks_address
                    .clone()
                    .ok_or_else(|| "Tor SOCKS listener is unavailable.".to_string());
            }
            if matches!(runtime.status.phase, TorPhase::Failed | TorPhase::Stopped) {
                return Err(
                    "Tor is not ready. Blackspace will not use a direct connection.".to_string(),
                );
            }
            drop(runtime);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err("Tor is not ready. Blackspace will not use a direct connection.".to_string())
    }

    async fn client_for_destination(&self, origin: &str) -> Result<Client, String> {
        let socks = self.ready_socks().await?;
        let mut clients = self.destination_clients.lock().await;
        if let Some(client) = clients.get(origin) {
            return Ok(client.clone());
        }
        let username: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();
        let password: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();
        let proxy = Proxy::all(format!("socks5h://{username}:{password}@{socks}"))
            .map_err(|_| "Could not configure the managed Tor proxy.".to_string())?;
        let client = Client::builder()
            .proxy(proxy)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(45))
            .timeout(Duration::from_secs(90))
            .build()
            .map_err(|_| "Could not initialize the Tor HTTP client.".to_string())?;
        clients.insert(origin.to_string(), client.clone());
        Ok(client)
    }

    async fn start(self: Arc<Self>, app: AppHandle) -> Result<(), String> {
        self.destination_clients.lock().await.clear();
        {
            let mut runtime = self.runtime.lock().await;
            if runtime.child.is_some() {
                return Ok(());
            }
            runtime.status = TorStatus {
                phase: TorPhase::Starting,
                bootstrap_percent: 0,
                message: "Starting managed Tor…".to_string(),
            };
        }

        let app_data = app
            .path()
            .app_local_data_dir()
            .map_err(|error| error.to_string())?;
        let tor_root = app_data.join("tor");
        let data_dir = tor_root.join("data");
        let control_file = tor_root.join("control-port");
        let cookie_file = tor_root.join("control-cookie");
        tokio::fs::create_dir_all(&data_dir)
            .await
            .map_err(|error| error.to_string())?;
        shutdown_stale_managed_tor(&control_file, &cookie_file).await;
        let _ = tokio::fs::remove_file(&control_file).await;
        let _ = tokio::fs::remove_file(&cookie_file).await;

        let resource_dir = app
            .path()
            .resource_dir()
            .map_err(|error| error.to_string())?;
        let support = resource_dir.join("tor-support");
        let args = tor_arguments(&data_dir, &control_file, &cookie_file, &support);
        let inherited_path = std::env::var("PATH").unwrap_or_default();
        let sidecar_path = format!("{};{inherited_path}", support.display());
        let command = app
            .shell()
            .sidecar("tor")
            .map_err(|error| format!("Managed Tor sidecar is missing: {error}"))?
            .env("PATH", sidecar_path)
            .args(args);
        let (mut events, child) = command.spawn().map_err(|error| error.to_string())?;
        {
            let mut runtime = self.runtime.lock().await;
            runtime.child = Some(child);
            runtime.status.phase = TorPhase::Bootstrapping;
            runtime.status.message = "Waiting for Tor control port…".to_string();
        }

        let event_manager = self.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(event) = events.recv().await {
                if let CommandEvent::Terminated(payload) = event {
                    let mut runtime = event_manager.runtime.lock().await;
                    runtime.child = None;
                    runtime.socks_address = None;
                    if !matches!(runtime.status.phase, TorPhase::Stopped) {
                        runtime.status = TorStatus {
                            phase: TorPhase::Failed,
                            bootstrap_percent: runtime.status.bootstrap_percent,
                            message: format!(
                                "Managed Tor exited unexpectedly ({:?}).",
                                payload.code
                            ),
                        };
                    }
                    drop(runtime);
                    event_manager.destination_clients.lock().await.clear();
                    break;
                }
            }
        });

        let bootstrap_manager = self.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(message) = bootstrap_manager
                .wait_until_ready(control_file, cookie_file)
                .await
            {
                let mut runtime = bootstrap_manager.runtime.lock().await;
                runtime.status = TorStatus {
                    phase: TorPhase::Failed,
                    bootstrap_percent: runtime.status.bootstrap_percent,
                    message,
                };
                runtime.socks_address = None;
            }
        });
        Ok(())
    }

    async fn wait_until_ready(
        &self,
        control_file: PathBuf,
        cookie_file: PathBuf,
    ) -> Result<(), String> {
        for _ in 0..240 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let Ok(control_value) = tokio::fs::read_to_string(&control_file).await else {
                continue;
            };
            let Ok(cookie) = tokio::fs::read(&cookie_file).await else {
                continue;
            };
            let control_address =
                parse_control_port_file(&control_value).map_err(|e| e.to_string())?;
            let response = control_query(
                &control_address,
                &cookie,
                "GETINFO status/bootstrap-phase\r\nGETINFO net/listeners/socks\r\n",
            )
            .await?;
            let progress = parse_bootstrap_progress(&response).map_err(|e| e.to_string())?;
            {
                let mut runtime = self.runtime.lock().await;
                runtime.status.bootstrap_percent = progress;
                runtime.status.message = format!("Tor bootstrap: {progress}%");
            }
            if progress == 100 {
                let socks = parse_socks_listener(&response).map_err(|e| e.to_string())?;
                let mut runtime = self.runtime.lock().await;
                runtime.socks_address = Some(socks);
                runtime.status = TorStatus {
                    phase: TorPhase::Ready,
                    bootstrap_percent: 100,
                    message: "Tor is ready. Onion-only networking is enforced.".to_string(),
                };
                return Ok(());
            }
        }
        Err("Tor did not finish bootstrapping within two minutes.".to_string())
    }

    async fn stop(&self) {
        let mut runtime = self.runtime.lock().await;
        if let Some(child) = runtime.child.take() {
            let _ = child.kill();
        }
        runtime.socks_address = None;
        runtime.status = TorStatus {
            phase: TorPhase::Stopped,
            bootstrap_percent: 0,
            message: "Tor stopped. Network operations are blocked.".to_string(),
        };
        drop(runtime);
        self.destination_clients.lock().await.clear();
    }
}

async fn shutdown_stale_managed_tor(control_file: &std::path::Path, cookie_file: &std::path::Path) {
    let Ok(control_value) = tokio::fs::read_to_string(control_file).await else {
        return;
    };
    let Ok(cookie) = tokio::fs::read(cookie_file).await else {
        return;
    };
    let Ok(control_address) = parse_control_port_file(&control_value) else {
        return;
    };
    if control_query(&control_address, &cookie, "SIGNAL SHUTDOWN\r\n")
        .await
        .is_err()
    {
        return;
    }
    // Tor acknowledges before its process and DataDirectory lock have fully
    // disappeared. Wait briefly so the replacement sidecar cannot race it.
    for _ in 0..20 {
        if TcpStream::connect(&control_address).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn tor_arguments(
    data_dir: &std::path::Path,
    control_file: &std::path::Path,
    cookie_file: &std::path::Path,
    support: &std::path::Path,
) -> Vec<String> {
    vec![
        "--ClientOnly".into(),
        "1".into(),
        "--DataDirectory".into(),
        data_dir.to_string_lossy().into_owned(),
        "--ControlPort".into(),
        "auto".into(),
        "--ControlPortWriteToFile".into(),
        control_file.to_string_lossy().into_owned(),
        "--CookieAuthentication".into(),
        "1".into(),
        "--CookieAuthFile".into(),
        cookie_file.to_string_lossy().into_owned(),
        "--SocksPort".into(),
        "auto IsolateSOCKSAuth ExtendedErrors".into(),
        "--SafeSocks".into(),
        "1".into(),
        "--SafeLogging".into(),
        "1".into(),
        "--Log".into(),
        "notice stdout".into(),
        "--GeoIPFile".into(),
        support.join("geoip").to_string_lossy().into_owned(),
        "--GeoIPv6File".into(),
        support.join("geoip6").to_string_lossy().into_owned(),
    ]
}

async fn control_query(address: &str, cookie: &[u8], commands: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|e| e.to_string())?;
    let cookie_hex = cookie
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    let request = format!("AUTHENTICATE {cookie_hex}\r\n{commands}QUIT\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut output = Vec::new();
    stream
        .read_to_end(&mut output)
        .await
        .map_err(|e| e.to_string())?;
    let response = String::from_utf8(output).map_err(|e| e.to_string())?;
    if !response.starts_with("250 OK") || response.contains("5  ") {
        return Err("Tor control authentication or query failed.".to_string());
    }
    Ok(response)
}

async fn tor_client(manager: &TorManager, server_url: &str) -> Result<(Client, String), String> {
    let origin = validate_v3_onion_origin(server_url).map_err(|error| error.to_string())?;
    let client = manager.client_for_destination(&origin).await?;
    Ok((client, origin))
}

fn safe_request_error(error: reqwest::Error) -> String {
    if error.is_timeout() {
        "Tor request timed out.".to_string()
    } else if error.is_connect() {
        "Could not connect to the onion service through Tor.".to_string()
    } else if error.is_decode() {
        "Mailbox returned an invalid response.".to_string()
    } else {
        "Tor request failed.".to_string()
    }
}

async fn request_json<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
) -> Result<T, String> {
    let response = request.send().await.map_err(safe_request_error)?;
    let status = response.status();
    if !status.is_success() {
        let problem = response.json::<ProblemV1>().await.ok();
        return Err(safe_mailbox_error(status.as_u16(), problem.as_ref()));
    }
    response.json().await.map_err(safe_request_error)
}

async fn request_no_content(request: reqwest::RequestBuilder) -> Result<(), String> {
    let response = request.send().await.map_err(safe_request_error)?;
    let status = response.status();
    if !status.is_success() {
        let problem = response.json::<ProblemV1>().await.ok();
        return Err(safe_mailbox_error(status.as_u16(), problem.as_ref()));
    }
    Ok(())
}

fn safe_mailbox_error(status: u16, problem: Option<&ProblemV1>) -> String {
    // Never forward arbitrary server text into the webview. These codes map to fixed,
    // non-secret wording defined by our own protocol.
    match problem.map(|problem| problem.code.as_str()) {
        Some("invalid_request") => {
            format!("Mailbox rejected an invalid request (status {status}).")
        }
        Some("unauthorized") => format!("Mailbox authorization failed (status {status})."),
        Some("delivery_unavailable") => {
            format!("Mailbox delivery is temporarily unavailable (status {status}).")
        }
        Some("internal_error") => {
            format!("Mailbox could not complete the operation (status {status}).")
        }
        _ => format!("Mailbox operation failed with status {status}."),
    }
}

#[tauri::command]
async fn tor_status(manager: State<'_, Arc<TorManager>>) -> Result<TorStatus, String> {
    Ok(manager.status().await)
}

#[tauri::command]
async fn get_server_info(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
) -> Result<ServerInfoV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(client.get(format!("{origin}/v1/info"))).await
}

#[tauri::command]
async fn provision_mailbox(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    registration_token: String,
    request: MailboxProvisionRequestV1,
) -> Result<MailboxProvisionResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/mailboxes"))
            .header(
                "authorization",
                format!("BlackspaceRegistration {registration_token}"),
            )
            .json(&request),
    )
    .await
}

#[tauri::command]
async fn create_deposit_capability(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
    request: CreateDepositCapabilityRequestV1,
) -> Result<CreateDepositCapabilityResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/mailbox/deposit-capabilities"))
            .header(
                "authorization",
                format!("BlackspaceAdmin {admin_capability}"),
            )
            .json(&request),
    )
    .await
}

#[tauri::command]
async fn revoke_deposit_capability(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
    capability_id: String,
) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(&capability_id)
        .map_err(|_| "Invalid capability identifier.".to_string())?;
    let (client, origin) = tor_client(&manager, &server_url).await?;
    let response = client
        .request(
            Method::DELETE,
            format!("{origin}/v1/mailbox/deposit-capabilities/{id}"),
        )
        .header(
            "authorization",
            format!("BlackspaceAdmin {admin_capability}"),
        )
        .send()
        .await
        .map_err(safe_request_error)?;
    if !response.status().is_success() {
        return Err("Capability revocation failed.".to_string());
    }
    Ok(())
}

#[tauri::command]
async fn deposit_envelope(
    manager: State<'_, Arc<TorManager>>,
    target: DepositTargetV1,
    envelope: EnvelopeV1,
) -> Result<DepositAcceptedV1, String> {
    let (client, origin) = tor_client(&manager, &target.onion_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/deposit/envelopes"))
            .header(
                "authorization",
                format!("BlackspaceDeposit {}", target.deposit_capability),
            )
            .header("content-type", "application/blackspace-envelope+json")
            .body(
                serde_json::to_vec(&envelope)
                    .map_err(|_| "Could not encode the encrypted envelope.".to_string())?,
            ),
    )
    .await
}

#[tauri::command]
async fn claim_key_package(
    manager: State<'_, Arc<TorManager>>,
    target: DepositTargetV1,
) -> Result<ClaimKeyPackageResponseV1, String> {
    let (client, origin) = tor_client(&manager, &target.onion_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/deposit/key-packages/claim"))
            .header(
                "authorization",
                format!("BlackspaceDeposit {}", target.deposit_capability),
            ),
    )
    .await
}

#[tauri::command]
async fn publish_key_packages(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
    request: PublishKeyPackagesRequestV1,
) -> Result<PublishKeyPackagesResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/mailbox/key-packages"))
            .header(
                "authorization",
                format!("BlackspaceAdmin {admin_capability}"),
            )
            .json(&request),
    )
    .await
}

#[tauri::command]
async fn recover_mailbox(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    old_admin_capability: String,
    request: RecoverMailboxRequestV1,
) -> Result<RecoverMailboxResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/mailbox/recover"))
            .header(
                "authorization",
                format!("BlackspaceAdmin {old_admin_capability}"),
            )
            .json(&request),
    )
    .await
}

#[tauri::command]
async fn rotate_read_capability(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
    request: RotateReadCapabilityRequestV1,
) -> Result<RotateReadCapabilityResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/mailbox/read-capability/rotate"))
            .header(
                "authorization",
                format!("BlackspaceAdmin {admin_capability}"),
            )
            .json(&request),
    )
    .await
}

#[tauri::command]
async fn pull_envelopes(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    read_capability: String,
    limit: u16,
) -> Result<PullResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/mailbox/pull"))
            .header("authorization", format!("BlackspaceRead {read_capability}"))
            .json(&PullRequestV1 { limit: Some(limit) }),
    )
    .await
}

#[tauri::command]
async fn acknowledge_envelopes(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    read_capability: String,
    acknowledgement_tokens: Vec<String>,
) -> Result<AckResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/mailbox/ack"))
            .header("authorization", format!("BlackspaceRead {read_capability}"))
            .json(&AckRequestV1 {
                acknowledgement_tokens,
            }),
    )
    .await
}

#[tauri::command]
async fn get_mls_state(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
) -> Result<Option<MlsStateResponseV1>, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    let response = client
        .get(format!("{origin}/v1/mailbox/mls-state"))
        .header(
            "authorization",
            format!("BlackspaceAdmin {admin_capability}"),
        )
        .send()
        .await
        .map_err(safe_request_error)?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }
    let status = response.status();
    if !status.is_success() {
        let problem = response.json::<ProblemV1>().await.ok();
        return Err(safe_mailbox_error(status.as_u16(), problem.as_ref()));
    }
    response
        .json::<MlsStateResponseV1>()
        .await
        .map(Some)
        .map_err(safe_request_error)
}

#[tauri::command]
async fn put_mls_state(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
    request: PutMlsStateRequestV1,
) -> Result<NativePutMlsStateResponse, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    let response = client
        .put(format!("{origin}/v1/mailbox/mls-state"))
        .header(
            "authorization",
            format!("BlackspaceAdmin {admin_capability}"),
        )
        .json(&request)
        .send()
        .await
        .map_err(safe_request_error)?;
    if response.status() == reqwest::StatusCode::CONFLICT {
        return Ok(NativePutMlsStateResponse {
            conflict: true,
            version: None,
        });
    }
    let status = response.status();
    if !status.is_success() {
        let problem = response.json::<ProblemV1>().await.ok();
        return Err(safe_mailbox_error(status.as_u16(), problem.as_ref()));
    }
    let result = response
        .json::<PutMlsStateResponseV1>()
        .await
        .map_err(safe_request_error)?;
    Ok(NativePutMlsStateResponse {
        conflict: false,
        version: Some(result.version),
    })
}

#[tauri::command]
async fn park_enrollment_parcel(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
    request: ParkEnrollmentParcelRequestV1,
) -> Result<ParkEnrollmentParcelResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(
        client
            .post(format!("{origin}/v1/enroll/parcels"))
            .header(
                "authorization",
                format!("BlackspaceAdmin {admin_capability}"),
            )
            .json(&request),
    )
    .await
}

#[tauri::command]
async fn claim_enrollment_parcel(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    claim_secret: String,
) -> Result<Option<ClaimEnrollmentParcelResponseV1>, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    let response = client
        .post(format!("{origin}/v1/enroll/parcels/claim"))
        .header("authorization", format!("BlackspaceEnroll {claim_secret}"))
        .send()
        .await
        .map_err(safe_request_error)?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let status = response.status();
    if !status.is_success() {
        let problem = response.json::<ProblemV1>().await.ok();
        return Err(safe_mailbox_error(status.as_u16(), problem.as_ref()));
    }
    response
        .json::<ClaimEnrollmentParcelResponseV1>()
        .await
        .map(Some)
        .map_err(safe_request_error)
}

#[tauri::command]
async fn register_device(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
    request: RegisterDeviceRequestV1,
) -> Result<(), String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_no_content(
        client
            .post(format!("{origin}/v1/mailbox/devices"))
            .header(
                "authorization",
                format!("BlackspaceAdmin {admin_capability}"),
            )
            .json(&request),
    )
    .await
}

#[tauri::command]
async fn list_devices(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
) -> Result<ListDevicesResponseV1, String> {
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_json(client.get(format!("{origin}/v1/mailbox/devices")).header(
        "authorization",
        format!("BlackspaceAdmin {admin_capability}"),
    ))
    .await
}

#[tauri::command]
async fn revoke_device(
    manager: State<'_, Arc<TorManager>>,
    server_url: String,
    admin_capability: String,
    device_id: String,
) -> Result<(), String> {
    let id =
        uuid::Uuid::parse_str(&device_id).map_err(|_| "Invalid device identifier.".to_string())?;
    let (client, origin) = tor_client(&manager, &server_url).await?;
    request_no_content(
        client
            .delete(format!("{origin}/v1/mailbox/devices/{id}"))
            .header(
                "authorization",
                format!("BlackspaceAdmin {admin_capability}"),
            ),
    )
    .await
}

pub fn run() {
    let manager = Arc::new(TorManager::new());
    let setup_manager = manager.clone();
    let shutdown_manager = manager.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(manager.clone())
        .manage(NativeCore::default())
        .manage(NativeVault::default())
        .setup(move |app| {
            let handle = app.handle().clone();
            let startup_manager = setup_manager.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(message) = startup_manager.clone().start(handle).await {
                    let mut runtime = startup_manager.runtime.lock().await;
                    runtime.status = TorStatus {
                        phase: TorPhase::Failed,
                        bootstrap_percent: 0,
                        message,
                    };
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            tor_status,
            get_server_info,
            provision_mailbox,
            create_deposit_capability,
            revoke_deposit_capability,
            deposit_envelope,
            claim_key_package,
            publish_key_packages,
            recover_mailbox,
            rotate_read_capability,
            initialize_core_identity,
            core_start_conversation,
            native_vault::native_vault_exists,
            native_vault::native_save_vault,
            native_vault::native_unlock_vault,
            native_vault::native_lock_vault,
            native_vault::native_delete_vault,
            pull_envelopes,
            acknowledge_envelopes,
            get_mls_state,
            put_mls_state,
            park_enrollment_parcel,
            claim_enrollment_parcel,
            register_device,
            list_devices,
            revoke_device,
        ])
        .on_window_event({
            move |_window, event| {
                if matches!(event, tauri::WindowEvent::Destroyed) {
                    let manager = shutdown_manager.clone();
                    tauri::async_runtime::spawn(async move {
                        manager.stop().await;
                    });
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Blackspace");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_arguments_enforce_client_only_and_safe_socks() {
        let args = tor_arguments(
            std::path::Path::new("data"),
            std::path::Path::new("control"),
            std::path::Path::new("cookie"),
            std::path::Path::new("support"),
        );
        assert!(args.windows(2).any(|pair| pair == ["--ClientOnly", "1"]));
        assert!(args.windows(2).any(|pair| pair == ["--SafeSocks", "1"]));
        assert!(args.iter().any(|value| value.contains("IsolateSOCKSAuth")));
    }

    #[test]
    fn mailbox_errors_only_expose_fixed_protocol_wording() {
        let invalid = ProblemV1 {
            code: "invalid_request".into(),
            message: "server-controlled detail must not be forwarded".into(),
        };
        assert_eq!(
            safe_mailbox_error(400, Some(&invalid)),
            "Mailbox rejected an invalid request (status 400)."
        );
        let unknown = ProblemV1 {
            code: "unknown".into(),
            message: "secret.onion token=abc".into(),
        };
        assert_eq!(
            safe_mailbox_error(418, Some(&unknown)),
            "Mailbox operation failed with status 418."
        );
    }

    #[tokio::test]
    async fn reuses_clients_per_destination_and_separates_onion_origins() {
        let manager = TorManager::new();
        {
            let mut runtime = manager.runtime.lock().await;
            runtime.status.phase = TorPhase::Ready;
            runtime.status.bootstrap_percent = 100;
            runtime.socks_address = Some("127.0.0.1:39050".into());
        }
        let first = format!("http://{}.onion", "a".repeat(56));
        let second = format!("http://{}.onion", "b".repeat(56));
        tor_client(&manager, &first).await.unwrap();
        tor_client(&manager, &first).await.unwrap();
        assert_eq!(manager.destination_clients.lock().await.len(), 1);
        tor_client(&manager, &second).await.unwrap();
        assert_eq!(manager.destination_clients.lock().await.len(), 2);

        manager.stop().await;
        assert!(manager.destination_clients.lock().await.is_empty());
    }
}
