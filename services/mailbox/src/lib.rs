use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header::CONTENT_TYPE},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blackspace_capabilities::{CapabilityKind, decode_verifier, generate_capability, verifier};
use blackspace_protocol::{
    AckRequestV1, AckResponseV1, ClaimEnrollmentParcelResponseV1, ClaimKeyPackageResponseV1,
    CreateDepositCapabilityRequestV1, CreateDepositCapabilityResponseV1, DepositAcceptedV1,
    DeviceV1, EnrollmentParcelStatusV1, EnvelopeV1, FinalizeEnrollmentParcelRequestV1,
    KeyPackageV1, ListDevicesResponseV1, MAX_KEY_PACKAGE_BATCH, MAX_PULL_BATCH,
    MAX_QUEUED_ENVELOPES, MAX_RETENTION_SECONDS, MLS_STATE_SIZE_CLASSES, MailboxProvisionRequestV1,
    MailboxProvisionResponseV1, MlsStateResponseV1, ParkEnrollmentParcelRequestV1,
    ParkEnrollmentParcelResponseV1, ProblemV1, PublishKeyPackagesRequestV1,
    PublishKeyPackagesResponseV1, PullRequestV1, PullResponseV1, PulledEnvelopeV1,
    PutMlsStateRequestV1, PutMlsStateResponseV1, RecoverMailboxRequestV1, RecoverMailboxResponseV1,
    RegisterDeviceRequestV1, RotateReadCapabilityRequestV1, RotateReadCapabilityResponseV1,
    SIZE_CLASSES, SecureDeviceResetRequestV1, SecureDeviceResetResponseV1, ServerInfoV1,
};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tracing::{error, info, warn};
use uuid::Uuid;

const MLS_CIPHERSUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
const MAX_KEY_PACKAGE_AGE_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    info: ServerInfoV1,
    deposit_limiter: Arc<DepositRateLimiter>,
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub listen_addr: SocketAddr,
    pub instance_name: String,
    pub onion_origin: Option<String>,
    pub https_origin: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = env_or_file("BLACKSPACE_DATABASE_URL")?;
        let listen_addr = std::env::var("BLACKSPACE_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse()?;
        Ok(Self {
            database_url,
            listen_addr,
            instance_name: std::env::var("BLACKSPACE_INSTANCE_NAME")
                .unwrap_or_else(|_| "Blackspace Private Alpha".into()),
            onion_origin: optional_env("BLACKSPACE_ONION_ORIGIN"),
            https_origin: optional_env("BLACKSPACE_HTTPS_ORIGIN"),
        })
    }

    fn server_info(&self) -> ServerInfoV1 {
        ServerInfoV1 {
            instance_name: self.instance_name.clone(),
            onion_origin: self.onion_origin.clone(),
            https_origin: self.https_origin.clone(),
            ..ServerInfoV1::default()
        }
    }
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_or_file(name: &str) -> anyhow::Result<String> {
    if let Ok(value) = std::env::var(name) {
        return Ok(value);
    }
    let file_name = format!("{name}_FILE");
    let path =
        std::env::var(&file_name).map_err(|_| anyhow::anyhow!("set {name} or {file_name}"))?;
    let value = std::fs::read_to_string(path)?.trim().to_string();
    if value.is_empty() {
        anyhow::bail!("{file_name} points to an empty secret");
    }
    Ok(value)
}

struct DepositRateLimiter {
    attempts: Mutex<DepositRateWindows>,
}

struct DepositRateWindows {
    windows: HashMap<[u8; 32], VecDeque<Instant>>,
    last_sweep: Instant,
}

impl Default for DepositRateLimiter {
    fn default() -> Self {
        Self {
            attempts: Mutex::new(DepositRateWindows {
                windows: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }
}

impl DepositRateLimiter {
    const WINDOW: Duration = Duration::from_secs(60);

    fn allow(&self, key: [u8; 32]) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&self, key: [u8; 32], now: Instant) -> bool {
        let mut state = self.attempts.lock().expect("rate limiter mutex poisoned");
        // The rate key is derived from the presented capability before validity
        // checks, so probing with random capabilities creates new entries. Drop
        // fully expired windows at most once per window so the map stays bounded
        // by recent traffic instead of growing for the life of the process.
        if now.duration_since(state.last_sweep) >= Self::WINDOW {
            state.windows.retain(|_, window| {
                while window
                    .front()
                    .is_some_and(|time| now.duration_since(*time) >= Self::WINDOW)
                {
                    window.pop_front();
                }
                !window.is_empty()
            });
            state.last_sweep = now;
        }
        let window = state.windows.entry(key).or_default();
        while window
            .front()
            .is_some_and(|time| now.duration_since(*time) >= Self::WINDOW)
        {
            window.pop_front();
        }
        if window.len() >= 30 {
            return false;
        }
        window.push_back(now);
        true
    }

    #[cfg(test)]
    fn tracked_keys(&self) -> usize {
        self.attempts
            .lock()
            .expect("rate limiter mutex poisoned")
            .windows
            .len()
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    fn invalid_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "The request is not valid.",
        }
    }
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "Authorization failed.",
        }
    }
    fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "delivery_unavailable",
            message: "Delivery is currently unavailable.",
        }
    }
    fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "delivery_unavailable",
            message: "Delivery is currently unavailable.",
        }
    }
    fn version_conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "version_conflict",
            message: "The stored state moved; re-read and retry.",
        }
    }
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "No matching resource.",
        }
    }
    fn internal(error: impl std::fmt::Display) -> Self {
        error!(error = %error, "mailbox operation failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "The operation could not be completed.",
        }
    }
}

fn invalid_registration(reason: &'static str) -> ApiError {
    // Reason labels are deliberately static and contain no capabilities, identity keys, or payloads.
    warn!(reason, "mailbox registration rejected");
    ApiError::invalid_request()
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(CONTENT_TYPE, "application/problem+json")],
            Json(ProblemV1 {
                code: self.code.into(),
                message: self.message.into(),
            }),
        )
            .into_response()
    }
}

pub async fn connect(config: &Config) -> anyhow::Result<AppState> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(AppState {
        pool,
        info: config.server_info(),
        deposit_limiter: Arc::new(DepositRateLimiter::default()),
    })
}

pub async fn create_registration_invite(
    config: &Config,
    lifetime_hours: u64,
) -> anyhow::Result<String> {
    if lifetime_hours == 0 || lifetime_hours > 24 * 7 {
        anyhow::bail!("registration invitation lifetime must be between 1 hour and 7 days");
    }
    let state = connect(config).await?;
    let token = generate_capability()?;
    let digest = verifier(CapabilityKind::Registration, &token)?;
    let expires_at = OffsetDateTime::now_utc() + time::Duration::hours(lifetime_hours as i64);
    sqlx::query(
        "INSERT INTO registration_invitations (id, verifier, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(Uuid::new_v4())
    .bind(digest.as_slice())
    .bind(expires_at)
    .execute(&state.pool)
    .await?;
    let onion = config.onion_origin.as_deref().unwrap_or("");
    let https = config.https_origin.as_deref().unwrap_or("");
    Ok(format!(
        "blackspace://join/v1?onion={}&https={}#token={token}",
        urlencoding::encode(onion),
        urlencoding::encode(https)
    ))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/v1/info", get(server_info))
        .route("/v1/mailboxes", post(provision_mailbox))
        .route(
            "/v1/mailbox/deposit-capabilities",
            post(create_deposit_capability),
        )
        .route(
            "/v1/mailbox/deposit-capabilities/{capability_id}",
            delete(revoke_deposit_capability),
        )
        .route("/v1/mailbox/key-packages", post(publish_key_packages))
        .route("/v1/mailbox/recover", post(recover_mailbox))
        .route(
            "/v1/mailbox/read-capability/rotate",
            post(rotate_read_capability),
        )
        .route(
            "/v1/mailbox/mls-state",
            get(get_mls_state).put(put_mls_state),
        )
        .route(
            "/v1/mailbox/devices",
            get(list_devices).post(register_device),
        )
        .route(
            "/v1/mailbox/devices/secure-reset",
            post(secure_device_reset),
        )
        .route("/v1/enroll/parcels", post(park_enrollment_parcel))
        .route(
            "/v1/enroll/parcels/{parcel_id}",
            axum::routing::put(finalize_enrollment_parcel),
        )
        .route("/v1/enroll/parcels/claim", post(claim_enrollment_parcel))
        .route("/v1/deposit/key-packages/claim", post(claim_key_package))
        .route("/v1/deposit/envelopes", post(deposit_envelope))
        .route("/v1/mailbox/pull", post(pull_envelopes))
        .route("/v1/mailbox/ack", post(acknowledge_envelopes))
        .layer(DefaultBodyLimit::max(3_800_000))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let state = connect(&config).await?;
    spawn_expiry_cleanup(state.pool.clone());
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!(listen_addr = %config.listen_addr, "mailbox service ready");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn cors_public_path(path: &str) -> bool {
    matches!(
        path,
        "/v1/info"
            | "/v1/deposit/key-packages/claim"
            | "/v1/deposit/envelopes"
            | "/v1/enroll/parcels/claim"
    )
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let public_cors = cors_public_path(request.uri().path());
    let preflight = public_cors && request.method() == Method::OPTIONS;
    let mut response = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    if public_cors {
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        headers.insert(
            "access-control-allow-methods",
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            "access-control-allow-headers",
            HeaderValue::from_static("authorization, content-type"),
        );
        headers.insert("access-control-max-age", HeaderValue::from_static("600"));
    }
    response
}

async fn health_live() -> StatusCode {
    StatusCode::NO_CONTENT
}
async fn health_ready(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    sqlx::query("SELECT 1")
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn server_info(State(state): State<AppState>) -> Json<ServerInfoV1> {
    Json(state.info)
}

async fn provision_mailbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MailboxProvisionRequestV1>,
) -> Result<(StatusCode, Json<MailboxProvisionResponseV1>), ApiError> {
    let token = authorization_capability(&headers, "BlackspaceRegistration")?;
    let registration =
        verifier(CapabilityKind::Registration, token).map_err(|_| ApiError::unauthorized())?;
    let read = decode_verifier(&request.read_capability_verifier)
        .map_err(|_| invalid_registration("read_verifier"))?;
    let admin = decode_verifier(&request.admin_capability_verifier)
        .map_err(|_| invalid_registration("admin_verifier"))?;
    let deposit = decode_verifier(&request.initial_deposit_capability_verifier)
        .map_err(|_| invalid_registration("deposit_verifier"))?;
    validate_identity(&request.identity_public_key)
        .map_err(|_| invalid_registration("identity"))?;
    let deposit_expiry = optional_expiry(request.initial_deposit_expires_at, MAX_RETENTION_SECONDS)
        .map_err(|_| invalid_registration("deposit_expiry"))?;
    let packages = validate_key_packages(&request.key_packages, &request.identity_public_key)
        .map_err(|_| invalid_registration("key_packages"))?;
    if packages.is_empty() {
        return Err(invalid_registration("key_packages_empty"));
    }

    let mut tx = state.pool.begin().await.map_err(ApiError::internal)?;
    let invite = sqlx::query(
        "SELECT r.id,r.expires_at,r.consumed_at,r.mailbox_id,r.initial_deposit_capability_id,
                m.read_capability_verifier,m.admin_capability_verifier,m.identity_public_key,
                d.verifier AS deposit_capability_verifier
         FROM registration_invitations r
         LEFT JOIN mailboxes m ON m.id=r.mailbox_id
         LEFT JOIN deposit_capabilities d ON d.id=r.initial_deposit_capability_id
         WHERE r.verifier=$1 AND r.revoked_at IS NULL
         FOR UPDATE OF r",
    )
    .bind(registration.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(ApiError::unauthorized)?;
    let invite_id: Uuid = invite.get("id");
    if invite
        .get::<Option<OffsetDateTime>, _>("consumed_at")
        .is_some()
    {
        let mailbox_id = invite
            .get::<Option<Uuid>, _>("mailbox_id")
            .ok_or_else(|| ApiError::internal("consumed invitation has no mailbox"))?;
        let deposit_id = invite
            .get::<Option<Uuid>, _>("initial_deposit_capability_id")
            .ok_or_else(|| ApiError::internal("consumed invitation has no deposit capability"))?;
        let stored_read = invite.get::<Option<Vec<u8>>, _>("read_capability_verifier");
        let stored_admin = invite.get::<Option<Vec<u8>>, _>("admin_capability_verifier");
        let stored_deposit = invite.get::<Option<Vec<u8>>, _>("deposit_capability_verifier");
        let stored_identity = invite.get::<Option<String>, _>("identity_public_key");
        let same_attempt = stored_read
            .as_deref()
            .is_some_and(|value| bool::from(value.ct_eq(read.as_slice())))
            && stored_admin
                .as_deref()
                .is_some_and(|value| bool::from(value.ct_eq(admin.as_slice())))
            && stored_deposit
                .as_deref()
                .is_some_and(|value| bool::from(value.ct_eq(deposit.as_slice())))
            && stored_identity.as_deref() == Some(request.identity_public_key.as_str());
        if !same_attempt {
            return Err(ApiError::unauthorized());
        }
        tx.commit().await.map_err(ApiError::internal)?;
        return Ok((
            StatusCode::OK,
            Json(MailboxProvisionResponseV1 {
                mailbox_id,
                initial_deposit_capability_id: deposit_id,
            }),
        ));
    }
    if invite.get::<OffsetDateTime, _>("expires_at") <= OffsetDateTime::now_utc() {
        return Err(ApiError::unauthorized());
    }

    let mailbox_id = Uuid::new_v4();
    let deposit_id = Uuid::new_v4();
    sqlx::query("INSERT INTO mailboxes (id, read_capability_verifier, admin_capability_verifier, identity_public_key) VALUES ($1,$2,$3,$4)")
        .bind(mailbox_id).bind(read.as_slice()).bind(admin.as_slice()).bind(&request.identity_public_key)
        .execute(&mut *tx).await.map_err(|error| map_conflict(error, "mailbox_conflict"))?;
    sqlx::query("INSERT INTO deposit_capabilities (id, mailbox_id, verifier, expires_at) VALUES ($1,$2,$3,$4)")
        .bind(deposit_id).bind(mailbox_id).bind(deposit.as_slice()).bind(deposit_expiry)
        .execute(&mut *tx).await.map_err(ApiError::internal)?;
    insert_key_packages(&mut tx, mailbox_id, packages).await?;
    sqlx::query("UPDATE registration_invitations SET consumed_at=now(),mailbox_id=$2,initial_deposit_capability_id=$3 WHERE id=$1")
        .bind(invite_id)
        .bind(mailbox_id)
        .bind(deposit_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(MailboxProvisionResponseV1 {
            mailbox_id,
            initial_deposit_capability_id: deposit_id,
        }),
    ))
}

async fn create_deposit_capability(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateDepositCapabilityRequestV1>,
) -> Result<(StatusCode, Json<CreateDepositCapabilityResponseV1>), ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    let digest = decode_verifier(&request.verifier).map_err(|_| ApiError::invalid_request())?;
    let expires_at = optional_expiry(request.expires_at, MAX_KEY_PACKAGE_AGE_SECONDS)?;
    let capability_id = Uuid::new_v4();
    sqlx::query("INSERT INTO deposit_capabilities (id, mailbox_id, verifier, expires_at) VALUES ($1,$2,$3,$4)")
        .bind(capability_id).bind(mailbox_id).bind(digest.as_slice()).bind(expires_at)
        .execute(&state.pool).await.map_err(|error| map_conflict(error, "capability_conflict"))?;
    Ok((
        StatusCode::CREATED,
        Json(CreateDepositCapabilityResponseV1 { capability_id }),
    ))
}

async fn revoke_deposit_capability(
    State(state): State<AppState>,
    Path(capability_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    sqlx::query("UPDATE deposit_capabilities SET revoked_at=now() WHERE id=$1 AND mailbox_id=$2 AND revoked_at IS NULL")
        .bind(capability_id).bind(mailbox_id).execute(&state.pool).await.map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Rotate only the read capability. Admin-authorized; leaves deposit capabilities,
/// key packages, and the queued envelopes intact. Used to cut a linked companion's
/// read access on unlink without the destructive recovery/takeover flow.
async fn rotate_read_capability(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RotateReadCapabilityRequestV1>,
) -> Result<Json<RotateReadCapabilityResponseV1>, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    let verifier = decode_verifier(&request.read_capability_verifier)
        .map_err(|_| ApiError::invalid_request())?;
    sqlx::query("UPDATE mailboxes SET read_capability_verifier=$1 WHERE id=$2")
        .bind(verifier.as_slice())
        .bind(mailbox_id)
        .execute(&state.pool)
        .await
        .map_err(|error| map_conflict(error, "read_capability_conflict"))?;
    Ok(Json(RotateReadCapabilityResponseV1 { ok: true }))
}

/// Read the shared MLS-state blob. Admin-gated: the private ratchet must never be
/// exposed to a read-capability holder. Returns 204 before the first device uploads.
async fn get_mls_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    let row = sqlx::query(
        "SELECT version, size_class, ciphertext FROM mls_state_blobs WHERE mailbox_id=$1",
    )
    .bind(mailbox_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    match row {
        None => Ok(StatusCode::NO_CONTENT.into_response()),
        Some(row) => Ok(Json(MlsStateResponseV1 {
            version: row.get("version"),
            size_class: row.get::<i32, _>("size_class") as usize,
            ciphertext: URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("ciphertext")),
        })
        .into_response()),
    }
}

/// Compare-and-swap write of the shared MLS-state blob. Succeeds only when
/// `expected_version` matches the stored version (0 for the first write); otherwise
/// 409. This is the cross-device guard that makes a ratchet fork impossible.
async fn put_mls_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PutMlsStateRequestV1>,
) -> Result<Json<PutMlsStateResponseV1>, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    if request.expected_version < 0 {
        return Err(ApiError::invalid_request());
    }
    let ciphertext = validate_sized_ciphertext(
        &request.ciphertext,
        request.size_class,
        &MLS_STATE_SIZE_CLASSES,
    )?;
    let mut tx = state.pool.begin().await.map_err(ApiError::internal)?;
    let current: Option<i64> =
        sqlx::query_scalar("SELECT version FROM mls_state_blobs WHERE mailbox_id=$1 FOR UPDATE")
            .bind(mailbox_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
    let next = cas_next_version(current, request.expected_version)
        .ok_or_else(ApiError::version_conflict)?;
    sqlx::query(
        "INSERT INTO mls_state_blobs (mailbox_id, version, size_class, ciphertext, updated_at)
         VALUES ($1,$2,$3,$4,now())
         ON CONFLICT (mailbox_id)
         DO UPDATE SET version=$2, size_class=$3, ciphertext=$4, updated_at=now()",
    )
    .bind(mailbox_id)
    .bind(next)
    .bind(request.size_class as i32)
    .bind(ciphertext)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(PutMlsStateResponseV1 { version: next }))
}

/// Begin a one-time enrollment ceremony. This first stage deliberately stores no
/// account ciphertext: it gives the new device only the trusted device's ephemeral
/// public key so both screens can authenticate the channel before secrets move.
async fn park_enrollment_parcel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ParkEnrollmentParcelRequestV1>,
) -> Result<(StatusCode, Json<ParkEnrollmentParcelResponseV1>), ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    let verifier =
        decode_verifier(&request.parcel_verifier).map_err(|_| ApiError::invalid_request())?;
    let eph_pub = URL_SAFE_NO_PAD
        .decode(&request.eph_pub)
        .map_err(|_| ApiError::invalid_request())?;
    if eph_pub.len() != 65 || URL_SAFE_NO_PAD.encode(eph_pub) != request.eph_pub {
        return Err(ApiError::invalid_request());
    }
    let expires_at = OffsetDateTime::from_unix_timestamp(request.expires_at)
        .map_err(|_| ApiError::invalid_request())?;
    let now = OffsetDateTime::now_utc();
    if expires_at <= now || expires_at > now + time::Duration::hours(24) {
        return Err(ApiError::invalid_request());
    }
    let parcel_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO enrollment_parcels (id, mailbox_id, verifier, eph_pub, expires_at)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(parcel_id)
    .bind(mailbox_id)
    .bind(verifier.as_slice())
    .bind(&request.eph_pub)
    .bind(expires_at)
    .execute(&state.pool)
    .await
    .map_err(|error| map_conflict(error, "parcel_conflict"))?;
    Ok((
        StatusCode::CREATED,
        Json(ParkEnrollmentParcelResponseV1 { parcel_id }),
    ))
}

/// Complete an authenticated enrollment ceremony after the human has compared the
/// SAS. Only now is the encrypted bundle accepted by the server.
async fn finalize_enrollment_parcel(
    State(state): State<AppState>,
    Path(parcel_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<FinalizeEnrollmentParcelRequestV1>,
) -> Result<StatusCode, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    let ciphertext =
        validate_sized_ciphertext(&request.ciphertext, request.size_class, &SIZE_CLASSES)?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&request.nonce)
        .map_err(|_| ApiError::invalid_request())?;
    if nonce.len() != 12 || URL_SAFE_NO_PAD.encode(nonce) != request.nonce {
        return Err(ApiError::invalid_request());
    }
    let result = sqlx::query(
        "UPDATE enrollment_parcels
         SET nonce=$1,size_class=$2,ciphertext=$3,finalized_at=now()
         WHERE id=$4 AND mailbox_id=$5 AND finalized_at IS NULL
           AND claimed_at IS NULL AND expires_at>now()",
    )
    .bind(&request.nonce)
    .bind(request.size_class as i32)
    .bind(ciphertext)
    .bind(parcel_id)
    .bind(mailbox_id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    if result.rows_affected() != 1 {
        return Err(ApiError::version_conflict());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Poll an enrollment parcel using the one-time bearer from the new-device offer.
/// Pending responses expose only the trusted ephemeral key. A ready response is
/// consumed atomically and contains the encrypted account bundle.
async fn claim_enrollment_parcel(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ClaimEnrollmentParcelResponseV1>, ApiError> {
    let raw = authorization_capability(&headers, "BlackspaceEnroll")?;
    let digest = verifier(CapabilityKind::Enroll, raw).map_err(|_| ApiError::not_found())?;
    let mut tx = state.pool.begin().await.map_err(ApiError::internal)?;
    let row = sqlx::query(
        "SELECT id, eph_pub, nonce, size_class, ciphertext, finalized_at FROM enrollment_parcels
         WHERE verifier=$1 AND claimed_at IS NULL AND expires_at > now()
         FOR UPDATE SKIP LOCKED",
    )
    .bind(digest.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(ApiError::not_found)?;
    let ready = row
        .get::<Option<OffsetDateTime>, _>("finalized_at")
        .is_some();
    if ready {
        let parcel_id: Uuid = row.get("id");
        sqlx::query("UPDATE enrollment_parcels SET claimed_at=now() WHERE id=$1")
            .bind(parcel_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
    }
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(ClaimEnrollmentParcelResponseV1 {
        status: if ready {
            EnrollmentParcelStatusV1::Ready
        } else {
            EnrollmentParcelStatusV1::PendingConfirmation
        },
        eph_pub: row.get("eph_pub"),
        nonce: row.get("nonce"),
        size_class: row
            .get::<Option<i32>, _>("size_class")
            .map(|value| value as usize),
        ciphertext: row
            .get::<Option<Vec<u8>>, _>("ciphertext")
            .map(|value| URL_SAFE_NO_PAD.encode(value)),
    }))
}

async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterDeviceRequestV1>,
) -> Result<StatusCode, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    if request.label.is_empty() || request.label.len() > 128 {
        return Err(ApiError::invalid_request());
    }
    sqlx::query(
        "INSERT INTO mailbox_devices (id, mailbox_id, label) VALUES ($1,$2,$3)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(request.device_id)
    .bind(mailbox_id)
    .bind(&request.label)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(StatusCode::CREATED)
}

async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListDevicesResponseV1>, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    let rows = sqlx::query(
        "SELECT id, label, extract(epoch from enrolled_at)::bigint AS enrolled_at, revoked_at
         FROM mailbox_devices WHERE mailbox_id=$1 ORDER BY enrolled_at",
    )
    .bind(mailbox_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(ListDevicesResponseV1 {
        devices: rows
            .into_iter()
            .map(|row| DeviceV1 {
                id: row.get("id"),
                label: row.get("label"),
                enrolled_at: row.get("enrolled_at"),
                revoked: row.get::<Option<OffsetDateTime>, _>("revoked_at").is_some(),
            })
            .collect(),
    }))
}

/// Secure v1 device removal. Device credentials are mailbox-wide in protocol v1,
/// so an individual stolen device cannot be cut off without also invalidating the
/// credentials held by every other secondary device. This operation atomically:
///   * rotates read and administrator capability verifiers,
///   * overwrites the shared state with a blob encrypted under a new client root,
///   * revokes every registered device except the caller.
/// The retained device persists the new raw secrets only after this transaction
/// succeeds; all other devices must complete the authenticated enrollment again.
async fn secure_device_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SecureDeviceResetRequestV1>,
) -> Result<Json<SecureDeviceResetResponseV1>, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    // Re-check the presented administrator credential while holding the mailbox
    // row lock. Without this, two concurrent resets authenticated with the same
    // old credential could both pass the preflight check and the second could
    // overwrite the first reset after its credentials had already been rotated.
    let presented_admin = verifier(
        CapabilityKind::Admin,
        authorization_capability(&headers, "BlackspaceAdmin")?,
    )
    .map_err(|_| ApiError::unauthorized())?;
    if request.expected_mls_state_version <= 0 {
        return Err(ApiError::invalid_request());
    }
    if request.revoke_deposit_capability_ids.len() > 16 {
        return Err(ApiError::invalid_request());
    }
    let read = decode_verifier(&request.read_capability_verifier)
        .map_err(|_| ApiError::invalid_request())?;
    let admin = decode_verifier(&request.admin_capability_verifier)
        .map_err(|_| ApiError::invalid_request())?;
    if bool::from(read.ct_eq(&admin)) {
        return Err(ApiError::invalid_request());
    }
    let ciphertext = validate_sized_ciphertext(
        &request.mls_state_ciphertext,
        request.mls_state_size_class,
        &MLS_STATE_SIZE_CLASSES,
    )?;

    let mut tx = state.pool.begin().await.map_err(ApiError::internal)?;
    let locked_mailbox = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM mailboxes
         WHERE id=$1 AND admin_capability_verifier=$2 AND disabled_at IS NULL
         FOR UPDATE",
    )
    .bind(mailbox_id)
    .bind(presented_admin.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    if locked_mailbox.is_none() {
        return Err(ApiError::unauthorized());
    }
    let current_device = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM mailbox_devices
         WHERE id=$1 AND mailbox_id=$2 AND revoked_at IS NULL FOR UPDATE",
    )
    .bind(request.current_device_id)
    .bind(mailbox_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    if current_device.is_none() {
        return Err(ApiError::unauthorized());
    }
    let current_version: i64 =
        sqlx::query_scalar("SELECT version FROM mls_state_blobs WHERE mailbox_id=$1 FOR UPDATE")
            .bind(mailbox_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(ApiError::version_conflict)?;
    let next = cas_next_version(Some(current_version), request.expected_mls_state_version)
        .ok_or_else(ApiError::version_conflict)?;

    sqlx::query(
        "UPDATE mls_state_blobs
         SET version=$1,size_class=$2,ciphertext=$3,updated_at=now()
         WHERE mailbox_id=$4",
    )
    .bind(next)
    .bind(request.mls_state_size_class as i32)
    .bind(ciphertext)
    .bind(mailbox_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    sqlx::query(
        "UPDATE mailboxes SET read_capability_verifier=$1,admin_capability_verifier=$2 WHERE id=$3",
    )
    .bind(read.as_slice())
    .bind(admin.as_slice())
    .bind(mailbox_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| map_conflict(error, "capability_conflict"))?;
    let revoked_devices = sqlx::query(
        "UPDATE mailbox_devices SET revoked_at=now()
         WHERE mailbox_id=$1 AND id<>$2 AND revoked_at IS NULL",
    )
    .bind(mailbox_id)
    .bind(request.current_device_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?
    .rows_affected();
    if !request.revoke_deposit_capability_ids.is_empty() {
        sqlx::query(
            "UPDATE deposit_capabilities SET revoked_at=now()
             WHERE mailbox_id=$1 AND id=ANY($2) AND revoked_at IS NULL",
        )
        .bind(mailbox_id)
        .bind(&request.revoke_deposit_capability_ids)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    }
    tx.commit().await.map_err(ApiError::internal)?;

    Ok(Json(SecureDeviceResetResponseV1 {
        version: next,
        revoked_devices,
    }))
}

async fn publish_key_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PublishKeyPackagesRequestV1>,
) -> Result<(StatusCode, Json<PublishKeyPackagesResponseV1>), ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    let identity: String =
        sqlx::query_scalar("SELECT identity_public_key FROM mailboxes WHERE id=$1")
            .bind(mailbox_id)
            .fetch_one(&state.pool)
            .await
            .map_err(ApiError::internal)?;
    let packages = validate_key_packages(&request.key_packages, &identity)?;
    if packages.is_empty() {
        return Err(ApiError::invalid_request());
    }
    let accepted = packages.len() as u16;
    let mut tx = state.pool.begin().await.map_err(ApiError::internal)?;
    insert_key_packages(&mut tx, mailbox_id, packages).await?;
    let available: i64 = sqlx::query_scalar("SELECT count(*) FROM key_packages WHERE mailbox_id=$1 AND claimed_at IS NULL AND expires_at > now()")
        .bind(mailbox_id).fetch_one(&mut *tx).await.map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(PublishKeyPackagesResponseV1 {
            accepted,
            available: available as u32,
        }),
    ))
}

async fn claim_key_package(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ClaimKeyPackageResponseV1>, ApiError> {
    let (mailbox_id, _) = authorize_deposit(&state, &headers).await?;
    let mut tx = state.pool.begin().await.map_err(ApiError::internal)?;
    let row = sqlx::query("SELECT package_id, protocol_version, ciphersuite, identity_public_key, key_package, extract(epoch from expires_at)::bigint AS expires_at FROM key_packages WHERE mailbox_id=$1 AND claimed_at IS NULL AND expires_at > now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1")
        .bind(mailbox_id).fetch_optional(&mut *tx).await.map_err(ApiError::internal)?
        .ok_or_else(ApiError::unavailable)?;
    let package = key_package_from_row(&row);
    sqlx::query("UPDATE key_packages SET claimed_at=now() WHERE package_id=$1")
        .bind(package.package_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(ClaimKeyPackageResponseV1 {
        key_package: package,
    }))
}

async fn deposit_envelope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<EnvelopeV1>,
) -> Result<(StatusCode, Json<DepositAcceptedV1>), ApiError> {
    require_content_type(&headers, "application/blackspace-envelope+json")?;
    let (mailbox_id, capability_id) = authorize_deposit(&state, &headers).await?;
    let raw = authorization_capability(&headers, "BlackspaceDeposit")?;
    let rate_key = verifier(CapabilityKind::Deposit, raw).map_err(|_| ApiError::unavailable())?;
    if !state.deposit_limiter.allow(rate_key) {
        return Err(ApiError::rate_limited());
    }
    let ciphertext = validate_envelope(&envelope)?;
    let expires_at = OffsetDateTime::from_unix_timestamp(envelope.expires_at)
        .map_err(|_| ApiError::invalid_request())?;
    let acknowledgement_token = generate_capability().map_err(ApiError::internal)?;
    let mut tx = state.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query("SELECT id FROM mailboxes WHERE id=$1 FOR UPDATE")
        .bind(mailbox_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query("DELETE FROM envelopes WHERE mailbox_id=$1 AND expires_at<=now()")
        .bind(mailbox_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM envelopes WHERE mailbox_id=$1")
        .bind(mailbox_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    if queued >= MAX_QUEUED_ENVELOPES {
        return Err(ApiError::unavailable());
    }
    sqlx::query("INSERT INTO envelopes (mailbox_id,envelope_id,version,expires_at,size_class,ciphertext,acknowledgement_token,deposit_capability_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(mailbox_id).bind(envelope.envelope_id).bind(envelope.version as i16).bind(expires_at)
        .bind(envelope.size_class as i32).bind(ciphertext).bind(acknowledgement_token).bind(capability_id)
        .execute(&mut *tx).await.map_err(|error| map_conflict(error, "duplicate_envelope"))?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(DepositAcceptedV1 { accepted: true }),
    ))
}

async fn pull_envelopes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PullRequestV1>,
) -> Result<Json<PullResponseV1>, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceRead",
        CapabilityKind::Read,
        "read_capability_verifier",
    )
    .await?;
    let limit = request.limit.unwrap_or(MAX_PULL_BATCH);
    if limit == 0 || limit > MAX_PULL_BATCH {
        return Err(ApiError::invalid_request());
    }
    sqlx::query("DELETE FROM envelopes WHERE mailbox_id=$1 AND expires_at<=now()")
        .bind(mailbox_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let rows = sqlx::query("SELECT envelope_id,version,extract(epoch from expires_at)::bigint AS expires_at,size_class,ciphertext,acknowledgement_token,deposit_capability_id FROM envelopes WHERE mailbox_id=$1 ORDER BY created_at,envelope_id LIMIT $2")
        .bind(mailbox_id).bind(i64::from(limit)).fetch_all(&state.pool).await.map_err(ApiError::internal)?;
    Ok(Json(PullResponseV1 {
        envelopes: rows
            .into_iter()
            .map(|row| PulledEnvelopeV1 {
                version: row.get::<i16, _>("version") as u16,
                envelope_id: row.get("envelope_id"),
                expires_at: row.get("expires_at"),
                size_class: row.get::<i32, _>("size_class") as usize,
                ciphertext: URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("ciphertext")),
                acknowledgement_token: row.get("acknowledgement_token"),
                deposit_capability_id: row.get("deposit_capability_id"),
            })
            .collect(),
    }))
}

async fn acknowledge_envelopes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AckRequestV1>,
) -> Result<Json<AckResponseV1>, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceRead",
        CapabilityKind::Read,
        "read_capability_verifier",
    )
    .await?;
    if request.acknowledgement_tokens.is_empty()
        || request.acknowledgement_tokens.len() > usize::from(MAX_PULL_BATCH)
        || request
            .acknowledgement_tokens
            .iter()
            .any(|token| verifier(CapabilityKind::Read, token).is_err())
    {
        return Err(ApiError::invalid_request());
    }
    let result =
        sqlx::query("DELETE FROM envelopes WHERE mailbox_id=$1 AND acknowledgement_token=ANY($2)")
            .bind(mailbox_id)
            .bind(&request.acknowledgement_tokens)
            .execute(&state.pool)
            .await
            .map_err(ApiError::internal)?;
    Ok(Json(AckResponseV1 {
        acknowledged: result.rows_affected(),
    }))
}

async fn recover_mailbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RecoverMailboxRequestV1>,
) -> Result<Json<RecoverMailboxResponseV1>, ApiError> {
    let mailbox_id = authorize_mailbox(
        &state.pool,
        &headers,
        "BlackspaceAdmin",
        CapabilityKind::Admin,
        "admin_capability_verifier",
    )
    .await?;
    validate_identity(&request.identity_public_key)?;
    let read = decode_verifier(&request.read_capability_verifier)
        .map_err(|_| ApiError::invalid_request())?;
    let admin = decode_verifier(&request.admin_capability_verifier)
        .map_err(|_| ApiError::invalid_request())?;
    if request.deposit_capabilities.is_empty()
        || request.deposit_capabilities.len() > MAX_KEY_PACKAGE_BATCH
    {
        return Err(ApiError::invalid_request());
    }
    let deposits: Vec<_> = request
        .deposit_capabilities
        .iter()
        .map(|cap| {
            Ok((
                decode_verifier(&cap.verifier).map_err(|_| ApiError::invalid_request())?,
                optional_expiry(cap.expires_at, MAX_KEY_PACKAGE_AGE_SECONDS)?,
            ))
        })
        .collect::<Result<_, ApiError>>()?;
    let packages = validate_key_packages(&request.key_packages, &request.identity_public_key)?;
    if packages.is_empty() {
        return Err(ApiError::invalid_request());
    }
    let mut tx = state.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query("SELECT id FROM mailboxes WHERE id=$1 FOR UPDATE")
        .bind(mailbox_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let purged = sqlx::query("DELETE FROM envelopes WHERE mailbox_id=$1")
        .bind(mailbox_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?
        .rows_affected();
    let revoked = sqlx::query("UPDATE deposit_capabilities SET revoked_at=now() WHERE mailbox_id=$1 AND revoked_at IS NULL").bind(mailbox_id).execute(&mut *tx).await.map_err(ApiError::internal)?.rows_affected();
    sqlx::query("DELETE FROM key_packages WHERE mailbox_id=$1")
        .bind(mailbox_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query("UPDATE mailboxes SET read_capability_verifier=$2,admin_capability_verifier=$3,identity_public_key=$4,recovered_at=now() WHERE id=$1")
        .bind(mailbox_id).bind(read.as_slice()).bind(admin.as_slice()).bind(&request.identity_public_key)
        .execute(&mut *tx).await.map_err(|error| map_conflict(error, "mailbox_conflict"))?;
    let mut ids = Vec::with_capacity(deposits.len());
    for (digest, expiry) in deposits {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO deposit_capabilities (id,mailbox_id,verifier,expires_at) VALUES ($1,$2,$3,$4)")
            .bind(id).bind(mailbox_id).bind(digest.as_slice()).bind(expiry).execute(&mut *tx).await.map_err(ApiError::internal)?;
        ids.push(id);
    }
    insert_key_packages(&mut tx, mailbox_id, packages).await?;
    sqlx::query("INSERT INTO mailbox_recoveries (id,mailbox_id,purged_envelopes,revoked_deposit_capabilities) VALUES ($1,$2,$3,$4)")
        .bind(Uuid::new_v4()).bind(mailbox_id).bind(purged as i64).bind(revoked as i64).execute(&mut *tx).await.map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(RecoverMailboxResponseV1 {
        mailbox_id,
        deposit_capability_ids: ids,
        purged_envelopes: purged,
    }))
}

async fn authorize_deposit(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Uuid, Uuid), ApiError> {
    let raw = authorization_capability(headers, "BlackspaceDeposit")?;
    let digest = verifier(CapabilityKind::Deposit, raw).map_err(|_| ApiError::unavailable())?;
    let row = sqlx::query("SELECT d.mailbox_id,d.id FROM deposit_capabilities d JOIN mailboxes m ON m.id=d.mailbox_id WHERE d.verifier=$1 AND d.revoked_at IS NULL AND (d.expires_at IS NULL OR d.expires_at>now()) AND m.disabled_at IS NULL")
        .bind(digest.as_slice()).fetch_optional(&state.pool).await.map_err(ApiError::internal)?.ok_or_else(ApiError::unavailable)?;
    Ok((row.get("mailbox_id"), row.get("id")))
}

fn authorization_capability<'a>(
    headers: &'a HeaderMap,
    expected: &str,
) -> Result<&'a str, ApiError> {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let (scheme, capability) = value.split_once(' ').ok_or_else(ApiError::unauthorized)?;
    if !bool::from(scheme.as_bytes().ct_eq(expected.as_bytes())) || capability.contains(' ') {
        return Err(ApiError::unauthorized());
    }
    Ok(capability)
}

async fn authorize_mailbox(
    pool: &PgPool,
    headers: &HeaderMap,
    scheme: &str,
    kind: CapabilityKind,
    column: &'static str,
) -> Result<Uuid, ApiError> {
    let raw = authorization_capability(headers, scheme)?;
    let digest = verifier(kind, raw).map_err(|_| ApiError::unauthorized())?;
    let query = format!("SELECT id FROM mailboxes WHERE {column}=$1 AND disabled_at IS NULL");
    sqlx::query_scalar(&query)
        .bind(digest.as_slice())
        .fetch_optional(pool)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::unauthorized)
}

fn validate_identity(identity: &str) -> Result<(), ApiError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(identity)
        .map_err(|_| ApiError::invalid_request())?;
    if !(32..=128).contains(&decoded.len()) || URL_SAFE_NO_PAD.encode(decoded) != identity {
        return Err(ApiError::invalid_request());
    }
    Ok(())
}

fn validate_key_packages(
    packages: &[KeyPackageV1],
    identity: &str,
) -> Result<Vec<(KeyPackageV1, Vec<u8>)>, ApiError> {
    if packages.is_empty() || packages.len() > MAX_KEY_PACKAGE_BATCH {
        return Err(ApiError::invalid_request());
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    packages
        .iter()
        .map(|package| {
            if package.protocol_version != 1
                || package.ciphersuite != MLS_CIPHERSUITE
                || package.identity_public_key != identity
                || package.expires_at <= now
                || package.expires_at > now + MAX_KEY_PACKAGE_AGE_SECONDS
            {
                return Err(ApiError::invalid_request());
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(&package.key_package)
                .map_err(|_| ApiError::invalid_request())?;
            if !(32..=65_536).contains(&bytes.len())
                || URL_SAFE_NO_PAD.encode(&bytes) != package.key_package
                || blackspace_core::validate_mls_key_package(identity, &bytes).is_err()
            {
                return Err(ApiError::invalid_request());
            }
            Ok((package.clone(), bytes))
        })
        .collect()
}

async fn insert_key_packages(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mailbox_id: Uuid,
    packages: Vec<(KeyPackageV1, Vec<u8>)>,
) -> Result<(), ApiError> {
    for (package, bytes) in packages {
        let expiry = OffsetDateTime::from_unix_timestamp(package.expires_at)
            .map_err(|_| ApiError::invalid_request())?;
        sqlx::query("INSERT INTO key_packages (package_id,mailbox_id,protocol_version,ciphersuite,identity_public_key,key_package,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(package.package_id).bind(mailbox_id).bind(package.protocol_version as i16).bind(package.ciphersuite)
            .bind(package.identity_public_key).bind(bytes).bind(expiry).execute(&mut **tx).await
            .map_err(|error| map_conflict(error, "key_package_conflict"))?;
    }
    Ok(())
}

fn key_package_from_row(row: &sqlx::postgres::PgRow) -> KeyPackageV1 {
    KeyPackageV1 {
        package_id: row.get("package_id"),
        protocol_version: row.get::<i16, _>("protocol_version") as u16,
        ciphersuite: row.get("ciphersuite"),
        identity_public_key: row.get("identity_public_key"),
        key_package: URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("key_package")),
        expires_at: row.get("expires_at"),
    }
}

fn validate_envelope(envelope: &EnvelopeV1) -> Result<Vec<u8>, ApiError> {
    if envelope.version != 1 {
        return Err(ApiError::invalid_request());
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if envelope.expires_at <= now || envelope.expires_at > now + MAX_RETENTION_SECONDS {
        return Err(ApiError::invalid_request());
    }
    validate_sized_ciphertext(&envelope.ciphertext, envelope.size_class, &SIZE_CLASSES)
}

/// Compare-and-swap decision for the shared MLS-state version. Returns the version
/// to store when `expected` matches the current state (absent state matches 0), or
/// `None` when the caller raced another device and must re-read.
fn cas_next_version(current: Option<i64>, expected: i64) -> Option<i64> {
    if current.unwrap_or(0) == expected {
        Some(expected + 1)
    } else {
        None
    }
}

/// Decode a base64url ciphertext and enforce that its exact length equals a declared,
/// allowed size class (fixed-size padding is what denies the server length metadata).
fn validate_sized_ciphertext(
    ciphertext: &str,
    size_class: usize,
    allowed: &[usize],
) -> Result<Vec<u8>, ApiError> {
    if !allowed.contains(&size_class) {
        return Err(ApiError::invalid_request());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(ciphertext)
        .map_err(|_| ApiError::invalid_request())?;
    if bytes.len() != size_class || URL_SAFE_NO_PAD.encode(&bytes) != ciphertext {
        return Err(ApiError::invalid_request());
    }
    Ok(bytes)
}

fn optional_expiry(value: Option<i64>, maximum: i64) -> Result<Option<OffsetDateTime>, ApiError> {
    value
        .map(|timestamp| {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            if timestamp <= now || timestamp > now + maximum {
                return Err(ApiError::invalid_request());
            }
            OffsetDateTime::from_unix_timestamp(timestamp).map_err(|_| ApiError::invalid_request())
        })
        .transpose()
}

fn require_content_type(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let actual = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim);
    if actual != Some(expected) {
        return Err(ApiError::invalid_request());
    }
    Ok(())
}

fn map_conflict(error: sqlx::Error, code: &'static str) -> ApiError {
    if matches!(&error, sqlx::Error::Database(db) if db.is_unique_violation()) {
        ApiError {
            status: StatusCode::CONFLICT,
            code,
            message: "The operation conflicts with existing state.",
        }
    } else {
        ApiError::internal(error)
    }
}

fn spawn_expiry_cleanup(pool: PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            for statement in [
                "DELETE FROM envelopes WHERE expires_at<=now()",
                "DELETE FROM key_packages WHERE expires_at<=now() OR claimed_at < now() - interval '24 hours'",
                "DELETE FROM registration_invitations WHERE expires_at < now() - interval '24 hours'",
                "DELETE FROM enrollment_parcels WHERE expires_at < now() OR claimed_at < now() - interval '1 hour'",
            ] {
                if let Err(error) = sqlx::query(statement).execute(&pool).await {
                    error!(error=%error, "expiry cleanup failed");
                }
            }
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}

pub fn parse_listen_addr(value: &str) -> anyhow::Result<SocketAddr> {
    Ok(SocketAddr::from_str(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_exact_size_and_expiry() {
        let envelope = EnvelopeV1 {
            version: 1,
            envelope_id: Uuid::new_v4(),
            expires_at: OffsetDateTime::now_utc().unix_timestamp() + 60,
            size_class: 1024,
            ciphertext: URL_SAFE_NO_PAD.encode([7_u8; 1024]),
        };
        assert_eq!(validate_envelope(&envelope).unwrap().len(), 1024);
    }

    #[test]
    fn cors_is_deliberately_narrow() {
        assert!(cors_public_path("/v1/deposit/envelopes"));
        assert!(!cors_public_path("/v1/mailbox/pull"));
        assert!(!cors_public_path("/v1/mailbox/recover"));
    }

    #[test]
    fn limiter_allows_thirty_per_minute() {
        let limiter = DepositRateLimiter::default();
        for _ in 0..30 {
            assert!(limiter.allow([4_u8; 32]));
        }
        assert!(!limiter.allow([4_u8; 32]));
    }

    #[test]
    fn cas_accepts_matching_version_and_rejects_races() {
        // First write: no stored state, expected 0 -> store version 1.
        assert_eq!(cas_next_version(None, 0), Some(1));
        // Matching expected version advances by one.
        assert_eq!(cas_next_version(Some(4), 4), Some(5));
        // A stale expected version (another device already committed) is rejected.
        assert_eq!(cas_next_version(Some(5), 4), None);
        // A first write that wrongly assumes existing state is rejected.
        assert_eq!(cas_next_version(None, 3), None);
    }

    #[test]
    fn sized_ciphertext_requires_exact_declared_class() {
        let padded = URL_SAFE_NO_PAD.encode([9_u8; 4096]);
        assert_eq!(
            validate_sized_ciphertext(&padded, 4096, &MLS_STATE_SIZE_CLASSES)
                .unwrap()
                .len(),
            4096
        );
        // Declared class not in the allowed set.
        assert!(validate_sized_ciphertext(&padded, 4096, &SIZE_CLASSES[..1]).is_err());
        // Actual length disagrees with the declared class.
        assert!(validate_sized_ciphertext(&padded, 16_384, &MLS_STATE_SIZE_CLASSES).is_err());
    }

    #[test]
    fn limiter_evicts_expired_windows() {
        let limiter = DepositRateLimiter::default();
        let start = Instant::now();
        assert!(limiter.allow_at([1_u8; 32], start));
        assert!(limiter.allow_at([2_u8; 32], start));
        assert_eq!(limiter.tracked_keys(), 2);
        // A request after the window elapses sweeps the expired entries.
        let later = start + DepositRateLimiter::WINDOW + Duration::from_secs(1);
        assert!(limiter.allow_at([3_u8; 32], later));
        assert_eq!(limiter.tracked_keys(), 1);
        // A key with recent attempts survives the sweep.
        assert!(limiter.allow_at([4_u8; 32], later + Duration::from_secs(30)));
        let final_sweep = later + DepositRateLimiter::WINDOW + Duration::from_secs(1);
        assert!(limiter.allow_at([5_u8; 32], final_sweep));
        assert_eq!(limiter.tracked_keys(), 2);
    }
}
