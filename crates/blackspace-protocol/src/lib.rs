//! Authoritative, versioned wire types for the Blackspace v0.1 private alpha.

use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const SIZE_CLASSES: [usize; 5] = [1_024, 4_096, 16_384, 65_536, 262_144];
/// Coarse size buckets for the shared MLS-state blob. Larger than the envelope
/// classes because the serialized OpenMLS client state grows with contacts and
/// key packages; the top bucket stays under the 3.8 MB request-body limit.
pub const MLS_STATE_SIZE_CLASSES: [usize; 6] =
    [4_096, 16_384, 65_536, 262_144, 1_048_576, 3_145_728];
pub const MAX_QUEUED_ENVELOPES: i64 = 1_000;
pub const DEFAULT_RETENTION_SECONDS: i64 = 14 * 24 * 60 * 60;
pub const MAX_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const MAX_PULL_BATCH: u16 = 100;
pub const MAX_KEY_PACKAGE_BATCH: usize = 50;
pub const DEFAULT_KEY_PACKAGE_POOL: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct FeatureFlagsV1 {
    pub opaque_transport: bool,
    pub key_packages: bool,
    pub mls: bool,
    pub registration_invites: bool,
    pub recovery_takeover: bool,
    pub companion_linking: bool,
    /// Floating-primary multi-device: shared MLS-state CAS blob + one-scan enrollment.
    /// Defaulted so a client can still parse an older server's /v1/info without it.
    #[serde(default)]
    pub multi_device: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ServerInfoV1 {
    pub instance_name: String,
    pub onion_origin: Option<String>,
    pub https_origin: Option<String>,
    pub protocol_versions: Vec<u16>,
    pub maximum_envelope_bytes: usize,
    pub envelope_size_classes: Vec<usize>,
    pub maximum_queued_envelopes: i64,
    pub default_retention_seconds: i64,
    pub maximum_retention_seconds: i64,
    pub maximum_pull_batch: u16,
    pub features: FeatureFlagsV1,
}

impl Default for ServerInfoV1 {
    fn default() -> Self {
        Self {
            instance_name: "Blackspace".into(),
            onion_origin: None,
            https_origin: None,
            protocol_versions: vec![PROTOCOL_VERSION],
            maximum_envelope_bytes: *SIZE_CLASSES.last().expect("size classes are non-empty"),
            envelope_size_classes: SIZE_CLASSES.to_vec(),
            maximum_queued_envelopes: MAX_QUEUED_ENVELOPES,
            default_retention_seconds: DEFAULT_RETENTION_SECONDS,
            maximum_retention_seconds: MAX_RETENTION_SECONDS,
            maximum_pull_batch: MAX_PULL_BATCH,
            features: FeatureFlagsV1 {
                opaque_transport: true,
                key_packages: true,
                mls: true,
                registration_invites: true,
                recovery_takeover: true,
                companion_linking: true,
                multi_device: true,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ProblemV1 {
    pub code: String,
    pub message: String,
}

/// An opaque, client-signed MLS key package. The mailbox validates bounds and
/// expiry; the claiming client authenticates it against `identity_public_key`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct KeyPackageV1 {
    pub package_id: Uuid,
    pub protocol_version: u16,
    pub ciphersuite: String,
    pub identity_public_key: String,
    pub key_package: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct MailboxProvisionRequestV1 {
    pub identity_public_key: String,
    pub read_capability_verifier: String,
    pub admin_capability_verifier: String,
    pub initial_deposit_capability_verifier: String,
    pub initial_deposit_expires_at: Option<i64>,
    pub key_packages: Vec<KeyPackageV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct MailboxProvisionResponseV1 {
    pub mailbox_id: Uuid,
    pub initial_deposit_capability_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct CreateDepositCapabilityRequestV1 {
    pub verifier: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct CreateDepositCapabilityResponseV1 {
    pub capability_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PublishKeyPackagesRequestV1 {
    pub key_packages: Vec<KeyPackageV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PublishKeyPackagesResponseV1 {
    pub accepted: u16,
    pub available: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ClaimKeyPackageResponseV1 {
    pub key_package: KeyPackageV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RecoverMailboxRequestV1 {
    pub identity_public_key: String,
    pub read_capability_verifier: String,
    pub admin_capability_verifier: String,
    pub deposit_capabilities: Vec<CreateDepositCapabilityRequestV1>,
    pub key_packages: Vec<KeyPackageV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RecoverMailboxResponseV1 {
    pub mailbox_id: Uuid,
    pub deposit_capability_ids: Vec<Uuid>,
    pub purged_envelopes: u64,
}

/// Rotate only the mailbox read capability. Used to cut a linked companion's
/// read access on unlink without the destructive full recovery/takeover flow.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RotateReadCapabilityRequestV1 {
    pub read_capability_verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RotateReadCapabilityResponseV1 {
    pub ok: bool,
}

// ---- Multi-device (floating primary): shared MLS-state blob + one-scan enrollment ----

/// The shared, client-encrypted MLS client state. `version` is a monotonically
/// increasing compare-and-swap counter: only the latest is stored (older ratchet
/// states are overwritten, limiting the forward-secrecy exposure of at-rest state).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct MlsStateResponseV1 {
    pub version: i64,
    pub size_class: usize,
    pub ciphertext: String,
}

/// Compare-and-swap write of the shared MLS state. The write succeeds only when
/// `expected_version` equals the currently stored version (0 for the first write);
/// otherwise the server returns 409 and the client re-reads before retrying. This
/// is what makes a ratchet fork impossible across concurrent devices.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PutMlsStateRequestV1 {
    pub expected_version: i64,
    pub size_class: usize,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PutMlsStateResponseV1 {
    pub version: i64,
}

/// A one-time enrollment parcel parked by an already-enrolled device for a new
/// device to claim. The ciphertext is sealed to the new device's ephemeral public
/// key (carried in `eph_pub`); the server sees only opaque bytes and never a secret.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ParkEnrollmentParcelRequestV1 {
    pub parcel_verifier: String,
    pub eph_pub: String,
    pub nonce: String,
    pub size_class: usize,
    pub ciphertext: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ParkEnrollmentParcelResponseV1 {
    pub parcel_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ClaimEnrollmentParcelResponseV1 {
    pub eph_pub: String,
    pub nonce: String,
    pub size_class: usize,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RegisterDeviceRequestV1 {
    pub device_id: Uuid,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct DeviceV1 {
    pub id: Uuid,
    pub label: String,
    pub enrolled_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ListDevicesResponseV1 {
    pub devices: Vec<DeviceV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct EnvelopeV1 {
    pub version: u16,
    pub envelope_id: Uuid,
    pub expires_at: i64,
    pub size_class: usize,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct DepositAcceptedV1 {
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Default)]
pub struct PullRequestV1 {
    pub limit: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PulledEnvelopeV1 {
    pub version: u16,
    pub envelope_id: Uuid,
    pub expires_at: i64,
    pub size_class: usize,
    pub ciphertext: String,
    pub acknowledgement_token: String,
    pub deposit_capability_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PullResponseV1 {
    pub envelopes: Vec<PulledEnvelopeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct AckRequestV1 {
    pub acknowledgement_tokens: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct AckResponseV1 {
    pub acknowledged: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransportMode {
    TorNative,
    TorWeb,
    HttpsWeb,
    CompatibilityWebDev,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct DepositTargetV1 {
    pub onion_url: String,
    pub https_url: Option<String>,
    pub deposit_capability: String,
}

#[doc(hidden)]
#[utoipa::path(get, path = "/v1/info", responses((status = 200, body = ServerInfoV1)))]
pub fn api_server_info() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/mailboxes", request_body = MailboxProvisionRequestV1,
    responses((status = 201, body = MailboxProvisionResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_provision_mailbox() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/mailbox/deposit-capabilities", request_body = CreateDepositCapabilityRequestV1,
    responses((status = 201, body = CreateDepositCapabilityResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_create_deposit_capability() {}

#[doc(hidden)]
#[utoipa::path(delete, path = "/v1/mailbox/deposit-capabilities/{capability_id}",
    params(("capability_id" = Uuid, Path)), responses((status = 204), (status = 401, body = ProblemV1)))]
pub fn api_revoke_deposit_capability() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/mailbox/key-packages", request_body = PublishKeyPackagesRequestV1,
    responses((status = 201, body = PublishKeyPackagesResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_publish_key_packages() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/deposit/key-packages/claim",
    responses((status = 200, body = ClaimKeyPackageResponseV1), (status = 503, body = ProblemV1)))]
pub fn api_claim_key_package() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/deposit/envelopes",
    request_body(content = EnvelopeV1, content_type = "application/blackspace-envelope+json"),
    responses((status = 202, body = DepositAcceptedV1), (status = 400, body = ProblemV1), (status = 503, body = ProblemV1)))]
pub fn api_deposit_envelope() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/mailbox/pull", request_body = PullRequestV1,
    responses((status = 200, body = PullResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_pull_envelopes() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/mailbox/ack", request_body = AckRequestV1,
    responses((status = 200, body = AckResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_acknowledge_envelopes() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/mailbox/recover", request_body = RecoverMailboxRequestV1,
    responses((status = 200, body = RecoverMailboxResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_recover_mailbox() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/mailbox/read-capability/rotate", request_body = RotateReadCapabilityRequestV1,
    responses((status = 200, body = RotateReadCapabilityResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_rotate_read_capability() {}

#[doc(hidden)]
#[utoipa::path(get, path = "/v1/mailbox/mls-state",
    responses((status = 200, body = MlsStateResponseV1), (status = 204), (status = 401, body = ProblemV1)))]
pub fn api_get_mls_state() {}

#[doc(hidden)]
#[utoipa::path(put, path = "/v1/mailbox/mls-state", request_body = PutMlsStateRequestV1,
    responses((status = 200, body = PutMlsStateResponseV1), (status = 401, body = ProblemV1), (status = 409, body = ProblemV1)))]
pub fn api_put_mls_state() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/enroll/parcels", request_body = ParkEnrollmentParcelRequestV1,
    responses((status = 201, body = ParkEnrollmentParcelResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_park_enrollment_parcel() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/enroll/parcels/claim",
    responses((status = 200, body = ClaimEnrollmentParcelResponseV1), (status = 404, body = ProblemV1)))]
pub fn api_claim_enrollment_parcel() {}

#[doc(hidden)]
#[utoipa::path(post, path = "/v1/mailbox/devices", request_body = RegisterDeviceRequestV1,
    responses((status = 201), (status = 401, body = ProblemV1)))]
pub fn api_register_device() {}

#[doc(hidden)]
#[utoipa::path(get, path = "/v1/mailbox/devices",
    responses((status = 200, body = ListDevicesResponseV1), (status = 401, body = ProblemV1)))]
pub fn api_list_devices() {}

#[doc(hidden)]
#[utoipa::path(delete, path = "/v1/mailbox/devices/{device_id}",
    params(("device_id" = Uuid, Path)), responses((status = 204), (status = 401, body = ProblemV1)))]
pub fn api_revoke_device() {}

#[derive(OpenApi)]
#[openapi(
    paths(
        api_server_info,
        api_provision_mailbox,
        api_create_deposit_capability,
        api_revoke_deposit_capability,
        api_publish_key_packages,
        api_claim_key_package,
        api_deposit_envelope,
        api_pull_envelopes,
        api_acknowledge_envelopes,
        api_recover_mailbox,
        api_rotate_read_capability,
        api_get_mls_state,
        api_put_mls_state,
        api_park_enrollment_parcel,
        api_claim_enrollment_parcel,
        api_register_device,
        api_list_devices,
        api_revoke_device
    ),
    components(schemas(
        FeatureFlagsV1,
        ServerInfoV1,
        ProblemV1,
        KeyPackageV1,
        MailboxProvisionRequestV1,
        MailboxProvisionResponseV1,
        CreateDepositCapabilityRequestV1,
        CreateDepositCapabilityResponseV1,
        PublishKeyPackagesRequestV1,
        PublishKeyPackagesResponseV1,
        ClaimKeyPackageResponseV1,
        RecoverMailboxRequestV1,
        RecoverMailboxResponseV1,
        RotateReadCapabilityRequestV1,
        RotateReadCapabilityResponseV1,
        MlsStateResponseV1,
        PutMlsStateRequestV1,
        PutMlsStateResponseV1,
        ParkEnrollmentParcelRequestV1,
        ParkEnrollmentParcelResponseV1,
        ClaimEnrollmentParcelResponseV1,
        RegisterDeviceRequestV1,
        DeviceV1,
        ListDevicesResponseV1,
        EnvelopeV1,
        DepositAcceptedV1,
        PullRequestV1,
        PulledEnvelopeV1,
        PullResponseV1,
        AckRequestV1,
        AckResponseV1,
        TransportMode,
        DepositTargetV1
    ))
)]
pub struct ProtocolSchemas;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_private_alpha_protocol() {
        let info = ServerInfoV1::default();
        assert!(info.features.opaque_transport);
        assert!(info.features.key_packages);
        assert!(info.features.mls);
        assert!(info.features.registration_invites);
        assert!(info.features.multi_device);
        assert_eq!(info.maximum_envelope_bytes, 262_144);
    }

    #[test]
    fn mls_state_buckets_are_ascending_and_capped() {
        assert!(MLS_STATE_SIZE_CLASSES.windows(2).all(|w| w[0] < w[1]));
        // Stay under the 3.8 MB request-body limit the router enforces.
        assert!(*MLS_STATE_SIZE_CLASSES.last().unwrap() < 3_800_000);
    }
}
