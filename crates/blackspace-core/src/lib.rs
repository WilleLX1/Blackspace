//! Shared Blackspace client core.
//!
//! This crate deliberately owns all identity, MLS, invitation and vault
//! operations so UI code only handles opaque serialized results.

use std::collections::HashMap;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    ProcessedMessageContent, ProtocolVersion, SenderRatchetConfiguration, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use url::Url;
use uuid::Uuid;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

pub const MLS_CIPHERSUITE_NAME: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
pub const KEY_PACKAGE_TARGET: usize = 20;
pub const KEY_PACKAGE_REPLENISH_AT: usize = 5;
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
pub type MlsStorageSnapshot = Vec<(Vec<u8>, Vec<u8>)>;
const VAULT_AAD: &[u8] = b"blackspace:v1:vault-record";
const RECOVERY_AAD: &[u8] = b"blackspace:v1:recovery-kit";

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("secure randomness is unavailable")]
    Randomness,
    #[error("the invitation is invalid")]
    InvalidInvitation,
    #[error("the identity material is invalid")]
    InvalidIdentity,
    #[error("the message is invalid")]
    InvalidMessage,
    #[error("the vault could not be unlocked")]
    VaultUnlock,
    #[error("the encrypted record is invalid")]
    InvalidRecord,
    #[error("MLS operation failed: {0}")]
    Mls(String),
    #[error("serialization failed")]
    Serialization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinInvitationV1 {
    pub onion_origin: String,
    pub https_origin: Option<String>,
    pub registration_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactInvitationV1 {
    pub onion_origin: String,
    pub https_origin: Option<String>,
    pub deposit_capability: String,
    pub identity_public_key: String,
    pub invite_id: Uuid,
}

pub fn parse_join_invitation(value: &str) -> Result<JoinInvitationV1, CoreError> {
    let url = parse_invitation_base(value, "join")?;
    let query = query_map(&url);
    let fragment = fragment_map(&url)?;
    let onion = required_origin(query.get("onion"), true)?;
    let https = optional_https_origin(query.get("https"))?;
    let token = fragment.get("token").ok_or(CoreError::InvalidInvitation)?;
    validate_capability(token)?;
    Ok(JoinInvitationV1 {
        onion_origin: onion,
        https_origin: https,
        registration_token: token.clone(),
    })
}

pub fn parse_contact_invitation(value: &str) -> Result<ContactInvitationV1, CoreError> {
    let url = parse_invitation_base(value, "contact")?;
    let query = query_map(&url);
    let fragment = fragment_map(&url)?;
    let onion = required_origin(query.get("onion"), true)?;
    let https = optional_https_origin(query.get("https"))?;
    let capability = fragment.get("cap").ok_or(CoreError::InvalidInvitation)?;
    validate_capability(capability)?;
    let identity = fragment
        .get("identity")
        .ok_or(CoreError::InvalidInvitation)?;
    validate_identity_public_key(identity)?;
    let invite_id = fragment
        .get("invite")
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(CoreError::InvalidInvitation)?;
    Ok(ContactInvitationV1 {
        onion_origin: onion,
        https_origin: https,
        deposit_capability: capability.clone(),
        identity_public_key: identity.clone(),
        invite_id,
    })
}

pub fn format_contact_invitation(invite: &ContactInvitationV1) -> Result<String, CoreError> {
    required_origin(Some(&invite.onion_origin), true)?;
    optional_https_origin(invite.https_origin.as_ref())?;
    validate_capability(&invite.deposit_capability)?;
    validate_identity_public_key(&invite.identity_public_key)?;
    let mut url =
        Url::parse("blackspace://contact/v1").map_err(|_| CoreError::InvalidInvitation)?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("onion", &invite.onion_origin);
        query.append_pair("https", invite.https_origin.as_deref().unwrap_or(""));
    }
    url.set_fragment(Some(&format!(
        "cap={}&identity={}&invite={}",
        invite.deposit_capability, invite.identity_public_key, invite.invite_id
    )));
    Ok(url.into())
}

fn parse_invitation_base(value: &str, host: &str) -> Result<Url, CoreError> {
    let url = Url::parse(value).map_err(|_| CoreError::InvalidInvitation)?;
    if url.scheme() != "blackspace"
        || url.host_str() != Some(host)
        || url.path() != "/v1"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(CoreError::InvalidInvitation);
    }
    Ok(url)
}

fn query_map(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into(), value.into()))
        .collect()
}

fn fragment_map(url: &Url) -> Result<HashMap<String, String>, CoreError> {
    let fragment = url.fragment().ok_or(CoreError::InvalidInvitation)?;
    url::form_urlencoded::parse(fragment.as_bytes())
        .map(|(key, value)| (key.into(), value.into()))
        .collect::<HashMap<_, _>>()
        .pipe(Ok)
}

trait Pipe: Sized {
    fn pipe<T>(self, function: impl FnOnce(Self) -> T) -> T {
        function(self)
    }
}
impl<T> Pipe for T {}

fn required_origin(value: Option<&String>, onion: bool) -> Result<String, CoreError> {
    let value = value
        .filter(|value| !value.is_empty())
        .ok_or(CoreError::InvalidInvitation)?;
    let url = Url::parse(value).map_err(|_| CoreError::InvalidInvitation)?;
    let host = url.host_str().ok_or(CoreError::InvalidInvitation)?;
    let valid_onion = host.len() == 62
        && host.ends_with(".onion")
        && host[..56]
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'));
    if url.username() != ""
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || (onion && (url.scheme() != "http" || !valid_onion))
    {
        return Err(CoreError::InvalidInvitation);
    }
    Ok(value.trim_end_matches('/').to_string())
}

fn optional_https_origin(value: Option<&String>) -> Result<Option<String>, CoreError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let url = Url::parse(value).map_err(|_| CoreError::InvalidInvitation)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CoreError::InvalidInvitation);
    }
    Ok(Some(value.trim_end_matches('/').to_string()))
}

fn validate_capability(value: &str) -> Result<(), CoreError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CoreError::InvalidInvitation)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(CoreError::InvalidInvitation);
    }
    Ok(())
}

fn validate_identity_public_key(value: &str) -> Result<(), CoreError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CoreError::InvalidIdentity)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(CoreError::InvalidIdentity);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityV1 {
    /// Stored only inside the encrypted vault.
    pub signing_private_key: Vec<u8>,
    pub signing_public_key: String,
}

impl IdentityV1 {
    pub fn generate() -> Result<Self, CoreError> {
        let mut private = [0_u8; 32];
        getrandom::fill(&mut private).map_err(|_| CoreError::Randomness)?;
        let signing = SigningKey::from_bytes(&private);
        Ok(Self {
            signing_private_key: private.to_vec(),
            signing_public_key: URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
        })
    }

    pub fn sign(&self, payload: &[u8]) -> Result<String, CoreError> {
        let private: [u8; 32] = self
            .signing_private_key
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidIdentity)?;
        Ok(URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&private).sign(payload).to_bytes()))
    }

    pub fn verify(&self, payload: &[u8], signature: &str) -> Result<(), CoreError> {
        verify_signature(&self.signing_public_key, payload, signature)
    }
}

pub fn verify_signature(
    public_key: &str,
    payload: &[u8],
    signature: &str,
) -> Result<(), CoreError> {
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|_| CoreError::InvalidIdentity)?
        .try_into()
        .map_err(|_| CoreError::InvalidIdentity)?;
    let signature = ed25519_dalek::Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| CoreError::InvalidIdentity)?,
    )
    .map_err(|_| CoreError::InvalidIdentity)?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| CoreError::InvalidIdentity)?
        .verify(payload, &signature)
        .map_err(|_| CoreError::InvalidIdentity)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApplicationMessageV1 {
    Text {
        message_id: Uuid,
        sent_at_ms: i64,
        body: String,
    },
    DeliveryReceipt {
        message_ids: Vec<Uuid>,
        delivered_at_ms: i64,
    },
    Profile {
        display_name: String,
        reply_target: ContactInvitationV1,
    },
    SessionReset {
        reset_id: Uuid,
        occurred_at_ms: i64,
    },
}

pub fn encode_application_message(message: &ApplicationMessageV1) -> Result<Vec<u8>, CoreError> {
    if let ApplicationMessageV1::Text { body, .. } = message {
        if body.trim().is_empty() || body.len() > MAX_TEXT_BYTES {
            return Err(CoreError::InvalidMessage);
        }
    }
    if let ApplicationMessageV1::Profile { display_name, .. } = message {
        if display_name.trim().is_empty() || display_name.chars().count() > 64 {
            return Err(CoreError::InvalidMessage);
        }
    }
    to_cbor(message)
}

pub fn decode_application_message(bytes: &[u8]) -> Result<ApplicationMessageV1, CoreError> {
    let message = from_cbor(bytes)?;
    encode_application_message(&message)?;
    Ok(message)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ClientPayloadV1 {
    Text {
        version: u8,
        message_id: Uuid,
        sent_at: i64,
        sender_identity: String,
        body: String,
    },
    DeliveryReceipt {
        version: u8,
        message_id: Uuid,
        sent_at: i64,
        sender_identity: String,
        delivered_ids: Vec<Uuid>,
    },
    Profile {
        version: u8,
        message_id: Uuid,
        sent_at: i64,
        sender_identity: String,
        display_name: String,
        reply_invitation: Option<String>,
        body: Option<String>,
    },
    SessionReset {
        version: u8,
        message_id: Uuid,
        sent_at: i64,
        sender_identity: String,
        display_name: Option<String>,
        reply_invitation: String,
    },
}

pub fn encode_client_payload(message: &ClientPayloadV1) -> Result<Vec<u8>, CoreError> {
    let (version, message_id, sent_at, identity) = match message {
        ClientPayloadV1::Text {
            version,
            message_id,
            sent_at,
            sender_identity,
            body,
        } => {
            if body.trim().is_empty() || body.len() > MAX_TEXT_BYTES {
                return Err(CoreError::InvalidMessage);
            }
            (*version, message_id, *sent_at, sender_identity)
        }
        ClientPayloadV1::DeliveryReceipt {
            version,
            message_id,
            sent_at,
            sender_identity,
            delivered_ids,
        } => {
            if delivered_ids.is_empty() || delivered_ids.len() > 100 {
                return Err(CoreError::InvalidMessage);
            }
            (*version, message_id, *sent_at, sender_identity)
        }
        ClientPayloadV1::Profile {
            version,
            message_id,
            sent_at,
            sender_identity,
            display_name,
            reply_invitation,
            body,
        } => {
            if display_name.trim().is_empty()
                || display_name.chars().count() > 64
                || body
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_TEXT_BYTES)
            {
                return Err(CoreError::InvalidMessage);
            }
            if let Some(invitation) = reply_invitation {
                parse_contact_invitation(invitation)?;
            }
            (*version, message_id, *sent_at, sender_identity)
        }
        ClientPayloadV1::SessionReset {
            version,
            message_id,
            sent_at,
            sender_identity,
            display_name,
            reply_invitation,
        } => {
            if display_name
                .as_ref()
                .is_some_and(|value| value.trim().is_empty() || value.chars().count() > 64)
            {
                return Err(CoreError::InvalidMessage);
            }
            parse_contact_invitation(reply_invitation)?;
            (*version, message_id, *sent_at, sender_identity)
        }
    };
    if version != 1 || message_id.is_nil() || sent_at <= 0 {
        return Err(CoreError::InvalidMessage);
    }
    validate_identity_public_key(identity)?;
    to_cbor(message)
}

pub fn decode_client_payload(bytes: &[u8]) -> Result<ClientPayloadV1, CoreError> {
    let message = from_cbor(bytes)?;
    encode_client_payload(&message)?;
    Ok(message)
}

pub fn verification_fingerprint(first: &str, second: &str) -> Result<FingerprintV1, CoreError> {
    validate_identity_public_key(first)?;
    validate_identity_public_key(second)?;
    let mut keys = [first, second];
    keys.sort_unstable();
    let digest = Sha256::new()
        .chain_update(b"blackspace:v1:contact-fingerprint:")
        .chain_update(
            URL_SAFE_NO_PAD
                .decode(keys[0])
                .map_err(|_| CoreError::InvalidIdentity)?,
        )
        .chain_update(
            URL_SAFE_NO_PAD
                .decode(keys[1])
                .map_err(|_| CoreError::InvalidIdentity)?,
        )
        .finalize();
    let words = bip39::Language::English.word_list();
    let mut indices = Vec::with_capacity(6);
    let mut accumulator: u128 = 0;
    for byte in digest.iter().take(9) {
        accumulator = (accumulator << 8) | u128::from(*byte);
    }
    for shift in (0..6).rev() {
        indices.push(((accumulator >> (shift * 11)) & 0x7ff) as usize);
    }
    Ok(FingerprintV1 {
        hex: hex::encode_upper(digest)
            .as_bytes()
            .chunks(8)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" "),
        words: indices
            .into_iter()
            .map(|index| words[index].to_string())
            .collect(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FingerprintV1 {
    pub hex: String,
    pub words: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedRecordV1 {
    pub version: u16,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub recovery: bool,
}

pub fn seal_with_passphrase<T: Serialize>(
    value: &T,
    passphrase: &str,
    recovery: bool,
) -> Result<Vec<u8>, CoreError> {
    if passphrase.chars().count() < 10 {
        return Err(CoreError::VaultUnlock);
    }
    let plaintext = Zeroizing::new(to_cbor(value)?);
    let mut salt = vec![0_u8; 16];
    let mut nonce = vec![0_u8; 12];
    getrandom::fill(&mut salt).map_err(|_| CoreError::Randomness)?;
    getrandom::fill(&mut nonce).map_err(|_| CoreError::Randomness)?;
    let key = derive_key(passphrase, &salt)?;
    let aad = if recovery { RECOVERY_AAD } else { VAULT_AAD };
    let ciphertext = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| CoreError::InvalidRecord)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::InvalidRecord)?;
    to_cbor(&EncryptedRecordV1 {
        version: 1,
        salt,
        nonce,
        ciphertext,
        recovery,
    })
}

pub fn open_with_passphrase<T: DeserializeOwned>(
    blob: &[u8],
    passphrase: &str,
    recovery: bool,
) -> Result<T, CoreError> {
    let record: EncryptedRecordV1 = from_cbor(blob)?;
    if record.version != 1
        || record.recovery != recovery
        || record.salt.len() != 16
        || record.nonce.len() != 12
    {
        return Err(CoreError::InvalidRecord);
    }
    let key = derive_key(passphrase, &record.salt)?;
    let aad = if recovery { RECOVERY_AAD } else { VAULT_AAD };
    let plaintext = Zeroizing::new(
        Aes256Gcm::new_from_slice(&*key)
            .map_err(|_| CoreError::VaultUnlock)?
            .decrypt(
                Nonce::from_slice(&record.nonce),
                Payload {
                    msg: &record.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CoreError::VaultUnlock)?,
    );
    from_cbor(&plaintext)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| CoreError::VaultUnlock)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| CoreError::VaultUnlock)?;
    Ok(key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsIdentityV1 {
    pub identity: IdentityV1,
    /// Serialized OpenMLS provider storage, containing unpublished private key-package material.
    pub provider_storage: MlsStorageSnapshot,
    pub key_packages: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MlsConversationBootstrapV1 {
    pub group_id: Vec<u8>,
    pub welcome: Vec<u8>,
    pub first_message: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinedConversationV1 {
    pub group_id: Vec<u8>,
    pub first_payload: Vec<u8>,
    pub peer_identity: Vec<u8>,
}

/// Preserve the immutable signing identity while intentionally discarding all
/// key-package private material and reusable MLS group sending state.
pub fn mls_recovery_identity_snapshot(client: &MlsIdentityV1) -> MlsIdentityV1 {
    MlsIdentityV1 {
        identity: client.identity.clone(),
        provider_storage: Vec::new(),
        key_packages: Vec::new(),
    }
}

pub fn generate_mls_identity(package_count: usize) -> Result<MlsIdentityV1, CoreError> {
    if package_count == 0 || package_count > 50 {
        return Err(CoreError::InvalidMessage);
    }
    let identity = IdentityV1::generate()?;
    let private = identity.signing_private_key.clone();
    let public = URL_SAFE_NO_PAD
        .decode(&identity.signing_public_key)
        .map_err(|_| CoreError::InvalidIdentity)?;
    let signer = SignatureKeyPair::from_raw(
        openmls_traits::types::SignatureScheme::ED25519,
        private,
        public.clone(),
    );
    let provider = OpenMlsRustCrypto::default();
    signer
        .store(provider.storage())
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    let credential = CredentialWithKey {
        credential: BasicCredential::new(public.clone()).into(),
        signature_key: public.into(),
    };
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let mut key_packages = Vec::with_capacity(package_count);
    for _ in 0..package_count {
        let bundle = KeyPackage::builder()
            .build(ciphersuite, &provider, &signer, credential.clone())
            .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
        key_packages.push(
            bundle
                .key_package()
                .tls_serialize_detached()
                .map_err(|_| CoreError::Serialization)?,
        );
    }
    let storage = provider
        .storage()
        .values
        .read()
        .map_err(|_| CoreError::Serialization)?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Ok(MlsIdentityV1 {
        identity,
        provider_storage: storage,
        key_packages,
    })
}

pub fn replenish_mls_key_packages(
    client: &mut MlsIdentityV1,
    package_count: usize,
) -> Result<Vec<Vec<u8>>, CoreError> {
    if package_count == 0 || package_count > 50 {
        return Err(CoreError::InvalidMessage);
    }
    let provider = provider_from_snapshot(&client.provider_storage)?;
    let signer = signer_for_identity(&client.identity)?;
    let credential = credential_for_identity(&client.identity)?;
    let mut packages = Vec::with_capacity(package_count);
    for _ in 0..package_count {
        let bundle = KeyPackage::builder()
            .build(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                &provider,
                &signer,
                credential.clone(),
            )
            .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
        packages.push(
            bundle
                .key_package()
                .tls_serialize_detached()
                .map_err(|_| CoreError::Serialization)?,
        );
    }
    client.key_packages.extend(packages.iter().cloned());
    client.provider_storage = snapshot_provider(&provider)?;
    Ok(packages)
}

pub fn validate_mls_key_package(
    recipient_identity: &str,
    recipient_key_package: &[u8],
) -> Result<(), CoreError> {
    validate_identity_public_key(recipient_identity)?;
    let provider = OpenMlsRustCrypto::default();
    let key_package = KeyPackageIn::tls_deserialize_exact(recipient_key_package)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    let expected = URL_SAFE_NO_PAD
        .decode(recipient_identity)
        .map_err(|_| CoreError::InvalidIdentity)?;
    if key_package.ciphersuite() != Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        || key_package.leaf_node().credential().serialized_content() != expected
    {
        return Err(CoreError::InvalidIdentity);
    }
    Ok(())
}

/// Create a two-member MLS group, add a verified recipient key package and
/// return the ordered Welcome/application bootstrap bundle.
pub fn start_mls_conversation(
    client: &mut MlsIdentityV1,
    recipient_identity: &str,
    recipient_key_package: &[u8],
    first_payload: &[u8],
) -> Result<MlsConversationBootstrapV1, CoreError> {
    validate_identity_public_key(recipient_identity)?;
    let provider = provider_from_snapshot(&client.provider_storage)?;
    let signer = signer_for_identity(&client.identity)?;
    let credential = credential_for_identity(&client.identity)?;
    let key_package = KeyPackageIn::tls_deserialize_exact(recipient_key_package)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    let expected = URL_SAFE_NO_PAD
        .decode(recipient_identity)
        .map_err(|_| CoreError::InvalidIdentity)?;
    if key_package.leaf_node().credential().serialized_content() != expected {
        return Err(CoreError::InvalidIdentity);
    }
    let config = group_create_config();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    let (_, welcome, _) = group
        .add_members(&provider, &signer, &[key_package])
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    group
        .merge_pending_commit(&provider)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    let message = group
        .create_message(&provider, &signer, first_payload)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    let output = MlsConversationBootstrapV1 {
        group_id: group.group_id().as_slice().to_vec(),
        welcome: welcome.to_bytes().map_err(|_| CoreError::Serialization)?,
        first_message: message.to_bytes().map_err(|_| CoreError::Serialization)?,
    };
    client.provider_storage = snapshot_provider(&provider)?;
    Ok(output)
}

/// Import an ordered bootstrap. The private key package required by the
/// Welcome is consumed from the client's OpenMLS provider storage.
pub fn join_mls_conversation(
    client: &mut MlsIdentityV1,
    welcome: &[u8],
    first_message: &[u8],
) -> Result<JoinedConversationV1, CoreError> {
    let provider = provider_from_snapshot(&client.provider_storage)?;
    let welcome = match MlsMessageIn::tls_deserialize_exact(welcome)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err(CoreError::Mls("expected Welcome message".into())),
    };
    let mut group = StagedWelcome::new_from_welcome(&provider, &group_join_config(), welcome, None)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?
        .into_group(&provider)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    let peer_identity = validate_two_member_group(&group, &client.identity.signing_public_key)?;
    let payload = process_mls_message(&mut group, &provider, first_message)?;
    let output = JoinedConversationV1 {
        group_id: group.group_id().as_slice().to_vec(),
        first_payload: payload,
        peer_identity,
    };
    client.provider_storage = snapshot_provider(&provider)?;
    Ok(output)
}

pub fn create_mls_message(
    client: &mut MlsIdentityV1,
    group_id: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let provider = provider_from_snapshot(&client.provider_storage)?;
    let signer = signer_for_identity(&client.identity)?;
    let group_id = GroupId::from_slice(group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?
        .ok_or_else(|| CoreError::Mls("conversation state is unavailable".into()))?;
    validate_two_member_group(&group, &client.identity.signing_public_key)?;
    let message = group
        .create_message(&provider, &signer, payload)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?
        .to_bytes()
        .map_err(|_| CoreError::Serialization)?;
    client.provider_storage = snapshot_provider(&provider)?;
    Ok(message)
}

pub fn process_mls_application_message(
    client: &mut MlsIdentityV1,
    group_id: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let provider = provider_from_snapshot(&client.provider_storage)?;
    let group_id = GroupId::from_slice(group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?
        .ok_or_else(|| CoreError::Mls("conversation state is unavailable".into()))?;
    validate_two_member_group(&group, &client.identity.signing_public_key)?;
    let payload = process_mls_message(&mut group, &provider, message)?;
    client.provider_storage = snapshot_provider(&provider)?;
    Ok(payload)
}

fn validate_two_member_group(group: &MlsGroup, own_identity: &str) -> Result<Vec<u8>, CoreError> {
    let members: Vec<Vec<u8>> = group
        .members()
        .map(|member| member.credential.serialized_content().to_vec())
        .collect();
    if members.len() != 2
        || members
            .iter()
            .filter(|identity| URL_SAFE_NO_PAD.encode(identity) == own_identity)
            .count()
            != 1
    {
        return Err(CoreError::Mls(
            "conversation must contain exactly two expected members".into(),
        ));
    }
    members
        .into_iter()
        .find(|identity| URL_SAFE_NO_PAD.encode(identity) != own_identity)
        .ok_or_else(|| CoreError::Mls("conversation has no peer identity".into()))
}

fn process_mls_message(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    message: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let protocol_message = MlsMessageIn::tls_deserialize_exact(message)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?
        .try_into_protocol_message()
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    let processed = group
        .process_message(provider, protocol_message)
        .map_err(|error| CoreError::Mls(format!("{error:?}")))?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => Ok(application.into_bytes()),
        _ => Err(CoreError::Mls("expected MLS application message".into())),
    }
}

fn group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(50, 2_000))
        .use_ratchet_tree_extension(true)
        .build()
}

fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(50, 2_000))
        .use_ratchet_tree_extension(true)
        .build()
}

fn signer_for_identity(identity: &IdentityV1) -> Result<SignatureKeyPair, CoreError> {
    let public = URL_SAFE_NO_PAD
        .decode(&identity.signing_public_key)
        .map_err(|_| CoreError::InvalidIdentity)?;
    if identity.signing_private_key.len() != 32 || public.len() != 32 {
        return Err(CoreError::InvalidIdentity);
    }
    Ok(SignatureKeyPair::from_raw(
        openmls_traits::types::SignatureScheme::ED25519,
        identity.signing_private_key.clone(),
        public,
    ))
}

fn credential_for_identity(identity: &IdentityV1) -> Result<CredentialWithKey, CoreError> {
    let public = URL_SAFE_NO_PAD
        .decode(&identity.signing_public_key)
        .map_err(|_| CoreError::InvalidIdentity)?;
    Ok(CredentialWithKey {
        credential: BasicCredential::new(public.clone()).into(),
        signature_key: public.into(),
    })
}

fn provider_from_snapshot(storage: &[(Vec<u8>, Vec<u8>)]) -> Result<OpenMlsRustCrypto, CoreError> {
    let provider = OpenMlsRustCrypto::default();
    let mut values = provider
        .storage()
        .values
        .write()
        .map_err(|_| CoreError::Serialization)?;
    values.extend(storage.iter().cloned());
    drop(values);
    Ok(provider)
}

fn snapshot_provider(provider: &OpenMlsRustCrypto) -> Result<MlsStorageSnapshot, CoreError> {
    Ok(provider
        .storage()
        .values
        .read()
        .map_err(|_| CoreError::Serialization)?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    let mut output = Vec::new();
    ciborium::ser::into_writer(value, &mut output).map_err(|_| CoreError::Serialization)?;
    Ok(output)
}

fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    ciborium::de::from_reader(bytes).map_err(|_| CoreError::Serialization)
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

/// Opaque browser bridge. Private material is serialized only as an opaque
/// state blob for immediate encryption by the vault layer.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_generate_mls_identity(package_count: usize) -> Result<String, JsValue> {
    #[derive(Serialize)]
    struct Output {
        identity_public_key: String,
        key_packages: Vec<String>,
        client_state: String,
    }
    let state = generate_mls_identity(package_count).map_err(js_error)?;
    serde_json::to_string(&Output {
        identity_public_key: state.identity.signing_public_key.clone(),
        key_packages: state
            .key_packages
            .iter()
            .map(|package| URL_SAFE_NO_PAD.encode(package))
            .collect(),
        client_state: URL_SAFE_NO_PAD.encode(to_cbor(&state).map_err(js_error)?),
    })
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_replenish_mls_key_packages(
    client_state: &str,
    package_count: usize,
) -> Result<String, JsValue> {
    #[derive(Serialize)]
    struct Output {
        client_state: String,
        key_packages: Vec<String>,
    }
    let mut state: MlsIdentityV1 =
        from_cbor(&URL_SAFE_NO_PAD.decode(client_state).map_err(js_error)?).map_err(js_error)?;
    let packages = replenish_mls_key_packages(&mut state, package_count).map_err(js_error)?;
    serde_json::to_string(&Output {
        client_state: URL_SAFE_NO_PAD.encode(to_cbor(&state).map_err(js_error)?),
        key_packages: packages
            .iter()
            .map(|package| URL_SAFE_NO_PAD.encode(package))
            .collect(),
    })
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_mls_recovery_identity_snapshot(client_state: &str) -> Result<String, JsValue> {
    let state: MlsIdentityV1 =
        from_cbor(&URL_SAFE_NO_PAD.decode(client_state).map_err(js_error)?).map_err(js_error)?;
    let recovery = mls_recovery_identity_snapshot(&state);
    Ok(URL_SAFE_NO_PAD.encode(to_cbor(&recovery).map_err(js_error)?))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_encode_client_payload(json: &str) -> Result<String, JsValue> {
    let payload: ClientPayloadV1 = serde_json::from_str(json).map_err(js_error)?;
    Ok(URL_SAFE_NO_PAD.encode(encode_client_payload(&payload).map_err(js_error)?))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_decode_client_payload(payload: &str) -> Result<String, JsValue> {
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(js_error)?;
    serde_json::to_string(&decode_client_payload(&bytes).map_err(js_error)?).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_verification_fingerprint(first: &str, second: &str) -> Result<String, JsValue> {
    serde_json::to_string(&verification_fingerprint(first, second).map_err(js_error)?)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_seal_recovery_state(json: &str, passphrase: &str) -> Result<String, JsValue> {
    let state: serde_json::Value = serde_json::from_str(json).map_err(js_error)?;
    Ok(URL_SAFE_NO_PAD.encode(seal_with_passphrase(&state, passphrase, true).map_err(js_error)?))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_open_recovery_state(blob: &str, passphrase: &str) -> Result<String, JsValue> {
    let bytes = URL_SAFE_NO_PAD.decode(blob).map_err(js_error)?;
    let state: serde_json::Value =
        open_with_passphrase(&bytes, passphrase, true).map_err(js_error)?;
    serde_json::to_string(&state).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_start_mls_conversation(
    client_state: &str,
    recipient_identity: &str,
    recipient_key_package: &str,
    first_payload: &str,
) -> Result<String, JsValue> {
    #[derive(Serialize)]
    struct Output {
        client_state: String,
        group_id: String,
        welcome: String,
        first_message: String,
    }
    let mut state: MlsIdentityV1 =
        from_cbor(&URL_SAFE_NO_PAD.decode(client_state).map_err(js_error)?).map_err(js_error)?;
    let bootstrap = start_mls_conversation(
        &mut state,
        recipient_identity,
        &URL_SAFE_NO_PAD
            .decode(recipient_key_package)
            .map_err(js_error)?,
        &URL_SAFE_NO_PAD.decode(first_payload).map_err(js_error)?,
    )
    .map_err(js_error)?;
    serde_json::to_string(&Output {
        client_state: URL_SAFE_NO_PAD.encode(to_cbor(&state).map_err(js_error)?),
        group_id: URL_SAFE_NO_PAD.encode(bootstrap.group_id),
        welcome: URL_SAFE_NO_PAD.encode(bootstrap.welcome),
        first_message: URL_SAFE_NO_PAD.encode(bootstrap.first_message),
    })
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_join_mls_conversation(
    client_state: &str,
    welcome: &str,
    first_message: &str,
) -> Result<String, JsValue> {
    #[derive(Serialize)]
    struct Output {
        client_state: String,
        group_id: String,
        first_payload: String,
        peer_identity: String,
    }
    let mut state: MlsIdentityV1 =
        from_cbor(&URL_SAFE_NO_PAD.decode(client_state).map_err(js_error)?).map_err(js_error)?;
    let joined = join_mls_conversation(
        &mut state,
        &URL_SAFE_NO_PAD.decode(welcome).map_err(js_error)?,
        &URL_SAFE_NO_PAD.decode(first_message).map_err(js_error)?,
    )
    .map_err(js_error)?;
    serde_json::to_string(&Output {
        client_state: URL_SAFE_NO_PAD.encode(to_cbor(&state).map_err(js_error)?),
        group_id: URL_SAFE_NO_PAD.encode(joined.group_id),
        first_payload: URL_SAFE_NO_PAD.encode(joined.first_payload),
        peer_identity: URL_SAFE_NO_PAD.encode(joined.peer_identity),
    })
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_create_mls_message(
    client_state: &str,
    group_id: &str,
    payload: &str,
) -> Result<String, JsValue> {
    #[derive(Serialize)]
    struct Output {
        client_state: String,
        message: String,
    }
    let mut state: MlsIdentityV1 =
        from_cbor(&URL_SAFE_NO_PAD.decode(client_state).map_err(js_error)?).map_err(js_error)?;
    let message = create_mls_message(
        &mut state,
        &URL_SAFE_NO_PAD.decode(group_id).map_err(js_error)?,
        &URL_SAFE_NO_PAD.decode(payload).map_err(js_error)?,
    )
    .map_err(js_error)?;
    serde_json::to_string(&Output {
        client_state: URL_SAFE_NO_PAD.encode(to_cbor(&state).map_err(js_error)?),
        message: URL_SAFE_NO_PAD.encode(message),
    })
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_process_mls_message(
    client_state: &str,
    group_id: &str,
    message: &str,
) -> Result<String, JsValue> {
    #[derive(Serialize)]
    struct Output {
        client_state: String,
        payload: String,
    }
    let mut state: MlsIdentityV1 =
        from_cbor(&URL_SAFE_NO_PAD.decode(client_state).map_err(js_error)?).map_err(js_error)?;
    let payload = process_mls_application_message(
        &mut state,
        &URL_SAFE_NO_PAD.decode(group_id).map_err(js_error)?,
        &URL_SAFE_NO_PAD.decode(message).map_err(js_error)?,
    )
    .map_err(js_error)?;
    serde_json::to_string(&Output {
        client_state: URL_SAFE_NO_PAD.encode(to_cbor(&state).map_err(js_error)?),
        payload: URL_SAFE_NO_PAD.encode(payload),
    })
    .map_err(js_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn onion() -> String {
        format!("http://{}.onion", "a".repeat(56))
    }

    #[test]
    fn invitation_round_trip_and_strict_validation() {
        let identity = IdentityV1::generate().unwrap();
        let invite = ContactInvitationV1 {
            onion_origin: onion(),
            https_origin: Some("https://example.com".into()),
            deposit_capability: URL_SAFE_NO_PAD.encode([4_u8; 32]),
            identity_public_key: identity.signing_public_key,
            invite_id: Uuid::new_v4(),
        };
        assert_eq!(
            parse_contact_invitation(&format_contact_invitation(&invite).unwrap()).unwrap(),
            invite
        );
        assert!(parse_contact_invitation("blackspace://contact/v1#cap=x").is_err());
    }

    #[test]
    fn encrypted_records_fail_closed() {
        let payload = ApplicationMessageV1::Text {
            message_id: Uuid::now_v7(),
            sent_at_ms: 1,
            body: "hello".into(),
        };
        let sealed = seal_with_passphrase(&payload, "correct horse battery staple", false).unwrap();
        let opened: ApplicationMessageV1 =
            open_with_passphrase(&sealed, "correct horse battery staple", false).unwrap();
        assert_eq!(opened, payload);
        assert!(
            open_with_passphrase::<ApplicationMessageV1>(&sealed, "wrong passphrase", false)
                .is_err()
        );
        assert!(!sealed.windows(5).any(|bytes| bytes == b"hello"));

        let recovery =
            seal_with_passphrase(&payload, "separate recovery passphrase", true).unwrap();
        let recovered: ApplicationMessageV1 =
            open_with_passphrase(&recovery, "separate recovery passphrase", true).unwrap();
        assert_eq!(recovered, payload);
        assert!(
            open_with_passphrase::<ApplicationMessageV1>(&recovery, "wrong passphrase", true)
                .is_err()
        );
        assert!(
            open_with_passphrase::<ApplicationMessageV1>(
                &recovery,
                "separate recovery passphrase",
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn identity_signatures_and_fingerprints_are_stable() {
        let alice = IdentityV1::generate().unwrap();
        let bob = IdentityV1::generate().unwrap();
        let signature = alice.sign(b"message").unwrap();
        alice.verify(b"message", &signature).unwrap();
        assert!(alice.verify(b"changed", &signature).is_err());
        assert_eq!(
            verification_fingerprint(&alice.signing_public_key, &bob.signing_public_key).unwrap(),
            verification_fingerprint(&bob.signing_public_key, &alice.signing_public_key).unwrap()
        );
    }

    #[test]
    fn openmls_key_packages_are_generated_from_the_identity() {
        let bundle = generate_mls_identity(2).unwrap();
        assert_eq!(bundle.key_packages.len(), 2);
        assert!(bundle.key_packages.iter().all(|package| package.len() > 32));
        assert!(!bundle.provider_storage.is_empty());
        validate_mls_key_package(&bundle.identity.signing_public_key, &bundle.key_packages[0])
            .unwrap();
        assert!(
            validate_mls_key_package(&bundle.identity.signing_public_key, &[7_u8; 64]).is_err()
        );
    }

    #[test]
    fn openmls_two_party_conversation_round_trip() {
        let mut alice = generate_mls_identity(2).unwrap();
        let mut bob = generate_mls_identity(2).unwrap();
        let bootstrap = start_mls_conversation(
            &mut alice,
            &bob.identity.signing_public_key,
            &bob.key_packages[0],
            b"first",
        )
        .unwrap();
        let joined =
            join_mls_conversation(&mut bob, &bootstrap.welcome, &bootstrap.first_message).unwrap();
        assert_eq!(joined.first_payload, b"first");
        assert_eq!(joined.group_id, bootstrap.group_id);
        let reply = create_mls_message(&mut bob, &joined.group_id, b"reply").unwrap();
        assert_eq!(
            process_mls_application_message(&mut alice, &bootstrap.group_id, &reply).unwrap(),
            b"reply"
        );
    }

    #[test]
    fn recovery_snapshot_preserves_identity_without_reusable_mls_state() {
        let client = generate_mls_identity(2).unwrap();
        let recovered = mls_recovery_identity_snapshot(&client);
        assert_eq!(
            recovered.identity.signing_public_key,
            client.identity.signing_public_key
        );
        assert_eq!(
            recovered.identity.signing_private_key,
            client.identity.signing_private_key
        );
        assert!(recovered.provider_storage.is_empty());
        assert!(recovered.key_packages.is_empty());
    }

    #[test]
    fn client_payload_cbor_round_trip_is_versioned_and_bounded() {
        let identity = IdentityV1::generate().unwrap();
        let message = ClientPayloadV1::Text {
            version: 1,
            message_id: Uuid::now_v7(),
            sent_at: 1,
            sender_identity: identity.signing_public_key,
            body: "hello".into(),
        };
        let encoded = encode_client_payload(&message).unwrap();
        assert_eq!(decode_client_payload(&encoded).unwrap(), message);
    }
}
