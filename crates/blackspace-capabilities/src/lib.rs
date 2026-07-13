//! High-entropy bearer capability generation and purpose-separated verifiers.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const CAPABILITY_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityKind {
    Bootstrap,
    Registration,
    Read,
    Admin,
    Deposit,
    /// One-time bearer that lets a new device claim its parked enrollment parcel.
    Enroll,
}

impl CapabilityKind {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Bootstrap => b"blackspace:v1:bootstrap:",
            Self::Registration => b"blackspace:v1:registration:",
            Self::Read => b"blackspace:v1:read:",
            Self::Admin => b"blackspace:v1:admin:",
            Self::Deposit => b"blackspace:v1:deposit:",
            Self::Enroll => b"blackspace:v1:enroll:",
        }
    }
}

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("secure operating-system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("capability must be unpadded base64url encoding exactly 32 bytes")]
    InvalidCapability,
    #[error("verifier must be unpadded base64url encoding exactly 32 bytes")]
    InvalidVerifier,
}

pub fn generate_capability() -> Result<String, CapabilityError> {
    let mut bytes = [0_u8; CAPABILITY_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CapabilityError::RandomnessUnavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn verifier(kind: CapabilityKind, capability: &str) -> Result<[u8; 32], CapabilityError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(capability)
        .map_err(|_| CapabilityError::InvalidCapability)?;
    if decoded.len() != CAPABILITY_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != capability {
        return Err(CapabilityError::InvalidCapability);
    }
    let mut hash = Sha256::new();
    hash.update(kind.domain());
    hash.update(decoded);
    Ok(hash.finalize().into())
}

pub fn encode_verifier(verifier: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(verifier)
}

pub fn decode_verifier(encoded: &str) -> Result<[u8; 32], CapabilityError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CapabilityError::InvalidVerifier)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(CapabilityError::InvalidVerifier);
    }
    decoded
        .try_into()
        .map_err(|_| CapabilityError::InvalidVerifier)
}

pub fn verifier_matches(expected: &[u8; 32], presented: &[u8; 32]) -> bool {
    bool::from(expected.ct_eq(presented))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_capability_round_trips() {
        let capability = generate_capability().unwrap();
        assert_eq!(capability.len(), 43);
        let digest = verifier(CapabilityKind::Read, &capability).unwrap();
        assert_eq!(decode_verifier(&encode_verifier(&digest)).unwrap(), digest);
    }

    #[test]
    fn verifiers_are_purpose_separated() {
        let capability = generate_capability().unwrap();
        assert_ne!(
            verifier(CapabilityKind::Read, &capability).unwrap(),
            verifier(CapabilityKind::Admin, &capability).unwrap()
        );
    }

    #[test]
    fn rejects_padding_and_wrong_lengths() {
        assert!(verifier(CapabilityKind::Read, "AA==").is_err());
        assert!(decode_verifier("AA").is_err());
    }
}
