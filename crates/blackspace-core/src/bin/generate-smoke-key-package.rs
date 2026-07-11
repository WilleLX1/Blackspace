use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;

#[derive(Serialize)]
struct SmokePackage {
    identity_public_key: String,
    key_package: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = blackspace_core::generate_mls_identity(1)?;
    println!(
        "{}",
        serde_json::to_string(&SmokePackage {
            identity_public_key: identity.identity.signing_public_key,
            key_package: URL_SAFE_NO_PAD.encode(&identity.key_packages[0]),
        })?
    );
    Ok(())
}
