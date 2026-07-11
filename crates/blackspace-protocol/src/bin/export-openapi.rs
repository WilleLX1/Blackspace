use blackspace_protocol::ProtocolSchemas;
use utoipa::OpenApi;

fn main() {
    let mut document = ProtocolSchemas::openapi();
    document.info.title = "Blackspace private-alpha messaging protocol".to_string();
    document.info.version = env!("CARGO_PKG_VERSION").to_string();
    document.info.description = Some(
        "Unaudited private-alpha protocol for invited, identity-bound, end-to-end encrypted one-to-one messaging over opaque mailbox servers."
            .to_string(),
    );
    println!(
        "{}",
        document
            .to_pretty_json()
            .expect("OpenAPI serialization failed")
    );
}
