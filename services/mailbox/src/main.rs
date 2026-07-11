use blackspace_mailbox::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_current_span(false)
        .with_span_list(false)
        .init();

    let config = Config::from_env()?;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("invite")
        && arguments.get(1).map(String::as_str) == Some("create")
    {
        let hours = arguments
            .windows(2)
            .find(|pair| pair[0] == "--hours")
            .and_then(|pair| pair[1].parse().ok())
            .unwrap_or(24);
        let invitation = blackspace_mailbox::create_registration_invite(&config, hours).await?;
        println!("{invitation}");
        return Ok(());
    }
    if !arguments.is_empty() {
        anyhow::bail!("usage: blackspace-mailbox [invite create [--hours 1..168]]");
    }
    blackspace_mailbox::serve(config).await
}
