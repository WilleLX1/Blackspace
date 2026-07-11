//! Validation and parsing at the Tor-only transport boundary.

use thiserror::Error;
use url::Url;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TorBoundaryError {
    #[error("Tor Native requires a canonical http:// v3 onion origin")]
    InvalidOnionOrigin,
    #[error("Tor control response is malformed")]
    InvalidControlResponse,
}

pub fn validate_v3_onion_origin(value: &str) -> Result<String, TorBoundaryError> {
    let url = Url::parse(value).map_err(|_| TorBoundaryError::InvalidOnionOrigin)?;
    let host = url.host_str().ok_or(TorBoundaryError::InvalidOnionOrigin)?;
    let onion_name = host
        .strip_suffix(".onion")
        .ok_or(TorBoundaryError::InvalidOnionOrigin)?;
    let valid_host = onion_name.len() == 56
        && onion_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte));
    let valid_origin = url.scheme() == "http"
        && valid_host
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.path().is_empty() || url.path() == "/");
    if !valid_origin {
        return Err(TorBoundaryError::InvalidOnionOrigin);
    }
    Ok(format!("http://{host}"))
}

pub fn parse_control_port_file(value: &str) -> Result<String, TorBoundaryError> {
    let address = value
        .trim()
        .strip_prefix("PORT=")
        .ok_or(TorBoundaryError::InvalidControlResponse)?;
    let parsed: std::net::SocketAddr = address
        .parse()
        .map_err(|_| TorBoundaryError::InvalidControlResponse)?;
    if !parsed.ip().is_loopback() {
        return Err(TorBoundaryError::InvalidControlResponse);
    }
    Ok(parsed.to_string())
}

pub fn parse_bootstrap_progress(response: &str) -> Result<u8, TorBoundaryError> {
    let progress = response
        .split_whitespace()
        .find_map(|part| part.strip_prefix("PROGRESS="))
        .ok_or(TorBoundaryError::InvalidControlResponse)?
        .trim_matches('"')
        .parse::<u8>()
        .map_err(|_| TorBoundaryError::InvalidControlResponse)?;
    if progress > 100 {
        return Err(TorBoundaryError::InvalidControlResponse);
    }
    Ok(progress)
}

pub fn parse_socks_listener(response: &str) -> Result<String, TorBoundaryError> {
    let line = response
        .lines()
        .find(|line| line.starts_with("250-net/listeners/socks="))
        .ok_or(TorBoundaryError::InvalidControlResponse)?;
    let address = line
        .trim_start_matches("250-net/listeners/socks=")
        .trim()
        .trim_matches('"');
    let first = address
        .split_whitespace()
        .next()
        .unwrap_or(address)
        .trim_matches('"');
    let parsed: std::net::SocketAddr = first
        .parse()
        .map_err(|_| TorBoundaryError::InvalidControlResponse)?;
    if !parsed.ip().is_loopback() {
        return Err(TorBoundaryError::InvalidControlResponse);
    }
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn onion() -> String {
        format!("{}.onion", "a".repeat(56))
    }

    #[test]
    fn accepts_only_canonical_v3_onion_origin() {
        assert_eq!(
            validate_v3_onion_origin(&format!("http://{}", onion())).unwrap(),
            format!("http://{}", onion())
        );
        assert!(validate_v3_onion_origin(&format!("https://{}", onion())).is_err());
        assert!(validate_v3_onion_origin(&format!("http://{}:8080", onion())).is_err());
        assert!(validate_v3_onion_origin("http://127.0.0.1").is_err());
        assert!(validate_v3_onion_origin("https://example.org").is_err());
    }

    #[test]
    fn parses_control_responses() {
        assert_eq!(
            parse_control_port_file("PORT=127.0.0.1:49100\n").unwrap(),
            "127.0.0.1:49100"
        );
        assert_eq!(parse_bootstrap_progress("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=80 TAG=ap_conn SUMMARY=done\r\n250 OK").unwrap(), 80);
        assert_eq!(
            parse_socks_listener("250-net/listeners/socks=\"127.0.0.1:49101\"\r\n250 OK").unwrap(),
            "127.0.0.1:49101"
        );
    }
}
