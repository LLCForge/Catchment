//! PoP identification from an HTTP response header (e.g. `x-served-by`).
//!
//! The request always connects to the anycast target address; the URL's host
//! name is only used for SNI / `Host`. Redirects are not followed and the body
//! is never read.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::config::{validate_http_target, HttpTarget};
use crate::dns;

const MAX_VALUE: usize = 255;

pub async fn identify(h: &HttpTarget, target: IpAddr, timeout: Duration) -> Result<Option<String>> {
    validate_http_target(h)?;
    let url = reqwest::Url::parse(&h.url)?;
    let host = url.host_str().context("url has no host")?.to_string();
    let port = url.port_or_known_default().context("url has no port")?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("catchment/", env!("CARGO_PKG_VERSION")))
        .resolve(&host, SocketAddr::new(target, port))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()?;
    let resp = client.get(url).send().await?;
    let values: Vec<String> = resp
        .headers()
        .get_all(h.header.as_str())
        .iter()
        .map(|v| dns::sanitize(v.as_bytes()))
        .collect();
    if values.is_empty() {
        return Ok(None);
    }
    let joined = values.join(", ");
    Ok(Some(joined.chars().take(MAX_VALUE).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum::routing::get;

    #[tokio::test]
    async fn reads_header_from_target_address() {
        let app = axum::Router::new().route(
            "/",
            get(|headers: HeaderMap| async move {
                let host = headers
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                (
                    [("x-served-by", "cache-ams1".to_string()), ("x-host", host)],
                    "ok",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let target = HttpTarget {
            url: format!("http://www.example.net:{port}/"),
            header: "X-Served-By".into(),
        };
        let v = identify(
            &target,
            "127.0.0.1".parse().unwrap(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(v.as_deref(), Some("cache-ams1"));
        let missing = HttpTarget {
            header: "x-missing".into(),
            ..target.clone()
        };
        let v = identify(
            &missing,
            "127.0.0.1".parse().unwrap(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(v, None);
        let bad = HttpTarget {
            url: "http://127.0.0.1/".into(),
            ..target
        };
        assert!(
            identify(&bad, "127.0.0.1".parse().unwrap(), Duration::from_secs(1))
                .await
                .is_err()
        );
    }
}
