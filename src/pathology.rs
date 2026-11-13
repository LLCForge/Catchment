//! Optional Pathology client: when a round shows catchment shifts, ask
//! Pathology which BGP path changes it saw for the service prefix since the
//! previous round (`GET /v1/routes?prefix=&since=&limit=`).
//!
//! The call is time-boxed and runs after the shift alerts were sent, so it
//! never delays or blocks an alert. Responses are untrusted and bounded.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::Value;

use crate::config::PathologyConfig;
use crate::dns::sanitize;
use crate::model::{rfc3339_ms, PathCorrelation, PathEvent};

const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_PATH_LEN: usize = 64;

#[derive(Deserialize)]
struct RoutesResponse {
    #[serde(default)]
    events: Vec<RawEvent>,
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(default)]
    time: String,
    #[serde(default)]
    peer: String,
    #[serde(default)]
    peer_asn: Option<u32>,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    as_path: Vec<Value>,
}

pub struct PathologyClient {
    http: reqwest::Client,
    base: reqwest::Url,
    token: Option<String>,
    limit: u32,
}

/// Parse a `/v1/routes` body into at most `limit` sanitized events.
pub fn parse_routes(body: &[u8], limit: usize) -> Result<Vec<PathEvent>> {
    let r: RoutesResponse = serde_json::from_slice(body).context("invalid Pathology response")?;
    Ok(r.events
        .into_iter()
        .take(limit)
        .map(|e| PathEvent {
            time: sanitize(e.time.as_bytes()),
            peer: sanitize(e.peer.as_bytes()),
            peer_asn: e.peer_asn,
            prefix: sanitize(e.prefix.as_bytes()),
            kind: match e.kind.as_str() {
                "announce" | "withdraw" => e.kind,
                _ => "unknown".into(),
            },
            as_path: e
                .as_path
                .iter()
                .filter_map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()))
                .take(MAX_PATH_LEN)
                .collect(),
        })
        .collect())
}

impl PathologyClient {
    pub fn new(cfg: &PathologyConfig) -> Result<Self> {
        let token = match &cfg.token_env {
            Some(var) => Some(llcforge_beacon::env_secret(var)?),
            None => None,
        };
        let http = reqwest::Client::builder()
            .user_agent(concat!("catchment/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(cfg.timeout)
            .timeout(cfg.timeout)
            .build()?;
        Ok(Self {
            http,
            base: reqwest::Url::parse(&cfg.url).context("[pathology] url")?,
            token,
            limit: cfg.limit,
        })
    }

    async fn routes(&self, prefix: IpNet, since: &str) -> Result<Vec<PathEvent>> {
        let url = self.base.join("/v1/routes")?;
        let mut req = self.http.get(url).query(&[
            ("prefix", prefix.to_string()),
            ("since", since.to_string()),
            ("limit", self.limit.to_string()),
        ]);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let mut resp = req.send().await?;
        let status = resp.status();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_BODY {
                bail!("Pathology response larger than {MAX_BODY} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            bail!("Pathology returned HTTP {}", status.as_u16());
        }
        parse_routes(&body, self.limit as usize)
    }

    /// Path changes since `since_ms`; errors are reported inside the result.
    pub async fn correlate(
        &self,
        prefix: IpNet,
        since_ms: u64,
        budget: Duration,
    ) -> PathCorrelation {
        let since = rfc3339_ms(since_ms);
        let res = tokio::time::timeout(budget, self.routes(prefix, &since)).await;
        let (events, error) = match res {
            Ok(Ok(ev)) => (ev, None),
            Ok(Err(e)) => (Vec::new(), Some(sanitize(format!("{e:#}").as_bytes()))),
            Err(_) => (Vec::new(), Some("Pathology query timed out".into())),
        };
        if let Some(e) = &error {
            tracing::warn!(error = %e, %prefix, "Pathology correlation failed");
        }
        PathCorrelation {
            prefix: prefix.to_string(),
            since,
            events,
            error,
        }
    }
}

/// One line per event for alert fields and the terminal report.
pub fn describe(e: &PathEvent) -> String {
    let path: Vec<String> = e.as_path.iter().map(u32::to_string).collect();
    let peer = match e.peer_asn {
        Some(asn) => format!("{} (AS{asn})", e.peer),
        None => e.peer.clone(),
    };
    if e.kind == "withdraw" {
        format!("{} withdraw via {peer}", e.time)
    } else {
        format!("{} {} via {peer}: {}", e.time, e.kind, path.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::http::HeaderMap;
    use axum::routing::get;
    use std::collections::HashMap;

    const FIXTURE: &str = r#"{"events":[
      {"time":"2026-01-01T00:05:00Z","peer":"192.0.2.1","peer_asn":64496,"prefix":"192.0.2.0/24",
       "kind":"announce","as_path":[64496,64500],"origin":"igp","communities":["64496:100"],"large_communities":[]},
      {"time":"2026-01-01T00:06:00Z","peer":"192.0.2.2","peer_asn":64497,"prefix":"192.0.2.0/24",
       "kind":"withdraw","as_path":[]},
      {"time":"x\u001b[2J","peer":"p","prefix":"p","kind":"bogus","as_path":[1,"set",4294967296]}
    ]}"#;

    #[test]
    fn parses_contract_shape() {
        let ev = parse_routes(FIXTURE.as_bytes(), 10).unwrap();
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].as_path, vec![64496, 64500]);
        assert_eq!(ev[0].peer_asn, Some(64496));
        assert_eq!(ev[1].kind, "withdraw");
        assert_eq!(ev[2].kind, "unknown");
        assert_eq!(ev[2].time, "x?[2J");
        assert_eq!(ev[2].as_path, vec![1]);
        assert_eq!(
            describe(&ev[0]),
            "2026-01-01T00:05:00Z announce via 192.0.2.1 (AS64496): 64496 64500"
        );
        assert_eq!(parse_routes(FIXTURE.as_bytes(), 1).unwrap().len(), 1);
        assert!(parse_routes(b"not json", 1).is_err());
    }

    #[tokio::test]
    async fn queries_with_token_and_handles_failures() {
        let app = axum::Router::new().route(
            "/v1/routes",
            get(
                |q: Query<HashMap<String, String>>, h: HeaderMap| async move {
                    let auth = h.get("authorization").and_then(|v| v.to_str().ok());
                    if auth != Some("Bearer s3cret") {
                        return (axum::http::StatusCode::UNAUTHORIZED, String::new());
                    }
                    assert_eq!(q.get("prefix").map(String::as_str), Some("192.0.2.0/24"));
                    assert_eq!(
                        q.get("since").map(String::as_str),
                        Some("2026-01-01T00:00:00Z")
                    );
                    (axum::http::StatusCode::OK, FIXTURE.to_string())
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let cfg = |token_env: Option<&str>| PathologyConfig {
            url: format!("http://{addr}"),
            token_env: token_env.map(Into::into),
            timeout: Duration::from_secs(5),
            limit: 100,
        };
        std::env::set_var("CATCHMENT_TEST_PATHOLOGY_TOKEN", "s3cret");
        let ok = PathologyClient::new(&cfg(Some("CATCHMENT_TEST_PATHOLOGY_TOKEN"))).unwrap();
        let prefix: IpNet = "192.0.2.0/24".parse().unwrap();
        let c = ok
            .correlate(prefix, 1_767_225_600_000, Duration::from_secs(5))
            .await;
        assert_eq!(c.error, None);
        assert_eq!(c.events.len(), 3);
        let anon = PathologyClient::new(&cfg(None)).unwrap();
        let c = anon
            .correlate(prefix, 1_767_225_600_000, Duration::from_secs(5))
            .await;
        assert!(c.error.unwrap().contains("401"));
        assert!(c.events.is_empty());
    }
}
