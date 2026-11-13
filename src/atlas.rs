//! RIPE Atlas REST API v2 adapter: create one-off DNS CHAOS / traceroute
//! measurements, wait for them, fetch and parse results.
//!
//! All Atlas JSON shapes live in this module; results are untrusted input.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::time::Instant;

use crate::dns;
use crate::model::Observation;

const MAX_BODY: usize = 64 * 1024 * 1024;
const MAX_ABUF: usize = 64 * 1024;
const PROBE_BATCH: usize = 200;

#[derive(Debug, Error)]
pub enum AtlasError {
    #[error("RIPE Atlas rate limit reached (retry after {0:?} s)")]
    RateLimited(Option<u64>),
    #[error("RIPE Atlas refused the request for lack of credits: {0}")]
    Credits(String),
    #[error("RIPE Atlas API error {status}: {detail}")]
    Api { status: u16, detail: String },
    #[error("RIPE Atlas request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid RIPE Atlas response: {0}")]
    Decode(String),
    #[error("RIPE Atlas response exceeds {MAX_BODY} bytes")]
    TooLarge,
}

// ---- request / response shapes -------------------------------------------

#[derive(Debug, Serialize)]
struct CreateRequest {
    definitions: Vec<Definition>,
    probes: Vec<ProbeSpec>,
}

#[derive(Debug, Serialize)]
struct Definition {
    #[serde(rename = "type")]
    kind: &'static str,
    af: u8,
    target: String,
    description: String,
    is_oneoff: bool,
    protocol: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_class: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_argument: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_probe_resolver: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_nsid_bit: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ProbeSpec {
    #[serde(rename = "type")]
    kind: &'static str,
    value: String,
    requested: u32,
}

#[derive(Debug, Deserialize)]
struct CreateResponse {
    measurements: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Deserialize)]
struct ErrorDetail {
    detail: Option<String>,
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MeasurementStatus {
    status: StatusInfo,
}

#[derive(Debug, Deserialize)]
struct StatusInfo {
    id: u32,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProbePage {
    results: Vec<ProbeMeta>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProbeMeta {
    pub id: u64,
    pub country_code: Option<String>,
    pub asn_v4: Option<u32>,
    pub asn_v6: Option<u32>,
    #[serde(default)]
    pub geometry: Option<Geometry>,
}

/// GeoJSON point `{"type":"Point","coordinates":[lon, lat]}`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Geometry {
    #[serde(default)]
    pub coordinates: Vec<f64>,
}

impl ProbeMeta {
    /// (lat, lon) when the probe publishes a sane location.
    pub fn location(&self) -> Option<(f64, f64)> {
        let c = &self.geometry.as_ref()?.coordinates;
        let (lon, lat) = (*c.first()?, *c.get(1)?);
        ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)).then_some((lat, lon))
    }
}

#[derive(Debug, Deserialize)]
struct Credits {
    current_balance: i64,
}

/// One element of `/measurements/{id}/results/`.
#[derive(Debug, Deserialize)]
struct RawResult {
    prb_id: u64,
    #[serde(rename = "type")]
    kind: String,
    dst_addr: Option<String>,
    result: Option<Value>,
    resultset: Option<Vec<ResultSetItem>>,
    error: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ResultSetItem {
    result: Option<Value>,
    error: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct DnsResult {
    rt: Option<f64>,
    abuf: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Hop {
    result: Option<Vec<Reply>>,
}

#[derive(Debug, Deserialize)]
struct Reply {
    from: Option<String>,
    rtt: Option<f64>,
}

// ---- parsing ---------------------------------------------------------------

/// Per-probe data extracted from one measurement's results.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ProbeResult {
    pub chaos: Option<String>,
    pub nsid: Option<String>,
    pub dns_rtt_ms: Option<f64>,
    pub last_hop: Option<IpAddr>,
    pub trace_rtt_ms: Option<f64>,
    pub error: Option<String>,
}

fn short_error(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    dns::sanitize(s.as_bytes())
}

fn parse_dns(result: &Value, out: &mut ProbeResult) {
    let Ok(r) = serde_json::from_value::<DnsResult>(result.clone()) else {
        out.error = Some("malformed dns result".into());
        return;
    };
    let Some(abuf) = r.abuf.filter(|a| a.len() <= MAX_ABUF) else {
        out.error = Some("dns result without abuf".into());
        return;
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(abuf.as_bytes())
        .map_err(|e| e.to_string())
        .and_then(|bytes| dns::parse_response(&bytes, None).map_err(|e| e.to_string()));
    match decoded {
        Ok(msg) => {
            out.chaos = msg.first_txt().map(str::to_string);
            out.nsid = msg.nsid;
            out.dns_rtt_ms = r.rt;
            if out.chaos.is_none() && out.nsid.is_none() {
                out.error = Some("no TXT answer".into());
            }
        }
        Err(e) => out.error = Some(format!("abuf: {e}")),
    }
}

fn parse_traceroute(result: &Value, dst: Option<IpAddr>, out: &mut ProbeResult) {
    let Ok(hops) = serde_json::from_value::<Vec<Hop>>(result.clone()) else {
        out.error = Some("malformed traceroute result".into());
        return;
    };
    for hop in &hops {
        let replies: Vec<(IpAddr, Option<f64>)> = hop
            .result
            .iter()
            .flatten()
            .filter_map(|r| Some((r.from.as_deref()?.parse().ok()?, r.rtt)))
            .collect();
        let min_rtt = |pred: &dyn Fn(&IpAddr) -> bool| {
            replies
                .iter()
                .filter(|(ip, _)| pred(ip))
                .filter_map(|(_, rtt)| *rtt)
                .reduce(f64::min)
        };
        if let Some(rtt) = min_rtt(&|ip| Some(*ip) == dst) {
            out.trace_rtt_ms = Some(rtt);
        }
        // The anycast address itself says nothing about the PoP; keep the hop before it.
        if let Some((ip, _)) = replies.iter().find(|(ip, _)| Some(*ip) != dst) {
            out.last_hop = Some(*ip);
        }
    }
}

/// Parse a results array (DNS or traceroute) into per-probe data.
pub fn parse_results(body: &[u8]) -> Result<BTreeMap<u64, ProbeResult>, AtlasError> {
    let raw: Vec<Value> =
        serde_json::from_slice(body).map_err(|e| AtlasError::Decode(e.to_string()))?;
    let mut out: BTreeMap<u64, ProbeResult> = BTreeMap::new();
    for item in raw {
        let r: RawResult = match serde_json::from_value(item) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "skipping malformed RIPE Atlas result");
                continue;
            }
        };
        let entry = out.entry(r.prb_id).or_default();
        if let Some(e) = &r.error {
            entry.error = Some(short_error(e));
        }
        match r.kind.as_str() {
            "dns" => {
                let mut results: Vec<&Value> = r.result.iter().collect();
                for item in r.resultset.iter().flatten() {
                    if let Some(e) = &item.error {
                        entry.error = Some(short_error(e));
                    }
                    results.extend(item.result.iter());
                }
                for res in results {
                    parse_dns(res, entry);
                    if entry.chaos.is_some() || entry.nsid.is_some() {
                        entry.error = None;
                        break;
                    }
                }
            }
            "traceroute" => {
                let dst = r.dst_addr.as_deref().and_then(|d| d.parse().ok());
                if let Some(res) = &r.result {
                    parse_traceroute(res, dst, entry);
                }
            }
            other => {
                entry.error = Some(format!(
                    "unsupported result type {}",
                    dns::sanitize(other.as_bytes())
                ));
            }
        }
    }
    Ok(out)
}

/// Merge DNS and traceroute data with probe metadata into observations of `target`.
pub fn to_observations(
    results: &BTreeMap<u64, ProbeResult>,
    meta: &BTreeMap<u64, ProbeMeta>,
    target: IpAddr,
) -> Vec<Observation> {
    results
        .iter()
        .map(|(id, r)| {
            let m = meta.get(id);
            let loc = m.and_then(ProbeMeta::location);
            Observation {
                vantage: format!("atlas:{id}"),
                target: Some(target),
                country: m
                    .and_then(|m| m.country_code.as_deref())
                    .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
                    .map(str::to_ascii_uppercase),
                asn: m.and_then(|m| if target.is_ipv6() { m.asn_v6 } else { m.asn_v4 }),
                lat: loc.map(|l| l.0),
                lon: loc.map(|l| l.1),
                chaos: r.chaos.clone(),
                nsid: r.nsid.clone(),
                last_hop: r.last_hop,
                rtt_ms: r.dns_rtt_ms.or(r.trace_rtt_ms),
                error: r.error.clone(),
                ..Observation::default()
            }
        })
        .collect()
}

/// Merge `src` into `dst`, keeping already-known fields.
pub fn merge(dst: &mut BTreeMap<u64, ProbeResult>, src: BTreeMap<u64, ProbeResult>) {
    for (id, r) in src {
        let e = dst.entry(id).or_default();
        e.chaos = e.chaos.take().or(r.chaos);
        e.nsid = e.nsid.take().or(r.nsid);
        e.dns_rtt_ms = e.dns_rtt_ms.or(r.dns_rtt_ms);
        e.last_hop = e.last_hop.or(r.last_hop);
        e.trace_rtt_ms = e.trace_rtt_ms.or(r.trace_rtt_ms);
        if e.chaos.is_some() || e.nsid.is_some() {
            e.error = None;
        } else {
            e.error = e.error.take().or(r.error);
        }
    }
}

// ---- client ----------------------------------------------------------------

pub struct AtlasClient {
    http: reqwest::Client,
    base: String,
    key: Option<String>,
}

impl AtlasClient {
    pub fn new(http: reqwest::Client, base: &str, key: Option<String>) -> Self {
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            key,
        }
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Vec<u8>, AtlasError> {
        let req = match &self.key {
            Some(k) => req.header("Authorization", format!("Key {k}")),
            None => req,
        };
        let mut resp = req.send().await?;
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok());
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(AtlasError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        if status.is_success() {
            return Ok(body);
        }
        if status.as_u16() == 429 {
            return Err(AtlasError::RateLimited(retry_after));
        }
        Err(api_error(status.as_u16(), &body))
    }

    /// Create a one-off measurement and return its id.
    async fn create(&self, request: &CreateRequest) -> Result<u64, AtlasError> {
        let body = self
            .send(
                self.http
                    .post(format!("{}/measurements/", self.base))
                    .json(request),
            )
            .await?;
        let resp: CreateResponse =
            serde_json::from_slice(&body).map_err(|e| AtlasError::Decode(e.to_string()))?;
        resp.measurements
            .first()
            .copied()
            .ok_or_else(|| AtlasError::Decode("no measurement id returned".into()))
    }

    pub async fn create_chaos(
        &self,
        target: IpAddr,
        qname: &str,
        nsid: bool,
        countries: &[String],
        per_country: u32,
    ) -> Result<u64, AtlasError> {
        let request = CreateRequest {
            definitions: vec![chaos_definition(target, qname, nsid)],
            probes: countries
                .iter()
                .map(|c| ProbeSpec {
                    kind: "countries",
                    value: c.clone(),
                    requested: per_country,
                })
                .collect(),
        };
        self.create(&request).await
    }

    /// CHAOS query to `target` from exactly the probes of measurement
    /// `probes_from` (dual-stack: the IPv6 run reuses the IPv4 probes).
    pub async fn create_chaos_from(
        &self,
        target: IpAddr,
        qname: &str,
        nsid: bool,
        probes_from: u64,
        requested: u32,
    ) -> Result<u64, AtlasError> {
        let request = CreateRequest {
            definitions: vec![chaos_definition(target, qname, nsid)],
            probes: vec![ProbeSpec {
                kind: "msm",
                value: probes_from.to_string(),
                requested,
            }],
        };
        self.create(&request).await
    }

    /// Current account balance (`GET /credits/`); needs a key with credit access.
    pub async fn balance(&self) -> Result<i64, AtlasError> {
        let body = self
            .send(
                self.http
                    .get(format!("{}/credits/", self.base))
                    .query(&[("fields", "current_balance")]),
            )
            .await?;
        let c: Credits =
            serde_json::from_slice(&body).map_err(|e| AtlasError::Decode(e.to_string()))?;
        Ok(c.current_balance)
    }

    /// Traceroute from exactly the probes that ran measurement `probes_from`.
    pub async fn create_traceroute(
        &self,
        target: IpAddr,
        probes_from: u64,
        requested: u32,
    ) -> Result<u64, AtlasError> {
        let request = CreateRequest {
            definitions: vec![Definition {
                kind: "traceroute",
                af: af(target),
                target: target.to_string(),
                description: format!("Catchment traceroute {target}"),
                is_oneoff: true,
                protocol: "ICMP",
                query_class: None,
                query_type: None,
                query_argument: None,
                use_probe_resolver: None,
                set_nsid_bit: None,
            }],
            probes: vec![ProbeSpec {
                kind: "msm",
                value: probes_from.to_string(),
                requested,
            }],
        };
        self.create(&request).await
    }

    /// Poll the measurement status until it is finished or `wait` elapses.
    pub async fn wait_finished(
        &self,
        id: u64,
        wait: Duration,
        poll: Duration,
    ) -> Result<(), AtlasError> {
        let deadline = Instant::now() + wait;
        loop {
            let body = self
                .send(self.http.get(format!("{}/measurements/{id}/", self.base)))
                .await?;
            let st: MeasurementStatus =
                serde_json::from_slice(&body).map_err(|e| AtlasError::Decode(e.to_string()))?;
            // 4 Stopped, 5 Forced to stop, 6 No suitable probes, 7 Failed, 8 Archived.
            if (4..=8).contains(&st.status.id) {
                tracing::info!(measurement = id, status = ?st.status.name, "measurement finished");
                return Ok(());
            }
            if Instant::now() + poll > deadline {
                tracing::warn!(measurement = id, "wait elapsed, fetching partial results");
                return Ok(());
            }
            tokio::time::sleep(poll).await;
        }
    }

    pub async fn results(&self, id: u64) -> Result<BTreeMap<u64, ProbeResult>, AtlasError> {
        let body = self
            .send(
                self.http
                    .get(format!("{}/measurements/{id}/results/", self.base))
                    .query(&[("format", "json")]),
            )
            .await?;
        parse_results(&body)
    }

    pub async fn probes(&self, ids: &[u64]) -> Result<BTreeMap<u64, ProbeMeta>, AtlasError> {
        let mut out = BTreeMap::new();
        for chunk in ids.chunks(PROBE_BATCH) {
            let list = chunk
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let body = self
                .send(self.http.get(format!("{}/probes/", self.base)).query(&[
                    ("id__in", list.as_str()),
                    ("fields", "id,country_code,asn_v4,asn_v6,geometry"),
                    ("page_size", "500"),
                ]))
                .await?;
            let page: ProbePage =
                serde_json::from_slice(&body).map_err(|e| AtlasError::Decode(e.to_string()))?;
            out.extend(page.results.into_iter().map(|p| (p.id, p)));
        }
        Ok(out)
    }
}

fn af(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        4
    } else {
        6
    }
}

fn chaos_definition(target: IpAddr, qname: &str, nsid: bool) -> Definition {
    Definition {
        kind: "dns",
        af: af(target),
        target: target.to_string(),
        description: format!("Catchment CHAOS {qname} {target}"),
        is_oneoff: true,
        protocol: "UDP",
        query_class: Some("CHAOS"),
        query_type: Some("TXT"),
        query_argument: Some(qname.to_string()),
        use_probe_resolver: Some(false),
        set_nsid_bit: nsid.then_some(true),
    }
}

fn api_error(status: u16, body: &[u8]) -> AtlasError {
    let detail = serde_json::from_slice::<ErrorBody>(body)
        .ok()
        .and_then(|b| b.error.detail.or(b.error.title))
        .map(|d| dns::sanitize(d.as_bytes()))
        .unwrap_or_else(|| "no error detail".into());
    if status == 402 || detail.to_ascii_lowercase().contains("credit") {
        AtlasError::Credits(detail)
    } else {
        AtlasError::Api { status, detail }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNS_FIXTURE: &str = include_str!("../tests/fixtures/atlas_dns_results.json");
    const TRACE_FIXTURE: &str = include_str!("../tests/fixtures/atlas_traceroute_results.json");

    #[test]
    fn parses_dns_fixture() {
        let r = parse_results(DNS_FIXTURE.as_bytes()).unwrap();
        assert_eq!(r[&1001].chaos.as_deref(), Some("fra1.example"));
        assert_eq!(r[&1001].dns_rtt_ms, Some(12.5));
        // Answer found in the second resultset item.
        assert_eq!(r[&1002].chaos.as_deref(), Some("ist1-01.example"));
        assert_eq!(r[&1003].chaos, None);
        assert!(r[&1003].error.as_deref().unwrap().contains("timeout"));
        assert!(r[&1004].error.as_deref().unwrap().starts_with("abuf"));
    }

    #[test]
    fn parses_traceroute_fixture() {
        let r = parse_results(TRACE_FIXTURE.as_bytes()).unwrap();
        assert_eq!(r[&1001].last_hop, Some("198.51.100.1".parse().unwrap()));
        assert_eq!(r[&1001].trace_rtt_ms, Some(10.1));
        // Unreached target: last responding hop, no rtt.
        assert_eq!(r[&1003].last_hop, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(r[&1003].trace_rtt_ms, None);
    }

    #[test]
    fn merges_and_builds_observations() {
        let mut all = parse_results(DNS_FIXTURE.as_bytes()).unwrap();
        merge(&mut all, parse_results(TRACE_FIXTURE.as_bytes()).unwrap());
        let mut meta = BTreeMap::new();
        meta.insert(
            1001,
            ProbeMeta {
                id: 1001,
                country_code: Some("DE".into()),
                asn_v4: Some(64496),
                asn_v6: None,
                geometry: serde_json::from_str(r#"{"type":"Point","coordinates":[8.68,50.11]}"#)
                    .ok(),
            },
        );
        let obs = to_observations(&all, &meta, "192.0.2.53".parse().unwrap());
        assert_eq!(obs[0].vantage, "atlas:1001");
        assert_eq!(obs[0].country.as_deref(), Some("DE"));
        assert_eq!(obs[0].asn, Some(64496));
        assert_eq!(obs[0].chaos.as_deref(), Some("fra1.example"));
        assert_eq!(obs[0].last_hop, Some("198.51.100.1".parse().unwrap()));
        assert_eq!(obs[0].rtt_ms, Some(12.5));
        assert_eq!((obs[0].lat, obs[0].lon), (Some(50.11), Some(8.68)));
        assert_eq!(obs[0].target, Some("192.0.2.53".parse().unwrap()));
        assert_eq!(obs[2].country, None);
    }

    #[test]
    fn rejects_non_array_and_skips_malformed_items() {
        assert!(parse_results(b"{\"error\":1}").is_err());
        let r = parse_results(br#"[{"type":"dns"},{"prb_id":7,"type":"ping"}]"#).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[&7].error.as_deref().unwrap().contains("unsupported"));
    }

    #[test]
    fn create_request_shape() {
        let req = CreateRequest {
            definitions: vec![chaos_definition(
                "192.0.2.53".parse().unwrap(),
                "id.server",
                true,
            )],
            probes: vec![ProbeSpec {
                kind: "countries",
                value: "TR".into(),
                requested: 5,
            }],
        };
        let v = serde_json::to_value(&req).unwrap();
        let d = &v["definitions"][0];
        assert_eq!(d["type"], "dns");
        assert_eq!(d["af"], 4);
        assert_eq!(d["query_class"], "CHAOS");
        assert_eq!(d["query_type"], "TXT");
        assert_eq!(d["query_argument"], "id.server");
        assert_eq!(d["use_probe_resolver"], false);
        assert_eq!(d["is_oneoff"], true);
        assert_eq!(d["set_nsid_bit"], true);
        let plain = serde_json::to_value(chaos_definition(
            "2001:db8::53".parse().unwrap(),
            "id.server",
            false,
        ))
        .unwrap();
        assert_eq!(plain["af"], 6);
        assert!(plain.get("set_nsid_bit").is_none());
        assert_eq!(v["probes"][0]["type"], "countries");
        assert_eq!(v["probes"][0]["requested"], 5);
    }

    #[test]
    fn parses_nsid_from_abuf_and_location() {
        let abuf = crate::dns::tests::txt_nsid_response(1, "id.server", b"x", b"fra1-ns");
        let body = format!(
            r#"[{{"prb_id":5,"type":"dns","result":{{"rt":3.5,"abuf":"{}"}}}}]"#,
            base64::engine::general_purpose::STANDARD.encode(abuf)
        );
        let r = parse_results(body.as_bytes()).unwrap();
        assert_eq!(r[&5].nsid.as_deref(), Some("fra1-ns"));
        let bad: ProbeMeta =
            serde_json::from_str(r#"{"id":1,"geometry":{"type":"Point","coordinates":[500,1]}}"#)
                .unwrap();
        assert_eq!(bad.location(), None);
        let none: ProbeMeta = serde_json::from_str(r#"{"id":1,"geometry":null}"#).unwrap();
        assert_eq!(none.location(), None);
        let c: Credits =
            serde_json::from_str(r#"{"current_balance":12345,"type":"credit"}"#).unwrap();
        assert_eq!(c.current_balance, 12345);
    }

    #[test]
    fn maps_api_errors() {
        let body = br#"{"error":{"status":402,"code":104,"title":"Payment Required","detail":"Not enough credits"}}"#;
        assert!(matches!(api_error(402, body), AtlasError::Credits(_)));
        let body = br#"{"error":{"status":400,"title":"Bad Request","detail":"Invalid target"}}"#;
        match api_error(400, body) {
            AtlasError::Api { status, detail } => {
                assert_eq!(status, 400);
                assert_eq!(detail, "Invalid target");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(api_error(500, b"<html>"), AtlasError::Api { .. }));
    }
}
