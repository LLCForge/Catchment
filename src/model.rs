//! Data types shared by vantage adapters, the attributor, the diff engine and exporters.

use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Raw measurement from one vantage point, before attribution.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// `local`, `atlas:<probe id>` or `agent:<name>`.
    pub vantage: String,
    /// Address probed (dual-stack rounds have two); `None` in rounds written by
    /// older versions, meaning the round's `target`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<IpAddr>,
    pub country: Option<String>,
    /// ASN the vantage point itself sits in.
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lon: Option<f64>,
    /// CHAOS TXT answer (sanitized).
    pub chaos: Option<String>,
    /// EDNS NSID payload (sanitized; hex when not printable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsid: Option<String>,
    /// Value of the configured HTTP identification header (sanitized).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_id: Option<String>,
    /// Last responding traceroute hop before the target.
    pub last_hop: Option<IpAddr>,
    pub last_hop_asn: Option<u32>,
    pub last_hop_rdns: Option<String>,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
    /// Why the local/agent traceroute did not run or failed (CHAOS still counts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Chaos,
    Nsid,
    Http,
    LastHopAsn,
    LastHopPrefix,
    Rdns,
}

impl MatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chaos => "chaos",
            Self::Nsid => "nsid",
            Self::Http => "http",
            Self::LastHopAsn => "last_hop_asn",
            Self::LastHopPrefix => "last_hop_prefix",
            Self::Rdns => "rdns",
        }
    }
}

/// Observation plus attribution. `pop == None` means unattributed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    #[serde(flatten)]
    pub obs: Observation,
    pub pop: Option<String>,
    pub matched_by: Option<MatchKind>,
}

pub const UNATTRIBUTED: &str = "unattributed";

impl Record {
    pub fn pop_label(&self) -> &str {
        self.pop.as_deref().unwrap_or(UNATTRIBUTED)
    }

    /// Address this record measured.
    pub fn target_or(&self, round_target: IpAddr) -> IpAddr {
        self.obs.target.unwrap_or(round_target)
    }
}

/// One measurement round, as persisted in the data directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Round {
    pub started_ms: u64,
    pub target: IpAddr,
    /// Service name (multi-service configs); `None` for the single-service form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Experiment label (`catchment probe --label before`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub records: Vec<Record>,
}

impl Round {
    pub fn started_rfc3339(&self) -> String {
        rfc3339_ms(self.started_ms)
    }

    pub fn service_label(&self) -> &str {
        self.service
            .as_deref()
            .unwrap_or(crate::config::LEGACY_SERVICE)
    }
}

pub fn rfc3339_ms(ms: u64) -> String {
    humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_millis(ms)).to_string()
}

/// "v4" / "v6".
pub fn family(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "v4"
    } else {
        "v6"
    }
}

/// A vantage point that landed in a different PoP than in the previous round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatchmentShift {
    pub vantage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<IpAddr>,
    pub country: Option<String>,
    pub from: String,
    pub to: String,
}

/// Shifts aggregated per country, address and PoP transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryShift {
    pub country: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<IpAddr>,
    pub from: String,
    pub to: String,
    pub vantages: usize,
}

/// Per-country latency regression against the stored baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencyRegression {
    pub country: String,
    pub target: IpAddr,
    pub baseline_ms: f64,
    pub current_ms: f64,
    pub vantages: usize,
}

/// One routing event returned by Pathology for the service prefix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathEvent {
    pub time: String,
    pub peer: String,
    pub peer_asn: Option<u32>,
    pub prefix: String,
    pub kind: String,
    pub as_path: Vec<u32>,
}

/// Pathology correlation for a round with shifts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathCorrelation {
    pub prefix: String,
    pub since: String,
    pub events: Vec<PathEvent>,
    /// Set when the Pathology query failed; `events` is then empty.
    pub error: Option<String>,
}

/// Everything one round produced: the round itself and its diff to the previous one.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub round: Round,
    pub previous_started_ms: Option<u64>,
    pub shifts: Vec<CatchmentShift>,
    pub country_shifts: Vec<CountryShift>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub latency_regressions: Vec<LatencyRegression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_correlation: Option<PathCorrelation>,
}

impl Report {
    /// A report without comparison data (`catchment show`).
    pub fn standalone(round: Round) -> Self {
        Self {
            round,
            previous_started_ms: None,
            shifts: Vec::new(),
            country_shifts: Vec::new(),
            latency_regressions: Vec::new(),
            path_correlation: None,
        }
    }
}
