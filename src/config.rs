//! TOML configuration: parsing and startup validation.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use llcforge_beacon::{AlertsConfig, HealthConfig, LogFormat, SilencesConfig};
use serde::{Deserialize, Deserializer, Serialize};

pub const DEFAULT_ATLAS_URL: &str = "https://atlas.ripe.net/api/v2";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
pub const MAX_SERVICES: usize = 64;
pub const LEGACY_SERVICE: &str = "default";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Single-service form: `[target]` + `[[pop]]` (service name "default").
    pub target: Option<Target>,
    #[serde(default, rename = "pop")]
    pub pops: Vec<PopRule>,
    /// Multi-service form: `[[service]]` tables, each with its own target and PoPs.
    #[serde(default, rename = "service")]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub vantage: Vantage,
    #[serde(default)]
    pub schedule: Schedule,
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub lookup: Lookup,
    #[serde(default)]
    pub metrics: Metrics,
    #[serde(default)]
    pub alarms: Alarms,
    pub pathology: Option<PathologyConfig>,
    #[serde(default)]
    pub logging: Logging,
    /// Alert queue, silences and Atlas budget ledger; defaults to `[storage] dir`.
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub silences: SilencesConfig,
    #[serde(default)]
    pub health: HealthConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub name: String,
    pub target: Target,
    #[serde(rename = "pop")]
    pub pops: Vec<PopRule>,
    /// Anycast prefix announced for this service (Pathology correlation).
    /// Defaults to the /24 (IPv4) or /48 (IPv6) around the target address.
    pub prefix: Option<IpNet>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// The anycast address being measured (IPv4 or IPv6).
    pub address: IpAddr,
    /// Optional IPv6 address of the same service, measured alongside for a
    /// dual-stack comparison (requires `address` to be IPv4).
    pub address6: Option<IpAddr>,
    /// CHAOS TXT name asked to identify the answering PoP.
    #[serde(default = "default_qname")]
    pub qname: String,
    /// Also run an ICMP traceroute from every RIPE Atlas probe.
    #[serde(default)]
    pub traceroute: bool,
    /// Ask for the EDNS NSID option (RFC 5001) with every CHAOS query.
    #[serde(default)]
    pub nsid: bool,
    /// HTTP response header identification (local vantage and agents only).
    pub http: Option<HttpTarget>,
}

impl Target {
    pub fn addresses(&self) -> Vec<IpAddr> {
        std::iter::once(self.address).chain(self.address6).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTarget {
    /// URL requested from the anycast address (the host name is sent as SNI/Host,
    /// the connection always goes to the target address).
    pub url: String,
    /// Response header that names the PoP, e.g. "x-served-by".
    pub header: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopRule {
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: Match,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// Glob (`*`, `?`) matched case-insensitively against the CHAOS TXT answer.
    pub chaos: Option<String>,
    /// Glob matched against the NSID (RFC 5001) payload.
    pub nsid: Option<String>,
    /// Glob matched against the configured HTTP response header.
    pub http: Option<String>,
    pub last_hop_asn: Option<u32>,
    pub last_hop_prefix: Option<IpNet>,
    /// Regex matched against the reverse DNS name of the last hop.
    pub rdns: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vantage {
    pub local: Option<LocalVantage>,
    pub ripe_atlas: Option<AtlasVantage>,
    #[serde(default, rename = "agent")]
    pub agents: Vec<AgentVantage>,
}

/// Local traceroute protocol (raw sockets; needs privileges).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceMode {
    #[default]
    Off,
    Icmp,
    Udp,
    Tcp,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVantage {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// ISO 3166 alpha-2 country of this machine, used for per-country aggregation.
    pub country: Option<String>,
    /// ASN this machine sits in (per-ASN aggregation).
    pub asn: Option<u32>,
    /// Latitude / longitude for the HTML map.
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    #[serde(default = "default_local_timeout", deserialize_with = "de_duration")]
    pub timeout: Duration,
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    #[serde(default)]
    pub traceroute: TraceMode,
    #[serde(default = "default_max_hops")]
    pub max_hops: u8,
    /// Destination port for UDP (first probe; +1 per hop) and TCP traceroute.
    pub trace_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtlasVantage {
    #[serde(default = "default_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_atlas_url")]
    pub base_url: String,
    pub probes: ProbeSelection,
    /// How long to wait for one-off measurements to finish before fetching results.
    #[serde(default = "default_wait", deserialize_with = "de_duration")]
    pub wait: Duration,
    #[serde(default = "default_poll", deserialize_with = "de_duration")]
    pub poll: Duration,
    #[serde(default)]
    pub budget: Budget,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSelection {
    pub countries: Vec<String>,
    pub per_country: u32,
}

/// RIPE Atlas credit caps. Costs are estimated before a measurement is created
/// (one-off DNS/UDP 20 credits per result, one-off traceroute 60 per result).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub daily_credits: Option<u64>,
    pub monthly_credits: Option<u64>,
    /// Skip Atlas when the account balance (GET /credits/) is below this.
    pub min_balance: Option<u64>,
}

/// A self-hosted `catchment agent` reached over mutual TLS.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVantage {
    pub name: String,
    /// `https://agent.example.net:8443`
    pub url: String,
    /// CA that signed the agent's server certificate.
    pub ca: PathBuf,
    /// Client certificate and key presented to the agent.
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Overrides the country the agent reports.
    pub country: Option<String>,
    #[serde(default = "default_agent_timeout", deserialize_with = "de_duration")]
    pub timeout: Duration,
    #[serde(default)]
    pub traceroute: TraceMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    #[serde(deserialize_with = "de_duration")]
    pub interval: Duration,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15 * 60),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    #[serde(default = "default_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_retain")]
    pub retain: usize,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            dir: default_dir(),
            retain: default_retain(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lookup {
    /// Resolver used for reverse DNS of last hops (required by `rdns` rules).
    pub dns_resolver: Option<SocketAddr>,
    /// Parallel RIPEstat / reverse DNS lookups.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// How long an enrichment result is reused across rounds.
    #[serde(default = "default_cache_ttl", deserialize_with = "de_duration")]
    pub cache_ttl: Duration,
}

impl Default for Lookup {
    fn default() -> Self {
        Self {
            dns_resolver: None,
            concurrency: default_concurrency(),
            cache_ttl: default_cache_ttl(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Prometheus + /healthz + /readyz (+ admin API) listener for `catchment run`,
    /// e.g. "127.0.0.1:9184".
    pub listen: Option<SocketAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alarms {
    /// Raise `catchment_shift` alerts (per service, country and transition).
    #[serde(default = "yes")]
    pub shift: bool,
    /// Minimum vantages that must make the same move before alerting.
    #[serde(default = "one")]
    pub shift_min_vantages: usize,
    #[serde(default)]
    pub latency: LatencyAlarm,
}

impl Default for Alarms {
    fn default() -> Self {
        Self {
            shift: true,
            shift_min_vantages: 1,
            latency: LatencyAlarm::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyAlarm {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Previous rounds whose per-country medians form the baseline.
    #[serde(default = "default_baseline_rounds")]
    pub baseline_rounds: usize,
    /// Vantages with an RTT a country needs in the current round.
    #[serde(default = "default_min_vantages")]
    pub min_vantages: usize,
    /// Alarm when current median > baseline * ratio ...
    #[serde(default = "default_ratio")]
    pub ratio: f64,
    /// ... and current median - baseline >= this many milliseconds.
    #[serde(default = "default_min_increase")]
    pub min_increase_ms: f64,
}

impl Default for LatencyAlarm {
    fn default() -> Self {
        Self {
            enabled: true,
            baseline_rounds: default_baseline_rounds(),
            min_vantages: default_min_vantages(),
            ratio: default_ratio(),
            min_increase_ms: default_min_increase(),
        }
    }
}

/// Optional Pathology API used to explain shifts (`GET /v1/routes`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathologyConfig {
    /// e.g. "http://127.0.0.1:8180" (plain http only for loopback hosts).
    pub url: String,
    pub token_env: Option<String>,
    #[serde(
        default = "default_pathology_timeout",
        deserialize_with = "de_duration"
    )]
    pub timeout: Duration,
    #[serde(default = "default_pathology_limit")]
    pub limit: u32,
}

/// Validated here; applied early by `main::logging_from_file` (before the
/// full load, so load errors are already logged in the configured format).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Logging {
    pub format: Option<LogFormat>,
    pub level: Option<String>,
}

fn default_qname() -> String {
    "hostname.bind".into()
}
fn yes() -> bool {
    true
}
fn one() -> usize {
    1
}
fn default_local_timeout() -> Duration {
    Duration::from_secs(2)
}
fn default_agent_timeout() -> Duration {
    Duration::from_secs(60)
}
fn default_attempts() -> u32 {
    3
}
fn default_max_hops() -> u8 {
    30
}
fn default_key_env() -> String {
    "RIPE_ATLAS_KEY".into()
}
fn default_atlas_url() -> String {
    DEFAULT_ATLAS_URL.into()
}
fn default_wait() -> Duration {
    Duration::from_secs(10 * 60)
}
fn default_poll() -> Duration {
    Duration::from_secs(30)
}
/// `$STATE_DIRECTORY` (systemd, container image) when set, else `./catchment-data`.
fn default_dir() -> PathBuf {
    std::env::var_os("STATE_DIRECTORY")
        .filter(|v| !v.is_empty())
        .map(|d| {
            let s = d.to_string_lossy().into_owned();
            PathBuf::from(s.split(':').next().unwrap_or(&s))
        })
        .unwrap_or_else(|| PathBuf::from("catchment-data"))
}
fn default_retain() -> usize {
    500
}
fn default_concurrency() -> usize {
    16
}
fn default_cache_ttl() -> Duration {
    Duration::from_secs(6 * 3600)
}
fn default_baseline_rounds() -> usize {
    8
}
fn default_min_vantages() -> usize {
    3
}
fn default_ratio() -> f64 {
    1.5
}
fn default_min_increase() -> f64 {
    20.0
}
fn default_pathology_timeout() -> Duration {
    Duration::from_secs(5)
}
fn default_pathology_limit() -> u32 {
    100
}

pub fn de_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    humantime::parse_duration(&s).map_err(serde::de::Error::custom)
}

/// What the configuration is going to be used for; validation differs slightly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Probe,
    Fetch,
}

/// A measured anycast service after normalisation of both config forms.
#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub target: Target,
    pub pops: Vec<PopRule>,
    pub prefix: IpNet,
    /// Round files of this service.
    pub dir: PathBuf,
}

/// /24 or /48 around an address: the smallest prefix normally accepted in the DFZ.
pub fn default_prefix(ip: IpAddr) -> IpNet {
    let len = if ip.is_ipv4() { 24 } else { 48 };
    IpNet::new(ip, len)
        .map(|n| n.trunc())
        .unwrap_or_else(|_| IpNet::from(ip))
}

impl Config {
    pub fn load(path: &Path, purpose: Purpose) -> Result<Self> {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        if meta.len() > MAX_CONFIG_BYTES {
            bail!("config {} is larger than 1 MiB", path.display());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        let cfg = Self::parse(&text)?;
        cfg.validate(purpose)?;
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).context("invalid config")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| self.storage.dir.clone())
    }

    /// Both config forms as a list. The single-service form keeps its rounds
    /// directly in `[storage] dir` (compatible with earlier versions).
    pub fn services(&self) -> Vec<Service> {
        let legacy = self.target.iter().map(|t| Service {
            name: LEGACY_SERVICE.into(),
            target: t.clone(),
            pops: self.pops.clone(),
            prefix: default_prefix(t.address),
            dir: self.storage.dir.clone(),
        });
        let named = self.services.iter().map(|s| Service {
            name: s.name.clone(),
            target: s.target.clone(),
            pops: s.pops.clone(),
            prefix: s.prefix.unwrap_or_else(|| default_prefix(s.target.address)),
            dir: self.storage.dir.join(&s.name),
        });
        legacy.chain(named).collect()
    }

    pub fn validate(&self, purpose: Purpose) -> Result<()> {
        match (self.target.is_some(), self.services.is_empty()) {
            (false, true) => bail!("configure [target] + [[pop]] or at least one [[service]]"),
            (true, false) => bail!("use either [target] + [[pop]] or [[service]], not both"),
            (true, true) => {}
            (false, false) => {
                if !self.pops.is_empty() {
                    bail!("top-level [[pop]] rules need [target]; put them in [[service.pop]]");
                }
            }
        }
        if self.services.len() > MAX_SERVICES {
            bail!("at most {MAX_SERVICES} [[service]] entries are supported");
        }
        let mut names = std::collections::HashSet::new();
        for s in &self.services {
            validate_name("[[service]]", &s.name)?;
            if s.name.eq_ignore_ascii_case(LEGACY_SERVICE) {
                bail!("[[service]] name \"default\" is reserved");
            }
            if !names.insert(s.name.to_ascii_lowercase()) {
                bail!("duplicate [[service]] name {:?}", s.name);
            }
            if let Some(p) = s.prefix {
                if !s.target.addresses().iter().any(|a| p.contains(a)) {
                    bail!(
                        "[[service]] {:?}: prefix {p} does not contain the target",
                        s.name
                    );
                }
            }
        }
        for svc in self.services() {
            validate_target(&svc.name, &svc.target)?;
            validate_pops(&svc.name, &svc.pops, self.lookup.dns_resolver.is_some())?;
            if svc.target.http.is_none() && svc.pops.iter().any(|p| p.matcher.http.is_some()) {
                bail!(
                    "service {:?} has an http rule but no target.http to probe",
                    svc.name
                );
            }
        }
        if let Some(local) = &self.vantage.local {
            if local.timeout.is_zero() || local.timeout > Duration::from_secs(30) {
                bail!("[vantage.local] timeout must be between 1ms and 30s");
            }
            if !(1..=10).contains(&local.attempts) {
                bail!("[vantage.local] attempts must be 1-10");
            }
            if let Some(c) = &local.country {
                validate_country(c)?;
            }
            validate_location("[vantage.local]", local.lat, local.lon)?;
            if !(1..=64).contains(&local.max_hops) {
                bail!("[vantage.local] max_hops must be 1-64");
            }
        }
        if let Some(atlas) = &self.vantage.ripe_atlas {
            validate_atlas(atlas, purpose)?;
        }
        let mut agent_names = std::collections::HashSet::new();
        for a in &self.vantage.agents {
            validate_name("[[vantage.agent]]", &a.name)?;
            if !agent_names.insert(a.name.as_str()) {
                bail!("duplicate [[vantage.agent]] name {:?}", a.name);
            }
            if !a.url.starts_with("https://") || a.url.len() > 2048 {
                bail!("[[vantage.agent]] {:?}: url must use https://", a.name);
            }
            if let Some(c) = &a.country {
                validate_country(c)?;
            }
            if a.timeout.is_zero() || a.timeout > Duration::from_secs(600) {
                bail!("[[vantage.agent]] {:?}: timeout must be 1ms-10m", a.name);
            }
        }
        if purpose == Purpose::Probe {
            let local = self.vantage.local.as_ref().is_some_and(|l| l.enabled);
            if !local && self.vantage.ripe_atlas.is_none() && self.vantage.agents.is_empty() {
                bail!("no vantage enabled: configure [vantage.local], [vantage.ripe_atlas] and/or [[vantage.agent]]");
            }
        }
        if self.schedule.interval < Duration::from_secs(60) {
            bail!("[schedule] interval must be at least 1m");
        }
        if self.storage.retain == 0 {
            bail!("[storage] retain must be at least 1");
        }
        if !(1..=256).contains(&self.lookup.concurrency) {
            bail!("[lookup] concurrency must be 1-256");
        }
        let lat = &self.alarms.latency;
        let latency_ok = (1..=100).contains(&lat.baseline_rounds)
            && lat.min_vantages > 0
            && lat.ratio.is_finite()
            && lat.ratio >= 1.0
            && lat.min_increase_ms.is_finite()
            && lat.min_increase_ms >= 0.0;
        if !latency_ok {
            bail!("[alarms.latency]: baseline_rounds 1-100, min_vantages >= 1, ratio >= 1, min_increase_ms >= 0");
        }
        if self.alarms.shift_min_vantages == 0 {
            bail!("[alarms] shift_min_vantages must be at least 1");
        }
        if let Some(p) = &self.pathology {
            validate_local_http_url("[pathology] url", &p.url)?;
            if p.timeout.is_zero() || p.timeout > Duration::from_secs(60) {
                bail!("[pathology] timeout must be 1ms-60s");
            }
            if !(1..=1000).contains(&p.limit) {
                bail!("[pathology] limit must be 1-1000");
            }
        }
        if let Some(level) = &self.logging.level {
            llcforge_beacon::logging::build_filter(level, None)
                .map_err(|e| anyhow::anyhow!("[logging] {e}"))?;
        }
        Ok(())
    }
}

fn validate_target(service: &str, t: &Target) -> Result<()> {
    validate_qname(&t.qname)?;
    if let Some(v6) = t.address6 {
        if !t.address.is_ipv4() || !v6.is_ipv6() {
            bail!("service {service:?}: dual-stack needs address = IPv4 and address6 = IPv6");
        }
    }
    if let Some(h) = &t.http {
        validate_http_target(h).with_context(|| format!("service {service:?}: target.http"))?;
    }
    Ok(())
}

pub fn validate_http_target(h: &HttpTarget) -> Result<()> {
    if h.url.len() > 2048 {
        bail!("url is longer than 2048 bytes");
    }
    let url = reqwest::Url::parse(&h.url).context("invalid url")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("url must use http:// or https://");
    }
    if !matches!(url.host(), Some(url::Host::Domain(_))) {
        bail!("url host must be a DNS name (the connection always goes to the target address)");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("url must not contain credentials");
    }
    let header_ok = !h.header.is_empty()
        && h.header.len() <= 64
        && h.header
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !header_ok {
        bail!("header must be 1-64 chars of [A-Za-z0-9_-]");
    }
    Ok(())
}

fn validate_pops(service: &str, pops: &[PopRule], has_resolver: bool) -> Result<()> {
    if pops.is_empty() {
        bail!("service {service:?}: at least one [[pop]] rule is required");
    }
    let mut seen = std::collections::HashSet::new();
    for pop in pops {
        validate_pop_name(&pop.name)?;
        if !seen.insert(pop.name.as_str()) {
            bail!("duplicate [[pop]] name {:?}", pop.name);
        }
        let m = &pop.matcher;
        if m.chaos.is_none()
            && m.nsid.is_none()
            && m.http.is_none()
            && m.last_hop_asn.is_none()
            && m.last_hop_prefix.is_none()
            && m.rdns.is_none()
        {
            bail!("[[pop]] {:?} has an empty match table", pop.name);
        }
        for (key, glob) in [("chaos", &m.chaos), ("nsid", &m.nsid), ("http", &m.http)] {
            if glob.as_ref().is_some_and(|g| g.is_empty() || g.len() > 255) {
                bail!("[[pop]] {:?}: {key} glob must be 1-255 chars", pop.name);
            }
        }
        if m.rdns.is_some() && !has_resolver {
            bail!(
                "[[pop]] {:?} uses an rdns rule; set [lookup] dns_resolver",
                pop.name
            );
        }
    }
    Ok(())
}

fn validate_atlas(atlas: &AtlasVantage, purpose: Purpose) -> Result<()> {
    if !atlas.base_url.starts_with("https://") {
        bail!("[vantage.ripe_atlas] base_url must use https://");
    }
    if atlas.api_key_env.is_empty() {
        bail!("[vantage.ripe_atlas] api_key_env must not be empty");
    }
    if atlas.probes.countries.is_empty() || atlas.probes.countries.len() > 250 {
        bail!("[vantage.ripe_atlas] probes.countries must list 1-250 countries");
    }
    for c in &atlas.probes.countries {
        validate_country(c)?;
    }
    if !(1..=500).contains(&atlas.probes.per_country) {
        bail!("[vantage.ripe_atlas] probes.per_country must be 1-500");
    }
    if atlas.poll < Duration::from_secs(5) || atlas.wait < atlas.poll {
        bail!("[vantage.ripe_atlas] poll must be >= 5s and wait >= poll");
    }
    if atlas.budget.daily_credits == Some(0) || atlas.budget.monthly_credits == Some(0) {
        bail!("[vantage.ripe_atlas.budget] caps must be positive (omit to disable)");
    }
    // The key is only needed to create measurements; fetching public results works without it.
    if purpose == Purpose::Probe && std::env::var(&atlas.api_key_env).is_err() {
        bail!(
            "environment variable {} (RIPE Atlas API key) is not set",
            atlas.api_key_env
        );
    }
    Ok(())
}

/// Plain http is accepted only for loopback hosts; anything else needs https.
pub fn validate_local_http_url(what: &str, raw: &str) -> Result<()> {
    if raw.len() > 2048 {
        bail!("{what} is longer than 2048 bytes");
    }
    let url = reqwest::Url::parse(raw).with_context(|| format!("{what} is not a URL"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match url.host() {
                Some(url::Host::Ipv4(a)) => a.is_loopback(),
                Some(url::Host::Ipv6(a)) => a.is_loopback(),
                Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                None => false,
            };
            if loopback {
                Ok(())
            } else {
                bail!("{what}: plain http:// is only allowed for loopback hosts")
            }
        }
        _ => bail!("{what} must use http:// or https://"),
    }
}

pub fn validate_country(c: &str) -> Result<()> {
    if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
        bail!("country {c:?} must be an ISO 3166 alpha-2 code like \"DE\"");
    }
    Ok(())
}

pub fn validate_location(what: &str, lat: Option<f64>, lon: Option<f64>) -> Result<()> {
    match (lat, lon) {
        (None, None) => Ok(()),
        (Some(la), Some(lo)) if (-90.0..=90.0).contains(&la) && (-180.0..=180.0).contains(&lo) => {
            Ok(())
        }
        _ => bail!("{what}: lat (-90..90) and lon (-180..180) must be set together"),
    }
}

fn validate_name(what: &str, name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && !name.starts_with('.');
    if !ok {
        bail!("{what} name {name:?} must be 1-64 chars of [A-Za-z0-9._-]");
    }
    Ok(())
}

fn validate_pop_name(name: &str) -> Result<()> {
    validate_name("[[pop]]", name)?;
    if name.eq_ignore_ascii_case("unattributed") {
        bail!("[[pop]] name \"unattributed\" is reserved");
    }
    Ok(())
}

pub fn validate_qname(name: &str) -> Result<()> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let ok = !trimmed.is_empty()
        && trimmed.len() <= 253
        && trimmed.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !ok {
        bail!("target qname {name:?} is not a valid DNS name");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
[target]
address = "192.0.2.53"

[[pop]]
name = "fra1"
match = { chaos = "fra1.*" }

[vantage.local]
country = "DE"
"#;

    #[test]
    fn parses_minimal_with_defaults() {
        let cfg = Config::parse(BASE).unwrap();
        cfg.validate(Purpose::Probe).unwrap();
        let t = cfg.target.as_ref().unwrap();
        assert_eq!(t.qname, "hostname.bind");
        assert!(!t.nsid);
        assert_eq!(cfg.schedule.interval, Duration::from_secs(900));
        assert_eq!(cfg.storage.retain, 500);
        let services = cfg.services();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "default");
        assert_eq!(services[0].dir, cfg.storage.dir);
        assert_eq!(services[0].prefix.to_string(), "192.0.2.0/24");
        assert!(cfg.vantage.local.unwrap().enabled);
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../catchment.example.toml");
        let cfg = Config::parse(text).unwrap();
        cfg.validate(Purpose::Fetch).unwrap();
        let services = cfg.services();
        assert!(services.len() >= 2);
        assert!(services[0].dir.ends_with(&services[0].name));
    }

    #[test]
    fn helm_default_config_is_valid() {
        let values = include_str!("../deploy/helm/catchment/values.yaml");
        let block: String = values
            .lines()
            .skip_while(|l| !l.starts_with("config: |"))
            .skip(1)
            .take_while(|l| l.is_empty() || l.starts_with("  "))
            .map(|l| {
                format!(
                    "{}
",
                    l.strip_prefix("  ").unwrap_or(l)
                )
            })
            .collect();
        let cfg = Config::parse(&block).unwrap();
        cfg.validate(Purpose::Probe).unwrap();
        assert_eq!(cfg.metrics.listen.unwrap().port(), 9184);
    }

    #[test]
    fn multi_service_form() {
        let text = r#"
[[service]]
name = "dns"
prefix = "192.0.2.0/23"
target = { address = "192.0.2.53", address6 = "2001:db8::53", nsid = true }
pop = [{ name = "fra1", match = { nsid = "fra1*" } }]

[[service]]
name = "cdn"
target = { address = "2001:db8:1::80", http = { url = "https://www.example.net/", header = "x-served-by" } }
pop = [{ name = "ams1", match = { http = "*ams1*" } }]

[vantage.local]
"#;
        let cfg = Config::parse(text).unwrap();
        cfg.validate(Purpose::Probe).unwrap();
        let s = cfg.services();
        assert_eq!(s[0].target.addresses().len(), 2);
        assert_eq!(s[1].prefix.to_string(), "2001:db8:1::/48");
        assert!(s[1].dir.ends_with("cdn"));
    }

    #[test]
    fn rejects_bad_values() {
        let cases = [
            BASE.replace("fra1.*", ""),
            BASE.replace("name = \"fra1\"", "name = \"<script>\""),
            BASE.replace("name = \"fra1\"", "name = \"unattributed\""),
            BASE.replace("country = \"DE\"", "country = \"de\""),
            BASE.replace("match = { chaos = \"fra1.*\" }", "match = {}"),
            BASE.replace("match = { chaos = \"fra1.*\" }", "match = { rdns = \"x\" }"),
            BASE.replace("match = { chaos = \"fra1.*\" }", "match = { http = \"x\" }"),
            BASE.replace("192.0.2.53\"", "192.0.2.53\"\naddress6 = \"192.0.2.54\""),
            BASE.replace(
                "192.0.2.53\"",
                "192.0.2.53\"\nhttp = { url = \"https://192.0.2.1/\", header = \"server\" }",
            ),
            format!("{BASE}\n[schedule]\ninterval = \"5s\"\n"),
            format!("{BASE}\n[pathology]\nurl = \"http://pathology.example.net\"\n"),
            format!("{BASE}\n[alarms.latency]\nratio = 0.5\n"),
            format!("{BASE}\n[[service]]\nname = \"x\"\ntarget = {{ address = \"192.0.2.1\" }}\npop = [{{ name = \"a\", match = {{ chaos = \"a\" }} }}]\n"),
            BASE.replace("[vantage.local]\ncountry = \"DE\"", ""),
        ];
        for text in cases {
            let cfg = Config::parse(&text).unwrap();
            assert!(cfg.validate(Purpose::Probe).is_err(), "accepted:\n{text}");
        }
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::parse(&format!("{BASE}\nbogus = 1\n")).is_err());
    }

    #[test]
    fn atlas_requires_https() {
        let text = format!(
            "{BASE}\n[vantage.ripe_atlas]\nbase_url = \"http://atlas.example\"\nprobes = {{ countries = [\"DE\"], per_country = 2 }}\n"
        );
        let cfg = Config::parse(&text).unwrap();
        assert!(cfg.validate(Purpose::Fetch).is_err());
    }

    #[test]
    fn local_http_urls() {
        assert!(validate_local_http_url("x", "http://127.0.0.1:8180").is_ok());
        assert!(validate_local_http_url("x", "http://[::1]:8180").is_ok());
        assert!(validate_local_http_url("x", "https://pathology.example.net").is_ok());
        assert!(validate_local_http_url("x", "http://198.51.100.1:8180").is_err());
        assert!(validate_local_http_url("x", "ftp://127.0.0.1").is_err());
    }

    #[test]
    fn qname_validation() {
        assert!(validate_qname("id.server").is_ok());
        assert!(validate_qname("hostname.bind.").is_ok());
        assert!(validate_qname("bad..name").is_err());
        assert!(validate_qname(&"a".repeat(64)).is_err());
    }
}
