//! Self-hosted vantage points: `catchment agent` serves `POST /v1/probe` over
//! mutual TLS, and the controller calls every `[[vantage.agent]]` each round.
//!
//! Trust model: only clients presenting a certificate signed by the agent's
//! configured CA are accepted (rustls `WebPkiClientVerifier`), and the agent
//! still refuses any target outside its own local allowlist, so a stolen
//! controller certificate cannot turn agents into a probing botnet.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipnet::IpNet;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::config::{
    de_duration, validate_country, validate_http_target, validate_location, validate_qname,
    AgentVantage, Logging, TraceMode,
};
use crate::dns::sanitize;
use crate::model::Observation;
use crate::probe::{self, ProbeLimits, ProbeRequest};

const MAX_REQUEST: usize = 16 * 1024;
const MAX_RESPONSE: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKES: usize = 64;

/// `catchment agent --config agent.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFile {
    pub agent: AgentConfig,
    /// Applied by `main::logging_from_file`.
    #[serde(default)]
    #[allow(dead_code)]
    pub logging: Logging,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub listen: SocketAddr,
    /// CA that signs the controller's client certificates.
    pub ca: PathBuf,
    /// This agent's server certificate chain and key.
    pub cert: PathBuf,
    pub key: PathBuf,
    /// The only addresses this agent will probe.
    pub allowed_targets: Vec<IpNet>,
    #[serde(default)]
    pub allow_traceroute: bool,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    #[serde(default = "default_timeout", deserialize_with = "de_duration")]
    pub timeout: Duration,
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    #[serde(default = "default_concurrent")]
    pub max_concurrent: usize,
}

fn default_timeout() -> Duration {
    Duration::from_secs(2)
}
fn default_attempts() -> u32 {
    3
}
fn default_concurrent() -> usize {
    4
}

impl AgentFile {
    pub fn load(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("cannot read agent config {}", path.display()))?;
        if meta.len() > 1024 * 1024 {
            bail!("agent config {} is larger than 1 MiB", path.display());
        }
        let text = std::fs::read_to_string(path)?;
        let f: AgentFile = toml::from_str(&text).context("invalid agent config")?;
        f.agent.validate()?;
        Ok(f)
    }
}

impl AgentConfig {
    fn validate(&self) -> Result<()> {
        if self.allowed_targets.is_empty() || self.allowed_targets.len() > 1024 {
            bail!("[agent] allowed_targets must list 1-1024 prefixes");
        }
        if let Some(c) = &self.country {
            validate_country(c)?;
        }
        validate_location("[agent]", self.lat, self.lon)?;
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(30) {
            bail!("[agent] timeout must be between 1ms and 30s");
        }
        if !(1..=10).contains(&self.attempts) || !(1..=64).contains(&self.max_concurrent) {
            bail!("[agent] attempts must be 1-10 and max_concurrent 1-64");
        }
        Ok(())
    }

    /// Refuses anything this agent was not explicitly allowed to do.
    pub fn check(&self, req: &ProbeRequest) -> Result<(), String> {
        if !self.allowed_targets.iter().any(|n| n.contains(&req.target)) {
            return Err(format!(
                "target {} is not in this agent's allowlist",
                req.target
            ));
        }
        validate_qname(&req.qname).map_err(|e| e.to_string())?;
        if let Some(h) = &req.http {
            validate_http_target(h).map_err(|e| format!("http: {e:#}"))?;
        }
        if req.traceroute != TraceMode::Off && !self.allow_traceroute {
            return Err("traceroute is disabled on this agent".into());
        }
        if !(1..=64).contains(&req.max_hops) {
            return Err("max_hops must be 1-64".into());
        }
        Ok(())
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("reading {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", path.display()))?;
    if certs.is_empty() {
        bail!("{} contains no certificate", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).with_context(|| format!("reading key {}", path.display()))
}

pub fn server_tls(cfg: &AgentConfig) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in load_certs(&cfg.ca)? {
        roots.add(c).context("invalid CA certificate")?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .context("client verifier")?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(&cfg.cert)?, load_key(&cfg.key)?)
        .context("agent certificate / key")?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

/// Accepted TLS connections handed to `axum::serve`. Handshakes run in their
/// own tasks (bounded, with a timeout) so a slow client cannot stall accept.
struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

fn tls_listener(listener: TcpListener, acceptor: TlsAcceptor) -> Result<TlsListener> {
    let local = listener.local_addr()?;
    let (tx, rx) = mpsc::channel(MAX_HANDSHAKES);
    let limit = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "agent accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue; // too many handshakes in flight: drop
            };
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                let _permit = permit;
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => {
                        let _ = tx.send((tls, peer)).await;
                    }
                    Ok(Err(e)) => tracing::info!(%peer, error = %e, "TLS handshake rejected"),
                    Err(_) => tracing::info!(%peer, "TLS handshake timed out"),
                }
            });
        }
    });
    Ok(TlsListener { rx, local })
}

struct AgentState {
    cfg: AgentConfig,
    limit: Arc<Semaphore>,
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

async fn probe_handler(
    State(st): State<Arc<AgentState>>,
    body: Result<Json<ProbeRequest>, JsonRejection>,
) -> Response {
    let req = match body {
        Ok(Json(r)) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &e.body_text()),
    };
    if let Err(e) = st.cfg.check(&req) {
        tracing::warn!(target = %req.target, reason = %e, "probe request refused");
        return json_error(StatusCode::FORBIDDEN, &e);
    }
    let Ok(_permit) = st.limit.clone().try_acquire_owned() else {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "agent busy");
    };
    let limits = ProbeLimits {
        timeout: st.cfg.timeout,
        attempts: st.cfg.attempts,
    };
    let mut obs = probe::run(&req, limits).await;
    obs.vantage = "agent".into();
    obs.country = st.cfg.country.clone();
    obs.asn = st.cfg.asn;
    obs.lat = st.cfg.lat;
    obs.lon = st.cfg.lon;
    Json(obs).into_response()
}

pub fn router(cfg: AgentConfig) -> Router {
    let limit = Arc::new(Semaphore::new(cfg.max_concurrent));
    Router::new()
        .route("/v1/probe", post(probe_handler))
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST))
        .with_state(Arc::new(AgentState { cfg, limit }))
}

/// Serves the agent API on an already bound listener until `shutdown` resolves.
pub async fn serve(
    cfg: AgentConfig,
    listener: TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(server_tls(&cfg)?);
    let tls = tls_listener(listener, acceptor)?;
    tracing::info!(addr = %tls.local, targets = cfg.allowed_targets.len(), "catchment agent listening (mTLS)");
    axum::serve(tls, router(cfg))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// Controller side of one `[[vantage.agent]]`.
pub struct AgentClient {
    pub name: String,
    url: reqwest::Url,
    http: reqwest::Client,
    country: Option<String>,
    pub traceroute: TraceMode,
}

impl AgentClient {
    pub fn new(cfg: &AgentVantage) -> Result<Self> {
        let read =
            |p: &PathBuf| std::fs::read(p).with_context(|| format!("reading {}", p.display()));
        let ca = reqwest::Certificate::from_pem(&read(&cfg.ca)?)
            .with_context(|| format!("agent {:?}: invalid CA", cfg.name))?;
        let mut pem = read(&cfg.cert)?;
        pem.push(b'\n');
        pem.extend(read(&cfg.key)?);
        let identity = reqwest::Identity::from_pem(&pem)
            .with_context(|| format!("agent {:?}: invalid client certificate/key", cfg.name))?;
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(cfg.timeout)
            .build()?;
        let url = reqwest::Url::parse(&cfg.url)
            .and_then(|u| u.join("/v1/probe"))
            .with_context(|| format!("agent {:?}: invalid url", cfg.name))?;
        Ok(Self {
            name: cfg.name.clone(),
            url,
            http,
            country: cfg.country.clone(),
            traceroute: cfg.traceroute,
        })
    }

    pub fn vantage(&self) -> String {
        format!("agent:{}", self.name)
    }

    /// Never fails: transport or agent errors end up in `Observation::error`.
    pub async fn probe(&self, req: &ProbeRequest) -> Observation {
        let mut obs = match self.call(req).await {
            Ok(o) => o,
            Err(e) => Observation {
                target: Some(req.target),
                error: Some(sanitize(format!("agent: {e:#}").as_bytes())),
                ..Observation::default()
            },
        };
        obs.vantage = self.vantage();
        if self.country.is_some() {
            obs.country = self.country.clone();
        }
        obs
    }

    async fn call(&self, req: &ProbeRequest) -> Result<Observation> {
        let mut resp = self.http.post(self.url.clone()).json(req).send().await?;
        let status = resp.status();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE {
                bail!("agent response larger than {MAX_RESPONSE} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let detail = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error")?.as_str().map(str::to_string))
                .unwrap_or_default();
            bail!("HTTP {}: {}", status.as_u16(), sanitize(detail.as_bytes()));
        }
        let o: Observation = serde_json::from_slice(&body).context("invalid agent response")?;
        Ok(clean(o, req))
    }
}

/// Agent answers are authenticated but still treated as untrusted input.
fn clean(o: Observation, req: &ProbeRequest) -> Observation {
    let s = |v: Option<String>| v.map(|v| sanitize(v.as_bytes()));
    let loc = (o.lat, o.lon);
    let loc_ok = validate_location("", loc.0, loc.1).is_ok();
    Observation {
        vantage: String::new(),
        target: Some(req.target),
        country: o.country.filter(|c| validate_country(c).is_ok()),
        asn: o.asn,
        lat: if loc_ok { loc.0 } else { None },
        lon: if loc_ok { loc.1 } else { None },
        chaos: s(o.chaos),
        nsid: s(o.nsid),
        http_id: s(o.http_id),
        last_hop: o.last_hop,
        last_hop_asn: None,
        last_hop_rdns: None,
        rtt_ms: o.rtt_ms.filter(|v| v.is_finite() && *v >= 0.0),
        error: s(o.error),
        trace_error: s(o.trace_error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
    };

    struct Pki {
        dir: PathBuf,
    }

    fn write(dir: &Path, name: &str, data: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    fn pki(tag: &str) -> Pki {
        let dir =
            std::env::temp_dir().join(format!("catchment-agent-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf = |names: Vec<String>, eku| {
            let key = KeyPair::generate().unwrap();
            let mut p = CertificateParams::new(names).unwrap();
            p.subject_alt_names
                .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
            p.extended_key_usages = vec![eku];
            (p.signed_by(&key, &ca, &ca_key).unwrap(), key)
        };
        let (srv, srv_key) = leaf(
            vec!["localhost".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (cli, cli_key) = leaf(
            vec!["controller".into()],
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        write(&dir, "ca.pem", &ca.pem());
        write(&dir, "agent.pem", &srv.pem());
        write(&dir, "agent-key.pem", &srv_key.serialize_pem());
        write(&dir, "client.pem", &cli.pem());
        write(&dir, "client-key.pem", &cli_key.serialize_pem());
        // A second, unrelated CA for the "wrong client" case.
        let rogue_key = KeyPair::generate().unwrap();
        let mut rogue_params = CertificateParams::new(vec!["rogue".into()]).unwrap();
        rogue_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let rogue = rogue_params.self_signed(&rogue_key).unwrap();
        write(&dir, "rogue.pem", &rogue.pem());
        write(&dir, "rogue-key.pem", &rogue_key.serialize_pem());
        Pki { dir }
    }

    fn agent_cfg(p: &Pki) -> AgentConfig {
        AgentConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca: p.dir.join("ca.pem"),
            cert: p.dir.join("agent.pem"),
            key: p.dir.join("agent-key.pem"),
            allowed_targets: vec!["127.0.0.0/8".parse().unwrap()],
            allow_traceroute: false,
            country: Some("NL".into()),
            asn: Some(64500),
            lat: Some(52.37),
            lon: Some(4.89),
            timeout: Duration::from_millis(300),
            attempts: 1,
            max_concurrent: 2,
        }
    }

    fn client(p: &Pki, addr: SocketAddr, cert: &str, key: &str) -> AgentClient {
        AgentClient::new(&AgentVantage {
            name: "ams".into(),
            url: format!("https://127.0.0.1:{}", addr.port()),
            ca: p.dir.join("ca.pem"),
            cert: p.dir.join(cert),
            key: p.dir.join(key),
            country: None,
            timeout: Duration::from_secs(10),
            traceroute: TraceMode::Off,
        })
        .unwrap()
    }

    fn request(target: &str) -> ProbeRequest {
        ProbeRequest {
            target: target.parse().unwrap(),
            qname: "hostname.bind".into(),
            nsid: true,
            http: None,
            traceroute: TraceMode::Off,
            max_hops: 30,
            trace_port: None,
        }
    }

    #[tokio::test]
    async fn mtls_probe_allowlist_and_rejection() {
        let p = pki("mtls");
        let cfg = agent_cfg(&p);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(cfg, listener, std::future::pending()));

        let good = client(&p, addr, "client.pem", "client-key.pem");
        let obs = good.probe(&request("127.0.0.1")).await;
        assert_eq!(obs.vantage, "agent:ams");
        assert_eq!(obs.country.as_deref(), Some("NL"));
        assert_eq!(obs.asn, Some(64500));
        assert!(
            !obs.error
                .as_deref()
                .unwrap_or_default()
                .starts_with("agent:"),
            "transport must succeed: {:?}",
            obs.error
        );

        let refused = good.probe(&request("192.0.2.53")).await;
        let err = refused.error.unwrap();
        assert!(err.contains("403") && err.contains("allowlist"), "{err}");

        let mut trace = request("127.0.0.1");
        trace.traceroute = TraceMode::Udp;
        let err = good.probe(&trace).await.error.unwrap();
        assert!(err.contains("traceroute is disabled"), "{err}");

        let rogue = client(&p, addr, "rogue.pem", "rogue-key.pem");
        let err = rogue.probe(&request("127.0.0.1")).await.error.unwrap();
        assert!(err.starts_with("agent:"), "{err}");
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[test]
    fn cleans_untrusted_agent_output() {
        let o = Observation {
            vantage: "spoofed".into(),
            country: Some("nl".into()),
            lat: Some(100.0),
            lon: Some(1.0),
            chaos: Some("fra1\u{1b}[31m".into()),
            rtt_ms: Some(f64::NAN),
            last_hop_asn: Some(1),
            ..Observation::default()
        };
        let c = clean(o, &request("127.0.0.1"));
        assert_eq!(c.country, None);
        assert_eq!((c.lat, c.lon), (None, None));
        assert_eq!(c.chaos.as_deref(), Some("fra1?[31m"));
        assert_eq!(c.rtt_ms, None);
        assert_eq!(c.last_hop_asn, None);
        assert_eq!(c.target, Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn example_agent_config_is_valid() {
        let f: AgentFile = toml::from_str(include_str!("../catchment-agent.example.toml")).unwrap();
        f.agent.validate().unwrap();
    }

    #[test]
    fn parses_agent_file() {
        let f: AgentFile = toml::from_str(
            r#"
[agent]
listen = "0.0.0.0:8443"
ca = "ca.pem"
cert = "agent.pem"
key = "agent-key.pem"
allowed_targets = ["192.0.2.0/24", "2001:db8::/32"]
country = "NL"
"#,
        )
        .unwrap();
        f.agent.validate().unwrap();
        assert!(f.agent.check(&request("192.0.2.53")).is_ok());
        assert!(f.agent.check(&request("198.51.100.1")).is_err());
        let mut bad = request("192.0.2.53");
        bad.qname = "a..b".into();
        assert!(f.agent.check(&bad).is_err());
    }
}
