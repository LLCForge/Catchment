//! One measurement round of one service:
//! collect -> enrich -> attribute -> diff -> alarms -> correlate -> persist.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use llcforge_beacon::{Alert, AlertHandle, Severity};
use tokio::task::JoinSet;

use crate::agent::AgentClient;
use crate::alarms::{self, LatencyTracker, TOOL};
use crate::atlas::{self, AtlasClient};
use crate::attribute::Attributor;
use crate::budget::{self, BudgetManager};
use crate::config::{Config, Service, TraceMode, DEFAULT_ATLAS_URL, LEGACY_SERVICE};
use crate::enrich::{self, SharedCache};
use crate::model::{Observation, Report, Round};
use crate::pathology::PathologyClient;
use crate::probe::{self, ProbeLimits, ProbeRequest};
use crate::store::Store;
use crate::{diff, dns};

pub enum Source {
    /// Probe now from every configured vantage.
    Probe,
    /// Reuse results of existing RIPE Atlas measurements.
    Fetch(Vec<u64>),
}

/// Process-wide state shared by every service.
pub struct Shared {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub cache: SharedCache,
    pub budget: Option<Arc<BudgetManager>>,
    pub alerts: AlertHandle,
    pub pathology: Option<PathologyClient>,
    pub agents: Vec<AgentClient>,
}

impl Shared {
    pub fn new(cfg: Arc<Config>, alerts: AlertHandle, cache: SharedCache) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("catchment/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .https_only(true)
            .build()?;
        let budget = match &cfg.vantage.ripe_atlas {
            Some(a) => Some(Arc::new(BudgetManager::open(
                cfg.data_dir().join("atlas-budget.json"),
                &a.budget,
            )?)),
            None => None,
        };
        let pathology = cfg
            .pathology
            .as_ref()
            .map(PathologyClient::new)
            .transpose()?;
        let agents = cfg
            .vantage
            .agents
            .iter()
            .map(AgentClient::new)
            .collect::<Result<_>>()?;
        Ok(Self {
            cfg,
            http,
            cache,
            budget,
            alerts,
            pathology,
            agents,
        })
    }

    fn atlas_client(&self) -> AtlasClient {
        let (base, key_env) = match &self.cfg.vantage.ripe_atlas {
            Some(a) => (a.base_url.as_str(), a.api_key_env.as_str()),
            None => (DEFAULT_ATLAS_URL, "RIPE_ATLAS_KEY"),
        };
        let key = std::env::var(key_env).ok().filter(|k| !k.trim().is_empty());
        AtlasClient::new(self.http.clone(), base, key)
    }
}

/// Per-service state.
pub struct Context {
    pub shared: Arc<Shared>,
    pub svc: Service,
    pub attributor: Attributor,
    pub store: Store,
    pub latency: Mutex<LatencyTracker>,
}

impl Context {
    pub fn new(shared: Arc<Shared>, svc: Service) -> Result<Self> {
        let attributor = Attributor::new(&svc.pops)?;
        let store = Store::new(svc.dir.clone(), shared.cfg.storage.retain);
        Ok(Self {
            shared,
            svc,
            attributor,
            store,
            latency: Mutex::new(LatencyTracker::default()),
        })
    }

    pub fn cfg(&self) -> &Config {
        &self.shared.cfg
    }

    fn request(&self, target: IpAddr, traceroute: TraceMode) -> ProbeRequest {
        let t = &self.svc.target;
        let local = self.cfg().vantage.local.as_ref();
        ProbeRequest {
            target,
            qname: t.qname.clone(),
            nsid: t.nsid,
            http: t.http.clone(),
            traceroute,
            max_hops: local.map(|l| l.max_hops).unwrap_or(30),
            trace_port: local.and_then(|l| l.trace_port),
        }
    }
}

/// Build one context per configured service.
pub fn contexts(shared: &Arc<Shared>) -> Result<Vec<Arc<Context>>> {
    shared
        .cfg
        .services()
        .into_iter()
        .map(|s| Context::new(shared.clone(), s).map(Arc::new))
        .collect()
}

async fn probe_local(ctx: &Context) -> Vec<Observation> {
    let Some(local) = ctx.cfg().vantage.local.as_ref().filter(|l| l.enabled) else {
        return Vec::new();
    };
    let limits = ProbeLimits {
        timeout: local.timeout,
        attempts: local.attempts,
    };
    let mut out = Vec::new();
    for target in ctx.svc.target.addresses() {
        let req = ctx.request(target, local.traceroute);
        let mut obs = probe::run(&req, limits).await;
        obs.vantage = "local".into();
        obs.country = local.country.clone();
        obs.asn = local.asn;
        obs.lat = local.lat;
        obs.lon = local.lon;
        if let Some(e) = &obs.trace_error {
            tracing::warn!(%target, error = %e, "local traceroute unavailable; CHAOS result kept");
        }
        out.push(obs);
    }
    out
}

async fn probe_agents(ctx: &Arc<Context>) -> Vec<Observation> {
    let mut tasks = JoinSet::new();
    for (i, agent) in ctx.shared.agents.iter().enumerate() {
        for target in ctx.svc.target.addresses() {
            let req = ctx.request(target, agent.traceroute);
            let ctx = ctx.clone();
            tasks.spawn(async move { ctx.shared.agents[i].probe(&req).await });
        }
    }
    let mut out = Vec::new();
    while let Some(r) = tasks.join_next().await {
        match r {
            Ok(obs) => out.push(obs),
            Err(e) => tracing::error!(error = %e, "agent task failed"),
        }
    }
    out.sort_by(|a, b| (&a.vantage, a.target).cmp(&(&b.vantage, b.target)));
    out
}

async fn atlas_observations(
    client: &AtlasClient,
    per_target: &[(IpAddr, Vec<u64>)],
) -> Result<Vec<Observation>, atlas::AtlasError> {
    let mut maps = Vec::new();
    let mut probe_ids = std::collections::BTreeSet::new();
    for (target, ids) in per_target {
        let mut all = BTreeMap::new();
        for id in ids {
            atlas::merge(&mut all, client.results(*id).await?);
        }
        probe_ids.extend(all.keys().copied());
        maps.push((*target, all));
    }
    let ids: Vec<u64> = probe_ids.into_iter().collect();
    let meta = client.probes(&ids).await?;
    Ok(maps
        .iter()
        .flat_map(|(target, all)| atlas::to_observations(all, &meta, *target))
        .collect())
}

fn budget_alert(e: &budget::Exceeded) -> Alert {
    Alert::new(
        TOOL,
        "atlas_budget",
        Severity::Warning,
        format!(
            "RIPE Atlas {} credit budget reached; Atlas measurements skipped",
            e.period
        ),
    )
    .resource("ripe-atlas")
    .field("spent", e.spent)
    .field("needed", e.cost)
    .field("cap", e.cap)
}

/// Enforces the credit budget; `Ok(false)` means skip Atlas this round.
async fn atlas_allowed(ctx: &Context, client: &AtlasClient, cost: u64) -> anyhow::Result<bool> {
    let Some(b) = &ctx.shared.budget else {
        return Ok(true);
    };
    if let Some(min) = b.min_balance {
        match client.balance().await {
            Ok(bal) if bal >= 0 && (bal as u64).saturating_sub(cost) >= min => {}
            Ok(bal) => {
                tracing::warn!(
                    balance = bal,
                    min_balance = min,
                    cost,
                    "RIPE Atlas balance too low; skipped"
                );
                ctx.shared.alerts.send(
                    Alert::new(
                        TOOL,
                        "atlas_budget",
                        Severity::Warning,
                        "RIPE Atlas balance below min_balance; Atlas measurements skipped",
                    )
                    .resource("ripe-atlas")
                    .field("balance", bal)
                    .field("min_balance", min),
                );
                return Ok(false);
            }
            Err(e) => {
                // Fail closed: without a balance we cannot honour min_balance.
                tracing::warn!(error = %e, "cannot read RIPE Atlas balance; Atlas skipped (min_balance set)");
                return Ok(false);
            }
        }
    }
    match b.reserve(cost, SystemTime::now())? {
        Ok(()) => Ok(true),
        Err(e) => {
            tracing::warn!(error = %e, "Atlas part of the round skipped");
            ctx.shared.alerts.send(budget_alert(&e));
            Ok(false)
        }
    }
}

async fn probe_atlas(ctx: &Context) -> Result<Vec<Observation>> {
    let Some(a) = &ctx.cfg().vantage.ripe_atlas else {
        return Ok(Vec::new());
    };
    let t = &ctx.svc.target;
    let client = ctx.shared.atlas_client();
    let requested = a.probes.per_country * a.probes.countries.len() as u32;
    let addresses = t.addresses();
    let cost = budget::estimate(u64::from(requested), addresses.len() as u64, t.traceroute);
    if !atlas_allowed(ctx, &client, cost).await? {
        return Ok(Vec::new());
    }
    let chaos = client
        .create_chaos(
            t.address,
            &t.qname,
            t.nsid,
            &a.probes.countries,
            a.probes.per_country,
        )
        .await?;
    tracing::info!(service = %ctx.svc.name, measurement = chaos, "created RIPE Atlas DNS CHAOS measurement");
    let mut per_target = vec![(t.address, vec![chaos])];
    if let Some(v6) = t.address6 {
        let id = client
            .create_chaos_from(v6, &t.qname, t.nsid, chaos, requested)
            .await?;
        tracing::info!(
            measurement = id,
            "created RIPE Atlas IPv6 DNS CHAOS measurement"
        );
        per_target.push((v6, vec![id]));
    }
    if t.traceroute {
        for (target, ids) in per_target.iter_mut() {
            let trace = client.create_traceroute(*target, chaos, requested).await?;
            tracing::info!(measurement = trace, %target, "created RIPE Atlas traceroute measurement");
            ids.push(trace);
        }
    }
    for (_, ids) in &per_target {
        for id in ids {
            client.wait_finished(*id, a.wait, a.poll).await?;
        }
    }
    Ok(atlas_observations(&client, &per_target).await?)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct RoundOptions {
    pub save: bool,
    pub label: Option<String>,
}

pub fn validate_label(label: &str) -> Result<()> {
    let ok = !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !ok {
        bail!("label {label:?} must be 1-64 chars of [A-Za-z0-9._-]");
    }
    Ok(())
}

pub async fn run_round(ctx: &Arc<Context>, source: &Source, opts: RoundOptions) -> Result<Report> {
    let started_ms = now_ms();
    let mut observations = Vec::new();
    match source {
        Source::Probe => {
            let (local, agents, atlas) =
                tokio::join!(probe_local(ctx), probe_agents(ctx), probe_atlas(ctx));
            observations.extend(local);
            observations.extend(agents);
            // Atlas trouble (credits, rate limit) must not discard the other vantages.
            match atlas {
                Ok(obs) => observations.extend(obs),
                Err(e) => {
                    tracing::warn!(service = %ctx.svc.name, error = %e, "RIPE Atlas part of the round skipped")
                }
            }
        }
        Source::Fetch(ids) => {
            let client = ctx.shared.atlas_client();
            observations =
                atlas_observations(&client, &[(ctx.svc.target.address, ids.clone())]).await?;
        }
    }
    if observations.is_empty() {
        bail!("round produced no observations");
    }
    let cfg = ctx.cfg();
    enrich::enrich(
        &mut observations,
        &ctx.attributor,
        enrich::Options {
            http: &ctx.shared.http,
            resolver: cfg.lookup.dns_resolver,
            concurrency: cfg.lookup.concurrency,
            cache: &ctx.shared.cache,
        },
    )
    .await;
    let round = Round {
        started_ms,
        target: ctx.svc.target.address,
        service: (ctx.svc.name != LEGACY_SERVICE).then(|| ctx.svc.name.clone()),
        label: opts.label,
        records: observations
            .into_iter()
            .map(|o| ctx.attributor.attribute(o))
            .collect(),
    };
    let lat_cfg = &cfg.alarms.latency;
    let history = ctx
        .store
        .recent(lat_cfg.baseline_rounds)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "could not load previous rounds; shift detection skipped");
            Vec::new()
        });
    let previous = history.first();
    let (shifts, country_shifts) = match previous {
        Some(p) => diff::diff(p, &round),
        None => Default::default(),
    };
    for s in &shifts {
        tracing::warn!(
            service = %ctx.svc.name,
            vantage = %s.vantage,
            country = s.country.as_deref().unwrap_or("-"),
            from = %s.from,
            to = %s.to,
            "CatchmentShift"
        );
    }
    let latency_regressions = if lat_cfg.enabled {
        alarms::latency_regressions(&round, &history, lat_cfg)
    } else {
        Vec::new()
    };
    let mut report = Report {
        round,
        previous_started_ms: previous.map(|p| p.started_ms),
        shifts,
        country_shifts,
        latency_regressions,
        path_correlation: None,
    };
    // Alerts first; nothing below may delay them.
    let alerts = &ctx.shared.alerts;
    if cfg.alarms.shift {
        for a in alarms::shift_alerts(&ctx.svc.name, &report, cfg.alarms.shift_min_vantages) {
            alerts.send(a);
        }
    }
    if lat_cfg.enabled {
        let mut tracker = ctx.latency.lock().unwrap_or_else(|p| p.into_inner());
        for a in tracker.update(&ctx.svc.name, &report.latency_regressions) {
            alerts.send(a);
        }
    }
    if let (Some(client), Some(since)) = (&ctx.shared.pathology, report.previous_started_ms) {
        if !report.shifts.is_empty() {
            let budget = cfg
                .pathology
                .as_ref()
                .map(|p| p.timeout)
                .unwrap_or(Duration::from_secs(5));
            let c = client.correlate(ctx.svc.prefix, since, budget).await;
            if let Some(a) = alarms::correlation_alert(&ctx.svc.name, &c) {
                alerts.send(a);
            }
            report.path_correlation = Some(c);
        }
    }
    if opts.save {
        let path = ctx.store.save(&report.round)?;
        tracing::info!(path = %path.display(), "round saved");
    }
    Ok(report)
}

/// Load a round from a file path or, failing that, by experiment label.
pub fn find_round(store: &Store, spec: &str) -> Result<Round> {
    let path = std::path::Path::new(spec);
    if path.is_file() {
        let meta = std::fs::metadata(path)?;
        if meta.len() > 64 * 1024 * 1024 {
            bail!("{spec} is larger than 64 MiB");
        }
        let bytes = std::fs::read(path)?;
        return Ok(serde_json::from_slice(&bytes)?);
    }
    validate_label(spec)?;
    store.latest_labeled(spec)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no saved round with label {:?}",
            dns::sanitize(spec.as_bytes())
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Purpose;

    fn ctx_for(dir: &std::path::Path, extra: &str) -> Arc<Context> {
        let text = format!(
            r#"
[target]
address = "127.0.0.1"
qname = "hostname.bind"

[[pop]]
name = "lo"
match = {{ chaos = "lo*" }}

[vantage.local]
country = "DE"
timeout = "200ms"
attempts = 1

[storage]
dir = "{}"
{extra}
"#,
            dir.display().to_string().replace('\\', "/")
        );
        let cfg = Config::parse(&text).unwrap();
        cfg.validate(Purpose::Probe).unwrap();
        let shared = Arc::new(
            Shared::new(
                Arc::new(cfg),
                AlertHandle::disabled(TOOL),
                enrich::Cache::shared(Duration::from_secs(60)),
            )
            .unwrap(),
        );
        contexts(&shared).unwrap().remove(0)
    }

    #[tokio::test]
    async fn local_round_saves_labels_and_finds_by_label() {
        let dir = std::env::temp_dir().join(format!("catchment-pipeline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ctx = ctx_for(&dir, "");
        let report = run_round(
            &ctx,
            &Source::Probe,
            RoundOptions {
                save: true,
                label: Some("before".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(report.round.records.len(), 1);
        assert_eq!(report.round.records[0].obs.vantage, "local");
        assert_eq!(report.round.service, None);
        let found = find_round(&ctx.store, "before").unwrap();
        assert_eq!(found.label.as_deref(), Some("before"));
        assert!(find_round(&ctx.store, "after").is_err());
        assert!(find_round(&ctx.store, "../etc").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn labels() {
        assert!(validate_label("before-v2").is_ok());
        assert!(validate_label("").is_err());
        assert!(validate_label("a b").is_err());
    }
}
