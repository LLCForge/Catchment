//! Catchment: anycast catchment prober.

mod agent;
mod aggregate;
mod alarms;
mod atlas;
mod attribute;
mod budget;
mod config;
mod diff;
mod dns;
mod enrich;
mod http_id;
mod metrics;
mod model;
mod output;
mod pathology;
mod pipeline;
mod probe;
mod store;
mod traceroute;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use llcforge_alert::cli::{run_silence_command, ServiceCommand, SilenceCommand};
use llcforge_alert::{
    health_router, init_logging, reload_router, run_service_command, silences_router, AlertHandle,
    ApiToken, Dispatcher, DispatcherOptions, LogFormat, Readiness, ReloadSignal, ServiceSpec,
    Shutdown, SilenceStore,
};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use config::{Config, Purpose};
use model::{Report, Round};
use pipeline::{Context, RoundOptions, Shared, Source};

const SPEC: ServiceSpec = ServiceSpec {
    bin: "catchment",
    display_name: "Catchment",
    description:
        "Anycast catchment prober: maps which PoP each vantage point lands in and detects shifts",
};

#[derive(Parser)]
#[command(name = "catchment", version, about = "Anycast catchment prober")]
struct Cli {
    /// Path to the TOML configuration (the agent configuration for `catchment agent`).
    #[arg(long, short, global = true, default_value = "catchment.toml")]
    config: PathBuf,
    /// Log format (overrides [logging] format).
    #[arg(long, global = true, value_parser = parse_log_format)]
    log_format: Option<LogFormat>,
    /// Log level or filter, e.g. "info" or "catchment=debug" (overrides [logging] level).
    #[arg(long, global = true)]
    log_level: Option<String>,
    #[command(subcommand)]
    command: Command,
}

fn parse_log_format(s: &str) -> Result<LogFormat, String> {
    s.parse()
}

#[derive(Subcommand)]
enum Command {
    /// Run one measurement round now and print the result.
    Probe {
        #[command(flatten)]
        out: OutputArgs,
        /// Experiment label stored with the round (see `compare`).
        #[arg(long)]
        label: Option<String>,
    },
    /// Attribute the results of existing RIPE Atlas measurements.
    Fetch {
        /// Measurement id (repeat for a DNS and a traceroute measurement).
        #[arg(long = "measurement", required = true)]
        measurements: Vec<u64>,
        #[command(flatten)]
        out: OutputArgs,
    },
    /// Re-render a saved round (default: the latest one in the data directory).
    Show {
        /// Round file to render instead of the latest.
        #[arg(long)]
        round: Option<PathBuf>,
        /// Service whose latest round to show (multi-service configs).
        #[arg(long)]
        service: Option<String>,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// Compare two rounds (experiment mode): labels or round file paths.
    Compare {
        #[arg(long)]
        before: String,
        #[arg(long)]
        after: String,
        #[arg(long)]
        service: Option<String>,
        #[arg(long, value_enum, default_value_t = CompareFormat::Table)]
        format: CompareFormat,
    },
    /// Daemon: probe every [schedule] interval, serve metrics/health, send alerts.
    Run {
        /// Rewrite this static HTML report after every round
        /// (multi-service: one file per service, `<name>-<service>.html`).
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// Self-hosted vantage point: serve the probe API over mutual TLS.
    Agent,
    /// Manage alert silences / maintenance windows.
    Silence {
        #[command(subcommand)]
        cmd: SilenceCommand,
    },
    /// Install, uninstall or run as a system service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCommand,
    },
}

#[derive(Args)]
struct OutputArgs {
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format: Format,
    /// Also write a static HTML report to this path.
    #[arg(long)]
    html: Option<PathBuf>,
    /// Do not persist this round (no shift detection next time).
    #[arg(long)]
    no_save: bool,
    /// Only this service (multi-service configs).
    #[arg(long)]
    service: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
    Csv,
}

#[derive(Clone, Copy, ValueEnum)]
enum CompareFormat {
    Table,
    Json,
}

/// `report.html` -> `report-<service>.html` when several services share one flag.
fn html_path(base: &Path, service: &str, multi: bool) -> PathBuf {
    if !multi {
        return base.to_path_buf();
    }
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "report".into());
    let ext = base
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    base.with_file_name(format!("{stem}-{service}{ext}"))
}

fn write_html(path: &Path, report: &Report) -> Result<()> {
    store::write_atomic(path, output::render_html(report).as_bytes())?;
    tracing::info!(path = %path.display(), "HTML report written");
    Ok(())
}

fn emit(reports: &[(String, Report)], format: Format, html: Option<&Path>) -> Result<()> {
    let multi = reports.len() > 1;
    let text = match format {
        Format::Table => reports
            .iter()
            .map(|(_, r)| output::render_table(r))
            .collect::<Vec<_>>()
            .join("\n"),
        Format::Json if multi => {
            let docs: Vec<serde_json::Value> = reports
                .iter()
                .map(|(_, r)| serde_json::from_str(&output::render_json(r)?).map_err(Into::into))
                .collect::<Result<_>>()?;
            serde_json::to_string_pretty(&docs)? + "\n"
        }
        Format::Json => output::render_json(&reports[0].1)?,
        Format::Csv => {
            let mut out = String::new();
            for (i, (_, r)) in reports.iter().enumerate() {
                let csv = output::render_csv(r);
                let body = if i == 0 {
                    csv.as_str()
                } else {
                    csv.split_once('\n').map(|x| x.1).unwrap_or_default()
                };
                out.push_str(body);
            }
            out
        }
    };
    print!("{text}");
    if let Some(base) = html {
        for (svc, r) in reports {
            write_html(&html_path(base, svc, multi), r)?;
        }
    }
    Ok(())
}

fn select_contexts(shared: &Arc<Shared>, service: Option<&str>) -> Result<Vec<Arc<Context>>> {
    let all = pipeline::contexts(shared)?;
    match service {
        None => Ok(all),
        Some(name) => {
            let picked: Vec<_> = all.into_iter().filter(|c| c.svc.name == name).collect();
            if picked.is_empty() {
                bail!(
                    "no service named {:?} in the configuration",
                    dns::sanitize(name.as_bytes())
                );
            }
            Ok(picked)
        }
    }
}

fn one_shot_shared(cfg: Config) -> Result<Arc<Shared>> {
    let ttl = cfg.lookup.cache_ttl;
    Ok(Arc::new(Shared::new(
        Arc::new(cfg),
        AlertHandle::disabled(SPEC.bin),
        enrich::Cache::shared(ttl),
    )?))
}

async fn one_shot(
    ctxs: Vec<Arc<Context>>,
    source: Source,
    out: OutputArgs,
    label: Option<String>,
) -> Result<()> {
    if let Some(l) = &label {
        pipeline::validate_label(l)?;
    }
    let work = async {
        let mut reports = Vec::new();
        for ctx in &ctxs {
            let opts = RoundOptions {
                save: !out.no_save,
                label: label.clone(),
            };
            reports.push((
                ctx.svc.name.clone(),
                pipeline::run_round(ctx, &source, opts).await?,
            ));
        }
        Ok::<_, anyhow::Error>(reports)
    };
    tokio::select! {
        reports = work => emit(&reports?, out.format, out.html.as_deref()),
        _ = llcforge_alert::service::shutdown_signal() => {
            tracing::warn!("interrupted, round discarded");
            Ok(())
        }
    }
}

enum Exit {
    Shutdown,
    Reload,
}

async fn run_all(ctxs: &[Arc<Context>], state: &metrics::Shared, html: Option<&Path>) {
    let multi = ctxs.len() > 1;
    let mut tasks = JoinSet::new();
    for ctx in ctxs {
        let ctx = ctx.clone();
        tasks.spawn(async move {
            let res = pipeline::run_round(
                &ctx,
                &Source::Probe,
                RoundOptions {
                    save: true,
                    label: None,
                },
            )
            .await;
            (ctx, res)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        let Ok((ctx, result)) = joined else {
            tracing::error!("round task panicked");
            continue;
        };
        let name = ctx.svc.name.as_str();
        match result {
            Ok(report) => {
                tracing::info!(
                    service = name,
                    vantages = report.round.records.len(),
                    shifts = report.shifts.len(),
                    regressions = report.latency_regressions.len(),
                    "round complete"
                );
                if let Some(base) = html {
                    if let Err(e) = write_html(&html_path(base, name, multi), &report) {
                        tracing::error!(error = %e, "could not write HTML report");
                    }
                }
                let active = ctx.latency.lock().map(|t| t.active()).unwrap_or(0);
                if let Ok(mut m) = state.lock() {
                    m.record(name, report, active);
                }
            }
            Err(e) => {
                tracing::error!(service = name, error = %e, "round failed");
                if let Ok(mut m) = state.lock() {
                    m.failed(name);
                }
            }
        }
    }
}

async fn schedule(
    ctxs: &[Arc<Context>],
    (start, interval): (tokio::time::Instant, Duration),
    state: &metrics::Shared,
    html: Option<&Path>,
    shutdown: &mut Shutdown,
    reload: &mut ReloadSignal,
) -> Exit {
    let mut tick = tokio::time::interval_at(start, interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.wait() => return Exit::Shutdown,
            Some(reason) = reload.recv() => {
                tracing::info!(?reason, "reloading configuration");
                return Exit::Reload;
            }
            _ = tick.tick() => {}
        }
        // A reload requested mid-round is picked up once the round is done.
        tokio::select! {
            _ = shutdown.wait() => return Exit::Shutdown,
            _ = run_all(ctxs, state, html) => {}
        }
    }
}

fn dispatcher_options(data: &Path, silences: &Arc<SilenceStore>) -> DispatcherOptions {
    DispatcherOptions {
        tool: SPEC.bin.into(),
        data_dir: Some(data.to_path_buf()),
        silences: Some(silences.clone()),
        http: None,
    }
}

fn daemon(config_path: PathBuf, mut shutdown: Shutdown, html: Option<PathBuf>) -> Result<()> {
    tokio::runtime::Runtime::new()?.block_on(async move {
        let mut cfg = Arc::new(Config::load(&config_path, Purpose::Probe)?);
        let data = cfg.data_dir();
        std::fs::create_dir_all(&data).with_context(|| format!("creating {}", data.display()))?;
        let silences = Arc::new(SilenceStore::open(cfg.silences.path_or(&data))?);
        let readiness = Readiness::new();
        readiness.register("scheduler");
        let mut dispatcher = Dispatcher::start(&cfg.alerts, dispatcher_options(&data, &silences))?;
        let mut reload = ReloadSignal::standard(Some(config_path.clone()))?;
        let state: metrics::Shared = Arc::default();
        let cache = enrich::Cache::shared(cfg.lookup.cache_ttl);

        // One admin listener for the process lifetime (changing its address needs a restart).
        if let Some(addr) = cfg.metrics.listen.or(cfg.health.listen) {
            let mut admin = metrics::router(state.clone()).merge(health_router(readiness.clone()));
            if let Some(var) = &cfg.silences.api_token_env {
                admin = admin.merge(silences_router(silences.clone(), ApiToken::from_env(var)?));
            }
            if let Some(var) = &cfg.health.admin_token_env {
                admin = admin.merge(reload_router(reload.trigger(), ApiToken::from_env(var)?));
            }
            let mut sd = shutdown.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    llcforge_alert::serve(addr, admin, async move { sd.wait().await }).await
                {
                    tracing::error!(error = %e, "metrics/health listener stopped");
                }
            });
        }

        let mut first_round = tokio::time::Instant::now();
        loop {
            let shared = Arc::new(Shared::new(
                cfg.clone(),
                dispatcher.handle(),
                cache.clone(),
            )?);
            if let Ok(mut m) = state.lock() {
                m.alerts = Some(dispatcher.metrics());
                m.budget = shared.budget.clone();
                m.cache = Some(cache.clone());
            }
            let ctxs = pipeline::contexts(&shared)?;
            readiness.set("scheduler", true);
            tracing::info!(
                interval = ?cfg.schedule.interval,
                services = ctxs.len(),
                agents = shared.agents.len(),
                "catchment daemon started"
            );
            let timing = (first_round, cfg.schedule.interval);
            match schedule(
                &ctxs,
                timing,
                &state,
                html.as_deref(),
                &mut shutdown,
                &mut reload,
            )
            .await
            {
                Exit::Shutdown => break,
                Exit::Reload => {
                    match Config::load(&config_path, Purpose::Probe) {
                        Ok(new) => {
                            dispatcher.shutdown(Duration::from_secs(5)).await;
                            let opts = dispatcher_options(&data, &silences);
                            dispatcher = Dispatcher::start(&new.alerts, opts)?;
                            cfg = Arc::new(new);
                            tracing::info!("configuration reloaded");
                        }
                        Err(e) => {
                            let error = format!("{e:#}");
                            tracing::error!(%error, "invalid configuration; keeping the old one");
                        }
                    }
                    // No extra (credit-consuming) round just because of a reload.
                    first_round = tokio::time::Instant::now() + cfg.schedule.interval;
                }
            }
        }
        dispatcher.shutdown(Duration::from_secs(5)).await;
        tracing::info!("shutdown complete");
        Ok(())
    })
}

fn show(
    cfg_path: &Path,
    round: Option<PathBuf>,
    service: Option<String>,
    format: Format,
    html: Option<&Path>,
) -> Result<()> {
    let (name, round): (String, Round) = match round {
        Some(path) => {
            let meta =
                std::fs::metadata(&path).with_context(|| format!("reading {}", path.display()))?;
            if meta.len() > 64 * 1024 * 1024 {
                bail!("{} is larger than 64 MiB", path.display());
            }
            let bytes =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let r: Round = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display()))?;
            (r.service_label().to_string(), r)
        }
        None => {
            let cfg = Config::load(cfg_path, Purpose::Fetch)?;
            let svc = pick_service(&cfg, service.as_deref())?;
            let r = store::Store::new(svc.dir.clone(), cfg.storage.retain)
                .latest()?
                .context("no saved round in the data directory")?;
            (svc.name, r)
        }
    };
    emit(&[(name, Report::standalone(round))], format, html)
}

fn pick_service(cfg: &Config, name: Option<&str>) -> Result<config::Service> {
    let services = cfg.services();
    match name {
        Some(n) => services
            .into_iter()
            .find(|s| s.name == n)
            .with_context(|| format!("no service named {:?}", dns::sanitize(n.as_bytes()))),
        None if services.len() == 1 => Ok(services.into_iter().next().context("no service")?),
        None => bail!("several services are configured; pick one with --service"),
    }
}

fn compare(
    cfg_path: &Path,
    before: &str,
    after: &str,
    service: Option<&str>,
    format: CompareFormat,
) -> Result<()> {
    // Two round files need no configuration; labels are looked up in the store.
    let (b, a) = if Path::new(before).is_file() && Path::new(after).is_file() {
        let none = store::Store::new(PathBuf::new(), 1);
        (
            pipeline::find_round(&none, before)?,
            pipeline::find_round(&none, after)?,
        )
    } else {
        let cfg = Config::load(cfg_path, Purpose::Fetch)?;
        let svc = pick_service(&cfg, service)?;
        let store = store::Store::new(svc.dir, cfg.storage.retain);
        (
            pipeline::find_round(&store, before)?,
            pipeline::find_round(&store, after)?,
        )
    };
    let c = aggregate::compare(&b, &a);
    match format {
        CompareFormat::Table => print!("{}", output::render_compare_table(&c)),
        CompareFormat::Json => println!("{}", serde_json::to_string_pretty(&c)?),
    }
    Ok(())
}

async fn run_agent(path: &Path) -> Result<()> {
    let file = agent::AgentFile::load(path)?;
    let listener = tokio::net::TcpListener::bind(file.agent.listen)
        .await
        .with_context(|| format!("binding {}", file.agent.listen))?;
    agent::serve(
        file.agent,
        listener,
        llcforge_alert::service::shutdown_signal(),
    )
    .await
}

async fn run_async(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Probe { out, label } => {
            let shared = one_shot_shared(Config::load(&cli.config, Purpose::Probe)?)?;
            let ctxs = select_contexts(&shared, out.service.as_deref())?;
            one_shot(ctxs, Source::Probe, out, label).await
        }
        Command::Fetch { measurements, out } => {
            let cfg = Config::load(&cli.config, Purpose::Fetch)?;
            if out.service.is_none() && cfg.services().len() > 1 {
                bail!("several services are configured; pick one with --service");
            }
            let shared = one_shot_shared(cfg)?;
            let ctxs = select_contexts(&shared, out.service.as_deref())?;
            one_shot(ctxs, Source::Fetch(measurements), out, None).await
        }
        Command::Show {
            round,
            service,
            format,
            html,
        } => show(&cli.config, round, service, format, html.as_deref()),
        Command::Compare {
            before,
            after,
            service,
            format,
        } => compare(&cli.config, &before, &after, service.as_deref(), format),
        Command::Agent => run_agent(&cli.config).await,
        Command::Run { .. } | Command::Silence { .. } | Command::Service { .. } => {
            unreachable!("handled outside the runtime")
        }
    }
}

/// [logging] from the config file, read leniently before the full load so
/// that load errors are logged in the configured format.
fn logging_from_file(path: &Path) -> (Option<LogFormat>, Option<String>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (None, None);
    };
    let Ok(v) = text.parse::<toml::Table>() else {
        return (None, None);
    };
    let l = v.get("logging").and_then(|l| l.as_table());
    let get = |k: &str| {
        l.and_then(|l| l.get(k))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    (get("format").and_then(|f| f.parse().ok()), get("level"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (file_format, file_level) = logging_from_file(&cli.config);
    let format = cli.log_format.or(file_format).unwrap_or_default();
    let level = cli
        .log_level
        .clone()
        .or(file_level)
        .unwrap_or_else(|| "info".into());
    if let Err(e) = init_logging(format, &level, None) {
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }
    let result = match cli.command {
        Command::Run { html } => {
            llcforge_alert::service::run_foreground(cli.config, move |c, sd| daemon(c, sd, html))
        }
        Command::Service { cmd } => {
            run_service_command(&SPEC, cmd.into_action(cli.config), |c, sd| {
                daemon(c, sd, None)
            })
        }
        Command::Silence { cmd } => (|| {
            let cfg = Config::load(&cli.config, Purpose::Fetch)?;
            run_silence_command(cmd, &cfg.silences.path_or(&cfg.data_dir()))
        })(),
        _ => match tokio::runtime::Runtime::new() {
            Ok(rt) => rt.block_on(run_async(cli)),
            Err(e) => Err(anyhow::anyhow!("cannot start runtime: {e}")),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_paths() {
        let p = Path::new("out/report.html");
        assert_eq!(html_path(p, "dns", false), PathBuf::from("out/report.html"));
        assert_eq!(
            html_path(p, "dns", true),
            PathBuf::from("out/report-dns.html")
        );
    }

    #[test]
    fn cli_parses_new_subcommands() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let c = Cli::try_parse_from([
            "catchment",
            "--config",
            "x.toml",
            "probe",
            "--label",
            "before",
            "--service",
            "dns",
        ])
        .unwrap();
        assert!(matches!(c.command, Command::Probe { label: Some(_), .. }));
        let c =
            Cli::try_parse_from(["catchment", "compare", "--before", "a", "--after", "b"]).unwrap();
        assert!(matches!(c.command, Command::Compare { .. }));
        assert!(Cli::try_parse_from(["catchment", "service", "run", "--config", "c.toml"]).is_ok());
        assert!(Cli::try_parse_from(["catchment", "silence", "list"]).is_ok());
        assert!(Cli::try_parse_from(["catchment", "--log-format", "json", "agent"]).is_ok());
    }
}
