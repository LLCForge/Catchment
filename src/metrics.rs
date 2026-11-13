//! Prometheus text exposition for `catchment run` (served together with
//! /healthz, /readyz and the llcforge-beacon admin API).

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

use crate::aggregate;
use crate::budget::BudgetManager;
use crate::enrich::{self, SharedCache};
use crate::model::{family, Report};

#[derive(Debug, Default)]
pub struct ServiceMetrics {
    pub rounds_ok: u64,
    pub rounds_failed: u64,
    pub shifts_total: u64,
    pub regressions_active: usize,
    pub last: Option<Report>,
}

#[derive(Default)]
pub struct Metrics {
    pub services: BTreeMap<String, ServiceMetrics>,
    pub alerts: Option<Arc<llcforge_beacon::Metrics>>,
    pub budget: Option<Arc<BudgetManager>>,
    pub cache: Option<SharedCache>,
}

pub type Shared = Arc<Mutex<Metrics>>;

fn label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

impl Metrics {
    pub fn record(&mut self, service: &str, report: Report, regressions_active: usize) {
        let m = self.services.entry(service.to_string()).or_default();
        m.rounds_ok += 1;
        m.shifts_total += report.shifts.len() as u64;
        m.regressions_active = regressions_active;
        m.last = Some(report);
    }

    pub fn failed(&mut self, service: &str) {
        self.services
            .entry(service.to_string())
            .or_default()
            .rounds_failed += 1;
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        header(
            &mut out,
            "catchment_rounds_total",
            "counter",
            "Measurement rounds by outcome.",
        );
        for (svc, m) in &self.services {
            let s = label(svc);
            let _ = writeln!(
                out,
                "catchment_rounds_total{{service=\"{s}\",outcome=\"ok\"}} {}",
                m.rounds_ok
            );
            let _ = writeln!(
                out,
                "catchment_rounds_total{{service=\"{s}\",outcome=\"failed\"}} {}",
                m.rounds_failed
            );
        }
        header(
            &mut out,
            "catchment_shifts_total",
            "counter",
            "Vantages that moved to another PoP.",
        );
        for (svc, m) in &self.services {
            let _ = writeln!(
                out,
                "catchment_shifts_total{{service=\"{}\"}} {}",
                label(svc),
                m.shifts_total
            );
        }
        header(
            &mut out,
            "catchment_latency_regressions",
            "gauge",
            "Countries currently in a latency regression.",
        );
        for (svc, m) in &self.services {
            let _ = writeln!(
                out,
                "catchment_latency_regressions{{service=\"{}\"}} {}",
                label(svc),
                m.regressions_active
            );
        }
        let lasts: Vec<(&String, &Report)> = self
            .services
            .iter()
            .filter_map(|(s, m)| Some((s, m.last.as_ref()?)))
            .collect();
        header(
            &mut out,
            "catchment_last_round_timestamp_seconds",
            "gauge",
            "Start of the last successful round.",
        );
        for (svc, r) in &lasts {
            let _ = writeln!(
                out,
                "catchment_last_round_timestamp_seconds{{service=\"{}\"}} {}",
                label(svc),
                r.round.started_ms / 1000
            );
        }
        header(
            &mut out,
            "catchment_vantages",
            "gauge",
            "Vantages per PoP, country and address family in the last round.",
        );
        for (svc, r) in &lasts {
            let mut counts: BTreeMap<(String, String, &str), u64> = BTreeMap::new();
            for rec in &r.round.records {
                let cc = rec.obs.country.clone().unwrap_or_default();
                let fam = family(rec.target_or(r.round.target));
                *counts
                    .entry((rec.pop_label().to_string(), cc, fam))
                    .or_default() += 1;
            }
            for ((pop, cc, fam), n) in counts {
                let _ = writeln!(
                    out,
                    "catchment_vantages{{service=\"{}\",pop=\"{}\",country=\"{}\",family=\"{fam}\"}} {n}",
                    label(svc),
                    label(&pop),
                    label(&cc)
                );
            }
        }
        header(
            &mut out,
            "catchment_round_shifts",
            "gauge",
            "Shifts detected in the last round.",
        );
        for (svc, r) in &lasts {
            let _ = writeln!(
                out,
                "catchment_round_shifts{{service=\"{}\"}} {}",
                label(svc),
                r.shifts.len()
            );
        }
        header(
            &mut out,
            "catchment_country_rtt_median_ms",
            "gauge",
            "Median RTT per country and address family in the last round.",
        );
        for (svc, r) in &lasts {
            for c in aggregate::country_latency(&r.round) {
                let _ = writeln!(
                    out,
                    "catchment_country_rtt_median_ms{{service=\"{}\",country=\"{}\",family=\"{}\"}} {:.3}",
                    label(svc),
                    label(&c.country),
                    family(c.target),
                    c.median_ms
                );
            }
        }
        header(
            &mut out,
            "catchment_dual_stack_pop_mismatch",
            "gauge",
            "Vantages whose IPv4 and IPv6 traffic lands in different PoPs.",
        );
        for (svc, r) in &lasts {
            if let Some(d) = aggregate::dual_stack(&r.round) {
                let _ = writeln!(
                    out,
                    "catchment_dual_stack_pop_mismatch{{service=\"{}\"}} {}",
                    label(svc),
                    d.different_pop
                );
            }
        }
        if let Some(b) = &self.budget {
            let usage = b.usage(SystemTime::now());
            header(
                &mut out,
                "catchment_atlas_credits_spent",
                "gauge",
                "RIPE Atlas credits booked (worst case) in the current UTC period.",
            );
            let _ = writeln!(
                out,
                "catchment_atlas_credits_spent{{period=\"day\"}} {}",
                usage.day_spent
            );
            let _ = writeln!(
                out,
                "catchment_atlas_credits_spent{{period=\"month\"}} {}",
                usage.month_spent
            );
            let (daily, monthly) = b.caps();
            header(
                &mut out,
                "catchment_atlas_credits_cap",
                "gauge",
                "Configured RIPE Atlas credit caps.",
            );
            if let Some(d) = daily {
                let _ = writeln!(out, "catchment_atlas_credits_cap{{period=\"day\"}} {d}");
            }
            if let Some(m) = monthly {
                let _ = writeln!(out, "catchment_atlas_credits_cap{{period=\"month\"}} {m}");
            }
        }
        if let Some(c) = &self.cache {
            header(
                &mut out,
                "catchment_enrich_cache_entries",
                "gauge",
                "Cached last-hop ASN / reverse DNS lookups.",
            );
            let _ = writeln!(
                out,
                "catchment_enrich_cache_entries {}",
                enrich::lock(c).len()
            );
        }
        if let Some(a) = &self.alerts {
            a.render_prometheus(&mut out);
        }
        out
    }
}

async fn metrics_handler(State(state): State<Shared>) -> impl IntoResponse {
    let body = state.lock().map(|m| m.render()).unwrap_or_default();
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// `GET /metrics` (unauthenticated, read-only; bind to loopback or a cluster network).
pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample_report;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn renders_metrics() {
        let mut m = Metrics::default();
        m.record("default", sample_report(), 1);
        m.failed("cdn");
        let text = m.render();
        assert!(text.contains("catchment_rounds_total{service=\"default\",outcome=\"ok\"} 1"));
        assert!(text.contains("catchment_rounds_total{service=\"cdn\",outcome=\"failed\"} 1"));
        assert!(text.contains(
            "catchment_vantages{service=\"default\",pop=\"fra1\",country=\"DE\",family=\"v4\"} 1"
        ));
        assert!(text.contains(
            "catchment_vantages{service=\"default\",pop=\"unattributed\",country=\"BR\",family=\"v4\"} 1"
        ));
        assert!(text.contains("catchment_shifts_total{service=\"default\"} 1"));
        assert!(text.contains("catchment_latency_regressions{service=\"default\"} 1"));
        assert!(text.contains("catchment_country_rtt_median_ms{service=\"default\",country=\"DE\",family=\"v4\"} 26.850"));
        assert_eq!(label("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[tokio::test]
    async fn serves_over_http() {
        let state: Shared = Arc::default();
        state.lock().unwrap().record("default", sample_report(), 0);
        let resp = router(state)
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("catchment_round_shifts{service=\"default\"} 1"));
    }
}
