//! Catchment shift and per-country latency regression alarms, delivered
//! through llcforge-alert.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use llcforge_alert::{Alert, Severity};

use crate::aggregate::{country_latency, median};
use crate::config::LatencyAlarm;
use crate::model::{family, LatencyRegression, PathCorrelation, Report, Round};
use crate::pathology;

pub const TOOL: &str = "catchment";

fn resource(service: &str, country: &str, target: Option<IpAddr>) -> String {
    match target {
        Some(t) => format!("{service}/{country}/{}", family(t)),
        None => format!("{service}/{country}"),
    }
}

/// One alert per (country, address family, transition) with enough vantages.
/// The id includes the transition, so a later different move is a new alert.
pub fn shift_alerts(service: &str, report: &Report, min_vantages: usize) -> Vec<Alert> {
    report
        .country_shifts
        .iter()
        .filter(|c| c.vantages >= min_vantages)
        .map(|c| {
            let res = resource(service, &c.country, c.target);
            let mut a = Alert::new(
                TOOL,
                "catchment_shift",
                Severity::Warning,
                format!(
                    "{service}: {} vantage(s) in {} moved {} -> {}",
                    c.vantages, c.country, c.from, c.to
                ),
            )
            .resource(res.clone())
            .id(format!("{TOOL}:catchment_shift:{res}:{}->{}", c.from, c.to))
            .summary(format!(
                "Anycast catchment changed between {} and {}.",
                report
                    .previous_started_ms
                    .map(crate::model::rfc3339_ms)
                    .unwrap_or_default(),
                report.round.started_rfc3339()
            ))
            .field("service", service)
            .field("country", &c.country)
            .field("from", &c.from)
            .field("to", &c.to)
            .field("vantages", c.vantages);
            if let Some(t) = c.target {
                a = a.field("target", t);
            }
            a
        })
        .collect()
}

/// Follow-up alert with the BGP path changes Pathology saw (sent after the
/// shift alerts, so the lookup never delays them).
pub fn correlation_alert(service: &str, c: &PathCorrelation) -> Option<Alert> {
    if c.events.is_empty() {
        return None;
    }
    let mut a = Alert::new(
        TOOL,
        "catchment_shift_paths",
        Severity::Info,
        format!(
            "{service}: {} BGP path change(s) for {} since {}",
            c.events.len(),
            c.prefix,
            c.since
        ),
    )
    .resource(format!("{service}/{}", c.prefix))
    .id(format!(
        "{TOOL}:catchment_shift_paths:{service}/{}:{}",
        c.prefix, c.since
    ))
    .field("prefix", &c.prefix)
    .field("events", c.events.len());
    for (i, e) in c.events.iter().take(5).enumerate() {
        a = a.field(format!("event{}", i + 1), pathology::describe(e));
    }
    Some(a)
}

/// Per-country median RTT now vs. the median of the per-round medians in
/// `history` (oldest rounds first or last, order does not matter).
pub fn latency_regressions(
    current: &Round,
    history: &[Round],
    cfg: &LatencyAlarm,
) -> Vec<LatencyRegression> {
    let mut baseline: BTreeMap<(String, IpAddr), Vec<f64>> = BTreeMap::new();
    for r in history {
        for c in country_latency(r) {
            baseline
                .entry((c.country, c.target))
                .or_default()
                .push(c.median_ms);
        }
    }
    let needed = cfg.baseline_rounds.div_ceil(2).max(1);
    country_latency(current)
        .into_iter()
        .filter(|c| c.vantages >= cfg.min_vantages)
        .filter_map(|c| {
            let mut hist = baseline.remove(&(c.country.clone(), c.target))?;
            if hist.len() < needed {
                return None;
            }
            let base = median(&mut hist)?;
            let regressed =
                c.median_ms > base * cfg.ratio && c.median_ms - base >= cfg.min_increase_ms;
            regressed.then_some(LatencyRegression {
                country: c.country,
                target: c.target,
                baseline_ms: base,
                current_ms: c.median_ms,
                vantages: c.vantages,
            })
        })
        .collect()
}

/// Remembers which regressions are open so they can be resolved.
#[derive(Debug, Default)]
pub struct LatencyTracker {
    active: BTreeSet<String>,
}

impl LatencyTracker {
    pub fn active(&self) -> usize {
        self.active.len()
    }

    pub fn update(&mut self, service: &str, regressions: &[LatencyRegression]) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let mut now = BTreeSet::new();
        for r in regressions {
            let res = resource(service, &r.country, Some(r.target));
            now.insert(res.clone());
            alerts.push(
                Alert::new(
                    TOOL,
                    "latency_regression",
                    Severity::Warning,
                    format!(
                        "{service}: median RTT in {} {:.1} ms (baseline {:.1} ms)",
                        r.country, r.current_ms, r.baseline_ms
                    ),
                )
                .resource(res)
                .field("service", service)
                .field("country", &r.country)
                .field("target", r.target)
                .field("current_ms", format!("{:.1}", r.current_ms))
                .field("baseline_ms", format!("{:.1}", r.baseline_ms))
                .field("vantages", r.vantages),
            );
        }
        for gone in self.active.difference(&now) {
            alerts.push(
                Alert::new(
                    TOOL,
                    "latency_regression",
                    Severity::Warning,
                    format!("{service}: latency back to baseline for {gone}"),
                )
                .resource(gone.clone())
                .resolved(true),
            );
        }
        self.active = now;
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CountryShift, Observation, Record};
    use crate::output::tests::sample_report;

    fn round(rtts: &[(&str, f64)]) -> Round {
        Round {
            started_ms: 0,
            target: "192.0.2.53".parse().unwrap(),
            service: None,
            label: None,
            records: rtts
                .iter()
                .enumerate()
                .map(|(i, (cc, rtt))| Record {
                    obs: Observation {
                        vantage: format!("atlas:{i}"),
                        country: Some(cc.to_string()),
                        rtt_ms: Some(*rtt),
                        ..Observation::default()
                    },
                    pop: None,
                    matched_by: None,
                })
                .collect(),
        }
    }

    #[test]
    fn shift_alert_ids_and_threshold() {
        let r = sample_report();
        let alerts = shift_alerts("default", &r, 1);
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].id,
            "catchment:catchment_shift:default/DE/v4:fra1->ist1"
        );
        assert!(shift_alerts("default", &r, 2).is_empty());
        let mut r2 = r.clone();
        r2.country_shifts = vec![CountryShift {
            country: "DE".into(),
            target: Some("2001:db8::53".parse().unwrap()),
            from: "fra1".into(),
            to: "ams1".into(),
            vantages: 3,
        }];
        let a = &shift_alerts("dns", &r2, 1)[0];
        assert_eq!(a.id, "catchment:catchment_shift:dns/DE/v6:fra1->ams1");
    }

    #[test]
    fn detects_and_resolves_latency_regression() {
        let cfg = LatencyAlarm::default();
        let history: Vec<Round> = (0..8)
            .map(|_| round(&[("DE", 10.0), ("DE", 12.0), ("DE", 11.0), ("TR", 40.0)]))
            .collect();
        let bad = round(&[("DE", 50.0), ("DE", 45.0), ("DE", 60.0), ("TR", 45.0)]);
        let regs = latency_regressions(&bad, &history, &cfg);
        assert_eq!(regs.len(), 1, "TR has too few vantages, DE regressed");
        assert_eq!(
            (
                regs[0].country.as_str(),
                regs[0].baseline_ms,
                regs[0].current_ms
            ),
            ("DE", 11.0, 50.0)
        );
        // Small absolute increase is ignored even when the ratio is exceeded.
        let small = round(&[("DE", 20.0), ("DE", 20.0), ("DE", 20.0)]);
        assert!(latency_regressions(&small, &history, &cfg).is_empty());
        // Not enough history: no verdict.
        assert!(latency_regressions(&bad, &history[..2], &cfg).is_empty());

        let mut t = LatencyTracker::default();
        let raised = t.update("dns", &regs);
        assert_eq!(raised.len(), 1);
        assert!(!raised[0].resolved);
        assert_eq!(t.active(), 1);
        let cleared = t.update("dns", &[]);
        assert_eq!(cleared.len(), 1);
        assert!(cleared[0].resolved);
        assert_eq!(cleared[0].id, raised[0].id);
        assert_eq!(t.active(), 0);
    }

    #[test]
    fn correlation_alert_lists_events() {
        let c = PathCorrelation {
            prefix: "192.0.2.0/24".into(),
            since: "2026-01-01T00:00:00Z".into(),
            events: crate::pathology::parse_routes(
                br#"{"events":[{"time":"t","peer":"192.0.2.1","peer_asn":64496,"prefix":"192.0.2.0/24","kind":"announce","as_path":[64496]}]}"#,
                10,
            )
            .unwrap(),
            error: None,
        };
        let a = correlation_alert("dns", &c).unwrap();
        assert_eq!(a.kind, "catchment_shift_paths");
        assert!(correlation_alert(
            "dns",
            &PathCorrelation {
                events: vec![],
                ..c
            }
        )
        .is_none());
    }
}
