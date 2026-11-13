//! Aggregations over rounds: per-ASN, per-country latency, dual-stack
//! comparison and before/after experiment comparison.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use serde::Serialize;

use crate::diff;
use crate::model::{family, CatchmentShift, Round};

pub fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let mid = values.len() / 2;
    Some(if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    })
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AsnRow {
    pub asn: Option<u32>,
    pub vantages: usize,
    /// PoP -> vantages.
    pub pops: BTreeMap<String, usize>,
}

/// Where each vantage ASN lands, largest ASNs first.
pub fn per_asn(round: &Round) -> Vec<AsnRow> {
    let mut map: BTreeMap<Option<u32>, BTreeMap<String, usize>> = BTreeMap::new();
    for r in &round.records {
        *map.entry(r.obs.asn)
            .or_default()
            .entry(r.pop_label().to_string())
            .or_default() += 1;
    }
    let mut rows: Vec<AsnRow> = map
        .into_iter()
        .map(|(asn, pops)| AsnRow {
            asn,
            vantages: pops.values().sum(),
            pops,
        })
        .collect();
    rows.sort_by(|a, b| b.vantages.cmp(&a.vantages).then(a.asn.cmp(&b.asn)));
    rows
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CountryLatency {
    pub country: String,
    pub target: IpAddr,
    pub median_ms: f64,
    pub vantages: usize,
}

/// Median RTT per (country, address) over vantages that have an RTT.
pub fn country_latency(round: &Round) -> Vec<CountryLatency> {
    let mut map: BTreeMap<(String, IpAddr), Vec<f64>> = BTreeMap::new();
    for r in &round.records {
        let (Some(cc), Some(rtt)) = (&r.obs.country, r.obs.rtt_ms) else {
            continue;
        };
        if rtt.is_finite() && rtt >= 0.0 {
            map.entry((cc.clone(), r.target_or(round.target)))
                .or_default()
                .push(rtt);
        }
    }
    map.into_iter()
        .filter_map(|((country, target), mut v)| {
            Some(CountryLatency {
                country,
                target,
                vantages: v.len(),
                median_ms: median(&mut v)?,
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DualRow {
    pub vantage: String,
    pub country: Option<String>,
    pub pop_v4: String,
    pub pop_v6: String,
    pub rtt_v4_ms: Option<f64>,
    pub rtt_v6_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DualStack {
    pub vantages: usize,
    pub same_pop: usize,
    pub different_pop: usize,
    /// Median of (IPv6 RTT - IPv4 RTT) over vantages with both.
    pub median_v6_minus_v4_ms: Option<f64>,
    /// Vantages whose IPv4 and IPv6 traffic lands in different PoPs.
    pub mismatches: Vec<DualRow>,
}

/// Only for rounds that measured both an IPv4 and an IPv6 address.
pub fn dual_stack(round: &Round) -> Option<DualStack> {
    let mut v4 = HashMap::new();
    let mut v6 = HashMap::new();
    for r in &round.records {
        let map = if r.target_or(round.target).is_ipv4() {
            &mut v4
        } else {
            &mut v6
        };
        map.insert(r.obs.vantage.as_str(), r);
    }
    if v4.is_empty() || v6.is_empty() {
        return None;
    }
    let both: BTreeSet<&str> = v4.keys().filter(|k| v6.contains_key(*k)).copied().collect();
    let mut deltas = Vec::new();
    let mut mismatches = Vec::new();
    for vantage in &both {
        let (a, b) = (v4[vantage], v6[vantage]);
        if let (Some(x), Some(y)) = (a.obs.rtt_ms, b.obs.rtt_ms) {
            deltas.push(y - x);
        }
        if a.pop_label() != b.pop_label() {
            mismatches.push(DualRow {
                vantage: vantage.to_string(),
                country: a.obs.country.clone(),
                pop_v4: a.pop_label().to_string(),
                pop_v6: b.pop_label().to_string(),
                rtt_v4_ms: a.obs.rtt_ms,
                rtt_v6_ms: b.obs.rtt_ms,
            });
        }
    }
    Some(DualStack {
        vantages: both.len(),
        same_pop: both.len() - mismatches.len(),
        different_pop: mismatches.len(),
        median_v6_minus_v4_ms: median(&mut deltas),
        mismatches,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PopDelta {
    pub pop: String,
    pub family: &'static str,
    pub before: usize,
    pub after: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LatencyDelta {
    pub country: String,
    pub family: &'static str,
    pub before_ms: Option<f64>,
    pub after_ms: Option<f64>,
}

/// Experiment comparison of two rounds (`catchment compare`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Comparison {
    pub service: String,
    pub before: RoundRef,
    pub after: RoundRef,
    pub pops: Vec<PopDelta>,
    pub moved: Vec<CatchmentShift>,
    pub latency: Vec<LatencyDelta>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoundRef {
    pub started: String,
    pub label: Option<String>,
    pub vantages: usize,
}

fn round_ref(r: &Round) -> RoundRef {
    RoundRef {
        started: r.started_rfc3339(),
        label: r.label.clone(),
        vantages: r.records.len(),
    }
}

pub fn compare(before: &Round, after: &Round) -> Comparison {
    let mut pops: BTreeMap<(String, &'static str), (usize, usize)> = BTreeMap::new();
    for (round, is_after) in [(before, false), (after, true)] {
        for r in &round.records {
            let e = pops
                .entry((r.pop_label().to_string(), family(r.target_or(round.target))))
                .or_default();
            if is_after {
                e.1 += 1;
            } else {
                e.0 += 1;
            }
        }
    }
    let lat = |r: &Round| -> BTreeMap<(String, &'static str), f64> {
        country_latency(r)
            .into_iter()
            .map(|c| ((c.country, family(c.target)), c.median_ms))
            .collect()
    };
    let (lb, la) = (lat(before), lat(after));
    let keys: BTreeSet<_> = lb.keys().chain(la.keys()).cloned().collect();
    Comparison {
        service: after.service_label().to_string(),
        before: round_ref(before),
        after: round_ref(after),
        pops: pops
            .into_iter()
            .map(|((pop, family), (b, a))| PopDelta {
                pop,
                family,
                before: b,
                after: a,
            })
            .collect(),
        moved: diff::diff(before, after).0,
        latency: keys
            .into_iter()
            .map(|k| LatencyDelta {
                before_ms: lb.get(&k).copied(),
                after_ms: la.get(&k).copied(),
                country: k.0,
                family: k.1,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Observation, Record};

    fn rec(v: &str, cc: &str, asn: u32, pop: &str, target: Option<&str>, rtt: f64) -> Record {
        Record {
            obs: Observation {
                vantage: v.into(),
                target: target.map(|t| t.parse().unwrap()),
                country: Some(cc.into()),
                asn: Some(asn),
                rtt_ms: Some(rtt),
                ..Observation::default()
            },
            pop: Some(pop.into()),
            matched_by: None,
        }
    }

    fn round(records: Vec<Record>, label: Option<&str>) -> Round {
        Round {
            started_ms: 0,
            target: "192.0.2.53".parse().unwrap(),
            service: Some("dns".into()),
            label: label.map(Into::into),
            records,
        }
    }

    #[test]
    fn medians() {
        assert_eq!(median(&mut []), None);
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&mut [4.0, 1.0, 2.0, 3.0]), Some(2.5));
    }

    #[test]
    fn asn_and_country_aggregation() {
        let r = round(
            vec![
                rec("a:1", "DE", 64500, "fra1", None, 10.0),
                rec("a:2", "DE", 64500, "ist1", None, 30.0),
                rec("a:3", "DE", 64501, "fra1", None, 20.0),
            ],
            None,
        );
        let rows = per_asn(&r);
        assert_eq!(rows[0].asn, Some(64500));
        assert_eq!(rows[0].vantages, 2);
        assert_eq!(rows[0].pops["ist1"], 1);
        let lat = country_latency(&r);
        assert_eq!(lat.len(), 1);
        assert_eq!((lat[0].median_ms, lat[0].vantages), (20.0, 3));
    }

    #[test]
    fn dual_stack_comparison() {
        let v6 = Some("2001:db8::53");
        let r = round(
            vec![
                rec("a:1", "DE", 1, "fra1", None, 10.0),
                rec("a:1", "DE", 1, "fra1", v6, 14.0),
                rec("a:2", "TR", 2, "ist1", None, 20.0),
                rec("a:2", "TR", 2, "fra1", v6, 60.0),
                rec("a:3", "US", 3, "nyc1", None, 5.0),
            ],
            None,
        );
        let d = dual_stack(&r).unwrap();
        assert_eq!((d.vantages, d.same_pop, d.different_pop), (2, 1, 1));
        assert_eq!(d.mismatches[0].vantage, "a:2");
        assert_eq!(d.median_v6_minus_v4_ms, Some(22.0));
        assert!(dual_stack(&round(vec![rec("a:1", "DE", 1, "fra1", None, 1.0)], None)).is_none());
    }

    #[test]
    fn experiment_compare() {
        let before = round(
            vec![
                rec("a:1", "DE", 1, "fra1", None, 10.0),
                rec("a:2", "TR", 2, "fra1", None, 50.0),
            ],
            Some("before"),
        );
        let after = round(
            vec![
                rec("a:1", "DE", 1, "fra1", None, 11.0),
                rec("a:2", "TR", 2, "ist1", None, 9.0),
            ],
            Some("after"),
        );
        let c = compare(&before, &after);
        assert_eq!(c.service, "dns");
        assert_eq!(c.before.label.as_deref(), Some("before"));
        assert_eq!(c.moved.len(), 1);
        assert_eq!(c.moved[0].to, "ist1");
        let fra = c.pops.iter().find(|p| p.pop == "fra1").unwrap();
        assert_eq!((fra.before, fra.after), (2, 1));
        let tr = c.latency.iter().find(|l| l.country == "TR").unwrap();
        assert_eq!((tr.before_ms, tr.after_ms), (Some(50.0), Some(9.0)));
    }
}
