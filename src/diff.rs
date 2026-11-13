//! Compares two rounds and emits `CatchmentShift` events per vantage and per country.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::model::{CatchmentShift, CountryShift, Round};

/// Vantages present in only one of the rounds are ignored: absence is not a move.
/// Records are compared per (vantage, probed address), so dual-stack rounds
/// report IPv4 and IPv6 moves separately.
pub fn diff(previous: &Round, current: &Round) -> (Vec<CatchmentShift>, Vec<CountryShift>) {
    let before: HashMap<(&str, IpAddr), &str> = previous
        .records
        .iter()
        .map(|r| {
            (
                (r.obs.vantage.as_str(), r.target_or(previous.target)),
                r.pop_label(),
            )
        })
        .collect();
    let mut shifts: Vec<CatchmentShift> = current
        .records
        .iter()
        .filter_map(|r| {
            let target = r.target_or(current.target);
            let from = *before.get(&(r.obs.vantage.as_str(), target))?;
            let to = r.pop_label();
            (from != to).then(|| CatchmentShift {
                vantage: r.obs.vantage.clone(),
                target: Some(target),
                country: r.obs.country.clone(),
                from: from.to_string(),
                to: to.to_string(),
            })
        })
        .collect();
    shifts.sort_by(|a, b| (&a.vantage, a.target).cmp(&(&b.vantage, b.target)));

    type Key = (String, Option<IpAddr>, String, String);
    let mut per_country: BTreeMap<Key, usize> = BTreeMap::new();
    for s in &shifts {
        let country = s.country.clone().unwrap_or_else(|| "??".into());
        *per_country
            .entry((country, s.target, s.from.clone(), s.to.clone()))
            .or_default() += 1;
    }
    let countries = per_country
        .into_iter()
        .map(|((country, target, from, to), vantages)| CountryShift {
            country,
            target,
            from,
            to,
            vantages,
        })
        .collect();
    (shifts, countries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Observation, Record};

    fn rec(vantage: &str, country: &str, pop: Option<&str>) -> Record {
        Record {
            obs: Observation {
                vantage: vantage.into(),
                country: Some(country.into()),
                ..Observation::default()
            },
            pop: pop.map(Into::into),
            matched_by: None,
        }
    }

    fn round(records: Vec<Record>) -> Round {
        Round {
            started_ms: 0,
            target: "192.0.2.53".parse().unwrap(),
            service: None,
            label: None,
            records,
        }
    }

    #[test]
    fn detects_moves_and_aggregates() {
        let prev = round(vec![
            rec("atlas:1", "DE", Some("fra1")),
            rec("atlas:2", "DE", Some("fra1")),
            rec("atlas:3", "TR", Some("ist1")),
            rec("atlas:4", "US", Some("nyc1")),
            rec("atlas:9", "BR", Some("nyc1")),
        ]);
        let cur = round(vec![
            rec("atlas:2", "DE", Some("ist1")),
            rec("atlas:1", "DE", Some("ist1")),
            rec("atlas:3", "TR", Some("ist1")),
            rec("atlas:4", "US", None),
            rec("atlas:5", "JP", Some("nyc1")),
        ]);
        let (shifts, countries) = diff(&prev, &cur);
        assert_eq!(shifts.len(), 3);
        assert_eq!(shifts[0].vantage, "atlas:1");
        assert_eq!(shifts[2].to, "unattributed");
        assert_eq!(
            countries,
            vec![
                CountryShift {
                    country: "DE".into(),
                    target: Some("192.0.2.53".parse().unwrap()),
                    from: "fra1".into(),
                    to: "ist1".into(),
                    vantages: 2
                },
                CountryShift {
                    country: "US".into(),
                    target: Some("192.0.2.53".parse().unwrap()),
                    from: "nyc1".into(),
                    to: "unattributed".into(),
                    vantages: 1
                },
            ]
        );
    }

    #[test]
    fn dual_stack_records_are_compared_per_address() {
        let v6: IpAddr = "2001:db8::53".parse().unwrap();
        let with = |pop: &str, target: Option<IpAddr>| {
            let mut r = rec("atlas:1", "DE", Some(pop));
            r.obs.target = target;
            r
        };
        let prev = round(vec![with("fra1", None), with("ams1", Some(v6))]);
        let cur = round(vec![with("fra1", None), with("fra1", Some(v6))]);
        let (shifts, countries) = diff(&prev, &cur);
        assert_eq!(shifts.len(), 1);
        assert_eq!(shifts[0].target, Some(v6));
        assert_eq!(
            (shifts[0].from.as_str(), shifts[0].to.as_str()),
            ("ams1", "fra1")
        );
        assert_eq!(countries[0].target, Some(v6));
    }

    #[test]
    fn identical_rounds_have_no_shifts() {
        let r = round(vec![rec("local", "TR", Some("ist1"))]);
        let (s, c) = diff(&r, &r);
        assert!(s.is_empty() && c.is_empty());
    }
}
