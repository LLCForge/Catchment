//! Maps observations to PoPs with the `[[pop]]` rules. Never guesses: no match means unattributed.

use anyhow::{Context, Result};
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};

use crate::config::PopRule;
use crate::model::{MatchKind, Observation, Record};

struct Rule {
    name: String,
    chaos: Option<String>,
    nsid: Option<String>,
    http: Option<String>,
    asn: Option<u32>,
    prefix: Option<IpNet>,
    rdns: Option<Regex>,
}

pub struct Attributor {
    rules: Vec<Rule>,
}

impl Attributor {
    pub fn new(pops: &[PopRule]) -> Result<Self> {
        let rules = pops
            .iter()
            .map(|p| {
                let rdns = p
                    .matcher
                    .rdns
                    .as_deref()
                    .map(|r| {
                        RegexBuilder::new(r)
                            .case_insensitive(true)
                            .size_limit(1 << 20)
                            .build()
                            .with_context(|| format!("[[pop]] {:?}: invalid rdns regex", p.name))
                    })
                    .transpose()?;
                Ok(Rule {
                    name: p.name.clone(),
                    chaos: p.matcher.chaos.as_deref().map(str::to_ascii_lowercase),
                    nsid: p.matcher.nsid.as_deref().map(str::to_ascii_lowercase),
                    http: p.matcher.http.as_deref().map(str::to_ascii_lowercase),
                    asn: p.matcher.last_hop_asn,
                    prefix: p.matcher.last_hop_prefix,
                    rdns,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self { rules })
    }

    pub fn needs_asn(&self) -> bool {
        self.rules.iter().any(|r| r.asn.is_some())
    }

    pub fn needs_rdns(&self) -> bool {
        self.rules.iter().any(|r| r.rdns.is_some())
    }

    fn glob_pop(&self, value: Option<&str>, pick: impl Fn(&Rule) -> Option<&str>) -> Option<&str> {
        let v = value?.to_ascii_lowercase();
        self.rules
            .iter()
            .find(|r| pick(r).is_some_and(|g| glob_match(g, &v)))
            .map(|r| r.name.as_str())
    }

    /// PoP named by the server itself (CHAOS, NSID or HTTP header), if any.
    pub fn identity_pop(&self, obs: &Observation) -> Option<(&str, MatchKind)> {
        self.glob_pop(obs.chaos.as_deref(), |r| r.chaos.as_deref())
            .map(|p| (p, MatchKind::Chaos))
            .or_else(|| {
                self.glob_pop(obs.nsid.as_deref(), |r| r.nsid.as_deref())
                    .map(|p| (p, MatchKind::Nsid))
            })
            .or_else(|| {
                self.glob_pop(obs.http_id.as_deref(), |r| r.http.as_deref())
                    .map(|p| (p, MatchKind::Http))
            })
    }

    /// Server identity first (CHAOS, NSID, HTTP header: strongest signals), then
    /// last-hop ASN, prefix and rDNS, each across all pops.
    pub fn attribute(&self, obs: Observation) -> Record {
        let found = self
            .identity_pop(&obs)
            .or_else(|| {
                let asn = obs.last_hop_asn?;
                self.find(|r| r.asn == Some(asn), MatchKind::LastHopAsn)
            })
            .or_else(|| {
                let ip = obs.last_hop?;
                self.find(
                    |r| r.prefix.is_some_and(|n| n.contains(&ip)),
                    MatchKind::LastHopPrefix,
                )
            })
            .or_else(|| {
                let name = obs.last_hop_rdns.as_deref()?;
                self.find(
                    |r| r.rdns.as_ref().is_some_and(|re| re.is_match(name)),
                    MatchKind::Rdns,
                )
            })
            .map(|(p, k)| (p.to_string(), k));
        let (pop, matched_by) = found.unzip();
        Record {
            obs,
            pop,
            matched_by,
        }
    }

    fn find(&self, pred: impl Fn(&Rule) -> bool, kind: MatchKind) -> Option<(&str, MatchKind)> {
        self.rules
            .iter()
            .find(|r| pred(r))
            .map(|r| (r.name.as_str(), kind))
    }
}

/// Glob with `*` (any run) and `?` (one char), no backtracking blow-up.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Match;

    fn rule(name: &str, m: Match) -> PopRule {
        PopRule {
            name: name.into(),
            matcher: m,
        }
    }

    fn attributor() -> Attributor {
        Attributor::new(&[
            rule(
                "fra1",
                Match {
                    chaos: Some("FRA1.*".into()),
                    ..Match::default()
                },
            ),
            rule(
                "ist1",
                Match {
                    chaos: Some("ist1-??.example".into()),
                    last_hop_asn: Some(64511),
                    ..Match::default()
                },
            ),
            rule(
                "nyc1",
                Match {
                    last_hop_prefix: Some("198.51.100.0/24".parse().unwrap()),
                    rdns: Some(r"\.nyc1\.example\.net$".into()),
                    ..Match::default()
                },
            ),
        ])
        .unwrap()
    }

    #[test]
    fn glob() {
        assert!(glob_match("fra1.*", "fra1.example"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(glob_match("ist1-??", "ist1-02"));
        assert!(!glob_match("ist1-??", "ist1-2"));
        assert!(!glob_match("fra1.*", "xfra1.example"));
        assert!(!glob_match(
            "a*b",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
        ));
    }

    #[test]
    fn chaos_wins_over_last_hop() {
        let r = attributor().attribute(Observation {
            chaos: Some("fra1.example".into()),
            last_hop_asn: Some(64511),
            ..Observation::default()
        });
        assert_eq!(r.pop.as_deref(), Some("fra1"));
        assert_eq!(r.matched_by, Some(MatchKind::Chaos));
    }

    #[test]
    fn nsid_and_http_identify() {
        let a = Attributor::new(&[
            rule(
                "ams1",
                Match {
                    nsid: Some("AMS1-*".into()),
                    ..Match::default()
                },
            ),
            rule(
                "lon1",
                Match {
                    http: Some("*lon1*".into()),
                    ..Match::default()
                },
            ),
        ])
        .unwrap();
        let r = a.attribute(Observation {
            chaos: Some("anything".into()),
            nsid: Some("ams1-ns2".into()),
            http_id: Some("cache-lon1-a".into()),
            ..Observation::default()
        });
        assert_eq!(
            (r.pop.as_deref(), r.matched_by),
            (Some("ams1"), Some(MatchKind::Nsid))
        );
        let r = a.attribute(Observation {
            http_id: Some("cache-LON1-a, cache-x".into()),
            ..Observation::default()
        });
        assert_eq!(
            (r.pop.as_deref(), r.matched_by),
            (Some("lon1"), Some(MatchKind::Http))
        );
    }

    #[test]
    fn falls_back_in_order() {
        let a = attributor();
        let asn = a.attribute(Observation {
            chaos: Some("unknown".into()),
            last_hop: Some("198.51.100.9".parse().unwrap()),
            last_hop_asn: Some(64511),
            ..Observation::default()
        });
        assert_eq!(
            (asn.pop.as_deref(), asn.matched_by),
            (Some("ist1"), Some(MatchKind::LastHopAsn))
        );

        let prefix = a.attribute(Observation {
            last_hop: Some("198.51.100.9".parse().unwrap()),
            ..Observation::default()
        });
        assert_eq!(prefix.matched_by, Some(MatchKind::LastHopPrefix));

        let rdns = a.attribute(Observation {
            last_hop: Some("203.0.113.1".parse().unwrap()),
            last_hop_rdns: Some("ae1.NYC1.example.net".into()),
            ..Observation::default()
        });
        assert_eq!(
            (rdns.pop.as_deref(), rdns.matched_by),
            (Some("nyc1"), Some(MatchKind::Rdns))
        );
    }

    #[test]
    fn unknown_is_unattributed() {
        let r = attributor().attribute(Observation {
            chaos: Some("lon1.example".into()),
            last_hop: Some("203.0.113.1".parse().unwrap()),
            last_hop_asn: Some(64500),
            ..Observation::default()
        });
        assert_eq!(r.pop, None);
        assert_eq!(r.pop_label(), "unattributed");
    }

    #[test]
    fn rejects_bad_regex() {
        let bad = rule(
            "x",
            Match {
                rdns: Some("(".into()),
                ..Match::default()
            },
        );
        assert!(Attributor::new(&[bad]).is_err());
    }
}
