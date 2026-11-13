//! Fills last-hop ASN (RIPEstat) and reverse DNS for observations that the
//! identity rules (CHAOS / NSID / HTTP) could not attribute, and only when some
//! rule needs them. Lookups run in parallel (bounded) and are cached.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::attribute::Attributor;
use crate::dns;
use crate::model::Observation;

const RIPESTAT_URL: &str = "https://stat.ripe.net/data/network-info/data.json";
const MAX_CACHE: usize = 100_000;
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
struct NetworkInfo {
    data: NetworkInfoData,
}

#[derive(Debug, Deserialize)]
struct NetworkInfoData {
    #[serde(default)]
    asns: Vec<String>,
}

/// First ASN of a RIPEstat `network-info` response.
pub fn parse_network_info(body: &[u8]) -> Option<u32> {
    let info: NetworkInfo = serde_json::from_slice(body).ok()?;
    info.data.asns.iter().find_map(|a| a.trim().parse().ok())
}

async fn lookup_asn(http: &reqwest::Client, ip: IpAddr) -> anyhow::Result<Option<u32>> {
    let mut resp = http
        .get(RIPESTAT_URL)
        .query(&[("resource", ip.to_string())])
        .send()
        .await?
        .error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_BODY {
            anyhow::bail!("RIPEstat response too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(parse_network_info(&body))
}

async fn lookup_rdns(resolver: SocketAddr, ip: IpAddr) -> anyhow::Result<Option<String>> {
    let (msg, _) = dns::query(
        resolver,
        &dns::ptr_name(ip),
        dns::TYPE_PTR,
        dns::CLASS_IN,
        Duration::from_secs(2),
        2,
    )
    .await?;
    Ok(msg.first_ptr().map(str::to_string))
}

type Entry<T> = (T, Instant);

/// Lookup results shared across rounds and services (bounded, with TTL).
/// Negative answers are cached too; failures are not.
pub struct Cache {
    ttl: Duration,
    asn: HashMap<IpAddr, Entry<Option<u32>>>,
    rdns: HashMap<IpAddr, Entry<Option<String>>>,
}

pub type SharedCache = Arc<Mutex<Cache>>;

impl Cache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            asn: HashMap::new(),
            rdns: HashMap::new(),
        }
    }

    pub fn shared(ttl: Duration) -> SharedCache {
        Arc::new(Mutex::new(Self::new(ttl)))
    }

    pub fn len(&self) -> usize {
        self.asn.len() + self.rdns.len()
    }

    fn fresh<T: Clone>(map: &HashMap<IpAddr, Entry<T>>, ip: &IpAddr, ttl: Duration) -> Option<T> {
        map.get(ip)
            .filter(|(_, at)| at.elapsed() < ttl)
            .map(|(v, _)| v.clone())
    }

    fn insert<T>(map: &mut HashMap<IpAddr, Entry<T>>, ip: IpAddr, v: T, ttl: Duration) {
        if map.len() >= MAX_CACHE {
            map.retain(|_, (_, at)| at.elapsed() < ttl);
            if map.len() >= MAX_CACHE {
                // shortcut: drop everything when full of fresh entries; an LRU is not worth it at this size.
                map.clear();
            }
        }
        map.insert(ip, (v, Instant::now()));
    }
}

pub fn lock(cache: &SharedCache) -> std::sync::MutexGuard<'_, Cache> {
    cache.lock().unwrap_or_else(|p| p.into_inner())
}

pub struct Options<'a> {
    pub http: &'a reqwest::Client,
    pub resolver: Option<SocketAddr>,
    pub concurrency: usize,
    pub cache: &'a SharedCache,
}

#[derive(Default)]
struct Found {
    asn: Option<u32>,
    rdns: Option<String>,
}

pub async fn enrich(observations: &mut [Observation], attributor: &Attributor, opts: Options<'_>) {
    let want_asn = attributor.needs_asn();
    let want_rdns = attributor.needs_rdns() && opts.resolver.is_some();
    if !want_asn && !want_rdns {
        return;
    }
    let ips: HashSet<IpAddr> = observations
        .iter()
        .filter(|o| attributor.identity_pop(o).is_none())
        .filter_map(|o| o.last_hop)
        .collect();
    let mut found: HashMap<IpAddr, Found> = HashMap::new();
    let mut todo = Vec::new();
    {
        let cache = lock(opts.cache);
        for ip in ips {
            let asn = want_asn
                .then(|| Cache::fresh(&cache.asn, &ip, cache.ttl))
                .flatten();
            let rdns = want_rdns
                .then(|| Cache::fresh(&cache.rdns, &ip, cache.ttl))
                .flatten();
            let need_asn = want_asn && asn.is_none();
            let need_rdns = want_rdns && rdns.is_none();
            found.insert(
                ip,
                Found {
                    asn: asn.flatten(),
                    rdns: rdns.flatten(),
                },
            );
            if need_asn || need_rdns {
                todo.push((ip, need_asn, need_rdns));
            }
        }
    }
    let cached = found.len() - todo.len();
    let limit = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for (ip, need_asn, need_rdns) in todo {
        let (http, limit, resolver) = (opts.http.clone(), limit.clone(), opts.resolver);
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await.ok()?;
            let asn = if need_asn {
                match lookup_asn(&http, ip).await {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::warn!(%ip, error = %e, "ASN lookup failed");
                        None
                    }
                }
            } else {
                None
            };
            let rdns = match (need_rdns, resolver) {
                (true, Some(r)) => match lookup_rdns(r, ip).await {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::debug!(%ip, error = %e, "reverse DNS lookup failed");
                        None
                    }
                },
                _ => None,
            };
            Some((ip, asn, rdns))
        });
    }
    let mut looked_up = 0usize;
    while let Some(res) = tasks.join_next().await {
        let Ok(Some((ip, asn, rdns))) = res else {
            continue;
        };
        looked_up += 1;
        let mut cache = lock(opts.cache);
        let ttl = cache.ttl;
        let entry = found.entry(ip).or_default();
        if let Some(asn) = asn {
            entry.asn = entry.asn.or(asn);
            Cache::insert(&mut cache.asn, ip, asn, ttl);
        }
        if let Some(rdns) = rdns {
            entry.rdns = entry.rdns.take().or(rdns.clone());
            Cache::insert(&mut cache.rdns, ip, rdns, ttl);
        }
    }
    tracing::debug!(cached, looked_up, "last-hop enrichment done");
    for o in observations.iter_mut() {
        if let Some(f) = o.last_hop.and_then(|ip| found.get(&ip)) {
            o.last_hop_asn = o.last_hop_asn.or(f.asn);
            o.last_hop_rdns = o.last_hop_rdns.take().or(f.rdns.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Match, PopRule};

    #[test]
    fn parses_ripestat_network_info() {
        let body = br#"{"status":"ok","data":{"asns":["64511"],"prefix":"198.51.100.0/24"}}"#;
        assert_eq!(parse_network_info(body), Some(64511));
        assert_eq!(parse_network_info(br#"{"data":{"asns":[]}}"#), None);
        assert_eq!(parse_network_info(b"not json"), None);
    }

    #[test]
    fn cache_ttl_and_bound() {
        let mut c = Cache::new(Duration::from_secs(60));
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        Cache::insert(&mut c.asn, ip, Some(64511), c.ttl);
        assert_eq!(Cache::fresh(&c.asn, &ip, c.ttl), Some(Some(64511)));
        assert_eq!(Cache::fresh(&c.asn, &ip, Duration::ZERO), None);
        for i in 0..MAX_CACHE as u32 + 5 {
            Cache::insert(&mut c.asn, IpAddr::from(i.to_be_bytes()), None, c.ttl);
        }
        assert!(c.len() <= MAX_CACHE);
    }

    #[tokio::test]
    async fn uses_cache_and_skips_identified() {
        let a = Attributor::new(&[
            PopRule {
                name: "fra1".into(),
                matcher: Match {
                    chaos: Some("fra1*".into()),
                    ..Match::default()
                },
            },
            PopRule {
                name: "ist1".into(),
                matcher: Match {
                    last_hop_asn: Some(64511),
                    ..Match::default()
                },
            },
        ])
        .unwrap();
        let hop: IpAddr = "198.51.100.1".parse().unwrap();
        let identified: IpAddr = "198.51.100.2".parse().unwrap();
        let mut obs = vec![
            Observation {
                last_hop: Some(hop),
                ..Observation::default()
            },
            Observation {
                chaos: Some("fra1.example".into()),
                last_hop: Some(identified),
                ..Observation::default()
            },
        ];
        let cache = Cache::shared(Duration::from_secs(60));
        {
            let mut c = lock(&cache);
            let ttl = c.ttl;
            Cache::insert(&mut c.asn, hop, Some(64511), ttl);
        }
        // Served from the cache: no network access; the CHAOS-identified
        // vantage is not looked up at all.
        let http = reqwest::Client::new();
        let opts = Options {
            http: &http,
            resolver: None,
            concurrency: 4,
            cache: &cache,
        };
        enrich(&mut obs, &a, opts).await;
        assert_eq!(obs[0].last_hop_asn, Some(64511));
        assert_eq!(obs[1].last_hop_asn, None);
        assert_eq!(lock(&cache).len(), 1);
    }
}
