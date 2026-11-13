//! RIPE Atlas credit budget: daily / monthly caps enforced before any
//! measurement is created, with a persistent ledger in the data directory.
//!
//! Costs follow the RIPE Atlas cost model: DNS over UDP costs 10 credits per
//! result, a default traceroute (3 packets) 30, and one-off measurements cost
//! twice as much. The ledger books the worst case (every requested probe
//! delivers) at creation time, so the caps are never exceeded by Catchment.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::Budget;
use crate::store::write_atomic;

pub const ONEOFF_DNS_CREDITS: u64 = 20;
pub const ONEOFF_TRACEROUTE_CREDITS: u64 = 60;
const MAX_LEDGER_BYTES: u64 = 64 * 1024;

/// Worst-case cost of one Atlas round of a service.
pub fn estimate(requested_probes: u64, families: u64, traceroute: bool) -> u64 {
    let per_result = ONEOFF_DNS_CREDITS
        + if traceroute {
            ONEOFF_TRACEROUTE_CREDITS
        } else {
            0
        };
    requested_probes
        .saturating_mul(families)
        .saturating_mul(per_result)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    pub day: String,
    pub day_spent: u64,
    pub month: String,
    pub month_spent: u64,
}

impl Ledger {
    /// Reset counters when the UTC day / month changed. `today` is "YYYY-MM-DD".
    fn roll(&mut self, today: &str) {
        if self.day != today {
            self.day = today.to_string();
            self.day_spent = 0;
        }
        let month = &today[..7.min(today.len())];
        if self.month != month {
            self.month = month.to_string();
            self.month_spent = 0;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("RIPE Atlas {period} budget exhausted: {spent} spent + {cost} needed > cap {cap} credits")]
pub struct Exceeded {
    pub period: &'static str,
    pub spent: u64,
    pub cost: u64,
    pub cap: u64,
}

pub struct BudgetManager {
    path: PathBuf,
    daily: Option<u64>,
    monthly: Option<u64>,
    pub min_balance: Option<u64>,
    ledger: Mutex<Ledger>,
}

pub fn today_utc(now: SystemTime) -> String {
    humantime::format_rfc3339_seconds(now).to_string()[..10].to_string()
}

impl BudgetManager {
    pub fn open(path: PathBuf, cfg: &Budget) -> Result<Self> {
        let ledger = match std::fs::metadata(&path) {
            Ok(m) if m.len() > MAX_LEDGER_BYTES => {
                anyhow::bail!("{} is larger than 64 KiB", path.display())
            }
            Ok(_) => {
                let bytes = std::fs::read(&path)?;
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ledger::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path,
            daily: cfg.daily_credits,
            monthly: cfg.monthly_credits,
            min_balance: cfg.min_balance,
            ledger: Mutex::new(ledger),
        })
    }

    pub fn usage(&self, now: SystemTime) -> Ledger {
        let mut l = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
        l.roll(&today_utc(now));
        l.clone()
    }

    pub fn caps(&self) -> (Option<u64>, Option<u64>) {
        (self.daily, self.monthly)
    }

    /// Books `cost` if it fits both caps; persists the ledger.
    pub fn reserve(&self, cost: u64, now: SystemTime) -> Result<Result<(), Exceeded>> {
        let mut l = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
        l.roll(&today_utc(now));
        for (period, spent, cap) in [
            ("daily", l.day_spent, self.daily),
            ("monthly", l.month_spent, self.monthly),
        ] {
            if let Some(cap) = cap {
                if spent.saturating_add(cost) > cap {
                    return Ok(Err(Exceeded {
                        period,
                        spent,
                        cost,
                        cap,
                    }));
                }
            }
        }
        l.day_spent = l.day_spent.saturating_add(cost);
        l.month_spent = l.month_spent.saturating_add(cost);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_atomic(&self.path, &serde_json::to_vec_pretty(&*l)?)?;
        Ok(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn estimates_worst_case() {
        assert_eq!(estimate(50, 1, false), 1000);
        assert_eq!(estimate(50, 2, true), 8000);
        assert_eq!(estimate(u64::MAX, 2, true), u64::MAX);
    }

    #[test]
    fn caps_roll_and_persist() {
        let dir = std::env::temp_dir().join(format!("catchment-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("atlas-budget.json");
        let cfg = Budget {
            daily_credits: Some(1000),
            monthly_credits: Some(1500),
            min_balance: None,
        };
        let day1 = UNIX_EPOCH + Duration::from_secs(1_767_225_600); // 2026-01-01
        let m = BudgetManager::open(path.clone(), &cfg).unwrap();
        assert!(m.reserve(600, day1).unwrap().is_ok());
        let over = m.reserve(600, day1).unwrap().unwrap_err();
        assert_eq!((over.period, over.spent, over.cap), ("daily", 600, 1000));
        // Next day: daily resets, monthly does not.
        let day2 = day1 + Duration::from_secs(86_400);
        let reopened = BudgetManager::open(path.clone(), &cfg).unwrap();
        assert_eq!(reopened.usage(day1).day_spent, 600);
        assert!(reopened.reserve(800, day2).unwrap().is_ok());
        let over = reopened.reserve(200, day2).unwrap().unwrap_err();
        assert_eq!(over.period, "monthly");
        // Next month: both reset.
        let feb = day1 + Duration::from_secs(31 * 86_400);
        assert!(reopened.reserve(900, feb).unwrap().is_ok());
        assert_eq!(reopened.usage(feb).month, "2026-02");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
