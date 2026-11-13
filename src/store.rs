//! Round persistence: one JSON file per round, atomic writes, bounded retention.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model::Round;

const PREFIX: &str = "round-";
const SUFFIX: &str = ".json";
const MAX_ROUND_BYTES: u64 = 64 * 1024 * 1024;

pub struct Store {
    dir: PathBuf,
    retain: usize,
}

impl Store {
    pub fn new(dir: PathBuf, retain: usize) -> Self {
        Self { dir, retain }
    }

    /// Round files sorted oldest first (names embed a zero-padded timestamp).
    fn round_files(&self) -> Result<Vec<PathBuf>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(PREFIX) && n.ends_with(SUFFIX))
            })
            .collect();
        files.sort();
        Ok(files)
    }

    fn load(path: &Path) -> Result<Round> {
        let len = fs::metadata(path)?.len();
        if len > MAX_ROUND_BYTES {
            anyhow::bail!("{} is larger than 64 MiB", path.display());
        }
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn latest(&self) -> Result<Option<Round>> {
        match self.round_files()?.pop() {
            Some(path) => Self::load(&path).map(Some),
            None => Ok(None),
        }
    }

    /// Up to `n` most recent rounds, newest first. Unreadable files are skipped.
    pub fn recent(&self, n: usize) -> Result<Vec<Round>> {
        let files = self.round_files()?;
        Ok(files
            .iter()
            .rev()
            .take(n)
            .filter_map(|p| match Self::load(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(error = %e, "skipping unreadable round");
                    None
                }
            })
            .collect())
    }

    /// Newest round carrying experiment label `label` (searches every retained round).
    pub fn latest_labeled(&self, label: &str) -> Result<Option<Round>> {
        for path in self.round_files()?.iter().rev() {
            match Self::load(path) {
                Ok(r) if r.label.as_deref() == Some(label) => return Ok(Some(r)),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "skipping unreadable round"),
            }
        }
        Ok(None)
    }

    pub fn save(&self, round: &Round) -> Result<PathBuf> {
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        let path = self
            .dir
            .join(format!("{PREFIX}{:020}{SUFFIX}", round.started_ms));
        write_atomic(&path, &serde_json::to_vec_pretty(round)?)?;
        let files = self.round_files()?;
        for old in files.iter().take(files.len().saturating_sub(self.retain)) {
            if let Err(e) = fs::remove_file(old) {
                tracing::warn!(path = %old.display(), error = %e, "could not prune old round");
            }
        }
        Ok(path)
    }
}

/// Write to a temp file in the same directory, fsync, then rename over the target.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("invalid output path")?;
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    let result = (|| -> Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("catchment-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn round(ms: u64) -> Round {
        Round {
            started_ms: ms,
            target: "2001:db8::53".parse().unwrap(),
            service: None,
            label: (ms == 1_000).then(|| "before".to_string()),
            records: Vec::new(),
        }
    }

    #[test]
    fn saves_loads_latest_and_prunes() {
        let dir = temp_dir("store");
        let store = Store::new(dir.clone(), 2);
        assert_eq!(store.latest().unwrap(), None);
        for ms in [900, 1_000, 20_000] {
            store.save(&round(ms)).unwrap();
        }
        assert_eq!(store.latest().unwrap(), Some(round(20_000)));
        assert_eq!(store.round_files().unwrap().len(), 2);
        let recent = store.recent(5).unwrap();
        assert_eq!(
            recent.iter().map(|r| r.started_ms).collect::<Vec<_>>(),
            vec![20_000, 1_000]
        );
        assert_eq!(store.latest_labeled("before").unwrap(), Some(round(1_000)));
        assert_eq!(store.latest_labeled("after").unwrap(), None);
        let leftovers = fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        fs::remove_dir_all(dir).unwrap();
    }
}
