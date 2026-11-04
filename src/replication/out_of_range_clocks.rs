//! When records left this node's range, kept across restarts (ADR-0028).
//!
//! A record becomes eligible to be erased only once its clock has run for
//! `PRUNE_HYSTERESIS_DURATION`, and disks run full of such records by design.
//! A restart that reset the clocks would leave a node with nothing it could
//! erase for that long.
//!
//! Clocks are wall-clock times, in memory as on disk, so they mean the same to
//! the next process. Time spent offline therefore counts towards the
//! hysteresis. A wall clock set back only delays an erasure, and an unreadable
//! file only starts the clocks again.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

use crate::ant_protocol::XorName;
use crate::logging::warn;

use super::write_file_atomic;

/// When each record first went out of range, saved to a file of its own.
#[derive(Debug)]
pub struct OutOfRangeClocks {
    path: PathBuf,
    clocks: RwLock<HashMap<XorName, SystemTime>>,
    /// Whether `clocks` differs from what was last saved.
    changed: AtomicBool,
}

impl OutOfRangeClocks {
    /// The clocks saved at `path`, or none if the file is missing or unreadable.
    ///
    /// This reads the file: call it off the async runtime where it can be large.
    pub fn load(path: PathBuf) -> Self {
        let clocks = read_clocks(&path);
        Self {
            path,
            clocks: RwLock::new(clocks),
            changed: AtomicBool::new(false),
        }
    }

    /// When `key`'s clock started, if it is running.
    pub fn since(&self, key: &XorName) -> Option<SystemTime> {
        self.clocks.read().get(key).copied()
    }

    /// Start `key`'s clock at `now` unless it is already running, and return
    /// when it started.
    pub fn start(&self, key: &XorName, now: SystemTime) -> SystemTime {
        let mut clocks = self.clocks.write();
        *clocks.entry(*key).or_insert_with(|| {
            self.changed.store(true, Ordering::Relaxed);
            now
        })
    }

    /// Stop `key`'s clock.
    pub fn clear(&self, key: &XorName) {
        if self.clocks.write().remove(key).is_some() {
            self.changed.store(true, Ordering::Relaxed);
        }
    }

    /// Stop the clock of every key `keep` rejects.
    pub fn retain(&self, keep: impl Fn(&XorName) -> bool) {
        let mut clocks = self.clocks.write();
        let before = clocks.len();
        clocks.retain(|key, _| keep(key));
        if clocks.len() != before {
            self.changed.store(true, Ordering::Relaxed);
        }
    }

    /// Save the clocks if they have changed. A failure is logged, the previous
    /// file stays, and the next call tries again.
    pub async fn save(&self) {
        if !self.changed.swap(false, Ordering::Relaxed) {
            return;
        }
        let encoded = encode(&self.clocks.read());
        let saved = match encoded {
            Ok(bytes) => write_file_atomic(&self.path, bytes).await,
            Err(e) => {
                warn!("Failed to encode out-of-range clocks: {e}");
                false
            }
        };
        if !saved {
            self.changed.store(true, Ordering::Relaxed);
        }
    }
}

/// How long a clock started at `first_seen` has run at `now`: nothing yet if the
/// wall clock has been set back past its start.
pub fn elapsed(first_seen: SystemTime, now: SystemTime) -> Duration {
    now.duration_since(first_seen).unwrap_or(Duration::ZERO)
}

fn read_clocks(path: &PathBuf) -> HashMap<XorName, SystemTime> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return HashMap::new(),
        Err(e) => {
            warn!("Failed to read out-of-range clocks at {path:?}: {e}");
            return HashMap::new();
        }
    };
    decode(&bytes).unwrap_or_else(|e| {
        warn!("Failed to decode out-of-range clocks at {path:?}: {e}");
        HashMap::new()
    })
}

fn encode(clocks: &HashMap<XorName, SystemTime>) -> postcard::Result<Vec<u8>> {
    let persisted: Vec<(XorName, u64)> = clocks
        .iter()
        .map(|(key, first_seen)| {
            let secs = first_seen
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs());
            (*key, secs)
        })
        .collect();
    postcard::to_allocvec(&persisted)
}

fn decode(bytes: &[u8]) -> postcard::Result<HashMap<XorName, SystemTime>> {
    let persisted: Vec<(XorName, u64)> = postcard::from_bytes(bytes)?;
    Ok(persisted
        .into_iter()
        .map(|(key, secs)| (key, UNIX_EPOCH + Duration::from_secs(secs)))
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const KEY: XorName = [0xAB; 32];
    const OTHER_KEY: XorName = [0xCD; 32];
    const AGE: Duration = Duration::from_hours(3);
    /// Saved clocks lose their sub-second part.
    const ROUNDING: Duration = Duration::from_secs(1);

    fn clocks_in(dir: &tempfile::TempDir) -> OutOfRangeClocks {
        OutOfRangeClocks::load(dir.path().join("clocks.bin"))
    }

    #[tokio::test]
    async fn a_saved_clock_keeps_its_start_and_so_counts_time_offline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first_seen = SystemTime::now() - AGE;
        let clocks = clocks_in(&dir);
        assert_eq!(clocks.start(&KEY, first_seen), first_seen);
        clocks.save().await;

        let restored = clocks_in(&dir).since(&KEY).expect("clock restored");

        let drift = elapsed(restored, first_seen);
        assert!(drift <= ROUNDING, "restored clock moved by {drift:?}");
        assert!(elapsed(restored, SystemTime::now()) + ROUNDING >= AGE);
    }

    #[test]
    fn a_running_clock_keeps_its_first_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let clocks = clocks_in(&dir);
        let first = SystemTime::now() - AGE;
        clocks.start(&KEY, first);
        assert_eq!(clocks.start(&KEY, SystemTime::now()), first);
    }

    #[test]
    fn a_wall_clock_set_back_shows_no_time_elapsed() {
        let now = SystemTime::now();
        assert_eq!(elapsed(now, now - AGE), Duration::ZERO);
        assert_eq!(elapsed(now - AGE, now), AGE);
    }

    #[tokio::test]
    async fn clocks_are_saved_only_when_they_changed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("clocks.bin");
        let clocks = clocks_in(&dir);

        clocks.save().await;
        assert!(!path.exists(), "nothing has changed yet");

        clocks.start(&KEY, SystemTime::now());
        clocks.save().await;
        assert!(path.exists());

        std::fs::remove_file(&path).expect("remove");
        clocks.start(&KEY, SystemTime::now());
        clocks.clear(&OTHER_KEY);
        clocks.retain(|_| true);
        clocks.save().await;
        assert!(!path.exists(), "none of those changed anything");

        clocks.clear(&KEY);
        clocks.save().await;
        assert!(path.exists(), "a stopped clock is a change");
    }

    #[tokio::test]
    async fn a_later_save_replaces_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let clocks = clocks_in(&dir);
        clocks.start(&KEY, SystemTime::now());
        clocks.save().await;
        clocks.clear(&KEY);
        clocks.start(&OTHER_KEY, SystemTime::now());
        clocks.save().await;

        let restored = clocks_in(&dir);
        assert!(restored.since(&KEY).is_none());
        assert!(restored.since(&OTHER_KEY).is_some());
    }

    #[test]
    fn a_missing_or_corrupt_file_gives_no_clocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(clocks_in(&dir).since(&KEY).is_none());

        std::fs::write(dir.path().join("clocks.bin"), [0xFF; 3]).expect("write");
        assert!(clocks_in(&dir).since(&KEY).is_none());
    }
}
