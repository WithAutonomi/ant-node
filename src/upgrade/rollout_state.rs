//! When this node first saw the release it is waiting to install, kept across restarts.
//!
//! A staged rollout spreads a release over a window so the fleet does not restart at once.
//! The delay is measured from the moment a node first sees the new version, and that moment
//! used to live only in memory: a node that restarted before its delay ran out started the
//! window again from zero. A node that restarts often enough never reaches the end of it,
//! and quietly stays on an old release for as long as it keeps restarting. That is the
//! difference between "the fleet had two weeks" and "the fleet had two weeks unless it
//! restarted", and only the first of those is something a later release can rely on.
//!
//! So the moment is written down. Deliberately small: one target, one timestamp, no history.
//!
//! Every failure here means "upgrade now" rather than "wait". A node that cannot record when
//! it started waiting has no way to prove it ever finished waiting, and the failure that
//! matters is the one that leaves a node behind, not the one that lets it upgrade a few hours
//! early with its share of the fleet.

use std::path::{Path, PathBuf};

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::logging::{debug, warn};

/// The file this lives in, under the node's own root.
///
/// Not the shared upgrade cache: that is keyed by machine and shared by every node on it,
/// and this is one node's place in one window.
const FILE: &str = "upgrade-rollout.json";

/// Bumped if the shape changes. An older or newer shape is treated as no record at all,
/// which means the node upgrades rather than waits.
const SCHEMA: u32 = 1;

/// A clock that has jumped further ahead than this makes the record meaningless.
///
/// Believing a stamp from the future would have a node wait out a delay that never elapses.
/// Rewriting it costs at most one node upgrading on a fresh window.
const IMPLAUSIBLE_FUTURE_SECS: u64 = 24 * 3600;

/// What was written down.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stamp {
    /// Shape of this record.
    schema: u32,
    /// The release being waited for.
    version: String,
    /// When this node first saw it, in Unix seconds.
    first_seen_unix: u64,
    /// The window in force when it was written, so a changed window is visible rather than
    /// silently reinterpreting an old stamp.
    window_hours: u64,
}

/// This node's place in the current rollout window.
#[derive(Debug, Clone)]
pub struct RolloutState {
    path: PathBuf,
}

impl RolloutState {
    /// Keep the record under this node's root directory.
    #[must_use]
    pub fn new(root_dir: &Path) -> Self {
        Self {
            path: root_dir.join(FILE),
        }
    }

    /// When this node first saw `version`, recording it if this is the first time.
    ///
    /// `None` means the answer could not be established, and the caller must read that as
    /// "the delay has elapsed". Waiting on an answer that cannot be written down is how a
    /// node waits forever.
    #[must_use]
    pub fn first_seen(&self, version: &Version, window_hours: u64) -> Option<u64> {
        let now = now_unix()?;
        match self.read() {
            Record::Stamped(stamp) => {
                if stamp.version == version.to_string() && stamp.window_hours == window_hours {
                    if stamp.first_seen_unix <= now.saturating_add(IMPLAUSIBLE_FUTURE_SECS) {
                        return Some(stamp.first_seen_unix.min(now));
                    }
                    warn!(
                        "Upgrade rollout: the recorded time for {version} is implausibly far \
                         in the future, so it cannot be used to measure a wait. Upgrading \
                         without waiting out this node's share of the window."
                    );
                    return None;
                }
            }
            // Nothing written down yet, which is the ordinary first sighting of a release.
            Record::Absent => {}
            // Something is at that name and it is not a record this build can read. Not
            // replaced with a fresh one: writing "now" over it restarts the window, and a
            // node whose disk keeps producing unreadable files would restart it on every
            // boot and never upgrade at all. Answering "no record" upgrades this node once
            // and is done with it.
            Record::Unreadable => {
                warn!(
                    "Upgrade rollout: {} cannot be read, so this node cannot tell when it \
                     began waiting for {version}. Upgrading without waiting out its share \
                     of the window.",
                    self.path.display()
                );
                return None;
            }
        }
        self.write(&Stamp {
            schema: SCHEMA,
            version: version.to_string(),
            first_seen_unix: now,
            window_hours,
        })?;
        Some(now)
    }

    /// Read the record.
    fn read(&self) -> Record {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Record::Absent,
            Err(_) => return Record::Unreadable,
        };
        let Ok(stamp) = serde_json::from_slice::<Stamp>(&bytes) else {
            return Record::Unreadable;
        };
        if stamp.schema == SCHEMA {
            Record::Stamped(stamp)
        } else {
            debug!(
                "Upgrade rollout: {} is schema {}, not {SCHEMA}; treating it as no record",
                self.path.display(),
                stamp.schema
            );
            Record::Unreadable
        }
    }

    /// Write the record, atomically and durably, or say it could not be written.
    ///
    /// Flushed rather than just written. The whole point is to survive a restart, and the
    /// restart most likely to lose an unflushed file is the abrupt kind this is measuring
    /// across.
    fn write(&self, stamp: &Stamp) -> Option<()> {
        let encoded = serde_json::to_vec(stamp).ok()?;
        let temp = self.path.with_extension("json.tmp");
        write_and_flush(&temp, &encoded)
            .and_then(|()| std::fs::rename(&temp, &self.path))
            .and_then(|()| flush_dir(self.path.parent().unwrap_or(&self.path)))
            .map_err(|e| {
                warn!(
                    "Upgrade rollout: could not record when this node first saw {}: {e}. It \
                     will upgrade without waiting out its share of the window rather than \
                     wait for a deadline it cannot remember.",
                    stamp.version
                );
                // A failed rename can leave the temporary file behind. Nothing reads it, but
                // leaving one per attempt in a node's root is untidy.
                let _ = std::fs::remove_file(&temp);
            })
            .ok()
    }
}

/// What is at the record's name.
enum Record {
    /// A record this build understands.
    Stamped(Stamp),
    /// Nothing, which is the ordinary first sighting of a release.
    Absent,
    /// Something that is not a record this build can read. Never quietly replaced: writing
    /// a fresh one restarts the window, and a disk that keeps producing unreadable files
    /// would restart it on every boot.
    Unreadable,
}

/// Write a file and flush it, so it is there after a power loss and not merely after a
/// clean shutdown.
fn write_and_flush(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Flush a directory, so the entry naming a file is durable too.
fn flush_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    // Off Unix a directory cannot be opened for this, and the rename is the platform's own
    // business. Not an error: the alternative is refusing to record anything at all.
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Now, in Unix seconds.
fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn version(v: &str) -> Version {
        Version::parse(v).unwrap()
    }

    #[test]
    fn the_window_survives_a_restart() {
        // The whole point. Asking twice, as two runs of the same node would, has to give the
        // same answer, or a node that restarts often never reaches the end of any window.
        let dir = TempDir::new().unwrap();
        let state = RolloutState::new(dir.path());
        let first = state.first_seen(&version("0.17.2"), 24).unwrap();

        let after_restart = RolloutState::new(dir.path());
        let second = after_restart.first_seen(&version("0.17.2"), 24).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn a_different_release_starts_a_new_window() {
        let dir = TempDir::new().unwrap();
        let state = RolloutState::new(dir.path());
        state.first_seen(&version("0.17.2"), 24).unwrap();

        // Written down as the new target, not silently answered from the old record.
        state.first_seen(&version("0.18.0"), 24).unwrap();
        let Record::Stamped(stamp) = state.read() else {
            panic!("the new target must have been written down")
        };
        assert_eq!(stamp.version, "0.18.0");
    }

    #[test]
    fn a_changed_window_starts_a_new_one_too() {
        // A stamp says when the wait began; the window says how long it is. Reusing a stamp
        // written under a different window silently reinterprets it.
        let dir = TempDir::new().unwrap();
        let state = RolloutState::new(dir.path());
        state.first_seen(&version("0.17.2"), 24).unwrap();
        state.first_seen(&version("0.17.2"), 1).unwrap();
        let Record::Stamped(stamp) = state.read() else {
            panic!("the new window must have been written down")
        };
        assert_eq!(stamp.window_hours, 1);
    }

    #[test]
    fn a_record_that_cannot_be_written_means_upgrade_rather_than_wait() {
        // A node that cannot record when it started waiting cannot prove it ever finished.
        // Upgrading early with its share of the fleet is the cheaper failure by far.
        let dir = TempDir::new().unwrap();
        let unwritable = dir.path().join("no").join("such").join("directory");
        let state = RolloutState::new(&unwritable);
        assert_eq!(state.first_seen(&version("0.17.2"), 24), None);
    }

    #[test]
    fn a_corrupt_record_means_upgrade_rather_than_a_fresh_window() {
        // Not replaced with a stamp of "now". That restarts the window, and a node whose
        // disk keeps producing unreadable files would restart it on every boot and never
        // upgrade at all. Answering "no record" upgrades this node once and is done.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(FILE), b"not json").unwrap();
        let state = RolloutState::new(dir.path());
        assert_eq!(state.first_seen(&version("0.17.2"), 24), None);
    }

    #[test]
    fn a_stamp_from_the_future_does_not_make_the_wait_endless() {
        // A clock that jumped forward and back would otherwise leave a node waiting out a
        // delay measured from a moment that has not happened yet.
        let dir = TempDir::new().unwrap();
        let state = RolloutState::new(dir.path());
        let now = now_unix().unwrap();
        state
            .write(&Stamp {
                schema: SCHEMA,
                version: "0.17.2".into(),
                first_seen_unix: now + 10 * IMPLAUSIBLE_FUTURE_SECS,
                window_hours: 24,
            })
            .unwrap();

        assert_eq!(state.first_seen(&version("0.17.2"), 24), None);
    }

    #[test]
    fn a_stamp_from_an_older_shape_means_upgrade_too() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(FILE),
            br#"{"schema":0,"version":"0.1.0","first_seen_unix":1,"window_hours":24}"#,
        )
        .unwrap();
        let state = RolloutState::new(dir.path());
        assert_eq!(state.first_seen(&version("0.17.2"), 24), None);
    }
}
