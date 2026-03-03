//! Prune tracking with time-based hysteresis (Section 11).
//!
//! Tracks when keys first go out of responsible range and only prunes
//! them after `PRUNE_HYSTERESIS_DURATION` of continuous out-of-range status.

use crate::client::XorName;
use crate::error::Result;
use crate::replication::persistence;
use crate::replication::routing;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::debug;

/// File name for persisted prune state.
const PRUNE_STATE_FILENAME: &str = "prune_state.bin";

/// Tracks out-of-range timestamps for stored records.
///
/// `RecordOutOfRangeFirstSeen(N, K)`: per-key timestamp recording when key `K`
/// was first continuously observed as out of storage-responsibility range.
#[derive(Debug, Default)]
pub struct RecordPruneTracker {
    /// Key → first time continuously out of range.
    timestamps: HashMap<XorName, SystemTime>,
}

/// Tracks out-of-range timestamps for paid-list entries.
///
/// `PaidOutOfRangeFirstSeen(N, K)`: independent of record prune tracking.
#[derive(Debug, Default)]
pub struct PaidPruneTracker {
    /// Key → first time continuously out of range for paid-list.
    timestamps: HashMap<XorName, SystemTime>,
}

/// Combined prune state for both record and paid-list tracking.
#[derive(Debug, Default)]
pub struct PruneTracker {
    /// Record out-of-range tracking.
    pub records: RecordPruneTracker,
    /// Paid-list out-of-range tracking (independent).
    pub paid: PaidPruneTracker,
    /// Path for persistence.
    path: Option<PathBuf>,
}

/// Serializable persistence format.
#[derive(Serialize, Deserialize)]
struct PruneStateData {
    record_timestamps: Vec<(XorName, u64)>,
    paid_timestamps: Vec<(XorName, u64)>,
}

impl RecordPruneTracker {
    /// Mark a key as out of range. Records the current time if not already tracked.
    pub fn mark_out_of_range(&mut self, key: XorName) {
        self.timestamps.entry(key).or_insert_with(SystemTime::now);
    }

    /// Clear the out-of-range timestamp (key is back in range).
    pub fn clear_in_range(&mut self, key: &XorName) {
        self.timestamps.remove(key);
    }

    /// Check if a key should be pruned (out of range for >= hysteresis duration).
    #[must_use]
    pub fn should_prune(&self, key: &XorName, hysteresis: Duration) -> bool {
        self.timestamps
            .get(key)
            .is_some_and(|first_seen| first_seen.elapsed().unwrap_or(Duration::ZERO) >= hysteresis)
    }

    /// Check if a key is currently tracked as out of range.
    #[must_use]
    pub fn is_tracked(&self, key: &XorName) -> bool {
        self.timestamps.contains_key(key)
    }
}

impl PaidPruneTracker {
    /// Mark a key as out of paid-list range.
    pub fn mark_out_of_range(&mut self, key: XorName) {
        self.timestamps.entry(key).or_insert_with(SystemTime::now);
    }

    /// Clear the out-of-range timestamp (self re-entered `PaidCloseGroup`).
    pub fn clear_in_range(&mut self, key: &XorName) {
        self.timestamps.remove(key);
    }

    /// Check if a paid-list entry should be pruned.
    #[must_use]
    pub fn should_prune(&self, key: &XorName, hysteresis: Duration) -> bool {
        self.timestamps
            .get(key)
            .is_some_and(|first_seen| first_seen.elapsed().unwrap_or(Duration::ZERO) >= hysteresis)
    }

    /// Check if a key is currently tracked as out of range.
    #[must_use]
    pub fn is_tracked(&self, key: &XorName) -> bool {
        self.timestamps.contains_key(key)
    }
}

impl PruneTracker {
    /// Load from disk or create fresh.
    ///
    /// # Errors
    ///
    /// Returns an error only if the directory cannot be created.
    pub fn load(root_dir: &Path) -> Result<Self> {
        let replication_dir = root_dir.join("replication");
        std::fs::create_dir_all(&replication_dir).map_err(|e| {
            crate::Error::Replication(format!("failed to create replication directory: {e}"))
        })?;

        let path = replication_dir.join(PRUNE_STATE_FILENAME);

        let mut tracker = Self {
            records: RecordPruneTracker::default(),
            paid: PaidPruneTracker::default(),
            path: Some(path.clone()),
        };

        if let Some(data) = persistence::safe_load::<PruneStateData>(&path) {
            for (key, secs) in data.record_timestamps {
                if let Some(time) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs)) {
                    tracker.records.timestamps.insert(key, time);
                }
            }
            for (key, secs) in data.paid_timestamps {
                if let Some(time) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs)) {
                    tracker.paid.timestamps.insert(key, time);
                }
            }
            debug!(
                "Loaded PruneTracker: {} record timestamps, {} paid timestamps",
                tracker.records.timestamps.len(),
                tracker.paid.timestamps.len()
            );
        }

        Ok(tracker)
    }

    /// Persist current state to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn flush(&self) -> Result<()> {
        let Some(ref path) = self.path else {
            return Ok(());
        };

        let data = PruneStateData {
            record_timestamps: self
                .records
                .timestamps
                .iter()
                .filter_map(|(k, t)| {
                    t.duration_since(SystemTime::UNIX_EPOCH)
                        .ok()
                        .map(|d| (*k, d.as_secs()))
                })
                .collect(),
            paid_timestamps: self
                .paid
                .timestamps
                .iter()
                .filter_map(|(k, t)| {
                    t.duration_since(SystemTime::UNIX_EPOCH)
                        .ok()
                        .map(|d| (*k, d.as_secs()))
                })
                .collect(),
        };

        persistence::atomic_write(path, &data)
    }
}

// ---------------------------------------------------------------------------
// Post-cycle prune pass (Section 11)
// ---------------------------------------------------------------------------

/// Result of a post-cycle prune pass.
#[derive(Debug, Clone, Default)]
pub struct PrunePassResult {
    /// Record keys eligible for deletion (past hysteresis).
    pub records_to_delete: Vec<XorName>,
    /// Paid-list keys eligible for removal (past hysteresis).
    pub paid_to_remove: Vec<XorName>,
    /// Number of record keys newly marked as out of range.
    pub records_newly_out_of_range: usize,
    /// Number of record keys cleared (back in range).
    pub records_cleared: usize,
    /// Number of paid keys newly marked as out of range.
    pub paid_newly_out_of_range: usize,
    /// Number of paid keys cleared (back in range).
    pub paid_cleared: usize,
}

/// Run a post-cycle prune pass (Section 11, triggered by `NeighborSyncCycleComplete`).
///
/// For each stored key, checks whether the node is still responsible. For each
/// paid-list key, checks whether the node is still in `PaidCloseGroup(K)`.
/// Updates the `PruneTracker` timestamps and returns keys eligible for deletion.
///
/// This is a local-state-only operation and does not require network lookups.
#[must_use]
pub fn run_prune_pass(
    self_id: &str,
    self_xor: &XorName,
    local_rt: &[(String, XorName)],
    stored_keys: &[XorName],
    paid_keys: &[XorName],
    tracker: &mut PruneTracker,
    hysteresis: Duration,
) -> PrunePassResult {
    let mut result = PrunePassResult::default();

    // Step 1: Check each stored record key (Section 11, step 1)
    for key in stored_keys {
        if routing::is_responsible(self_id, self_xor, key, local_rt) {
            // In range: clear any out-of-range timestamp
            if tracker.records.is_tracked(key) {
                tracker.records.clear_in_range(key);
                result.records_cleared += 1;
            }
        } else {
            // Out of range: mark if not already tracked
            if !tracker.records.is_tracked(key) {
                tracker.records.mark_out_of_range(*key);
                result.records_newly_out_of_range += 1;
            }
            // Check if past hysteresis → eligible for deletion
            if tracker.records.should_prune(key, hysteresis) {
                result.records_to_delete.push(*key);
            }
        }
    }

    // Step 2: Check each paid-list key (Section 11, step 2)
    for key in paid_keys {
        if routing::is_in_paid_close_group(self_id, self_xor, key, local_rt) {
            // In range: clear any out-of-range timestamp
            if tracker.paid.is_tracked(key) {
                tracker.paid.clear_in_range(key);
                result.paid_cleared += 1;
            }
        } else {
            // Out of range: mark if not already tracked
            if !tracker.paid.is_tracked(key) {
                tracker.paid.mark_out_of_range(*key);
                result.paid_newly_out_of_range += 1;
            }
            // Check if past hysteresis → eligible for removal
            if tracker.paid.should_prune(key, hysteresis) {
                result.paid_to_remove.push(*key);
            }
        }
    }

    // Step 3: Clean up tracker entries for keys marked for deletion.
    // This prevents unbounded memory growth from orphaned timestamps
    // when the caller deletes the returned keys.
    for key in &result.records_to_delete {
        tracker.records.clear_in_range(key);
    }
    for key in &result.paid_to_remove {
        tracker.paid.clear_in_range(key);
    }

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_record_prune_lifecycle() {
        let mut tracker = RecordPruneTracker::default();
        let key = [0xAA; 32];
        let hysteresis = Duration::from_secs(100);

        // Not tracked initially
        assert!(!tracker.is_tracked(&key));
        assert!(!tracker.should_prune(&key, hysteresis));

        // Mark out of range
        tracker.mark_out_of_range(key);
        assert!(tracker.is_tracked(&key));
        // Not enough time has passed
        assert!(!tracker.should_prune(&key, hysteresis));

        // Back in range clears timestamp
        tracker.clear_in_range(&key);
        assert!(!tracker.is_tracked(&key));
    }

    #[test]
    fn test_record_prune_with_zero_hysteresis() {
        let mut tracker = RecordPruneTracker::default();
        let key = [0xBB; 32];

        tracker.mark_out_of_range(key);
        // Zero hysteresis means immediate prune eligibility
        assert!(tracker.should_prune(&key, Duration::ZERO));
    }

    #[test]
    fn test_paid_prune_independent() {
        let mut records = RecordPruneTracker::default();
        let mut paid = PaidPruneTracker::default();
        let key = [0xCC; 32];

        // Mark only in records, not in paid
        records.mark_out_of_range(key);
        assert!(records.is_tracked(&key));
        assert!(!paid.is_tracked(&key));

        // Clear records, mark paid
        records.clear_in_range(&key);
        paid.mark_out_of_range(key);
        assert!(!records.is_tracked(&key));
        assert!(paid.is_tracked(&key));
    }

    #[test]
    fn test_prune_tracker_persistence() {
        let dir = TempDir::new().expect("create temp dir");
        let key1 = [0x01; 32];
        let key2 = [0x02; 32];

        // Write
        {
            let mut tracker = PruneTracker::load(dir.path()).expect("load");
            tracker.records.mark_out_of_range(key1);
            tracker.paid.mark_out_of_range(key2);
            tracker.flush().expect("flush");
        }

        // Read back
        {
            let tracker = PruneTracker::load(dir.path()).expect("reload");
            assert!(tracker.records.is_tracked(&key1));
            assert!(!tracker.records.is_tracked(&key2));
            assert!(!tracker.paid.is_tracked(&key1));
            assert!(tracker.paid.is_tracked(&key2));
        }
    }

    #[test]
    fn test_mark_idempotent() {
        let mut tracker = RecordPruneTracker::default();
        let key = [0xDD; 32];

        tracker.mark_out_of_range(key);
        let first_time = tracker.timestamps[&key];

        // Marking again should not update the timestamp
        tracker.mark_out_of_range(key);
        assert_eq!(tracker.timestamps[&key], first_time);
    }

    // -----------------------------------------------------------------------
    // Prune pass tests
    // -----------------------------------------------------------------------

    fn make_local_rt(n: usize) -> Vec<(String, XorName)> {
        (0..n)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let byte = (i + 1) as u8;
                let mut xor = [0x00; 32];
                xor[0] = byte;
                (format!("peer_{i}"), xor)
            })
            .collect()
    }

    #[test]
    fn test_prune_pass_in_range_keys_not_marked() {
        let self_id = "self";
        let self_xor = [0x01; 32]; // very close to key [0x00; 32]
        let local_rt = make_local_rt(5);
        let key = [0x00; 32]; // self is responsible for this key
        let mut tracker = PruneTracker::default();

        let result = run_prune_pass(
            self_id,
            &self_xor,
            &local_rt,
            &[key],
            &[],
            &mut tracker,
            Duration::from_secs(3600),
        );

        assert!(result.records_to_delete.is_empty());
        assert_eq!(result.records_newly_out_of_range, 0);
        assert!(!tracker.records.is_tracked(&key));
    }

    #[test]
    fn test_prune_pass_out_of_range_marked() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from key — not responsible
        let local_rt = make_local_rt(10);
        let key = [0x00; 32];
        let mut tracker = PruneTracker::default();

        let result = run_prune_pass(
            self_id,
            &self_xor,
            &local_rt,
            &[key],
            &[],
            &mut tracker,
            Duration::from_secs(3600),
        );

        // Key should be newly marked out of range, but not yet eligible
        assert_eq!(result.records_newly_out_of_range, 1);
        assert!(result.records_to_delete.is_empty());
        assert!(tracker.records.is_tracked(&key));
    }

    #[test]
    fn test_prune_pass_zero_hysteresis_immediate_delete() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from key
        let local_rt = make_local_rt(10);
        let key = [0x00; 32];
        let mut tracker = PruneTracker::default();

        // First pass: marks out of range
        let _ = run_prune_pass(
            self_id,
            &self_xor,
            &local_rt,
            &[key],
            &[],
            &mut tracker,
            Duration::ZERO,
        );

        // Second pass with zero hysteresis: should be eligible immediately
        let result = run_prune_pass(
            self_id,
            &self_xor,
            &local_rt,
            &[key],
            &[],
            &mut tracker,
            Duration::ZERO,
        );

        assert!(result.records_to_delete.contains(&key));
    }

    #[test]
    fn test_prune_pass_clears_when_back_in_range() {
        let self_id = "self";
        let self_xor_far = [0xFF; 32]; // far from key
        let self_xor_close = [0x01; 32]; // close to key
                                         // Need enough peers to push self out of CLOSE_GROUP_SIZE when far
        let local_rt = make_local_rt(10);
        let key = [0x00; 32];
        let mut tracker = PruneTracker::default();

        // Pass 1: out of range (self is far, plenty of closer peers)
        let r1 = run_prune_pass(
            self_id,
            &self_xor_far,
            &local_rt,
            &[key],
            &[],
            &mut tracker,
            Duration::from_secs(3600),
        );
        assert_eq!(r1.records_newly_out_of_range, 1);
        assert!(tracker.records.is_tracked(&key));

        // Pass 2: back in range (self moved closer, now among nearest)
        let r2 = run_prune_pass(
            self_id,
            &self_xor_close,
            &local_rt,
            &[key],
            &[],
            &mut tracker,
            Duration::from_secs(3600),
        );
        assert_eq!(r2.records_cleared, 1);
        assert!(!tracker.records.is_tracked(&key));
    }

    #[test]
    fn test_prune_pass_paid_keys() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from key — not in PaidCloseGroup
        let local_rt = make_local_rt(25); // Many peers closer than self
        let key = [0x00; 32];
        let mut tracker = PruneTracker::default();

        let result = run_prune_pass(
            self_id,
            &self_xor,
            &local_rt,
            &[],
            &[key],
            &mut tracker,
            Duration::from_secs(3600),
        );

        assert_eq!(result.paid_newly_out_of_range, 1);
        assert!(result.paid_to_remove.is_empty()); // Not past hysteresis yet
        assert!(tracker.paid.is_tracked(&key));
    }

    #[test]
    fn test_prune_pass_paid_in_range() {
        let self_id = "self";
        let self_xor = [0x01; 32]; // close to key
        let local_rt = make_local_rt(5); // Small network — self in PaidCloseGroup
        let key = [0x00; 32];
        let mut tracker = PruneTracker::default();

        let result = run_prune_pass(
            self_id,
            &self_xor,
            &local_rt,
            &[],
            &[key],
            &mut tracker,
            Duration::from_secs(3600),
        );

        assert_eq!(result.paid_newly_out_of_range, 0);
        assert!(result.paid_to_remove.is_empty());
        assert!(!tracker.paid.is_tracked(&key));
    }

    #[test]
    fn test_prune_pass_cleans_up_deleted_entries() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from key
        let local_rt = make_local_rt(10);
        let key = [0x00; 32];
        let mut tracker = PruneTracker::default();

        // Mark the key out of range manually so we control the timestamp
        tracker.records.mark_out_of_range(key);
        assert!(tracker.records.is_tracked(&key));

        // Run prune pass with zero hysteresis → eligible for deletion
        let result = run_prune_pass(
            self_id,
            &self_xor,
            &local_rt,
            &[key],
            &[],
            &mut tracker,
            Duration::ZERO,
        );
        assert!(result.records_to_delete.contains(&key));
        // Tracker entry should be cleaned up to prevent unbounded growth
        assert!(!tracker.records.is_tracked(&key));
    }
}
