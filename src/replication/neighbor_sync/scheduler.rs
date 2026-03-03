//! Round-robin neighbor sync scheduler (Section 6.2 rules 1-3, 16-17).
//!
//! Manages the sync cycle: snapshots close neighbors, tracks cursor position,
//! handles cooldown and unreachable peer removal, and detects cycle completion.

use crate::client::XorName;
use crate::replication::params::{NEIGHBOR_SYNC_PEER_COUNT, NEIGHBOR_SYNC_SCOPE};
use crate::replication::routing;
use std::collections::HashMap;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Sync cycle state
// ---------------------------------------------------------------------------

/// Round-robin neighbor sync scheduler.
///
/// Manages the lifecycle of a sync cycle: snapshotting close neighbors,
/// advancing the cursor, removing peers on cooldown or unreachable, and
/// detecting cycle completion.
#[derive(Debug)]
pub struct SyncScheduler {
    /// Current snapshot of close neighbors in deterministic order.
    snapshot: Vec<(String, XorName)>,
    /// Current cursor position into the snapshot.
    cursor: usize,
    /// Per-peer last-successful-sync timestamp.
    last_synced: HashMap<String, Instant>,
    /// Cooldown duration for per-peer sync spacing.
    cooldown: std::time::Duration,
}

impl SyncScheduler {
    /// Create a new scheduler with a fresh snapshot from the routing view.
    #[must_use]
    pub fn new(
        self_xor: &XorName,
        local_rt: &[(String, XorName)],
        cooldown: std::time::Duration,
    ) -> Self {
        let snapshot = routing::close_neighbors(self_xor, local_rt, NEIGHBOR_SYNC_SCOPE);
        Self {
            snapshot,
            cursor: 0,
            last_synced: HashMap::new(),
            cooldown,
        }
    }

    /// Select the next batch of peers to sync with (Section 6.2 rule 2).
    ///
    /// Returns up to `NEIGHBOR_SYNC_PEER_COUNT` peers, skipping those
    /// on cooldown (removed from snapshot) and advancing the cursor.
    #[must_use]
    pub fn select_sync_set(&mut self) -> Vec<(String, XorName)> {
        let mut sync_set = Vec::new();
        let now = Instant::now();

        while sync_set.len() < NEIGHBOR_SYNC_PEER_COUNT && self.cursor < self.snapshot.len() {
            let (peer_id, peer_xor) = &self.snapshot[self.cursor];

            // Check cooldown (Section 6.2 rule 2a)
            if let Some(last) = self.last_synced.get(peer_id) {
                if now.duration_since(*last) < self.cooldown {
                    // Remove from snapshot and continue scanning
                    self.snapshot.remove(self.cursor);
                    continue;
                }
            }

            sync_set.push((peer_id.clone(), *peer_xor));
            self.cursor += 1;
        }

        sync_set
    }

    /// Mark a peer as successfully synced (updates cooldown timestamp).
    pub fn mark_synced(&mut self, peer_id: &str) {
        self.last_synced.insert(peer_id.to_string(), Instant::now());
    }

    /// Remove an unreachable peer from the snapshot (Section 6.2 rule 3).
    ///
    /// Returns `true` if the peer was found and removed.
    pub fn remove_peer(&mut self, peer_id: &str) -> bool {
        if let Some(pos) = self.snapshot.iter().position(|(id, _)| id == peer_id) {
            self.snapshot.remove(pos);
            // Adjust cursor if removal was before current position
            if pos < self.cursor {
                self.cursor = self.cursor.saturating_sub(1);
            }
            true
        } else {
            false
        }
    }

    /// Check if the current cycle is complete (Section 6.2 rule 17).
    #[must_use]
    pub fn is_cycle_complete(&self) -> bool {
        self.cursor >= self.snapshot.len()
    }

    /// Start a fresh cycle by re-snapshotting from current routing view.
    ///
    /// Resets the cursor to 0 and takes a new snapshot of close neighbors.
    pub fn new_cycle(&mut self, self_xor: &XorName, local_rt: &[(String, XorName)]) {
        self.snapshot = routing::close_neighbors(self_xor, local_rt, NEIGHBOR_SYNC_SCOPE);
        self.cursor = 0;
    }

    /// Current cursor position.
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Number of peers remaining in the current snapshot.
    #[must_use]
    pub fn snapshot_len(&self) -> usize {
        self.snapshot.len()
    }

    /// Number of peers remaining to scan (after cursor).
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.snapshot.len().saturating_sub(self.cursor)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
    fn test_scheduler_initial_snapshot() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(10);
        let cooldown = std::time::Duration::from_secs(3600);

        let scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);

        // Snapshot should contain up to NEIGHBOR_SYNC_SCOPE peers
        assert!(scheduler.snapshot_len() <= NEIGHBOR_SYNC_SCOPE);
        assert!(!scheduler.is_cycle_complete());
        assert_eq!(scheduler.cursor(), 0);
    }

    #[test]
    fn test_select_sync_set_respects_count() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(20);
        let cooldown = std::time::Duration::from_secs(3600);

        let mut scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);
        let batch = scheduler.select_sync_set();

        assert_eq!(batch.len(), NEIGHBOR_SYNC_PEER_COUNT);
        assert_eq!(scheduler.cursor(), NEIGHBOR_SYNC_PEER_COUNT);
    }

    #[test]
    fn test_select_sync_set_small_network() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(2);
        let cooldown = std::time::Duration::from_secs(3600);

        let mut scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);
        let batch = scheduler.select_sync_set();

        // Only 2 peers available, less than NEIGHBOR_SYNC_PEER_COUNT
        assert_eq!(batch.len(), 2);
        assert!(scheduler.is_cycle_complete());
    }

    #[test]
    fn test_remove_unreachable_peer() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(10);
        let cooldown = std::time::Duration::from_secs(3600);

        let mut scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);
        let initial_len = scheduler.snapshot_len();

        // Remove a peer from the snapshot
        let removed = scheduler.remove_peer("peer_0");
        assert!(removed);
        assert_eq!(scheduler.snapshot_len(), initial_len - 1);

        // Removing again returns false
        let removed_again = scheduler.remove_peer("peer_0");
        assert!(!removed_again);
    }

    #[test]
    fn test_remove_peer_adjusts_cursor() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(10);
        let cooldown = std::time::Duration::from_secs(3600);

        let mut scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);

        // Advance cursor by selecting a batch
        let batch = scheduler.select_sync_set();
        let cursor_before = scheduler.cursor();
        assert!(!batch.is_empty());

        // Remove a peer before the cursor
        if let Some((peer_id, _)) = batch.first() {
            scheduler.remove_peer(peer_id);
            // Cursor should decrease by 1
            assert_eq!(scheduler.cursor(), cursor_before - 1);
        }
    }

    #[test]
    fn test_cycle_complete_detection() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(5);
        let cooldown = std::time::Duration::from_secs(3600);

        let mut scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);

        // Select batches until cycle completes
        while !scheduler.is_cycle_complete() {
            let batch = scheduler.select_sync_set();
            if batch.is_empty() {
                break;
            }
        }

        assert!(scheduler.is_cycle_complete());
    }

    #[test]
    fn test_new_cycle_resets() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(5);
        let cooldown = std::time::Duration::from_secs(3600);

        let mut scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);

        // Complete the first cycle
        while !scheduler.is_cycle_complete() {
            let batch = scheduler.select_sync_set();
            if batch.is_empty() {
                break;
            }
        }

        // Start a new cycle
        scheduler.new_cycle(&self_xor, &local_rt);
        assert_eq!(scheduler.cursor(), 0);
        assert!(!scheduler.is_cycle_complete());
    }

    #[test]
    fn test_cooldown_skips_peer() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(10);
        // Very long cooldown so all synced peers are skipped
        let cooldown = std::time::Duration::from_secs(999_999);

        let mut scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);

        // Select first batch and mark all as synced
        let batch = scheduler.select_sync_set();
        for (peer_id, _) in &batch {
            scheduler.mark_synced(peer_id);
        }

        // Start a new cycle — the synced peers should be skipped
        scheduler.new_cycle(&self_xor, &local_rt);
        let initial_len = scheduler.snapshot_len();
        let batch2 = scheduler.select_sync_set();

        // Cooldown peers are removed from snapshot during selection
        assert!(scheduler.snapshot_len() < initial_len);
        // batch2 should not contain any of the previously synced peers
        let synced_ids: std::collections::HashSet<&str> =
            batch.iter().map(|(id, _)| id.as_str()).collect();
        for (peer_id, _) in &batch2 {
            assert!(!synced_ids.contains(peer_id.as_str()));
        }
    }

    #[test]
    fn test_remaining_decreases() {
        let self_xor = [0x00; 32];
        let local_rt = make_local_rt(10);
        let cooldown = std::time::Duration::from_secs(3600);

        let mut scheduler = SyncScheduler::new(&self_xor, &local_rt, cooldown);
        let initial_remaining = scheduler.remaining();
        assert!(initial_remaining > 0);

        let _ = scheduler.select_sync_set();
        assert!(scheduler.remaining() < initial_remaining);
    }
}
