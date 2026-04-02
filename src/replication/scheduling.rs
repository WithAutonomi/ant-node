//! Scheduling and queue management (Section 12).
//!
//! Manages `PendingVerify`, `FetchQueue`, and `InFlightFetch` queues for the
//! replication pipeline. Each key progresses through at most one queue at a
//! time, with strict dedup across all three stages.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use tracing::debug;

use crate::ant_protocol::XorName;
use crate::replication::types::{FetchCandidate, VerificationEntry};
use saorsa_core::identity::PeerId;

// ---------------------------------------------------------------------------
// In-flight entry
// ---------------------------------------------------------------------------

/// An in-flight fetch entry tracking an active download.
#[derive(Debug, Clone)]
pub struct InFlightEntry {
    /// The key being fetched.
    pub key: XorName,
    /// The peer we are currently fetching from.
    pub source: PeerId,
    /// When the fetch started.
    pub started_at: Instant,
    /// All verified sources for this key.
    pub all_sources: Vec<PeerId>,
    /// Sources already attempted (failed or in progress).
    pub tried: HashSet<PeerId>,
}

// ---------------------------------------------------------------------------
// Central queue manager
// ---------------------------------------------------------------------------

/// Central queue manager for the replication pipeline.
///
/// Maintains three stages of the pipeline with global dedup:
/// 1. **`PendingVerify`** -- keys awaiting quorum verification.
/// 2. **`FetchQueue`** -- quorum-passed keys waiting for a fetch slot.
/// 3. **`InFlightFetch`** -- keys actively being downloaded.
pub struct ReplicationQueues {
    /// Keys awaiting quorum result (dedup by key).
    // TODO: Add capacity bound to prevent unbounded growth under network flood.
    // Consider evicting farthest-distance entries when at capacity.
    pending_verify: HashMap<XorName, VerificationEntry>,
    /// Presence-quorum-passed or paid-list-authorized keys waiting for fetch.
    // TODO: Add capacity bound (e.g. MAX_FETCH_QUEUE_SIZE) to prevent
    // unbounded growth. Reject or evict farthest-distance candidates when full.
    fetch_queue: BinaryHeap<FetchCandidate>,
    /// Keys present in `fetch_queue` for O(1) dedup.
    fetch_queue_keys: HashSet<XorName>,
    /// Active downloads keyed by `XorName`.
    in_flight_fetch: HashMap<XorName, InFlightEntry>,
}

impl Default for ReplicationQueues {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicationQueues {
    /// Create new empty queues.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_verify: HashMap::new(),
            fetch_queue: BinaryHeap::new(),
            fetch_queue_keys: HashSet::new(),
            in_flight_fetch: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // PendingVerify
    // -----------------------------------------------------------------------

    /// Add a key to pending verification if not already present in any queue.
    ///
    /// Returns `true` if the key was newly added (Rule 8: cross-queue dedup).
    pub fn add_pending_verify(&mut self, key: XorName, entry: VerificationEntry) -> bool {
        if self.contains_key(&key) {
            return false;
        }
        self.pending_verify.insert(key, entry);
        true
    }

    /// Get a reference to a pending verification entry.
    #[must_use]
    pub fn get_pending(&self, key: &XorName) -> Option<&VerificationEntry> {
        self.pending_verify.get(key)
    }

    /// Get a mutable reference to a pending verification entry.
    pub fn get_pending_mut(&mut self, key: &XorName) -> Option<&mut VerificationEntry> {
        self.pending_verify.get_mut(key)
    }

    /// Remove a key from pending verification.
    pub fn remove_pending(&mut self, key: &XorName) -> Option<VerificationEntry> {
        self.pending_verify.remove(key)
    }

    /// Collect all pending verification keys (for batch processing).
    #[must_use]
    pub fn pending_keys(&self) -> Vec<XorName> {
        self.pending_verify.keys().copied().collect()
    }

    /// Number of keys in pending verification.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_verify.len()
    }

    // -----------------------------------------------------------------------
    // FetchQueue
    // -----------------------------------------------------------------------

    /// Enqueue a key for fetch with its distance and verified sources.
    ///
    /// No-op if the key is already in any pipeline stage (Rule 8: cross-queue
    /// dedup).
    pub fn enqueue_fetch(&mut self, key: XorName, distance: XorName, sources: Vec<PeerId>) {
        if self.pending_verify.contains_key(&key)
            || self.fetch_queue_keys.contains(&key)
            || self.in_flight_fetch.contains_key(&key)
        {
            return;
        }
        self.fetch_queue_keys.insert(key);
        self.fetch_queue.push(FetchCandidate {
            key,
            distance,
            sources,
        });
    }

    /// Dequeue the nearest fetch candidate.
    ///
    /// Returns `None` when the queue is empty.  Silently skips candidates
    /// that are somehow already in-flight.  Concurrency is enforced by the
    /// fetch worker, not by this method.
    pub fn dequeue_fetch(&mut self) -> Option<FetchCandidate> {
        while let Some(candidate) = self.fetch_queue.pop() {
            self.fetch_queue_keys.remove(&candidate.key);
            if !self.in_flight_fetch.contains_key(&candidate.key) {
                return Some(candidate);
            }
        }
        None
    }

    /// Number of keys waiting in the fetch queue.
    #[must_use]
    pub fn fetch_queue_count(&self) -> usize {
        self.fetch_queue.len()
    }

    // -----------------------------------------------------------------------
    // InFlightFetch
    // -----------------------------------------------------------------------

    /// Mark a key as in-flight (actively being fetched from `source`).
    pub fn start_fetch(&mut self, key: XorName, source: PeerId, all_sources: Vec<PeerId>) {
        let mut tried = HashSet::new();
        tried.insert(source);
        self.in_flight_fetch.insert(
            key,
            InFlightEntry {
                key,
                source,
                started_at: Instant::now(),
                all_sources,
                tried,
            },
        );
    }

    /// Mark a fetch as completed (success or permanent failure).
    pub fn complete_fetch(&mut self, key: &XorName) -> Option<InFlightEntry> {
        self.in_flight_fetch.remove(key)
    }

    /// Mark the current fetch attempt as failed and try the next untried source.
    ///
    /// Returns the next source peer if one is available, or `None` if all
    /// sources have been exhausted.
    pub fn retry_fetch(&mut self, key: &XorName) -> Option<PeerId> {
        let entry = self.in_flight_fetch.get_mut(key)?;
        entry.tried.insert(entry.source);

        let next = entry
            .all_sources
            .iter()
            .find(|p| !entry.tried.contains(p))
            .copied();

        if let Some(next_peer) = next {
            entry.source = next_peer;
            entry.tried.insert(next_peer);
            Some(next_peer)
        } else {
            None
        }
    }

    /// Number of in-flight fetches.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight_fetch.len()
    }

    // -----------------------------------------------------------------------
    // Cross-queue queries
    // -----------------------------------------------------------------------

    /// Check if a key is present in any pipeline stage.
    #[must_use]
    pub fn contains_key(&self, key: &XorName) -> bool {
        self.pending_verify.contains_key(key)
            || self.fetch_queue_keys.contains(key)
            || self.in_flight_fetch.contains_key(key)
    }

    /// Check if all bootstrap-related work is done.
    ///
    /// Returns `true` when none of the given bootstrap keys remain in any queue.
    #[must_use]
    pub fn is_bootstrap_work_empty(&self, bootstrap_keys: &HashSet<XorName>) -> bool {
        !bootstrap_keys.iter().any(|k| self.contains_key(k))
    }

    /// Evict stale pending-verification entries older than `max_age`.
    pub fn evict_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        let before = self.pending_verify.len();
        self.pending_verify
            .retain(|_, entry| now.duration_since(entry.created_at) < max_age);
        let evicted = before.saturating_sub(self.pending_verify.len());
        if evicted > 0 {
            debug!("Evicted {evicted} stale pending-verification entries");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::replication::types::{HintPipeline, VerificationState};

    /// Build a `PeerId` from a single byte (zero-padded to 32 bytes).
    fn peer_id_from_byte(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    /// Build an `XorName` from a single byte (repeated to 32 bytes).
    fn xor_name_from_byte(b: u8) -> XorName {
        [b; 32]
    }

    /// Create a minimal `VerificationEntry` for testing.
    fn test_entry(sender_byte: u8) -> VerificationEntry {
        VerificationEntry {
            state: VerificationState::PendingVerify,
            pipeline: HintPipeline::Replica,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            hint_sender: peer_id_from_byte(sender_byte),
        }
    }

    // -- add_pending_verify dedup ------------------------------------------

    #[test]
    fn add_pending_verify_new_key_succeeds() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        assert!(queues.add_pending_verify(key, test_entry(1)));
        assert_eq!(queues.pending_count(), 1);
    }

    #[test]
    fn add_pending_verify_duplicate_rejected() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        assert!(queues.add_pending_verify(key, test_entry(1)));
        assert!(!queues.add_pending_verify(key, test_entry(2)));
        assert_eq!(queues.pending_count(), 1);
    }

    #[test]
    fn add_pending_verify_rejected_if_in_fetch_queue() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x02);
        let distance = xor_name_from_byte(0x10);
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(1)]);

        assert!(
            !queues.add_pending_verify(key, test_entry(1)),
            "should reject key already in fetch queue"
        );
    }

    #[test]
    fn add_pending_verify_rejected_if_in_flight() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x03);
        let source = peer_id_from_byte(1);
        queues.start_fetch(key, source, vec![source]);

        assert!(
            !queues.add_pending_verify(key, test_entry(1)),
            "should reject key already in-flight"
        );
    }

    // -- enqueue/dequeue ordering -----------------------------------------

    #[test]
    fn dequeue_returns_nearest_first() {
        let mut queues = ReplicationQueues::new();

        let near_key = xor_name_from_byte(0x01);
        let far_key = xor_name_from_byte(0x02);
        let near_dist = [0x00; 32]; // nearest
        let far_dist = [0xFF; 32]; // farthest

        queues.enqueue_fetch(far_key, far_dist, vec![peer_id_from_byte(1)]);
        queues.enqueue_fetch(near_key, near_dist, vec![peer_id_from_byte(2)]);

        let first = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(first.key, near_key, "nearest key should dequeue first");

        let second = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(second.key, far_key, "farthest key should dequeue second");
    }

    #[test]
    fn enqueue_dedup_prevents_duplicates() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);

        queues.enqueue_fetch(key, [0x10; 32], vec![peer_id_from_byte(1)]);
        queues.enqueue_fetch(key, [0x10; 32], vec![peer_id_from_byte(2)]);

        assert_eq!(
            queues.fetch_queue_count(),
            1,
            "duplicate enqueue should be ignored"
        );
    }

    // -- in-flight tracking -----------------------------------------------

    #[test]
    fn start_and_complete_fetch() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        let source = peer_id_from_byte(1);

        queues.start_fetch(key, source, vec![source]);
        assert_eq!(queues.in_flight_count(), 1);

        let completed = queues.complete_fetch(&key);
        assert!(completed.is_some());
        assert_eq!(queues.in_flight_count(), 0);
    }

    #[test]
    fn complete_nonexistent_returns_none() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x99);
        assert!(queues.complete_fetch(&key).is_none());
    }

    // -- retry_fetch ------------------------------------------------------

    #[test]
    fn retry_fetch_returns_next_untried_source() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        let source_a = peer_id_from_byte(1);
        let source_b = peer_id_from_byte(2);
        let source_c = peer_id_from_byte(3);

        queues.start_fetch(key, source_a, vec![source_a, source_b, source_c]);

        // First retry: should skip source_a (already tried), return source_b.
        let next = queues.retry_fetch(&key);
        assert_eq!(next, Some(source_b));

        // Second retry: should return source_c.
        let next = queues.retry_fetch(&key);
        assert_eq!(next, Some(source_c));

        // Third retry: all exhausted.
        let next = queues.retry_fetch(&key);
        assert!(next.is_none(), "all sources exhausted");
    }

    #[test]
    fn retry_fetch_nonexistent_returns_none() {
        let mut queues = ReplicationQueues::new();
        assert!(queues.retry_fetch(&xor_name_from_byte(0xFF)).is_none());
    }

    // -- contains_key across pipelines ------------------------------------

    #[test]
    fn contains_key_in_pending() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_in_fetch_queue() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x02);
        queues.enqueue_fetch(key, [0x10; 32], vec![peer_id_from_byte(1)]);
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_in_flight() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x03);
        queues.start_fetch(key, peer_id_from_byte(1), vec![]);
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_absent() {
        let queues = ReplicationQueues::new();
        assert!(!queues.contains_key(&xor_name_from_byte(0xFF)));
    }

    // -- bootstrap work empty ---------------------------------------------

    #[test]
    fn bootstrap_work_empty_when_no_keys_present() {
        let queues = ReplicationQueues::new();
        let bootstrap_keys: HashSet<XorName> = [xor_name_from_byte(0x01), xor_name_from_byte(0x02)]
            .into_iter()
            .collect();
        assert!(queues.is_bootstrap_work_empty(&bootstrap_keys));
    }

    #[test]
    fn bootstrap_work_not_empty_when_key_in_pending() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        let bootstrap_keys: HashSet<XorName> = std::iter::once(key).collect();
        assert!(!queues.is_bootstrap_work_empty(&bootstrap_keys));
    }

    // -- evict_stale ------------------------------------------------------

    #[test]
    fn evict_stale_removes_old_entries() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);

        // Create entry with a backdated timestamp. Use a small subtraction
        // to avoid `checked_sub` returning `None` on freshly-booted CI runners.
        let mut entry = test_entry(1);
        entry.created_at = Instant::now()
            .checked_sub(Duration::from_secs(2))
            .unwrap_or_else(Instant::now);
        queues.pending_verify.insert(key, entry);

        assert_eq!(queues.pending_count(), 1);
        queues.evict_stale(Duration::from_secs(1));
        assert_eq!(
            queues.pending_count(),
            0,
            "entry older than max_age should be evicted"
        );
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        queues.evict_stale(Duration::from_secs(3600));
        assert_eq!(
            queues.pending_count(),
            1,
            "fresh entry should not be evicted"
        );
    }

    // -- remove_pending ---------------------------------------------------

    #[test]
    fn remove_pending_returns_entry() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        let removed = queues.remove_pending(&key);
        assert!(removed.is_some());
        assert_eq!(queues.pending_count(), 0);
    }

    #[test]
    fn remove_pending_nonexistent_returns_none() {
        let mut queues = ReplicationQueues::new();
        assert!(queues.remove_pending(&xor_name_from_byte(0xFF)).is_none());
    }

    // -----------------------------------------------------------------------
    // Section 18 scenarios
    // -----------------------------------------------------------------------

    /// Scenario 8: A key already in `PendingVerify` cannot be enqueued into
    /// `FetchQueue` (cross-queue dedup). Also, a key in `FetchQueue` cannot be
    /// re-added to `PendingVerify`.
    #[test]
    fn scenario_8_duplicate_key_not_double_queued() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xE0);
        let distance = xor_name_from_byte(0x10);

        // Step 1: Add to PendingVerify.
        assert!(
            queues.add_pending_verify(key, test_entry(1)),
            "first add to PendingVerify should succeed"
        );
        assert!(
            queues.contains_key(&key),
            "key should be present in pipeline"
        );

        // Step 2: Attempt to enqueue fetch while still in PendingVerify.
        // enqueue_fetch checks all three stages (pending_verify,
        // fetch_queue_keys, in_flight), so this is a no-op while the key
        // is still in PendingVerify.
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(2)]);
        // Verify the key is still tracked via the cross-stage check.
        assert!(queues.contains_key(&key), "key should still be in pipeline");

        // Step 3: Remove from PendingVerify, add to FetchQueue.
        queues.remove_pending(&key);
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(3)]);
        assert_eq!(queues.fetch_queue_count(), 1);

        // Step 4: Attempt to re-add to PendingVerify -> should fail.
        assert!(
            !queues.add_pending_verify(key, test_entry(4)),
            "key in FetchQueue should be rejected from PendingVerify"
        );

        // Step 5: Dequeue, start fetch -> key is in-flight.
        let candidate = queues.dequeue_fetch().expect("should dequeue");
        queues.start_fetch(
            candidate.key,
            candidate.sources[0],
            candidate.sources.clone(),
        );

        // Step 6: Attempt to add to PendingVerify while in-flight -> reject.
        assert!(
            !queues.add_pending_verify(key, test_entry(5)),
            "key in-flight should be rejected from PendingVerify"
        );

        // Step 7: Attempt to enqueue fetch while in-flight -> no-op.
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(6)]);
        // fetch_queue should still be empty (the enqueue was a no-op).
        assert_eq!(
            queues.fetch_queue_count(),
            0,
            "enqueue_fetch should be no-op for in-flight key"
        );
    }

    /// Scenario 8 (continued): Verify that pipeline field for a key
    /// admitted as both replica and paid hint collapses to Replica only,
    /// because cross-set precedence in admission gives replica priority.
    #[test]
    fn scenario_8_replica_and_paid_hint_collapses_to_replica() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xE1);

        // Simulate admission result: key was in both replica_hints and
        // paid_hints, so admission gives it HintPipeline::Replica.
        let entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            pipeline: HintPipeline::Replica, // Cross-set precedence result.
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            hint_sender: peer_id_from_byte(1),
        };

        assert!(queues.add_pending_verify(key, entry));

        let pending = queues.get_pending(&key).expect("should be pending");
        assert_eq!(
            pending.pipeline,
            HintPipeline::Replica,
            "key in both hint sets should be Replica pipeline"
        );

        // A second add (e.g. from paid hints arriving separately) is rejected.
        let paid_entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            pipeline: HintPipeline::PaidOnly,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            hint_sender: peer_id_from_byte(2),
        };

        assert!(
            !queues.add_pending_verify(key, paid_entry),
            "duplicate key should be rejected regardless of pipeline"
        );

        // Pipeline stays Replica.
        let pending = queues.get_pending(&key).expect("should still be pending");
        assert_eq!(
            pending.pipeline,
            HintPipeline::Replica,
            "pipeline should remain Replica after duplicate rejection"
        );
    }

    /// Scenario 3: Neighbor-sync unknown key transitions through the full
    /// state machine to stored.
    ///
    /// Exercises the complete queue pipeline that a key follows when it
    /// arrives as a neighbor-sync hint, passes quorum verification, is
    /// fetched, and completes:
    ///   `PendingVerify` → (quorum pass) → `QueuedForFetch` → `Fetching` → `Stored`
    #[test]
    fn scenario_3_neighbor_sync_quorum_pass_full_pipeline() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x03);
        let distance = xor_name_from_byte(0x01);
        let source_a = peer_id_from_byte(1);
        let source_b = peer_id_from_byte(2);
        let hint_sender = peer_id_from_byte(3);

        // Stage 1: Hint admitted → PendingVerify
        let entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            pipeline: HintPipeline::Replica,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            hint_sender,
        };
        assert!(
            queues.add_pending_verify(key, entry),
            "new key should be admitted to PendingVerify"
        );
        assert!(queues.contains_key(&key));
        assert_eq!(queues.pending_count(), 1);

        // Stage 2: Quorum passes — remove from pending and enqueue for fetch
        // with the verified sources discovered during the quorum round.
        let removed = queues.remove_pending(&key);
        assert!(removed.is_some(), "key should exist in pending");
        assert_eq!(queues.pending_count(), 0);

        queues.enqueue_fetch(key, distance, vec![source_a, source_b]);
        assert_eq!(queues.fetch_queue_count(), 1);
        assert!(
            queues.contains_key(&key),
            "key should be in pipeline (fetch queue)"
        );

        // Stage 3: Dequeue → Fetching
        let candidate = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(candidate.key, key);
        assert_eq!(candidate.sources.len(), 2);
        queues.start_fetch(key, source_a, candidate.sources);
        assert_eq!(queues.in_flight_count(), 1);
        assert_eq!(queues.fetch_queue_count(), 0);
        assert!(
            queues.contains_key(&key),
            "key should be in pipeline (in-flight)"
        );

        // Stage 4: Fetch completes → Stored
        let completed = queues.complete_fetch(&key);
        assert!(
            completed.is_some(),
            "should have in-flight entry to complete"
        );
        assert_eq!(queues.in_flight_count(), 0);
        assert!(
            !queues.contains_key(&key),
            "key should be fully processed out of pipeline"
        );
    }
}
