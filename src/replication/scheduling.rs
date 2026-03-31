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
    pending_verify: HashMap<XorName, VerificationEntry>,
    /// Presence-quorum-passed or paid-list-authorized keys waiting for fetch.
    fetch_queue: BinaryHeap<FetchCandidate>,
    /// Keys present in `fetch_queue` for O(1) dedup.
    fetch_queue_keys: HashSet<XorName>,
    /// Active downloads keyed by `XorName`.
    in_flight_fetch: HashMap<XorName, InFlightEntry>,
    /// Maximum concurrent fetches (adjustable between bootstrap and normal).
    max_concurrent_fetch: usize,
}

impl ReplicationQueues {
    /// Create new empty queues with the given fetch concurrency limit.
    #[must_use]
    pub fn new(max_concurrent_fetch: usize) -> Self {
        Self {
            pending_verify: HashMap::new(),
            fetch_queue: BinaryHeap::new(),
            fetch_queue_keys: HashSet::new(),
            in_flight_fetch: HashMap::new(),
            max_concurrent_fetch,
        }
    }

    /// Update the fetch concurrency limit (e.g. after bootstrap drains).
    pub fn set_max_concurrent_fetch(&mut self, max: usize) {
        self.max_concurrent_fetch = max;
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
    /// No-op if the key is already in the fetch queue or in-flight.
    pub fn enqueue_fetch(&mut self, key: XorName, distance: XorName, sources: Vec<PeerId>) {
        if self.fetch_queue_keys.contains(&key) || self.in_flight_fetch.contains_key(&key) {
            return;
        }
        self.fetch_queue_keys.insert(key);
        self.fetch_queue.push(FetchCandidate {
            key,
            distance,
            sources,
            tried: HashSet::new(),
        });
    }

    /// Dequeue the nearest fetch candidate if there is capacity.
    ///
    /// Returns `None` when the concurrency limit is reached or the queue is
    /// empty. Silently skips candidates that are somehow already in-flight.
    pub fn dequeue_fetch(&mut self) -> Option<FetchCandidate> {
        if self.in_flight_fetch.len() >= self.max_concurrent_fetch {
            return None;
        }
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
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x01);
        assert!(queues.add_pending_verify(key, test_entry(1)));
        assert_eq!(queues.pending_count(), 1);
    }

    #[test]
    fn add_pending_verify_duplicate_rejected() {
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x01);
        assert!(queues.add_pending_verify(key, test_entry(1)));
        assert!(!queues.add_pending_verify(key, test_entry(2)));
        assert_eq!(queues.pending_count(), 1);
    }

    #[test]
    fn add_pending_verify_rejected_if_in_fetch_queue() {
        let mut queues = ReplicationQueues::new(10);
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
        let mut queues = ReplicationQueues::new(10);
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
        let mut queues = ReplicationQueues::new(10);

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
    fn dequeue_respects_concurrency_limit() {
        let concurrency_limit = 1;
        let mut queues = ReplicationQueues::new(concurrency_limit);

        let key_a = xor_name_from_byte(0x01);
        let key_b = xor_name_from_byte(0x02);
        queues.enqueue_fetch(key_a, [0x10; 32], vec![peer_id_from_byte(1)]);
        queues.enqueue_fetch(key_b, [0x20; 32], vec![peer_id_from_byte(2)]);

        // Start one fetch to fill the limit.
        queues.start_fetch(xor_name_from_byte(0xFF), peer_id_from_byte(3), vec![]);

        assert!(
            queues.dequeue_fetch().is_none(),
            "should not dequeue when at concurrency limit"
        );
    }

    #[test]
    fn enqueue_dedup_prevents_duplicates() {
        let mut queues = ReplicationQueues::new(10);
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
        let mut queues = ReplicationQueues::new(10);
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
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x99);
        assert!(queues.complete_fetch(&key).is_none());
    }

    // -- retry_fetch ------------------------------------------------------

    #[test]
    fn retry_fetch_returns_next_untried_source() {
        let mut queues = ReplicationQueues::new(10);
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
        let mut queues = ReplicationQueues::new(10);
        assert!(queues.retry_fetch(&xor_name_from_byte(0xFF)).is_none());
    }

    // -- contains_key across pipelines ------------------------------------

    #[test]
    fn contains_key_in_pending() {
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_in_fetch_queue() {
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x02);
        queues.enqueue_fetch(key, [0x10; 32], vec![peer_id_from_byte(1)]);
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_in_flight() {
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x03);
        queues.start_fetch(key, peer_id_from_byte(1), vec![]);
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_absent() {
        let queues = ReplicationQueues::new(10);
        assert!(!queues.contains_key(&xor_name_from_byte(0xFF)));
    }

    // -- bootstrap work empty ---------------------------------------------

    #[test]
    fn bootstrap_work_empty_when_no_keys_present() {
        let queues = ReplicationQueues::new(10);
        let bootstrap_keys: HashSet<XorName> = [xor_name_from_byte(0x01), xor_name_from_byte(0x02)]
            .into_iter()
            .collect();
        assert!(queues.is_bootstrap_work_empty(&bootstrap_keys));
    }

    #[test]
    fn bootstrap_work_not_empty_when_key_in_pending() {
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        let bootstrap_keys: HashSet<XorName> = std::iter::once(key).collect();
        assert!(!queues.is_bootstrap_work_empty(&bootstrap_keys));
    }

    // -- evict_stale ------------------------------------------------------

    #[test]
    fn evict_stale_removes_old_entries() {
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x01);

        // Create entry with a backdated timestamp.
        let mut entry = test_entry(1);
        entry.created_at = Instant::now()
            .checked_sub(Duration::from_secs(120))
            .unwrap();
        queues.pending_verify.insert(key, entry);

        assert_eq!(queues.pending_count(), 1);
        queues.evict_stale(Duration::from_secs(60));
        assert_eq!(
            queues.pending_count(),
            0,
            "entry older than max_age should be evicted"
        );
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let mut queues = ReplicationQueues::new(10);
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
        let mut queues = ReplicationQueues::new(10);
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        let removed = queues.remove_pending(&key);
        assert!(removed.is_some());
        assert_eq!(queues.pending_count(), 0);
    }

    #[test]
    fn remove_pending_nonexistent_returns_none() {
        let mut queues = ReplicationQueues::new(10);
        assert!(queues.remove_pending(&xor_name_from_byte(0xFF)).is_none());
    }

    // -- set_max_concurrent_fetch -----------------------------------------

    #[test]
    fn set_max_concurrent_fetch_allows_more_dequeues() {
        let mut queues = ReplicationQueues::new(0); // no fetches allowed
        let key = xor_name_from_byte(0x01);
        queues.enqueue_fetch(key, [0x10; 32], vec![peer_id_from_byte(1)]);

        assert!(
            queues.dequeue_fetch().is_none(),
            "should not dequeue at limit 0"
        );

        queues.set_max_concurrent_fetch(1);
        assert!(
            queues.dequeue_fetch().is_some(),
            "should dequeue after increasing limit"
        );
    }
}
