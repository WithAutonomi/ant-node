//! Scheduling and queue management (Section 12).
//!
//! Manages `PendingVerify`, `FetchQueue`, and `InFlightFetch` queues for the
//! replication pipeline. Each key progresses through at most one queue at a
//! time, with strict dedup across all three stages.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::logging::debug;

use crate::ant_protocol::XorName;
use crate::replication::types::{
    FetchCandidate, HintPipeline, VerificationEntry, VerificationState,
};
use saorsa_core::identity::PeerId;

/// Global hard upper bound on the number of keys held in `pending_verify`.
///
/// Without a bound, a peer in the local routing table can flood
/// `NeighborSyncRequest` messages (each capped only by
/// `MAX_REPLICATION_MESSAGE_SIZE` ≈ 10 MiB, i.e. ~320k 32-byte hints per
/// message) and grow this map without limit, exhausting node memory and
/// driving a self-amplifying storm of outbound verification requests.
///
/// `131_072` entries is far above any legitimate aggregate need while
/// bounding worst-case memory to a few tens of MiB (each `VerificationEntry`
/// is on the order of a few hundred bytes; its sub-collections are populated
/// only from close-group-sized verification evidence, never from attacker
/// hint volume).
///
/// This global cap alone is **not** sufficient: with blind capacity-reject a
/// single malicious routing-table peer could fill the whole map with cheap
/// admission-passing junk and starve every honest peer's hints until the
/// 30-minute `evict_stale` backstop fires (and re-fill immediately after).
/// Honest-replication fairness is therefore enforced by
/// [`MAX_PENDING_VERIFY_PER_PEER`] below; this global value is only the
/// memory backstop.
pub const MAX_PENDING_VERIFY: usize = 131_072;

/// Per-source hard cap on `pending_verify` entries attributed to a single
/// `hint_sender` peer.
///
/// This is the actual D1 defence. Each pending entry records the peer that
/// hinted it (`VerificationEntry::hint_sender`); a single source may occupy
/// at most this many slots. A flooding peer can therefore consume only its
/// own quota — it can never deny slots to honest peers, because honest
/// sources are accounted independently. Set well above any legitimate
/// per-peer hint working set (a healthy neighbour syncs at most a few
/// thousand keys to us per cycle) yet small enough that
/// `MAX_PENDING_VERIFY / MAX_PENDING_VERIFY_PER_PEER` distinct malicious
/// peers would be required to approach the global cap.
///
/// Residual (accepted, follow-up): with the current ratio, ~16 distinct
/// `PeerId`s that are *all* simultaneously in the victim's routing table
/// (gated by `sender_in_rt`) could still collectively reach the global
/// `MAX_PENDING_VERIFY` backstop. `hint_sender` is the cryptographically
/// authenticated connection identity (not a forgeable payload field), so
/// this requires running ~16 real Kademlia-adjacent Sybil nodes — a large
/// step up from the single-peer pre-fix attack, and the worst case degrades
/// only to the bounded memory backstop, not silent permanent starvation of
/// non-Sybil peers (each keeps its independent quota). A future hardening
/// (reserved headroom for under-quota sources, or a per-source cap that
/// scales with distinct-source pressure) is tracked as a follow-up and is
/// intentionally out of scope for this `DoS` fix.
pub const MAX_PENDING_VERIFY_PER_PEER: usize = 8_192;

/// Hard upper bound on the number of keys held in `fetch_queue`.
///
/// `fetch_queue` is fed only by `enqueue_fetch`, which is reached **after** a
/// key passes quorum verification in `run_verification_cycle` — attacker junk
/// keys (no real holder) fail quorum and never reach this stage, so the
/// bounded-and-fair `pending_verify` upstream is the primary protection. This
/// global cap remains as a defence-in-depth memory backstop and is dropped
/// (consistent with the existing cross-queue-dedup no-op contract of
/// `enqueue_fetch`) when full.
pub const MAX_FETCH_QUEUE: usize = 131_072;

/// Outcome of [`ReplicationQueues::add_pending_verify`].
///
/// Distinguishes "the key is already being handled" from "the key was
/// silently dropped due to a queue capacity bound". Bootstrap drain
/// accounting and source-side retry logic MUST treat `CapacityRejected` as
/// outstanding work; treating it like a dedup hit was the silent-drop
/// regression introduced when the queues first became bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionResult {
    /// New entry inserted into `pending_verify`.
    Admitted,
    /// Key was already in some pipeline stage; the existing entry is left
    /// in place. No retry required.
    AlreadyPresent,
    /// Global or per-source capacity bound rejected the entry. The caller
    /// MUST treat this as work still to do (not as silently completed).
    CapacityRejected,
}

impl AdmissionResult {
    /// `true` only for [`AdmissionResult::Admitted`]. Preserves call sites
    /// that only want to know "did the insert happen".
    #[must_use]
    pub fn admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }
}

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
    /// Pending-verification entry to restore if all fetch sources fail.
    pub retry_verification: Option<VerificationEntry>,
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
///
/// A key promoted from `PendingVerify` to fetch keeps a reserved verification
/// slot until it either stores successfully or returns to `PendingVerify`.
/// That reservation prevents unrelated new hints from stealing the capacity
/// needed to retry verification after every fetch source fails.
pub struct ReplicationQueues {
    /// Keys awaiting quorum result (dedup by key).
    ///
    /// Capacity-bounded by [`MAX_PENDING_VERIFY`]: admissions are rejected
    /// once full, preventing unbounded growth under a network hint flood.
    pending_verify: HashMap<XorName, VerificationEntry>,
    /// Presence-quorum-passed or paid-list-authorized keys waiting for fetch.
    ///
    /// Capacity-bounded by [`MAX_FETCH_QUEUE`]: enqueues are dropped once
    /// full, preventing unbounded growth under a network hint flood.
    fetch_queue: BinaryHeap<FetchCandidate>,
    /// Keys present in `fetch_queue` for O(1) dedup.
    fetch_queue_keys: HashSet<XorName>,
    /// Active downloads keyed by `XorName`.
    in_flight_fetch: HashMap<XorName, InFlightEntry>,
    /// Number of `pending_verify` entries currently attributed to each
    /// `hint_sender` peer. Maintained in lockstep with `pending_verify`
    /// (insert/remove/evict).
    pending_per_sender: HashMap<PeerId, usize>,
    /// Pending-verification capacity slots reserved by retry-capable keys that
    /// have left `pending_verify` for `fetch_queue` / `in_flight_fetch`.
    retry_reserved_slots: usize,
    /// Per-source view of [`Self::retry_reserved_slots`].
    retry_reserved_per_sender: HashMap<PeerId, usize>,
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
            pending_per_sender: HashMap::new(),
            retry_reserved_slots: 0,
            retry_reserved_per_sender: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // PendingVerify
    // -----------------------------------------------------------------------

    /// Add a key to pending verification if not already present in any queue.
    ///
    /// Returns an [`AdmissionResult`] distinguishing the three outcomes:
    /// * `Admitted` — newly inserted.
    /// * `AlreadyPresent` — Rule 8 cross-queue dedup (the key is already in
    ///   `pending_verify`, `fetch_queue`, or `in_flight_fetch`); the existing
    ///   entry remains and there is no work to retry.
    /// * `CapacityRejected` — global or per-source bound hit; the work is
    ///   genuinely lost and the caller (e.g. bootstrap drain accounting,
    ///   source-side retry) MUST treat this as still-outstanding work, not as
    ///   "done". Without this distinction a bootstrap snapshot whose hints
    ///   are capacity-rejected would silently mark itself drained.
    pub fn add_pending_verify(
        &mut self,
        key: XorName,
        entry: VerificationEntry,
    ) -> AdmissionResult {
        if self.contains_key(&key) {
            return AdmissionResult::AlreadyPresent;
        }
        if self.pending_capacity_used() >= MAX_PENDING_VERIFY {
            debug!(
                "pending_verify at global capacity ({MAX_PENDING_VERIFY}); rejecting key {}",
                hex::encode(key)
            );
            return AdmissionResult::CapacityRejected;
        }
        let sender = entry.hint_sender;
        let sender_count = self.sender_capacity_used(&sender);
        if sender_count >= MAX_PENDING_VERIFY_PER_PEER {
            debug!(
                "peer {sender} at per-source pending cap ({MAX_PENDING_VERIFY_PER_PEER}); \
                 rejecting key {} (honest peers are unaffected)",
                hex::encode(key)
            );
            return AdmissionResult::CapacityRejected;
        }
        self.insert_pending_unchecked(key, entry);
        AdmissionResult::Admitted
    }

    fn pending_capacity_used(&self) -> usize {
        self.pending_verify
            .len()
            .saturating_add(self.retry_reserved_slots)
    }

    fn sender_capacity_used(&self, sender: &PeerId) -> usize {
        self.pending_per_sender
            .get(sender)
            .copied()
            .unwrap_or(0)
            .saturating_add(
                self.retry_reserved_per_sender
                    .get(sender)
                    .copied()
                    .unwrap_or(0),
            )
    }

    /// Decrement (and prune at zero) the per-sender counter for `sender`.
    ///
    /// Kept private so the counter can only move in lockstep with
    /// `pending_verify` mutations. The decrement uses `saturating_sub` so a
    /// hypothetical future invariant break (a release without a matching
    /// admission) self-heals to zero instead of panicking on `usize`
    /// underflow; `debug_assert!` still surfaces such a break in test builds.
    fn release_sender_slot(pending_per_sender: &mut HashMap<PeerId, usize>, sender: &PeerId) {
        if let Some(count) = pending_per_sender.get_mut(sender) {
            debug_assert!(*count > 0, "per-sender counter underflow for {sender}");
            *count = count.saturating_sub(1);
            if *count == 0 {
                pending_per_sender.remove(sender);
            }
        }
    }

    fn insert_pending_unchecked(&mut self, key: XorName, entry: VerificationEntry) {
        let sender = entry.hint_sender;
        let replaced = self.pending_verify.insert(key, entry);
        debug_assert!(
            replaced.is_none(),
            "pending entry inserted twice for {}",
            hex::encode(key)
        );
        *self.pending_per_sender.entry(sender).or_insert(0) += 1;
    }

    fn reserve_retry_slot(&mut self, sender: PeerId) {
        self.retry_reserved_slots = self.retry_reserved_slots.saturating_add(1);
        *self.retry_reserved_per_sender.entry(sender).or_insert(0) += 1;
    }

    fn release_retry_slot(&mut self, sender: &PeerId) {
        if !self.retry_reserved_per_sender.contains_key(sender) {
            return;
        }
        self.retry_reserved_slots = self.retry_reserved_slots.saturating_sub(1);
        Self::release_sender_slot(&mut self.retry_reserved_per_sender, sender);
    }

    fn release_retry_slot_for_entry(&mut self, entry: &InFlightEntry) {
        if let Some(verification) = &entry.retry_verification {
            self.release_retry_slot(&verification.hint_sender);
        }
    }

    fn release_retry_slot_for_candidate(&mut self, candidate: &FetchCandidate) {
        if let Some(verification) = &candidate.retry_verification {
            self.release_retry_slot(&verification.hint_sender);
        }
    }

    /// Get a reference to a pending verification entry.
    #[must_use]
    pub fn get_pending(&self, key: &XorName) -> Option<&VerificationEntry> {
        self.pending_verify.get(key)
    }

    /// Advance a pending entry's verification `state`, returning the entry's
    /// `pipeline` (so the caller can branch on it) when the key was found.
    ///
    /// Replaces a prior `get_pending_mut` which handed out `&mut VerificationEntry`
    /// and relied on a doc-comment to keep callers from re-assigning
    /// `hint_sender`. The per-source quota counter (`pending_per_sender`) is
    /// keyed by `hint_sender` recorded at admission; re-attributing a live
    /// entry to a different peer would orphan a count and silently desync
    /// the quota — exactly the silent-starvation class this fix prevents.
    /// Narrowing the mutation API to a single setter makes that mistake
    /// impossible to commit by accident.
    pub fn set_pending_state(
        &mut self,
        key: &XorName,
        state: VerificationState,
    ) -> Option<HintPipeline> {
        let entry = self.pending_verify.get_mut(key)?;
        entry.state = state;
        Some(entry.pipeline)
    }

    /// Remove a key from pending verification.
    pub fn remove_pending(&mut self, key: &XorName) -> Option<VerificationEntry> {
        let removed = self.pending_verify.remove(key);
        if let Some(entry) = &removed {
            Self::release_sender_slot(&mut self.pending_per_sender, &entry.hint_sender);
        }
        removed
    }

    /// Collect all pending verification keys (for batch processing).
    #[must_use]
    pub fn pending_keys(&self) -> Vec<XorName> {
        self.pending_verify.keys().copied().collect()
    }

    /// Collect pending verification keys whose retry delay has elapsed.
    #[must_use]
    pub fn ready_pending_keys(&self, now: Instant) -> Vec<XorName> {
        self.pending_verify
            .iter()
            .filter_map(|(key, entry)| (entry.next_verify_at <= now).then_some(*key))
            .collect()
    }

    /// Defer a pending key before its next verification attempt.
    pub fn defer_pending(&mut self, key: &XorName, retry_after: Duration) -> bool {
        let Some(entry) = self.pending_verify.get_mut(key) else {
            return false;
        };
        entry.next_verify_at = Instant::now() + retry_after;
        true
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
    /// Returns `true` if the candidate was enqueued, `false` if it was
    /// already present in any pipeline stage (Rule 8: cross-queue dedup) or
    /// the `fetch_queue` is at [`MAX_FETCH_QUEUE`].
    ///
    /// Callers that have removed the key from `pending_verify` immediately
    /// before this call should prefer [`promote_pending_to_fetch`](Self::promote_pending_to_fetch),
    /// which performs the move atomically and leaves the pending entry in
    /// place when the fetch queue is full (so verified work is retried on
    /// the next cycle instead of being silently lost).
    pub fn enqueue_fetch(&mut self, key: XorName, distance: XorName, sources: Vec<PeerId>) -> bool {
        if self.pending_verify.contains_key(&key)
            || self.fetch_queue_keys.contains(&key)
            || self.in_flight_fetch.contains_key(&key)
        {
            return false;
        }
        if self.fetch_queue.len() >= MAX_FETCH_QUEUE {
            debug!(
                "fetch_queue at capacity ({MAX_FETCH_QUEUE}); dropping new key {}",
                hex::encode(key)
            );
            return false;
        }
        self.enqueue_fetch_with_retry(key, distance, sources, None)
    }

    fn enqueue_fetch_with_retry(
        &mut self,
        key: XorName,
        distance: XorName,
        sources: Vec<PeerId>,
        retry_verification: Option<VerificationEntry>,
    ) -> bool {
        if self.pending_verify.contains_key(&key)
            || self.fetch_queue_keys.contains(&key)
            || self.in_flight_fetch.contains_key(&key)
        {
            return false;
        }
        if self.fetch_queue.len() >= MAX_FETCH_QUEUE {
            debug!(
                "fetch_queue at capacity ({MAX_FETCH_QUEUE}); dropping new key {}",
                hex::encode(key)
            );
            return false;
        }
        self.fetch_queue_keys.insert(key);
        self.fetch_queue.push(FetchCandidate {
            key,
            distance,
            sources,
            retry_verification,
        });
        true
    }

    /// Atomically promote a key from `pending_verify` to `fetch_queue`.
    ///
    /// Checks `fetch_queue` capacity FIRST, then removes the pending entry
    /// and enqueues the fetch candidate. If `fetch_queue` is full, the
    /// pending entry is **left in place** so the next verification cycle
    /// can retry — preventing the silent-drop regression where a verified
    /// key removed from `pending_verify` could be dropped by a full fetch
    /// queue and lost from every stage.
    ///
    /// Returns `true` on successful promotion, `false` when the fetch queue
    /// is at capacity (pending entry preserved).
    pub fn promote_pending_to_fetch(
        &mut self,
        key: XorName,
        distance: XorName,
        sources: Vec<PeerId>,
    ) -> bool {
        if self.fetch_queue.len() >= MAX_FETCH_QUEUE {
            debug!(
                "fetch_queue at capacity ({MAX_FETCH_QUEUE}); leaving {} pending \
                 for retry next cycle",
                hex::encode(key)
            );
            return false;
        }
        // Capacity confirmed; safe to release the pending slot and enqueue.
        let retry_verification = self.remove_pending(&key);
        let retry_sender = retry_verification
            .as_ref()
            .map(|verification| verification.hint_sender);
        if let Some(sender) = retry_sender {
            self.reserve_retry_slot(sender);
        }
        // enqueue_fetch returns false only on capacity or already-queued; the
        // capacity check above and the just-removed pending state make this
        // succeed. If a concurrent path put the key into fetch_queue/in_flight
        // between, dropping the duplicate is fine.
        let enqueued = self.enqueue_fetch_with_retry(key, distance, sources, retry_verification);
        if !enqueued {
            if let Some(sender) = retry_sender {
                self.release_retry_slot(&sender);
            }
        }
        enqueued
    }

    /// Dequeue the nearest fetch candidate.
    ///
    /// Returns `None` when the queue is empty.  Silently skips candidates
    /// that are somehow already in-flight.  Concurrency is enforced by the
    /// fetch worker, not by this method.
    ///
    /// A returned candidate may carry a live verification retry-slot
    /// reservation. Callers must consume it with
    /// [`Self::start_dequeued_fetch`], [`Self::discard_fetch_candidate`], or
    /// [`Self::requeue_candidate_for_verification`] so that reservation is
    /// either transferred, released, or restored to `pending_verify`.
    pub fn dequeue_fetch(&mut self) -> Option<FetchCandidate> {
        while let Some(candidate) = self.fetch_queue.pop() {
            self.fetch_queue_keys.remove(&candidate.key);
            if !self.in_flight_fetch.contains_key(&candidate.key) {
                return Some(candidate);
            }
            self.release_retry_slot_for_candidate(&candidate);
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
    ///
    /// Candidates returned by [`Self::dequeue_fetch`] MUST be consumed by a
    /// by-value dequeued-candidate method instead. They may carry a live
    /// verification retry-slot reservation; [`Self::start_dequeued_fetch`]
    /// transfers that reservation into the in-flight entry.
    pub fn start_fetch(&mut self, key: XorName, source: PeerId, all_sources: Vec<PeerId>) {
        self.start_fetch_with_retry(key, source, all_sources, None);
    }

    /// Mark a key as in-flight and retain verification retry metadata.
    ///
    /// This is for direct starts where the caller already owns any retry
    /// reservation paired with `retry_verification`. Candidates obtained from
    /// [`Self::dequeue_fetch`] MUST be consumed intact via a by-value
    /// dequeued-candidate method, otherwise their reserved verification
    /// capacity can be orphaned.
    pub fn start_fetch_with_retry(
        &mut self,
        key: XorName,
        source: PeerId,
        all_sources: Vec<PeerId>,
        retry_verification: Option<VerificationEntry>,
    ) {
        let mut tried = HashSet::new();
        tried.insert(source);
        let replaced = self.in_flight_fetch.insert(
            key,
            InFlightEntry {
                key,
                source,
                started_at: Instant::now(),
                all_sources,
                tried,
                retry_verification,
            },
        );
        if let Some(entry) = replaced {
            self.release_retry_slot_for_entry(&entry);
        }
    }

    /// Consume a dequeued fetch candidate and transfer its retry reservation
    /// into the in-flight entry.
    pub fn start_dequeued_fetch(&mut self, candidate: FetchCandidate, source: PeerId) {
        let FetchCandidate {
            key,
            sources,
            retry_verification,
            ..
        } = candidate;
        self.start_fetch_with_retry(key, source, sources, retry_verification);
    }

    /// Mark a fetch as completed (success or permanent failure).
    pub fn complete_fetch(&mut self, key: &XorName) -> Option<InFlightEntry> {
        let removed = self.in_flight_fetch.remove(key);
        if let Some(entry) = &removed {
            self.release_retry_slot_for_entry(entry);
        }
        removed
    }

    /// Drop a dequeued fetch candidate without starting it.
    pub fn discard_fetch_candidate(&mut self, candidate: FetchCandidate) {
        let FetchCandidate {
            retry_verification, ..
        } = candidate;
        if let Some(verification) = retry_verification {
            self.release_retry_slot(&verification.hint_sender);
        }
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

    /// Consume a dequeued candidate and restore its verification entry for a
    /// later retry when retry metadata exists.
    pub fn requeue_candidate_for_verification(
        &mut self,
        candidate: FetchCandidate,
        retry_after: Duration,
    ) -> bool {
        let FetchCandidate {
            key,
            retry_verification,
            ..
        } = candidate;
        let Some(mut verification) = retry_verification else {
            return false;
        };
        let sender = verification.hint_sender;

        verification.state = VerificationState::PendingVerify;
        verification.verified_sources.clear();
        verification.tried_sources.clear();
        verification.next_verify_at = Instant::now() + retry_after;

        self.insert_pending_unchecked(key, verification);
        self.release_retry_slot(&sender);
        true
    }

    /// Complete an exhausted fetch and restore its verification entry for a
    /// later retry when retry metadata exists.
    pub fn requeue_fetch_for_verification(&mut self, key: &XorName, retry_after: Duration) -> bool {
        let Some(mut entry) = self.in_flight_fetch.remove(key) else {
            return false;
        };
        let Some(mut verification) = entry.retry_verification.take() else {
            return false;
        };
        let sender = verification.hint_sender;

        verification.state = VerificationState::PendingVerify;
        verification.verified_sources.clear();
        verification.tried_sources.clear();
        verification.next_verify_at = Instant::now() + retry_after;

        self.insert_pending_unchecked(*key, verification);
        self.release_retry_slot(&sender);
        true
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
    pub fn evict_stale(&mut self, max_age: Duration) -> Vec<XorName> {
        let now = Instant::now();
        let evicted_keys = self
            .pending_verify
            .iter()
            .filter_map(|(key, entry)| {
                (now.duration_since(entry.created_at) >= max_age).then_some(*key)
            })
            .collect::<Vec<_>>();

        for key in &evicted_keys {
            if let Some(entry) = self.pending_verify.remove(key) {
                Self::release_sender_slot(&mut self.pending_per_sender, &entry.hint_sender);
            }
        }

        if !evicted_keys.is_empty() {
            debug!(
                "Evicted {} stale pending-verification entries",
                evicted_keys.len()
            );
        }

        evicted_keys
    }

    /// Number of `pending_verify` entries currently attributed to `sender`.
    /// Includes retry reservations held by verified keys currently in the fetch
    /// pipeline, because those reservations still consume the sender's fairness
    /// quota.
    #[must_use]
    pub fn pending_count_for_sender(&self, sender: &PeerId) -> usize {
        self.sender_capacity_used(sender)
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

    fn xor_name_from_u32(value: u32) -> XorName {
        let mut name = [0u8; 32];
        name[..4].copy_from_slice(&value.to_le_bytes());
        name
    }

    /// Create a minimal `VerificationEntry` for testing.
    fn test_entry(sender_byte: u8) -> VerificationEntry {
        let now = Instant::now();
        VerificationEntry {
            state: VerificationState::PendingVerify,
            pipeline: HintPipeline::Replica,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: now,
            next_verify_at: now,
            hint_sender: peer_id_from_byte(sender_byte),
        }
    }

    struct ReservedCandidateAtSenderCap {
        queues: ReplicationQueues,
        key: XorName,
        source: PeerId,
        hint_sender: PeerId,
        fresh_key: XorName,
        candidate: FetchCandidate,
        base_sender_count: usize,
        pre_promotion_sender_count: usize,
    }

    fn assert_sender_cap_rejects_key(
        queues: &mut ReplicationQueues,
        key: XorName,
        sender_byte: u8,
    ) {
        assert_eq!(
            queues.add_pending_verify(key, test_entry(sender_byte)),
            AdmissionResult::CapacityRejected,
            "fresh key should be rejected while sender capacity is exhausted"
        );
    }

    fn assert_sender_released_slot_admits_key(
        queues: &mut ReplicationQueues,
        sender: &PeerId,
        sender_byte: u8,
        key: XorName,
        expected_count_before_admission: usize,
    ) {
        assert_eq!(
            queues.pending_count_for_sender(sender),
            expected_count_before_admission,
            "sender capacity should return to the expected count"
        );
        assert!(
            queues
                .add_pending_verify(key, test_entry(sender_byte))
                .admitted(),
            "fresh key should be admitted after a retry reservation is released"
        );
        assert_eq!(
            queues.pending_count_for_sender(sender),
            expected_count_before_admission + 1,
            "fresh key should consume the released sender slot"
        );
    }

    fn reserved_candidate_at_sender_cap() -> ReservedCandidateAtSenderCap {
        const PROMOTED_KEY_INDEX: u32 = 40_000;
        const FILLER_KEY_OFFSET: u32 = 50_000;
        const FRESH_KEY_INDEX: u32 = 60_000;
        const DISTANCE_BYTE: u8 = 0x01;
        const SOURCE_BYTE: u8 = 2;
        const HINT_SENDER_BYTE: u8 = 9;

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_u32(PROMOTED_KEY_INDEX);
        let distance = xor_name_from_byte(DISTANCE_BYTE);
        let source = peer_id_from_byte(SOURCE_BYTE);
        let hint_sender = peer_id_from_byte(HINT_SENDER_BYTE);
        let fresh_key = xor_name_from_u32(FRESH_KEY_INDEX);
        let base_sender_count = MAX_PENDING_VERIFY_PER_PEER - 1;
        let pre_promotion_sender_count = MAX_PENDING_VERIFY_PER_PEER;

        assert!(queues
            .add_pending_verify(key, test_entry(HINT_SENDER_BYTE))
            .admitted());
        for i in 0..base_sender_count {
            let key_index = FILLER_KEY_OFFSET + u32::try_from(i).expect("test index fits u32");
            assert!(
                queues
                    .add_pending_verify(xor_name_from_u32(key_index), test_entry(HINT_SENDER_BYTE))
                    .admitted(),
                "filler key should be admitted before the sender reaches its cap"
            );
        }
        assert_eq!(
            queues.pending_count_for_sender(&hint_sender),
            pre_promotion_sender_count,
            "sender should be exactly at capacity before promotion"
        );
        assert_sender_cap_rejects_key(&mut queues, fresh_key, HINT_SENDER_BYTE);

        assert!(queues.promote_pending_to_fetch(key, distance, vec![source]));
        assert_eq!(
            queues.pending_count_for_sender(&hint_sender),
            pre_promotion_sender_count,
            "promoted candidate should retain its sender capacity reservation"
        );
        assert_sender_cap_rejects_key(&mut queues, fresh_key, HINT_SENDER_BYTE);

        let candidate = queues.dequeue_fetch().expect("fetch candidate");
        ReservedCandidateAtSenderCap {
            queues,
            key,
            source,
            hint_sender,
            fresh_key,
            candidate,
            base_sender_count,
            pre_promotion_sender_count,
        }
    }

    // -- add_pending_verify dedup ------------------------------------------

    #[test]
    fn add_pending_verify_new_key_succeeds() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        assert!(queues.add_pending_verify(key, test_entry(1)).admitted());
        assert_eq!(queues.pending_count(), 1);
    }

    #[test]
    fn add_pending_verify_duplicate_rejected() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        assert!(queues.add_pending_verify(key, test_entry(1)).admitted());
        assert!(!queues.add_pending_verify(key, test_entry(2)).admitted());
        assert_eq!(queues.pending_count(), 1);
    }

    #[test]
    fn add_pending_verify_rejected_if_in_fetch_queue() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x02);
        let distance = xor_name_from_byte(0x10);
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(1)]);

        assert!(
            !queues.add_pending_verify(key, test_entry(1)).admitted(),
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
            !queues.add_pending_verify(key, test_entry(1)).admitted(),
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
        queues.discard_fetch_candidate(first);

        let second = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(second.key, far_key, "farthest key should dequeue second");
        queues.discard_fetch_candidate(second);
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

    #[test]
    fn exhausted_promoted_fetch_requeues_verification() {
        const KEY_BYTE: u8 = 0x44;
        const DISTANCE_BYTE: u8 = 0x01;
        const SOURCE_BYTE: u8 = 2;
        const HINT_SENDER_BYTE: u8 = 9;
        const RETRY_DELAY: Duration = Duration::from_secs(15);
        const RETRY_DELAY_SLACK: Duration = Duration::from_secs(1);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(KEY_BYTE);
        let distance = xor_name_from_byte(DISTANCE_BYTE);
        let source = peer_id_from_byte(SOURCE_BYTE);
        let hint_sender = peer_id_from_byte(HINT_SENDER_BYTE);
        let mut entry = test_entry(HINT_SENDER_BYTE);
        entry.hint_sender = hint_sender;

        assert!(queues.add_pending_verify(key, entry).admitted());
        assert!(queues.promote_pending_to_fetch(key, distance, vec![source]));

        let candidate = queues.dequeue_fetch().expect("fetch candidate");
        queues.start_dequeued_fetch(candidate, source);

        assert!(
            queues.retry_fetch(&key).is_none(),
            "single source should be exhausted"
        );
        assert!(queues.requeue_fetch_for_verification(&key, RETRY_DELAY));

        assert_eq!(queues.in_flight_count(), 0);
        assert_eq!(queues.pending_count_for_sender(&hint_sender), 1);
        assert!(
            queues.ready_pending_keys(Instant::now()).is_empty(),
            "requeued key should observe retry delay"
        );

        let after_retry = Instant::now() + RETRY_DELAY + RETRY_DELAY_SLACK;
        assert_eq!(queues.ready_pending_keys(after_retry), vec![key]);
    }

    #[test]
    fn promoted_fetch_reserves_sender_capacity_for_requeue() {
        const PROMOTED_KEY_INDEX: u32 = 10_000;
        const EXTRA_KEY_OFFSET: u32 = 20_000;
        const REJECTED_KEY_INDEX: u32 = 30_000;
        const DISTANCE_BYTE: u8 = 0x01;
        const SOURCE_BYTE: u8 = 2;
        const HINT_SENDER_BYTE: u8 = 9;
        const RETRY_DELAY: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_u32(PROMOTED_KEY_INDEX);
        let distance = xor_name_from_byte(DISTANCE_BYTE);
        let source = peer_id_from_byte(SOURCE_BYTE);
        let hint_sender = peer_id_from_byte(HINT_SENDER_BYTE);
        let mut entry = test_entry(HINT_SENDER_BYTE);
        entry.hint_sender = hint_sender;

        assert!(queues.add_pending_verify(key, entry).admitted());
        assert!(queues.promote_pending_to_fetch(key, distance, vec![source]));
        assert_eq!(
            queues.pending_count_for_sender(&hint_sender),
            1,
            "fetch candidate must retain its sender quota reservation"
        );

        for i in 0..(MAX_PENDING_VERIFY_PER_PEER - 1) {
            let key_index = EXTRA_KEY_OFFSET + u32::try_from(i).expect("test index fits u32");
            let mut entry = test_entry(HINT_SENDER_BYTE);
            entry.hint_sender = hint_sender;
            assert!(
                queues
                    .add_pending_verify(xor_name_from_u32(key_index), entry)
                    .admitted(),
                "sender should admit up to the quota not including the reserved fetch slot"
            );
        }

        let mut rejected_entry = test_entry(HINT_SENDER_BYTE);
        rejected_entry.hint_sender = hint_sender;
        assert_eq!(
            queues.add_pending_verify(xor_name_from_u32(REJECTED_KEY_INDEX), rejected_entry),
            AdmissionResult::CapacityRejected,
            "reserved fetch slot must count toward the per-sender capacity"
        );

        let candidate = queues.dequeue_fetch().expect("fetch candidate");
        queues.start_dequeued_fetch(candidate, source);
        assert!(
            queues.retry_fetch(&key).is_none(),
            "single source should be exhausted"
        );
        assert!(
            queues.requeue_fetch_for_verification(&key, RETRY_DELAY),
            "requeue must use the reserved slot even while the sender is at capacity"
        );

        assert!(queues.get_pending(&key).is_some());
        assert_eq!(queues.pending_count(), MAX_PENDING_VERIFY_PER_PEER);
        assert_eq!(
            queues.pending_count_for_sender(&hint_sender),
            MAX_PENDING_VERIFY_PER_PEER
        );
    }

    #[test]
    fn start_dequeued_fetch_then_complete_releases_reserved_sender_capacity() {
        const HINT_SENDER_BYTE: u8 = 9;

        let ReservedCandidateAtSenderCap {
            mut queues,
            key,
            source,
            hint_sender,
            fresh_key,
            candidate,
            base_sender_count,
            ..
        } = reserved_candidate_at_sender_cap();

        queues.start_dequeued_fetch(candidate, source);
        assert!(queues.complete_fetch(&key).is_some());

        assert_sender_released_slot_admits_key(
            &mut queues,
            &hint_sender,
            HINT_SENDER_BYTE,
            fresh_key,
            base_sender_count,
        );
    }

    #[test]
    fn start_dequeued_fetch_then_exhaust_requeues_with_reserved_sender_capacity() {
        const HINT_SENDER_BYTE: u8 = 9;
        const RETRY_DELAY: Duration = Duration::from_secs(15);

        let ReservedCandidateAtSenderCap {
            mut queues,
            key,
            source,
            hint_sender,
            fresh_key,
            candidate,
            pre_promotion_sender_count,
            ..
        } = reserved_candidate_at_sender_cap();

        queues.start_dequeued_fetch(candidate, source);
        assert!(
            queues.retry_fetch(&key).is_none(),
            "single source should be exhausted"
        );
        assert!(
            queues.requeue_fetch_for_verification(&key, RETRY_DELAY),
            "exhausted fetch should restore retry metadata"
        );

        assert!(queues.get_pending(&key).is_some());
        assert_eq!(
            queues.pending_count_for_sender(&hint_sender),
            pre_promotion_sender_count,
            "requeued key should convert its reservation back to a pending slot"
        );
        assert_sender_cap_rejects_key(&mut queues, fresh_key, HINT_SENDER_BYTE);
    }

    #[test]
    fn discard_dequeued_fetch_candidate_releases_reserved_sender_capacity() {
        const HINT_SENDER_BYTE: u8 = 9;

        let ReservedCandidateAtSenderCap {
            mut queues,
            hint_sender,
            fresh_key,
            candidate,
            base_sender_count,
            ..
        } = reserved_candidate_at_sender_cap();

        queues.discard_fetch_candidate(candidate);

        assert_sender_released_slot_admits_key(
            &mut queues,
            &hint_sender,
            HINT_SENDER_BYTE,
            fresh_key,
            base_sender_count,
        );
    }

    #[test]
    fn requeue_dequeued_fetch_candidate_restores_pending_sender_capacity() {
        const HINT_SENDER_BYTE: u8 = 9;
        const RETRY_DELAY: Duration = Duration::from_secs(15);

        let ReservedCandidateAtSenderCap {
            mut queues,
            key,
            hint_sender,
            fresh_key,
            candidate,
            pre_promotion_sender_count,
            ..
        } = reserved_candidate_at_sender_cap();

        assert!(
            queues.requeue_candidate_for_verification(candidate, RETRY_DELAY),
            "dequeued retry candidate should be restored to pending verification"
        );

        assert!(queues.get_pending(&key).is_some());
        assert_eq!(
            queues.pending_count_for_sender(&hint_sender),
            pre_promotion_sender_count,
            "requeued candidate should convert its reservation back to a pending slot"
        );
        assert_sender_cap_rejects_key(&mut queues, fresh_key, HINT_SENDER_BYTE);
    }

    #[test]
    fn no_sources_dequeued_candidate_requeues_for_verification() {
        const KEY_INDEX: u32 = 70_000;
        const DISTANCE_BYTE: u8 = 0x01;
        const HINT_SENDER_BYTE: u8 = 9;
        const VERIFIED_SOURCE_BYTE: u8 = 2;
        const TRIED_SOURCE_BYTE: u8 = 3;
        const RETRY_DELAY: Duration = Duration::from_secs(15);
        const RETRY_DELAY_SLACK: Duration = Duration::from_secs(1);
        const REQUEUED_SENDER_COUNT: usize = 1;
        const EMPTY_SENDER_COUNT: usize = 0;

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_u32(KEY_INDEX);
        let distance = xor_name_from_byte(DISTANCE_BYTE);
        let hint_sender = peer_id_from_byte(HINT_SENDER_BYTE);
        let verified_source = peer_id_from_byte(VERIFIED_SOURCE_BYTE);
        let tried_source = peer_id_from_byte(TRIED_SOURCE_BYTE);
        let mut entry = test_entry(HINT_SENDER_BYTE);
        entry.state = VerificationState::QueuedForFetch;
        entry.verified_sources.push(verified_source);
        entry.tried_sources.insert(tried_source);

        assert!(queues.add_pending_verify(key, entry).admitted());
        assert!(queues.promote_pending_to_fetch(key, distance, Vec::new()));

        let candidate = queues.dequeue_fetch().expect("fetch candidate");
        assert!(
            candidate.sources.is_empty(),
            "test candidate should exercise the no-sources branch"
        );
        assert!(
            queues.requeue_candidate_for_verification(candidate, RETRY_DELAY),
            "no-sources retry candidate should be restored to pending verification"
        );

        let pending = queues.get_pending(&key).expect("key should be pending");
        assert_eq!(pending.state, VerificationState::PendingVerify);
        assert!(
            pending.verified_sources.is_empty(),
            "verified sources should be cleared before retry"
        );
        assert!(
            pending.tried_sources.is_empty(),
            "tried sources should be cleared before retry"
        );
        assert_eq!(
            queues.pending_count_for_sender(&hint_sender),
            REQUEUED_SENDER_COUNT,
            "retry reservation should be converted back to one pending slot"
        );
        assert!(
            queues.ready_pending_keys(Instant::now()).is_empty(),
            "requeued key should observe retry delay"
        );

        let after_retry = Instant::now() + RETRY_DELAY + RETRY_DELAY_SLACK;
        assert_eq!(queues.ready_pending_keys(after_retry), vec![key]);

        assert!(queues.remove_pending(&key).is_some());
        assert_eq!(
            queues.pending_count_for_sender(&hint_sender),
            EMPTY_SENDER_COUNT,
            "removing the requeued entry should leave no reserved sender slot"
        );
    }

    #[test]
    fn exhausted_direct_fetch_remains_terminal() {
        const KEY_BYTE: u8 = 0x45;
        const DISTANCE_BYTE: u8 = 0x01;
        const SOURCE_BYTE: u8 = 2;
        const RETRY_DELAY: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(KEY_BYTE);
        let source = peer_id_from_byte(SOURCE_BYTE);

        queues.enqueue_fetch(key, xor_name_from_byte(DISTANCE_BYTE), vec![source]);
        let candidate = queues.dequeue_fetch().expect("fetch candidate");
        queues.start_dequeued_fetch(candidate, source);

        assert!(
            queues.retry_fetch(&key).is_none(),
            "single source should be exhausted"
        );
        assert!(!queues.requeue_fetch_for_verification(&key, RETRY_DELAY));
        assert_eq!(queues.in_flight_count(), 0);
        assert_eq!(queues.pending_count(), 0);
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

        // Go through the public `add_pending_verify` so the per-sender
        // counter is correctly bumped — the entry's `hint_sender` slot must
        // be released by `evict_stale` and we want to exercise that path.
        let mut entry = test_entry(1);
        let sender = entry.hint_sender;
        // Backdate via the same defensive checked_sub used elsewhere so
        // freshly-booted CI clocks don't trip us up.
        entry.created_at = Instant::now()
            .checked_sub(Duration::from_secs(2))
            .unwrap_or_else(Instant::now);
        assert!(queues.add_pending_verify(key, entry).admitted());

        assert_eq!(queues.pending_count(), 1);
        assert_eq!(queues.pending_count_for_sender(&sender), 1);

        let evicted = queues.evict_stale(Duration::from_secs(1));
        assert_eq!(evicted, vec![key]);
        assert_eq!(
            queues.pending_count(),
            0,
            "entry older than max_age should be evicted"
        );
        // Per-sender counter must be released alongside the map removal.
        assert_eq!(
            queues.pending_count_for_sender(&sender),
            0,
            "evict_stale must release the per-sender slot"
        );
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        let evicted = queues.evict_stale(Duration::from_secs(3600));
        assert!(
            evicted.is_empty(),
            "fresh entry should not be reported as evicted"
        );
        assert_eq!(
            queues.pending_count(),
            1,
            "fresh entry should not be evicted"
        );
    }

    #[test]
    fn deferred_pending_key_is_not_ready_until_retry_time() {
        const RETRY_DELAY: Duration = Duration::from_secs(15);
        const RETRY_DELAY_SLACK: Duration = Duration::from_secs(1);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xAA);
        queues.add_pending_verify(key, test_entry(1));

        assert_eq!(queues.ready_pending_keys(Instant::now()), vec![key]);
        assert!(queues.defer_pending(&key, RETRY_DELAY));
        assert!(
            queues.ready_pending_keys(Instant::now()).is_empty(),
            "deferred key should not be retried immediately"
        );

        let after_retry = Instant::now() + RETRY_DELAY + RETRY_DELAY_SLACK;
        assert_eq!(queues.ready_pending_keys(after_retry), vec![key]);
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
            queues.add_pending_verify(key, test_entry(1)).admitted(),
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
            !queues.add_pending_verify(key, test_entry(4)).admitted(),
            "key in FetchQueue should be rejected from PendingVerify"
        );

        // Step 5: Dequeue, start fetch -> key is in-flight.
        let candidate = queues.dequeue_fetch().expect("should dequeue");
        let source = candidate.sources[0];
        queues.start_dequeued_fetch(candidate, source);

        // Step 6: Attempt to add to PendingVerify while in-flight -> reject.
        assert!(
            !queues.add_pending_verify(key, test_entry(5)).admitted(),
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
            next_verify_at: Instant::now(),
            hint_sender: peer_id_from_byte(1),
        };

        assert!(queues.add_pending_verify(key, entry).admitted());

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
            next_verify_at: Instant::now(),
            hint_sender: peer_id_from_byte(2),
        };

        assert!(
            !queues.add_pending_verify(key, paid_entry).admitted(),
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
            next_verify_at: Instant::now(),
            hint_sender,
        };
        assert!(
            queues.add_pending_verify(key, entry).admitted(),
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
        queues.start_dequeued_fetch(candidate, source_a);
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
