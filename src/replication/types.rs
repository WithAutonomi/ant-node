//! Core types for the replication subsystem.
//!
//! These types represent the state machine states, queue entries, and domain
//! concepts from the Kademlia-style replication design (see
//! `docs/REPLICATION_DESIGN.md`).

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::ant_protocol::XorName;
use saorsa_core::identity::PeerId;

// ---------------------------------------------------------------------------
// Verification state machine (Section 8 of REPLICATION_DESIGN.md)
// ---------------------------------------------------------------------------

/// Verification state machine.
///
/// Each unknown key transitions through these states exactly once per offer
/// lifecycle.  See Section 8 of `REPLICATION_DESIGN.md` for the full
/// state-transition diagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationState {
    /// Offer received, not yet processed.
    OfferReceived,
    /// Passed admission filter, awaiting quorum / paid-list verification.
    PendingVerify,
    /// Presence quorum passed (>= `QuorumNeeded` positives from
    /// `QuorumTargets`).
    QuorumVerified,
    /// Paid-list authorisation succeeded (>= `ConfirmNeeded` confirmations or
    /// derived from replica majority).
    PaidListVerified,
    /// Queued for record fetch.
    QueuedForFetch,
    /// Actively fetching from a verified source.
    Fetching,
    /// Successfully stored locally.
    Stored,
    /// Fetch failed but retryable (alternate sources remain).
    FetchRetryable,
    /// Fetch permanently abandoned (terminal failure or no alternate sources).
    FetchAbandoned,
    /// Quorum failed definitively (both paid-list and presence impossible this
    /// round).
    QuorumFailed,
    /// Quorum inconclusive (timeout with neither success nor fail-fast).
    QuorumInconclusive,
    /// Terminal: quorum abandoned, key forgotten.
    QuorumAbandoned,
    /// Terminal: key returned to idle (forgotten, requires new offer to
    /// re-enter).
    Idle,
}

// ---------------------------------------------------------------------------
// Hint pipeline classification
// ---------------------------------------------------------------------------

/// Whether a key was admitted via replica hints or paid hints only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HintPipeline {
    /// Key is in the admitted replica-hint pipeline (fetch-eligible).
    Replica,
    /// Key is in the paid-hint-only pipeline (`PaidForList` update only, no
    /// fetch).
    PaidOnly,
}

// ---------------------------------------------------------------------------
// Pending-verification table entry
// ---------------------------------------------------------------------------

/// Entry in the pending-verification table.
///
/// Tracks a single key through the verification FSM, recording which peers
/// responded and which have been tried for fetch.
#[derive(Debug, Clone)]
pub struct VerificationEntry {
    /// Current state in the verification FSM.
    pub state: VerificationState,
    /// Which pipeline admitted this key.
    pub pipeline: HintPipeline,
    /// Peers that responded `Present` during verification (verified fetch
    /// sources).
    pub verified_sources: Vec<PeerId>,
    /// Peers already tried for fetch (to avoid retrying the same source).
    pub tried_sources: HashSet<PeerId>,
    /// When this entry was created.
    pub created_at: Instant,
    /// The peer that originally hinted this key (for source tracking).
    pub hint_sender: PeerId,
}

// ---------------------------------------------------------------------------
// Fetch queue candidate
// ---------------------------------------------------------------------------

/// A candidate queued for fetch, ordered by relevance (nearest-first).
///
/// Implements [`Ord`] with *reversed* distance comparison so that a
/// [`BinaryHeap`](std::collections::BinaryHeap) (max-heap) dequeues the
/// nearest key first.
#[derive(Debug, Clone)]
pub struct FetchCandidate {
    /// The key to fetch.
    pub key: XorName,
    /// XOR distance from self to key (for priority ordering).
    pub distance: XorName,
    /// Verified source peers that responded `Present`.
    pub sources: Vec<PeerId>,
}

impl Eq for FetchCandidate {}

impl PartialEq for FetchCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance && self.key == other.key
    }
}

impl Ord for FetchCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering: smaller distance = higher priority (BinaryHeap is
        // max-heap).  Tie-break on key for consistency with PartialEq.
        other
            .distance
            .cmp(&self.distance)
            .then_with(|| self.key.cmp(&other.key))
    }
}

impl PartialOrd for FetchCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// Verification evidence types
// ---------------------------------------------------------------------------

/// Per-key presence evidence from a verification round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresenceEvidence {
    /// Peer holds the record.
    Present,
    /// Peer does not hold the record.
    Absent,
    /// Peer did not respond in time (neutral, not negative).
    Unresolved,
}

/// Per-key paid-list evidence from a verification round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaidListEvidence {
    /// Peer confirms key is in its `PaidForList`.
    Confirmed,
    /// Peer says key is NOT in its `PaidForList`.
    NotFound,
    /// Peer did not respond in time (neutral).
    Unresolved,
}

/// Aggregated verification evidence for a single key from one verification
/// round.
#[derive(Debug, Clone)]
pub struct KeyVerificationEvidence {
    /// Presence evidence per peer (from `QuorumTargets`).
    pub presence: HashMap<PeerId, PresenceEvidence>,
    /// Paid-list evidence per peer (from `PaidTargets`).
    pub paid_list: HashMap<PeerId, PaidListEvidence>,
}

// ---------------------------------------------------------------------------
// Failure evidence (Section 14 — TrustEngine integration)
// ---------------------------------------------------------------------------

/// Failure evidence types emitted to `TrustEngine` (Section 14).
#[derive(Debug, Clone)]
pub enum FailureEvidence {
    /// Failed fetch attempt from a source peer.
    ReplicationFailure {
        /// The peer that failed to serve the record.
        peer: PeerId,
        /// The key that could not be fetched.
        key: XorName,
    },
    /// Audit failure with confirmed responsible keys.
    AuditFailure {
        /// Unique identifier for the audit challenge.
        challenge_id: u64,
        /// The peer that was challenged.
        challenged_peer: PeerId,
        /// Keys confirmed as failed.
        confirmed_failed_keys: Vec<XorName>,
        /// Why the audit failed.
        reason: AuditFailureReason,
    },
    /// Peer claiming bootstrap past grace period.
    BootstrapClaimAbuse {
        /// The offending peer.
        peer: PeerId,
        /// When this peer was first seen.
        first_seen: Instant,
    },
}

/// Reason for audit failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditFailureReason {
    /// Peer timed out (no response within deadline).
    Timeout,
    /// Response was malformed.
    MalformedResponse,
    /// One or more per-key digest mismatches.
    DigestMismatch,
    /// Key was absent (signalled by sentinel digest).
    KeyAbsent,
    /// Peer explicitly rejected the audit challenge.
    Rejected,
}

// ---------------------------------------------------------------------------
// Peer sync tracking
// ---------------------------------------------------------------------------

/// Record of sync history with a peer, for `RepairOpportunity` tracking.
#[derive(Debug, Clone)]
pub struct PeerSyncRecord {
    /// Last time we successfully synced with this peer.
    pub last_sync: Option<Instant>,
    /// Number of full neighbor-sync cycles completed since last sync with this
    /// peer.
    pub cycles_since_sync: u32,
}

impl PeerSyncRecord {
    /// Whether this peer has had a repair opportunity (synced at least once
    /// and at least one subsequent cycle has completed).
    #[must_use]
    pub fn has_repair_opportunity(&self) -> bool {
        self.last_sync.is_some() && self.cycles_since_sync >= 1
    }
}

// ---------------------------------------------------------------------------
// Neighbor sync cycle state
// ---------------------------------------------------------------------------

/// Neighbor sync cycle state.
///
/// Tracks a deterministic walk through the current close-group snapshot,
/// per-peer cooldown times, and bootstrap claim first-seen timestamps.
#[derive(Debug)]
pub struct NeighborSyncState {
    /// Deterministic ordering of peers for the current cycle (snapshot).
    pub order: Vec<PeerId>,
    /// Current cursor position into `order`.
    pub cursor: usize,
    /// Per-peer last successful sync time (for cooldown).
    pub last_sync_times: HashMap<PeerId, Instant>,
    /// Bootstrap claim first-seen timestamps per peer.
    ///
    /// Entries are removed when a peer passes or fails audit (i.e. stops
    /// claiming bootstrap). Under Sybil attack with many distinct peer IDs
    /// perpetually claiming bootstrap, this map grows unboundedly. In practice
    /// the trust engine limits Sybil impact before this becomes a memory issue.
    pub bootstrap_claims: HashMap<PeerId, Instant>,
}

impl NeighborSyncState {
    /// Create a new cycle from the given close neighbors.
    #[must_use]
    pub fn new_cycle(close_neighbors: Vec<PeerId>) -> Self {
        Self {
            order: close_neighbors,
            cursor: 0,
            last_sync_times: HashMap::new(),
            bootstrap_claims: HashMap::new(),
        }
    }

    /// Whether the current cycle is complete.
    #[must_use]
    pub fn is_cycle_complete(&self) -> bool {
        self.cursor >= self.order.len()
    }
}

// ---------------------------------------------------------------------------
// Bootstrap drain state (Section 16)
// ---------------------------------------------------------------------------

/// Bootstrap drain state tracking (Section 16).
#[derive(Debug)]
pub struct BootstrapState {
    /// Whether bootstrap is complete (all peer requests done, queues empty).
    pub drained: bool,
    /// Number of bootstrap peer requests still pending.
    pub pending_peer_requests: usize,
    /// Keys discovered during bootstrap that are still in the verification /
    /// fetch pipeline.
    pub pending_keys: HashSet<XorName>,
}

impl BootstrapState {
    /// Create initial bootstrap state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            drained: false,
            pending_peer_requests: 0,
            pending_keys: HashSet::new(),
        }
    }

    /// Check if bootstrap is drained.
    ///
    /// Only returns `true` after [`super::bootstrap::check_bootstrap_drained`] or
    /// [`super::bootstrap::mark_bootstrap_drained`] has explicitly set the flag. A fresh
    /// `BootstrapState` is NOT drained — the audit loop must wait until
    /// bootstrap work has actually completed (Invariant 19).
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.drained
    }

    /// Remove a key from the bootstrap pending set.
    ///
    /// Called when a key terminally leaves the verification/fetch pipeline
    /// (stored, abandoned, quorum failed, etc.) so the drain check set
    /// shrinks incrementally rather than being re-scanned in full.
    pub fn remove_key(&mut self, key: &XorName) {
        self.pending_keys.remove(key);
    }
}

impl Default for BootstrapState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BinaryHeap;

    use super::*;

    /// Helper: build a `PeerId` from a single byte (zero-padded to 32 bytes).
    fn peer_id_from_byte(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    // -- FetchCandidate ordering -------------------------------------------

    #[test]
    fn fetch_candidate_nearest_key_has_highest_priority() {
        let near = FetchCandidate {
            key: [1u8; 32],
            distance: [
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            sources: vec![peer_id_from_byte(1)],
        };

        let far = FetchCandidate {
            key: [2u8; 32],
            distance: [
                0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            sources: vec![peer_id_from_byte(2)],
        };

        // In a max-heap the "greatest" element pops first.
        // Our reversed Ord makes smaller-distance candidates greater.
        assert!(near > far, "nearer candidate should compare greater");

        let mut heap = BinaryHeap::new();
        heap.push(far.clone());
        heap.push(near.clone());

        assert_eq!(heap.len(), 2, "heap should contain both candidates");

        let first = heap.pop();
        assert!(first.is_some(), "first pop should succeed");
        assert_eq!(
            first.map(|c| c.key),
            Some(near.key),
            "nearest key should pop first"
        );

        let second = heap.pop();
        assert!(second.is_some(), "second pop should succeed");
        assert_eq!(
            second.map(|c| c.key),
            Some(far.key),
            "farthest key should pop second"
        );
    }

    #[test]
    fn fetch_candidate_same_distance_and_key_is_equal() {
        let a = FetchCandidate {
            key: [1u8; 32],
            distance: [5u8; 32],
            sources: vec![],
        };

        let b = FetchCandidate {
            key: [1u8; 32],
            distance: [5u8; 32],
            sources: vec![],
        };

        assert_eq!(
            a.cmp(&b),
            Ordering::Equal,
            "same distance + same key should yield Equal"
        );
        assert_eq!(a, b, "PartialEq must agree with Ord");
    }

    #[test]
    fn fetch_candidate_same_distance_different_key_is_deterministic() {
        let a = FetchCandidate {
            key: [1u8; 32],
            distance: [5u8; 32],
            sources: vec![],
        };

        let b = FetchCandidate {
            key: [2u8; 32],
            distance: [5u8; 32],
            sources: vec![],
        };

        assert_ne!(
            a.cmp(&b),
            Ordering::Equal,
            "same distance + different key must not be Equal"
        );
        assert_ne!(a, b, "PartialEq must agree with Ord");
    }

    // -- PeerSyncRecord ----------------------------------------------------

    #[test]
    fn peer_sync_record_no_sync_yet() {
        let record = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 0,
        };
        assert!(
            !record.has_repair_opportunity(),
            "never-synced peer has no repair opportunity"
        );
    }

    #[test]
    fn peer_sync_record_synced_but_no_cycle() {
        let record = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 0,
        };
        assert!(
            !record.has_repair_opportunity(),
            "synced peer with zero subsequent cycles has no repair opportunity"
        );
    }

    #[test]
    fn peer_sync_record_synced_with_cycle() {
        let record = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 1,
        };
        assert!(
            record.has_repair_opportunity(),
            "synced peer with >= 1 cycle should have repair opportunity"
        );
    }

    #[test]
    fn peer_sync_record_no_sync_many_cycles() {
        let record = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 10,
        };
        assert!(
            !record.has_repair_opportunity(),
            "never-synced peer has no repair opportunity regardless of cycle count"
        );
    }

    // -- NeighborSyncState -------------------------------------------------

    #[test]
    fn neighbor_sync_empty_cycle_is_immediately_complete() {
        let state = NeighborSyncState::new_cycle(vec![]);
        assert!(
            state.is_cycle_complete(),
            "empty neighbor list means cycle is complete"
        );
    }

    #[test]
    fn neighbor_sync_new_cycle_not_complete() {
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let state = NeighborSyncState::new_cycle(peers);
        assert!(
            !state.is_cycle_complete(),
            "fresh cycle with peers should not be complete"
        );
    }

    #[test]
    fn neighbor_sync_cycle_completes_when_cursor_reaches_end() {
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);

        // Simulate stepping through the cycle.
        state.cursor = 2;
        assert!(
            !state.is_cycle_complete(),
            "cursor at len-1 should not be complete"
        );

        state.cursor = 3;
        assert!(
            state.is_cycle_complete(),
            "cursor at len should be complete"
        );
    }

    #[test]
    fn neighbor_sync_cursor_past_end_is_still_complete() {
        let peers = vec![peer_id_from_byte(1)];
        let mut state = NeighborSyncState::new_cycle(peers);
        state.cursor = 5;
        assert!(
            state.is_cycle_complete(),
            "cursor past end should still report complete"
        );
    }

    // -- BootstrapState ----------------------------------------------------

    #[test]
    fn bootstrap_state_initial_not_drained() {
        // A freshly created state must NOT report drained — the bootstrap
        // sync task has not started yet (Invariant 19 race prevention).
        let state = BootstrapState::new();
        assert!(
            !state.is_drained(),
            "initial state must not be drained before bootstrap begins"
        );
    }

    #[test]
    fn bootstrap_state_pending_requests_block_drain() {
        let mut state = BootstrapState::new();
        state.pending_peer_requests = 3;
        assert!(
            !state.is_drained(),
            "pending peer requests should block drain"
        );
    }

    #[test]
    fn bootstrap_state_pending_keys_block_drain() {
        let mut state = BootstrapState::new();
        state.pending_keys.insert([42u8; 32]);
        assert!(!state.is_drained(), "pending keys should block drain");
    }

    #[test]
    fn bootstrap_state_explicit_drained_overrides() {
        let mut state = BootstrapState::new();
        state.pending_peer_requests = 5;
        state.pending_keys.insert([99u8; 32]);
        state.drained = true;
        assert!(
            state.is_drained(),
            "explicit drained flag should override pending counts"
        );
    }

    #[test]
    fn bootstrap_state_requires_explicit_drain() {
        let mut state = BootstrapState::new();
        state.pending_peer_requests = 2;
        state.pending_keys.insert([1u8; 32]);

        // Simulate completing work — but without explicit drain flag.
        state.pending_peer_requests = 0;
        state.pending_keys.clear();

        assert!(
            !state.is_drained(),
            "clearing counters alone must not drain — requires check_bootstrap_drained"
        );

        // Explicit drain (set by check_bootstrap_drained or mark_bootstrap_drained).
        state.drained = true;
        assert!(state.is_drained(), "explicit flag should drain");
    }

    #[test]
    fn bootstrap_state_default_matches_new() {
        let from_new = BootstrapState::new();
        let from_default = BootstrapState::default();

        assert_eq!(from_new.drained, from_default.drained);
        assert_eq!(
            from_new.pending_peer_requests,
            from_default.pending_peer_requests
        );
        assert_eq!(from_new.pending_keys, from_default.pending_keys);
    }

    // -- Scenario tests -------------------------------------------------------

    /// #13: Bootstrap not drained while `pending_keys` overlap with the
    /// pipeline. Keys must be removed from `pending_keys` for drain to occur.
    #[test]
    fn bootstrap_drain_requires_empty_pending_keys() {
        let key_a: XorName = [0xA0; 32];
        let key_b: XorName = [0xB0; 32];
        let key_c: XorName = [0xC0; 32];

        let mut state = BootstrapState::new();
        state.pending_peer_requests = 0; // requests already done
        state.pending_keys = std::iter::once(key_a)
            .chain(std::iter::once(key_b))
            .chain(std::iter::once(key_c))
            .collect();

        assert!(
            !state.is_drained(),
            "should NOT be drained while pending_keys still has entries"
        );

        // Simulate pipeline processing — remove one key at a time.
        state.pending_keys.remove(&key_a);
        assert!(!state.is_drained(), "still not drained with 2 pending keys");

        state.pending_keys.remove(&key_b);
        assert!(!state.is_drained(), "still not drained with 1 pending key");

        state.pending_keys.remove(&key_c);
        assert!(
            !state.is_drained(),
            "removing all keys is necessary but not sufficient — needs explicit drain"
        );

        // Simulate check_bootstrap_drained setting the flag.
        state.drained = true;
        assert!(state.is_drained(), "explicit drain flag should finalize");
    }

    /// Verify that the FSM terminal states are distinguishable and document
    /// which variants are logically terminal (no outgoing transitions).
    #[test]
    fn verification_state_terminal_variants() {
        let terminal_states = [
            VerificationState::QuorumAbandoned,
            VerificationState::FetchAbandoned,
            VerificationState::Stored,
            VerificationState::Idle,
        ];

        // All terminal states must be distinct from each other.
        for (i, a) in terminal_states.iter().enumerate() {
            for (j, b) in terminal_states.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a, b,
                        "terminal states at indices {i} and {j} must be distinct"
                    );
                }
            }
        }

        // Terminal states must be distinct from all non-terminal states.
        let non_terminal_states = [
            VerificationState::OfferReceived,
            VerificationState::PendingVerify,
            VerificationState::QuorumVerified,
            VerificationState::PaidListVerified,
            VerificationState::QueuedForFetch,
            VerificationState::Fetching,
            VerificationState::FetchRetryable,
            VerificationState::QuorumFailed,
            VerificationState::QuorumInconclusive,
        ];

        for terminal in &terminal_states {
            for non_terminal in &non_terminal_states {
                assert_ne!(
                    terminal, non_terminal,
                    "terminal state {terminal:?} must not equal non-terminal state {non_terminal:?}"
                );
            }
        }
    }

    /// `has_repair_opportunity` requires BOTH a previous sync AND at least
    /// one subsequent cycle.
    #[test]
    fn repair_opportunity_requires_both_sync_and_cycle() {
        // last_sync = Some, cycles_since_sync = 0 → false (synced but no cycle yet)
        let synced_no_cycle = PeerSyncRecord {
            last_sync: Some(
                Instant::now()
                    .checked_sub(std::time::Duration::from_secs(2))
                    .unwrap_or_else(Instant::now),
            ),
            cycles_since_sync: 0,
        };
        assert!(
            !synced_no_cycle.has_repair_opportunity(),
            "synced with zero subsequent cycles should NOT have repair opportunity"
        );

        // last_sync = None, cycles_since_sync = 5 → false (never synced)
        let never_synced = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 5,
        };
        assert!(
            !never_synced.has_repair_opportunity(),
            "never-synced peer should NOT have repair opportunity regardless of cycles"
        );

        // last_sync = Some, cycles_since_sync = 1 → true
        let ready = PeerSyncRecord {
            last_sync: Some(
                Instant::now()
                    .checked_sub(std::time::Duration::from_secs(5))
                    .unwrap_or_else(Instant::now),
            ),
            cycles_since_sync: 1,
        };
        assert!(
            ready.has_repair_opportunity(),
            "synced peer with >= 1 cycle SHOULD have repair opportunity"
        );
    }
}
