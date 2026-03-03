//! New-node bootstrap sync logic (Section 16).
//!
//! Manages the bootstrap lifecycle: peer request tracking, work-queue
//! draining detection, and `BootstrapDrained` transition.
//!
//! All functions are pure state management (no networking). The caller
//! drives the bootstrap by feeding events into the tracker.

use crate::client::XorName;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Peer request tracking (Section 16, steps 2-3)
// ---------------------------------------------------------------------------

/// Status of a bootstrap peer request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRequestStatus {
    /// Request sent, awaiting response.
    Pending,
    /// Response received and processed.
    Completed,
    /// Request timed out or peer was unreachable.
    TimedOut,
}

/// Tracks bootstrap peer request lifecycle.
#[derive(Debug)]
pub struct BootstrapTracker {
    /// Per-peer request status.
    peer_status: Vec<(String, PeerRequestStatus)>,
    /// Keys discovered during bootstrap that need verification.
    pending_verify: HashSet<XorName>,
    /// Keys in the fetch pipeline.
    pending_fetch: HashSet<XorName>,
    /// Whether `BootstrapDrained` has been set.
    drained: bool,
}

impl BootstrapTracker {
    /// Create a new tracker for the given set of bootstrap peers.
    #[must_use]
    pub fn new(peers: &[(String, XorName)]) -> Self {
        let peer_status = peers
            .iter()
            .map(|(id, _)| (id.clone(), PeerRequestStatus::Pending))
            .collect();

        Self {
            peer_status,
            pending_verify: HashSet::new(),
            pending_fetch: HashSet::new(),
            drained: false,
        }
    }

    /// Record that a peer responded successfully.
    pub fn mark_completed(&mut self, peer_id: &str) {
        if let Some((_, status)) = self.peer_status.iter_mut().find(|(id, _)| id == peer_id) {
            *status = PeerRequestStatus::Completed;
        }
    }

    /// Record that a peer request timed out.
    pub fn mark_timed_out(&mut self, peer_id: &str) {
        if let Some((_, status)) = self.peer_status.iter_mut().find(|(id, _)| id == peer_id) {
            *status = PeerRequestStatus::TimedOut;
        }
    }

    /// Add keys discovered during bootstrap that need verification.
    pub fn add_pending_verify(&mut self, keys: &[XorName]) {
        for key in keys {
            self.pending_verify.insert(*key);
        }
    }

    /// Mark a key as verified (moved to fetch or rejected).
    pub fn remove_pending_verify(&mut self, key: &XorName) {
        self.pending_verify.remove(key);
    }

    /// Add keys that are in the fetch pipeline.
    pub fn add_pending_fetch(&mut self, keys: &[XorName]) {
        for key in keys {
            self.pending_fetch.insert(*key);
        }
    }

    /// Mark a key as fetched (completed or abandoned).
    pub fn remove_pending_fetch(&mut self, key: &XorName) {
        self.pending_fetch.remove(key);
    }

    /// Check if all peer requests have finished (response or timeout).
    #[must_use]
    pub fn all_peers_finished(&self) -> bool {
        self.peer_status
            .iter()
            .all(|(_, s)| *s != PeerRequestStatus::Pending)
    }

    /// Check if all bootstrap work queues are empty.
    #[must_use]
    pub fn queues_empty(&self) -> bool {
        self.pending_verify.is_empty() && self.pending_fetch.is_empty()
    }

    /// Check and transition `BootstrapDrained` (Section 16, step 9).
    ///
    /// Returns `true` if this call is the transition from `false` to `true`.
    pub fn check_drained(&mut self) -> bool {
        if self.drained {
            return false; // Already drained, no transition
        }

        if self.all_peers_finished() && self.queues_empty() {
            self.drained = true;
            true // Transition occurred
        } else {
            false
        }
    }

    /// Whether bootstrap is fully drained.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.drained
    }

    /// Number of peers still pending.
    #[must_use]
    pub fn peers_pending(&self) -> usize {
        self.peer_status
            .iter()
            .filter(|(_, s)| *s == PeerRequestStatus::Pending)
            .count()
    }

    /// Total number of bootstrap peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peer_status.len()
    }

    /// Number of keys pending verification.
    #[must_use]
    pub fn pending_verify_count(&self) -> usize {
        self.pending_verify.len()
    }

    /// Number of keys pending fetch.
    #[must_use]
    pub fn pending_fetch_count(&self) -> usize {
        self.pending_fetch.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_peers(n: usize) -> Vec<(String, XorName)> {
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
    fn test_new_tracker() {
        let peers = make_peers(3);
        let tracker = BootstrapTracker::new(&peers);

        assert_eq!(tracker.peer_count(), 3);
        assert_eq!(tracker.peers_pending(), 3);
        assert!(!tracker.is_drained());
        assert!(!tracker.all_peers_finished());
    }

    #[test]
    fn test_mark_completed() {
        let peers = make_peers(2);
        let mut tracker = BootstrapTracker::new(&peers);

        tracker.mark_completed("peer_0");
        assert_eq!(tracker.peers_pending(), 1);

        tracker.mark_completed("peer_1");
        assert_eq!(tracker.peers_pending(), 0);
        assert!(tracker.all_peers_finished());
    }

    #[test]
    fn test_mark_timed_out() {
        let peers = make_peers(2);
        let mut tracker = BootstrapTracker::new(&peers);

        tracker.mark_timed_out("peer_0");
        tracker.mark_completed("peer_1");
        assert!(tracker.all_peers_finished());
    }

    #[test]
    fn test_drained_requires_peers_finished_and_queues_empty() {
        let peers = make_peers(1);
        let mut tracker = BootstrapTracker::new(&peers);

        // Queues empty but peer still pending
        assert!(!tracker.check_drained());

        // Add pending verify work
        tracker.add_pending_verify(&[[0x01; 32]]);
        tracker.mark_completed("peer_0");

        // Peer finished but queue not empty
        assert!(!tracker.check_drained());

        // Clear queue
        tracker.remove_pending_verify(&[0x01; 32]);
        assert!(tracker.check_drained()); // Transition!
        assert!(tracker.is_drained());
    }

    #[test]
    fn test_drained_transition_fires_once() {
        let peers = make_peers(1);
        let mut tracker = BootstrapTracker::new(&peers);
        tracker.mark_completed("peer_0");

        let first = tracker.check_drained();
        let second = tracker.check_drained();

        assert!(first); // First call is the transition
        assert!(!second); // Already drained
    }

    #[test]
    fn test_pending_verify_and_fetch_tracking() {
        let peers = make_peers(1);
        let mut tracker = BootstrapTracker::new(&peers);
        tracker.mark_completed("peer_0");

        let key1 = [0xAA; 32];
        let key2 = [0xBB; 32];

        tracker.add_pending_verify(&[key1, key2]);
        assert_eq!(tracker.pending_verify_count(), 2);
        assert!(!tracker.queues_empty());

        tracker.remove_pending_verify(&key1);
        tracker.remove_pending_verify(&key2);

        tracker.add_pending_fetch(&[key1]);
        assert_eq!(tracker.pending_fetch_count(), 1);
        assert!(!tracker.queues_empty());

        tracker.remove_pending_fetch(&key1);
        assert!(tracker.queues_empty());
    }

    #[test]
    fn test_empty_bootstrap() {
        // Edge case: no peers at all
        let mut tracker = BootstrapTracker::new(&[]);

        assert!(tracker.all_peers_finished());
        assert!(tracker.queues_empty());
        assert!(tracker.check_drained());
        assert!(tracker.is_drained());
    }

    #[test]
    fn test_mark_unknown_peer_is_noop() {
        let peers = make_peers(1);
        let mut tracker = BootstrapTracker::new(&peers);

        // Marking an unknown peer should not panic or change state
        tracker.mark_completed("unknown");
        assert_eq!(tracker.peers_pending(), 1);
    }
}
