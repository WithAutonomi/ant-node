//! Core replication types (Section 3 of the design spec).

use crate::client::XorName;
use std::collections::HashMap;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Evidence types (Section 7.5, 7.6)
// ---------------------------------------------------------------------------

/// Binary presence evidence for a key on a given peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceEvidence {
    /// Key exists locally on the peer.
    Present,
    /// Key not found locally on the peer.
    Absent,
    /// Timeout / no-response (neutral, not a negative vote).
    Unresolved,
}

/// Paid-list evidence for a key on a given peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaidListEvidence {
    /// Key is in the peer's `PaidForList`.
    Paid,
    /// Key is NOT in the peer's `PaidForList`.
    NotPaid,
    /// Timeout / no-response (neutral).
    Unresolved,
}

// ---------------------------------------------------------------------------
// Hint pipeline discriminator (Section 6.2 rule 9)
// ---------------------------------------------------------------------------

/// Which pipeline a hint-discovered key follows.
///
/// Cross-set precedence: if a key appears in both replica and paid hints,
/// only the `Replica` pipeline is used (Section 6.2 rule 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintPipeline {
    /// Key is in the admitted replica-hint pipeline (fetch-eligible).
    Replica,
    /// Key is in the paid-hint-only pipeline (`PaidForList` update only, no fetch).
    PaidOnly,
}

impl HintPipeline {
    /// Whether this pipeline allows record fetch.
    #[must_use]
    pub fn is_fetch_eligible(&self) -> bool {
        matches!(self, Self::Replica)
    }
}

// ---------------------------------------------------------------------------
// Per-key per-peer evidence (Section 9)
// ---------------------------------------------------------------------------

/// Collected evidence for a single key from a single peer during verification.
#[derive(Debug, Clone, Copy)]
pub struct PeerKeyEvidence {
    /// Presence evidence.
    pub presence: PresenceEvidence,
    /// Paid-list evidence (only populated for peers in `PaidTargets`).
    pub paid_list: PaidListEvidence,
}

impl PeerKeyEvidence {
    /// Create evidence where both fields are unresolved.
    #[must_use]
    pub fn unresolved() -> Self {
        Self {
            presence: PresenceEvidence::Unresolved,
            paid_list: PaidListEvidence::Unresolved,
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap claim tracker (Section 6.2 rule 3b, Section 14)
// ---------------------------------------------------------------------------

/// Tracks when each peer first claimed bootstrap status.
///
/// Used to enforce `BOOTSTRAP_CLAIM_GRACE_PERIOD` before emitting
/// `BootstrapClaimAbuse` evidence.
#[derive(Debug, Default)]
pub struct BootstrapClaimTracker {
    /// Peer ID → first-observed bootstrap claim time.
    claims: HashMap<String, Instant>,
}

impl BootstrapClaimTracker {
    /// Record a bootstrap claim from a peer. Returns the first-seen time.
    pub fn record_claim(&mut self, peer_id: &str) -> Instant {
        *self
            .claims
            .entry(peer_id.to_string())
            .or_insert_with(Instant::now)
    }

    /// Clear a bootstrap claim (peer responded normally).
    pub fn clear_claim(&mut self, peer_id: &str) {
        self.claims.remove(peer_id);
    }

    /// Get the first-seen time for a peer's bootstrap claim, if any.
    #[must_use]
    pub fn first_seen(&self, peer_id: &str) -> Option<Instant> {
        self.claims.get(peer_id).copied()
    }

    /// Check if the grace period has elapsed for a peer.
    #[must_use]
    pub fn is_past_grace_period(&self, peer_id: &str, grace_period: std::time::Duration) -> bool {
        self.claims
            .get(peer_id)
            .is_some_and(|first_seen| first_seen.elapsed() >= grace_period)
    }
}

// ---------------------------------------------------------------------------
// Verification key context
// ---------------------------------------------------------------------------

/// Context carried for a key undergoing verification.
#[derive(Debug, Clone)]
pub struct VerificationContext {
    /// The key being verified.
    pub key: XorName,
    /// Which pipeline this key follows.
    pub pipeline: HintPipeline,
    /// Peers that responded `Present` (verified fetch sources).
    pub present_peers: Vec<String>,
    /// Peers already tried for fetch (to avoid retrying).
    pub tried_sources: Vec<String>,
}

impl VerificationContext {
    /// Create a new verification context.
    #[must_use]
    pub fn new(key: XorName, pipeline: HintPipeline) -> Self {
        Self {
            key,
            pipeline,
            present_peers: Vec::new(),
            tried_sources: Vec::new(),
        }
    }

    /// Get the next untried source peer, if any.
    #[must_use]
    pub fn next_untried_source(&self) -> Option<&str> {
        self.present_peers
            .iter()
            .find(|p| !self.tried_sources.contains(p))
            .map(String::as_str)
    }

    /// Mark a source as tried.
    pub fn mark_tried(&mut self, peer_id: &str) {
        if !self.tried_sources.iter().any(|p| p == peer_id) {
            self.tried_sources.push(peer_id.to_string());
        }
    }

    /// Whether any untried verified source remains.
    #[must_use]
    pub fn has_untried_sources(&self) -> bool {
        self.next_untried_source().is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_hint_pipeline_fetch_eligibility() {
        assert!(HintPipeline::Replica.is_fetch_eligible());
        assert!(!HintPipeline::PaidOnly.is_fetch_eligible());
    }

    #[test]
    fn test_peer_key_evidence_unresolved() {
        let evidence = PeerKeyEvidence::unresolved();
        assert_eq!(evidence.presence, PresenceEvidence::Unresolved);
        assert_eq!(evidence.paid_list, PaidListEvidence::Unresolved);
    }

    #[test]
    fn test_bootstrap_claim_tracker() {
        let mut tracker = BootstrapClaimTracker::default();
        let grace = std::time::Duration::from_secs(10);

        // First claim
        let first = tracker.record_claim("peer1");
        assert_eq!(tracker.first_seen("peer1"), Some(first));

        // Second call returns same instant
        let second = tracker.record_claim("peer1");
        assert_eq!(first, second);

        // Not past grace period yet
        assert!(!tracker.is_past_grace_period("peer1", grace));

        // Clear and check
        tracker.clear_claim("peer1");
        assert!(tracker.first_seen("peer1").is_none());
    }

    #[test]
    fn test_verification_context_sources() {
        let key = [0xAA; 32];
        let mut ctx = VerificationContext::new(key, HintPipeline::Replica);

        ctx.present_peers.push("peer_a".to_string());
        ctx.present_peers.push("peer_b".to_string());

        assert_eq!(ctx.next_untried_source(), Some("peer_a"));
        assert!(ctx.has_untried_sources());

        ctx.mark_tried("peer_a");
        assert_eq!(ctx.next_untried_source(), Some("peer_b"));

        ctx.mark_tried("peer_b");
        assert!(ctx.next_untried_source().is_none());
        assert!(!ctx.has_untried_sources());
    }
}
