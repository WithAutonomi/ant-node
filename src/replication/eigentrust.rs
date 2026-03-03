//! `EigenTrust` integration for replication evidence (Section 14).
//!
//! Defines the evidence types emitted by replication and a trait-based
//! interface for decoupling from the trust subsystem. The actual trust
//! score computation is outside replication scope.

use crate::client::XorName;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Evidence types (Section 14)
// ---------------------------------------------------------------------------

/// Evidence of a failed fetch attempt from a source peer.
///
/// Emitted per peer per failed fetch attempt (Section 14, rule 3).
#[derive(Debug, Clone)]
pub struct ReplicationFailure {
    /// Peer that failed to serve the record.
    pub source_peer: String,
    /// Key that was being fetched.
    pub key: XorName,
    /// Whether the key was later successfully fetched from an alternate source.
    pub stale: bool,
}

/// Evidence of a storage audit failure.
///
/// Emitted only after responsibility confirmation (Section 15, step 11d).
#[derive(Debug, Clone)]
pub struct AuditFailure {
    /// Unique challenge identifier.
    pub challenge_id: u64,
    /// Peer that was challenged.
    pub challenged_peer: String,
    /// Keys confirmed failed after responsibility check.
    pub confirmed_failed_keys: Vec<XorName>,
    /// Human-readable failure reason.
    pub reason: String,
}

/// Evidence of bootstrap claim abuse (Section 14, rule 7).
///
/// Emitted when a peer continues claiming bootstrap status after
/// `BOOTSTRAP_CLAIM_GRACE_PERIOD` has elapsed.
#[derive(Debug, Clone)]
pub struct BootstrapClaimAbuse {
    /// Peer making the stale bootstrap claim.
    pub peer_id: String,
    /// When the peer first claimed bootstrap status.
    pub first_seen: Instant,
}

// ---------------------------------------------------------------------------
// Evidence trait (Section 14, rule 1)
// ---------------------------------------------------------------------------

/// Trait for emitting replication trust evidence to the `EigenTrust` subsystem.
///
/// Replication MUST emit evidence through this trait. Trust-score computation
/// and peer eviction decisions are owned by the `EigenTrust` implementation
/// (Section 14, rules 2, 9).
pub trait EigenTrustSink: Send + Sync {
    /// Report a failed fetch attempt.
    fn report_replication_failure(&self, evidence: ReplicationFailure);

    /// Report a confirmed audit failure.
    ///
    /// The caller MUST have already run responsibility confirmation
    /// (Section 15, step 11) before calling this.
    fn report_audit_failure(&self, evidence: AuditFailure);

    /// Report bootstrap claim abuse.
    fn report_bootstrap_claim_abuse(&self, evidence: BootstrapClaimAbuse);

    /// Mark a previous `ReplicationFailure` as stale/low-confidence
    /// because the key was later fetched from an alternate source (Section 14, rule 4).
    fn mark_failure_stale(&self, source_peer: &str, key: &XorName);
}

// ---------------------------------------------------------------------------
// No-op stub implementation
// ---------------------------------------------------------------------------

/// No-op `EigenTrust` sink that discards all evidence.
///
/// Used as a placeholder until the saorsa-core trust API is available.
#[derive(Debug, Default)]
pub struct NoOpEigenTrust;

impl EigenTrustSink for NoOpEigenTrust {
    fn report_replication_failure(&self, _evidence: ReplicationFailure) {}
    fn report_audit_failure(&self, _evidence: AuditFailure) {}
    fn report_bootstrap_claim_abuse(&self, _evidence: BootstrapClaimAbuse) {}
    fn mark_failure_stale(&self, _source_peer: &str, _key: &XorName) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_does_not_panic() {
        let sink = NoOpEigenTrust;

        sink.report_replication_failure(ReplicationFailure {
            source_peer: "peer_a".to_string(),
            key: [0x01; 32],
            stale: false,
        });

        sink.report_audit_failure(AuditFailure {
            challenge_id: 1,
            challenged_peer: "peer_b".to_string(),
            confirmed_failed_keys: vec![[0x02; 32]],
            reason: "digest mismatch".to_string(),
        });

        sink.report_bootstrap_claim_abuse(BootstrapClaimAbuse {
            peer_id: "peer_c".to_string(),
            first_seen: Instant::now(),
        });

        sink.mark_failure_stale("peer_a", &[0x01; 32]);
    }

    #[test]
    fn test_replication_failure_fields() {
        let evidence = ReplicationFailure {
            source_peer: "peer_x".to_string(),
            key: [0xAA; 32],
            stale: false,
        };
        assert_eq!(evidence.source_peer, "peer_x");
        assert_eq!(evidence.key, [0xAA; 32]);
        assert!(!evidence.stale);
    }

    #[test]
    fn test_audit_failure_fields() {
        let evidence = AuditFailure {
            challenge_id: 42,
            challenged_peer: "peer_y".to_string(),
            confirmed_failed_keys: vec![[0xBB; 32], [0xCC; 32]],
            reason: "timeout".to_string(),
        };
        assert_eq!(evidence.challenge_id, 42);
        assert_eq!(evidence.confirmed_failed_keys.len(), 2);
    }
}
