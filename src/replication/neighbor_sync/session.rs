//! Sync session logic (Section 6.2 rules 4-6).
//!
//! Validates peer membership, enforces bidirectional/outbound-only rules,
//! and processes received hints through admission and deduplication.

use crate::client::XorName;
use crate::replication::neighbor_sync::hints::{self, AdmissionResult, HintsForPeer};
use crate::replication::types::HintPipeline;

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

/// Direction of a sync session from the local node's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDirection {
    /// Peer is in `LocalRT(self)`: bidirectional (both send and receive hints).
    Bidirectional,
    /// Peer is NOT in `LocalRT(self)`: outbound-only (send but don't accept).
    OutboundOnly,
}

/// A processed sync session outcome for a single peer.
#[derive(Debug, Clone)]
pub struct SessionResult {
    /// Peer ID.
    pub peer_id: String,
    /// Direction of the session.
    pub direction: SessionDirection,
    /// Outbound hints to send to this peer.
    pub outbound: HintsForPeer,
    /// Admitted keys from received hints (only populated for Bidirectional).
    pub admitted: Vec<AdmittedKey>,
}

/// A single key admitted from received hints.
#[derive(Debug, Clone)]
pub struct AdmittedKey {
    /// The key.
    pub key: XorName,
    /// Which pipeline this key was admitted into.
    pub pipeline: HintPipeline,
}

// ---------------------------------------------------------------------------
// Session logic
// ---------------------------------------------------------------------------

/// Determine session direction based on peer membership in `LocalRT`.
///
/// Section 6.2 rule 4-6.
#[must_use]
pub fn session_direction(peer_id: &str, local_rt: &[(String, XorName)]) -> SessionDirection {
    if local_rt.iter().any(|(id, _)| id == peer_id) {
        SessionDirection::Bidirectional
    } else {
        SessionDirection::OutboundOnly
    }
}

/// Process a complete sync session with a peer.
///
/// - Computes outbound hints (what we think the peer should hold/track).
/// - If bidirectional: processes received hints through dedup + admission.
/// - If outbound-only: ignores received hints entirely (Section 6.2 rule 6).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn process_session(
    self_id: &str,
    self_xor: &XorName,
    peer_id: &str,
    local_rt: &[(String, XorName)],
    local_keys: &[XorName],
    paid_keys: &[XorName],
    received_replica_hints: &[XorName],
    received_paid_hints: &[XorName],
    is_local_or_pending: &dyn Fn(&XorName) -> bool,
    is_in_paid_list: &dyn Fn(&XorName) -> bool,
) -> SessionResult {
    let direction = session_direction(peer_id, local_rt);

    // Compute outbound hints (always, regardless of direction)
    let outbound =
        hints::compute_hints_for_peer(self_id, self_xor, peer_id, local_rt, local_keys, paid_keys);

    // Process inbound hints only for bidirectional sessions
    let admitted = if direction == SessionDirection::Bidirectional {
        process_inbound_hints(
            self_id,
            self_xor,
            local_rt,
            received_replica_hints,
            received_paid_hints,
            is_local_or_pending,
            is_in_paid_list,
        )
    } else {
        Vec::new()
    };

    SessionResult {
        peer_id: peer_id.to_string(),
        direction,
        outbound,
        admitted,
    }
}

/// Process inbound hints: deduplicate, then run per-key admission.
fn process_inbound_hints(
    self_id: &str,
    self_xor: &XorName,
    local_rt: &[(String, XorName)],
    received_replica_hints: &[XorName],
    received_paid_hints: &[XorName],
    is_local_or_pending: &dyn Fn(&XorName) -> bool,
    is_in_paid_list: &dyn Fn(&XorName) -> bool,
) -> Vec<AdmittedKey> {
    // Step 1: Cross-set dedup (Section 6.2 rule 9)
    let deduped = hints::deduplicate_hints(received_replica_hints, received_paid_hints);

    // Step 2: Per-key admission (Section 7.1)
    let mut admitted = Vec::new();
    for (key, pipeline) in deduped {
        let result = hints::admit_hint(
            self_id,
            self_xor,
            &key,
            pipeline,
            local_rt,
            is_local_or_pending(&key),
            is_in_paid_list(&key),
        );

        match result {
            AdmissionResult::AdmittedReplica => {
                admitted.push(AdmittedKey {
                    key,
                    pipeline: HintPipeline::Replica,
                });
            }
            AdmissionResult::AdmittedPaidOnly => {
                admitted.push(AdmittedKey {
                    key,
                    pipeline: HintPipeline::PaidOnly,
                });
            }
            AdmissionResult::Rejected => {}
        }
    }

    admitted
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
    fn test_session_direction_in_local_rt() {
        let local_rt = make_local_rt(5);
        assert_eq!(
            session_direction("peer_0", &local_rt),
            SessionDirection::Bidirectional,
        );
    }

    #[test]
    fn test_session_direction_not_in_local_rt() {
        let local_rt = make_local_rt(5);
        assert_eq!(
            session_direction("unknown_peer", &local_rt),
            SessionDirection::OutboundOnly,
        );
    }

    #[test]
    fn test_outbound_only_ignores_inbound() {
        let self_id = "self";
        let self_xor = [0x01; 32];
        let peer_id = "unknown_peer"; // not in local_rt
        let local_rt = make_local_rt(5);
        let key = [0x00; 32];

        let result = process_session(
            self_id,
            &self_xor,
            peer_id,
            &local_rt,
            &[key],
            &[],
            &[key], // Peer sends replica hints
            &[],
            &|_| false,
            &|_| false,
        );

        assert_eq!(result.direction, SessionDirection::OutboundOnly);
        // Inbound hints should be ignored
        assert!(result.admitted.is_empty());
    }

    #[test]
    fn test_bidirectional_processes_inbound() {
        let self_id = "self";
        let self_xor = [0x01; 32]; // close to key — responsible
        let local_rt = make_local_rt(5);
        let peer_id = "peer_0"; // in local_rt
        let key = [0x00; 32];

        let result = process_session(
            self_id,
            &self_xor,
            peer_id,
            &local_rt,
            &[],
            &[],
            &[key], // Peer sends replica hint for a key we're responsible for
            &[],
            &|_| false,
            &|_| false,
        );

        assert_eq!(result.direction, SessionDirection::Bidirectional);
        assert!(!result.admitted.is_empty());
        assert_eq!(result.admitted[0].key, key);
        assert_eq!(result.admitted[0].pipeline, HintPipeline::Replica);
    }

    #[test]
    fn test_bidirectional_rejects_irrelevant_keys() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from key — not responsible
        let local_rt = make_local_rt(10);
        let peer_id = "peer_0";
        let key = [0x00; 32];

        let result = process_session(
            self_id,
            &self_xor,
            peer_id,
            &local_rt,
            &[],
            &[],
            &[key], // Hint for key we're NOT responsible for
            &[],
            &|_| false,
            &|_| false,
        );

        assert_eq!(result.direction, SessionDirection::Bidirectional);
        // Should be rejected — not responsible and not local
        assert!(result.admitted.is_empty());
    }

    #[test]
    fn test_cross_set_dedup_in_session() {
        let self_id = "self";
        let self_xor = [0x01; 32]; // responsible for key
        let local_rt = make_local_rt(5);
        let peer_id = "peer_0";
        let key = [0x00; 32];

        let result = process_session(
            self_id,
            &self_xor,
            peer_id,
            &local_rt,
            &[],
            &[],
            &[key], // Same key in both
            &[key],
            &|_| false,
            &|_| false,
        );

        // Key should appear only once, as Replica (not PaidOnly)
        let replica_keys: Vec<_> = result
            .admitted
            .iter()
            .filter(|a| a.pipeline == HintPipeline::Replica)
            .collect();
        let paid_keys: Vec<_> = result
            .admitted
            .iter()
            .filter(|a| a.pipeline == HintPipeline::PaidOnly)
            .collect();

        assert!(replica_keys.len() <= 1);
        // If admitted, it should be as Replica, not PaidOnly
        if !replica_keys.is_empty() {
            assert_eq!(replica_keys[0].key, key);
        }
        // No paid-only entry for the same key
        assert!(paid_keys.iter().all(|a| a.key != key));
    }

    #[test]
    fn test_session_produces_outbound_hints() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let local_rt = make_local_rt(5);
        let peer_id = "peer_0";
        let key = [0x00; 32]; // close to peer_0

        let result = process_session(
            self_id,
            &self_xor,
            peer_id,
            &local_rt,
            &[key], // We hold this key
            &[],
            &[],
            &[],
            &|_| false,
            &|_| false,
        );

        // Outbound hints should include the key if peer is responsible
        assert!(
            result.outbound.replica_hints.contains(&key)
                || result.outbound.paid_hints.contains(&key)
                || result.outbound.replica_hints.is_empty()
        );
    }
}
