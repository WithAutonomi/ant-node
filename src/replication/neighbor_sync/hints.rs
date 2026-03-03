//! Hint construction and admission rules (Section 6.2 rules 7, 9; Section 7.1).
//!
//! Sender-side: compute which keys a given peer should hold or track.
//! Receiver-side: validate incoming hints against admission criteria.

use crate::client::XorName;
use crate::replication::routing;
use crate::replication::types::HintPipeline;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Sender-side hint construction (Section 6.2 rule 7)
// ---------------------------------------------------------------------------

/// Hints computed by the sender for a specific receiver peer.
#[derive(Debug, Clone)]
pub struct HintsForPeer {
    /// Keys the receiver should hold as replicas
    /// (receiver is among `CLOSE_GROUP_SIZE` nearest to K).
    pub replica_hints: Vec<XorName>,
    /// Keys the receiver should track in `PaidForList`
    /// (receiver is among `PAID_LIST_CLOSE_GROUP_SIZE` nearest to K).
    pub paid_hints: Vec<XorName>,
}

/// Compute sender-side hints for a specific receiver peer.
///
/// Uses the sender's `SelfInclusiveRT` to determine which keys
/// the receiver should hold (replica) or track (paid-list).
///
/// `local_keys` are the keys the sender holds locally.
/// `paid_keys` are the keys in the sender's `PaidForList`.
#[must_use]
pub fn compute_hints_for_peer(
    self_id: &str,
    self_xor: &XorName,
    receiver_id: &str,
    local_rt: &[(String, XorName)],
    local_keys: &[XorName],
    paid_keys: &[XorName],
) -> HintsForPeer {
    // Build sender's SelfInclusiveRT for hint construction (Section 6.2 rule 7)
    let mut self_inclusive_rt: Vec<(String, XorName)> = local_rt.to_vec();
    self_inclusive_rt.push((self_id.to_string(), *self_xor));

    let mut replica_hints = Vec::new();
    let mut paid_hints = Vec::new();

    // Check each local key: is the receiver in CloseGroup(K) per sender's view?
    for key in local_keys {
        let close = routing::close_group(
            key,
            &self_inclusive_rt,
            crate::replication::params::CLOSE_GROUP_SIZE,
        );
        if close.iter().any(|(id, _)| id == receiver_id) {
            replica_hints.push(*key);
        }
    }

    // Check each paid key: is the receiver in PaidCloseGroup(K) per sender's view?
    // Only add to paid hints if NOT already in replica hints (cross-set dedup).
    let replica_set: HashSet<XorName> = replica_hints.iter().copied().collect();
    for key in paid_keys {
        if replica_set.contains(key) {
            continue; // Section 6.2 rule 9: replica takes precedence
        }
        let paid_group = routing::close_group(
            key,
            &self_inclusive_rt,
            crate::replication::params::PAID_LIST_CLOSE_GROUP_SIZE,
        );
        if paid_group.iter().any(|(id, _)| id == receiver_id) {
            paid_hints.push(*key);
        }
    }

    HintsForPeer {
        replica_hints,
        paid_hints,
    }
}

// ---------------------------------------------------------------------------
// Receiver-side admission (Section 7.1)
// ---------------------------------------------------------------------------

/// Outcome of admitting a single hinted key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionResult {
    /// Key admitted into the replica-hint pipeline (fetch-eligible).
    AdmittedReplica,
    /// Key admitted into the paid-hint-only pipeline (no fetch).
    AdmittedPaidOnly,
    /// Key rejected (not relevant to receiver).
    Rejected,
}

/// Check admission for a single hinted key from a neighbor sync session.
///
/// Returns the admission result based on Section 7.1 rules:
/// - Replica hint: receiver is `IsResponsible(self, K)` or key is already local/pending.
/// - Paid hint: receiver is in `PaidCloseGroup(K)` or key already in `PaidForList`.
///
/// `is_local_or_pending` should return `true` if the key is already in
/// the local store or in a pending verification/fetch pipeline.
#[must_use]
pub fn admit_hint(
    self_id: &str,
    self_xor: &XorName,
    key: &XorName,
    pipeline: HintPipeline,
    local_rt: &[(String, XorName)],
    is_local_or_pending: bool,
    is_in_paid_list: bool,
) -> AdmissionResult {
    match pipeline {
        HintPipeline::Replica => {
            if is_local_or_pending || routing::is_responsible(self_id, self_xor, key, local_rt) {
                AdmissionResult::AdmittedReplica
            } else {
                AdmissionResult::Rejected
            }
        }
        HintPipeline::PaidOnly => {
            if is_in_paid_list || routing::is_in_paid_close_group(self_id, self_xor, key, local_rt)
            {
                AdmissionResult::AdmittedPaidOnly
            } else {
                AdmissionResult::Rejected
            }
        }
    }
}

/// Process received hint sets with cross-set deduplication (Section 6.2 rule 9).
///
/// Returns a list of `(key, pipeline)` pairs with duplicates resolved:
/// if a key appears in both replica and paid hints, only the replica entry
/// is kept.
#[must_use]
pub fn deduplicate_hints(
    replica_hints: &[XorName],
    paid_hints: &[XorName],
) -> Vec<(XorName, HintPipeline)> {
    let mut result = Vec::new();
    let mut seen: HashSet<XorName> = HashSet::new();

    // Replica hints take precedence
    for key in replica_hints {
        if seen.insert(*key) {
            result.push((*key, HintPipeline::Replica));
        }
    }

    // Paid hints only if not already in replica set
    for key in paid_hints {
        if seen.insert(*key) {
            result.push((*key, HintPipeline::PaidOnly));
        }
    }

    result
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
    fn test_compute_hints_for_close_peer() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        // Receiver is peer_0 with xor [0x01, 0, 0, ...] — very close to key [0x00; 32]
        let receiver_id = "peer_0";
        let local_rt = make_local_rt(10);
        let key = [0x00; 32]; // close to receiver
        let local_keys = vec![key];
        let paid_keys = vec![key];

        let hints = compute_hints_for_peer(
            self_id,
            &self_xor,
            receiver_id,
            &local_rt,
            &local_keys,
            &paid_keys,
        );

        // Receiver should be responsible for this key (close enough)
        assert!(hints.replica_hints.contains(&key));
        // Key in both → cross-set dedup removes from paid
        assert!(!hints.paid_hints.contains(&key));
    }

    #[test]
    fn test_compute_hints_cross_set_dedup() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let receiver_id = "peer_0";
        let local_rt = make_local_rt(5);
        let key = [0x00; 32];

        let hints = compute_hints_for_peer(
            self_id,
            &self_xor,
            receiver_id,
            &local_rt,
            &[key],
            &[key], // same key in both
        );

        // If key appears in replica, it must NOT appear in paid
        if hints.replica_hints.contains(&key) {
            assert!(!hints.paid_hints.contains(&key));
        }
    }

    #[test]
    fn test_admit_replica_responsible() {
        let self_id = "self";
        let self_xor = [0x01; 32]; // close to key
        let key = [0x00; 32];
        let local_rt = make_local_rt(5);

        let result = admit_hint(
            self_id,
            &self_xor,
            &key,
            HintPipeline::Replica,
            &local_rt,
            false,
            false,
        );
        assert_eq!(result, AdmissionResult::AdmittedReplica);
    }

    #[test]
    fn test_admit_replica_already_local() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from key — not responsible
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        // Not responsible, but key is already local
        let result = admit_hint(
            self_id,
            &self_xor,
            &key,
            HintPipeline::Replica,
            &local_rt,
            true,
            false,
        );
        assert_eq!(result, AdmissionResult::AdmittedReplica);
    }

    #[test]
    fn test_admit_replica_rejected() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from key
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let result = admit_hint(
            self_id,
            &self_xor,
            &key,
            HintPipeline::Replica,
            &local_rt,
            false,
            false,
        );
        assert_eq!(result, AdmissionResult::Rejected);
    }

    #[test]
    fn test_admit_paid_in_paid_close_group() {
        let self_id = "self";
        let self_xor = [0x01; 32]; // close to key
        let key = [0x00; 32];
        let local_rt = make_local_rt(5);

        let result = admit_hint(
            self_id,
            &self_xor,
            &key,
            HintPipeline::PaidOnly,
            &local_rt,
            false,
            false,
        );
        assert_eq!(result, AdmissionResult::AdmittedPaidOnly);
    }

    #[test]
    fn test_admit_paid_already_in_list() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from key
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let result = admit_hint(
            self_id,
            &self_xor,
            &key,
            HintPipeline::PaidOnly,
            &local_rt,
            false,
            true, // already in PaidForList
        );
        assert_eq!(result, AdmissionResult::AdmittedPaidOnly);
    }

    #[test]
    fn test_deduplicate_hints_cross_set() {
        let key_both = [0xAA; 32];
        let key_replica = [0xBB; 32];
        let key_paid = [0xCC; 32];

        let replica = vec![key_both, key_replica];
        let paid = vec![key_both, key_paid];

        let result = deduplicate_hints(&replica, &paid);

        // key_both should be Replica (not PaidOnly)
        let both_entry = result.iter().find(|(k, _)| *k == key_both);
        assert_eq!(both_entry, Some(&(key_both, HintPipeline::Replica)));

        // key_replica is Replica
        let replica_entry = result.iter().find(|(k, _)| *k == key_replica);
        assert_eq!(replica_entry, Some(&(key_replica, HintPipeline::Replica)));

        // key_paid is PaidOnly
        let paid_entry = result.iter().find(|(k, _)| *k == key_paid);
        assert_eq!(paid_entry, Some(&(key_paid, HintPipeline::PaidOnly)));

        // Total: 3 entries (no duplicates)
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_deduplicate_hints_all_replica() {
        let keys = vec![[0xAA; 32], [0xBB; 32]];
        let result = deduplicate_hints(&keys, &[]);

        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|(_, p)| *p == HintPipeline::Replica));
    }

    #[test]
    fn test_deduplicate_hints_all_paid() {
        let keys = vec![[0xAA; 32], [0xBB; 32]];
        let result = deduplicate_hints(&[], &keys);

        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|(_, p)| *p == HintPipeline::PaidOnly));
    }
}
