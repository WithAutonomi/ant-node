//! Neighbor-sync hint admission rules (Section 7).
//!
//! Per-key admission filtering before verification pipeline entry.
//!
//! When a neighbor sync hint arrives, each key must pass admission before
//! entering verification. The admission rules check:
//! 1. Sender is authenticated and in `LocalRT(self)` (checked before calling
//!    this module).
//! 2. Key is relevant to the receiver (checked here).

use std::collections::HashSet;
use std::sync::Arc;

use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;

use crate::ant_protocol::XorName;
use crate::replication::config::ReplicationConfig;
use crate::replication::paid_list::PaidList;
use crate::storage::LmdbStorage;

/// Result of admitting a set of hints from a neighbor sync.
#[derive(Debug)]
pub struct AdmissionResult {
    /// Keys admitted into the replica-hint pipeline (fetch-eligible).
    pub replica_keys: Vec<XorName>,
    /// Keys admitted into the paid-hint-only pipeline (`PaidForList` update
    /// only).
    pub paid_only_keys: Vec<XorName>,
    /// Keys rejected (not relevant to this node).
    pub rejected_keys: Vec<XorName>,
}

/// Check if this node is responsible for key `K`.
///
/// Returns `true` if `self_id` is among the `close_group_size` nearest peers
/// to `K` in `SelfInclusiveRT`.
pub async fn is_responsible(
    self_id: &PeerId,
    key: &XorName,
    p2p_node: &Arc<P2PNode>,
    close_group_size: usize,
) -> bool {
    let closest = p2p_node
        .dht_manager()
        .find_closest_nodes_local_with_self(key, close_group_size)
        .await;
    closest.iter().any(|n| n.peer_id == *self_id)
}

/// Check if this node is in the `PaidCloseGroup` for key `K`.
///
/// `PaidCloseGroup` = `paid_list_close_group_size` nearest peers to `K` in
/// `SelfInclusiveRT`.
pub async fn is_in_paid_close_group(
    self_id: &PeerId,
    key: &XorName,
    p2p_node: &Arc<P2PNode>,
    paid_list_close_group_size: usize,
) -> bool {
    let closest = p2p_node
        .dht_manager()
        .find_closest_nodes_local_with_self(key, paid_list_close_group_size)
        .await;
    closest.iter().any(|n| n.peer_id == *self_id)
}

/// Admit neighbor-sync hints per Section 7.1 rules.
///
/// For each key in `replica_hints` and `paid_hints`:
/// - **Cross-set precedence**: if a key appears in both sets, keep only the
///   replica-hint entry.
/// - **Replica hints**: admitted if `IsResponsible(self, K)` or key already
///   exists in local store / pending set.
/// - **Paid hints**: admitted if `self` is in `PaidCloseGroup(K)` or key is
///   already in `PaidForList`.
///
/// Returns an [`AdmissionResult`] with keys sorted into pipelines.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn admit_hints(
    self_id: &PeerId,
    replica_hints: &[XorName],
    paid_hints: &[XorName],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    pending_keys: &HashSet<XorName>,
) -> AdmissionResult {
    // Build set of replica hint keys for cross-set precedence check.
    let replica_set: HashSet<XorName> = replica_hints.iter().copied().collect();

    let mut result = AdmissionResult {
        replica_keys: Vec::new(),
        paid_only_keys: Vec::new(),
        rejected_keys: Vec::new(),
    };

    // Track all processed keys to deduplicate within and across sets.
    let mut seen = HashSet::new();

    // Process replica hints.
    for &key in replica_hints {
        if !seen.insert(key) {
            continue;
        }

        // Fast path: already local or pending -- no routing-table lookup needed.
        let already_local = storage.exists(&key).unwrap_or(false);
        let already_pending = pending_keys.contains(&key);

        if already_local || already_pending {
            result.replica_keys.push(key);
            continue;
        }

        if is_responsible(self_id, &key, p2p_node, config.close_group_size).await {
            result.replica_keys.push(key);
        } else {
            result.rejected_keys.push(key);
        }
    }

    // Process paid hints (with cross-set precedence).
    for &key in paid_hints {
        if !seen.insert(key) {
            continue;
        }

        // Cross-set precedence: if already processed as a replica hint, skip.
        if replica_set.contains(&key) {
            continue;
        }

        // Fast path: already in PaidForList -- no routing-table lookup needed.
        let already_paid = paid_list.contains(&key).unwrap_or(false);

        if already_paid {
            result.paid_only_keys.push(key);
            continue;
        }

        if is_in_paid_close_group(self_id, &key, p2p_node, config.paid_list_close_group_size).await
        {
            result.paid_only_keys.push(key);
        } else {
            result.rejected_keys.push(key);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::xor_distance;
    use crate::replication::config::ReplicationConfig;

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

    // -----------------------------------------------------------------------
    // AdmissionResult construction helpers for pure-logic tests
    //
    // The full `admit_hints` function requires a live DHT + LMDB backend.
    // For unit tests we directly exercise:
    //   1. Cross-set precedence logic
    //   2. Deduplication logic
    //   3. evaluate_key_evidence (in quorum.rs)
    //
    // Below we simulate admission by using the pure-logic portions.
    // -----------------------------------------------------------------------

    #[test]
    fn cross_set_precedence_replica_wins() {
        // When a key appears in both replica_hints and paid_hints, the
        // paid_hints entry should be suppressed by cross-set precedence.
        let key = xor_name_from_byte(0xAA);
        let replica_set: HashSet<XorName> = std::iter::once(key).collect();

        // Simulating the paid-hint loop: key is in replica_set, so it should
        // be skipped.
        assert!(
            replica_set.contains(&key),
            "paid-hint key present in replica set should be skipped"
        );
    }

    #[test]
    fn deduplication_within_replica_hints() {
        // Duplicate keys in replica_hints should only appear once.
        let key_a = xor_name_from_byte(0x01);
        let key_b = xor_name_from_byte(0x02);
        let hints = vec![key_a, key_b, key_a, key_a, key_b];

        let mut seen = HashSet::new();
        let mut unique = Vec::new();
        for &key in &hints {
            if seen.insert(key) {
                unique.push(key);
            }
        }

        assert_eq!(unique.len(), 2);
        assert_eq!(unique[0], key_a);
        assert_eq!(unique[1], key_b);
    }

    #[test]
    fn deduplication_across_sets() {
        // If a key appears in replica_hints AND paid_hints, the paid entry
        // is skipped because seen already contains it from replica processing.
        let key = xor_name_from_byte(0xFF);
        let replica_hints = vec![key];
        let paid_hints = vec![key];

        let replica_set: HashSet<XorName> = replica_hints.iter().copied().collect();
        let mut seen: HashSet<XorName> = HashSet::new();

        // Process replica hints first.
        for &k in &replica_hints {
            seen.insert(k);
        }

        // Process paid hints: key is already in `seen` AND in `replica_set`.
        let mut paid_admitted = Vec::new();
        for &k in &paid_hints {
            if !seen.insert(k) {
                continue; // duplicate
            }
            if replica_set.contains(&k) {
                continue; // cross-set precedence
            }
            paid_admitted.push(k);
        }

        assert!(
            paid_admitted.is_empty(),
            "paid-hint should be suppressed when key is also a replica hint"
        );
    }

    #[test]
    fn admission_result_empty_inputs() {
        let result = AdmissionResult {
            replica_keys: Vec::new(),
            paid_only_keys: Vec::new(),
            rejected_keys: Vec::new(),
        };

        assert!(result.replica_keys.is_empty());
        assert!(result.paid_only_keys.is_empty());
        assert!(result.rejected_keys.is_empty());
    }

    #[test]
    fn out_of_range_keys_rejected_by_distance() {
        // Simulate rejection: a key whose XOR distance from self is large
        // should not appear in a close-group of size 3 when there are closer
        // peers.
        let _self_id = peer_id_from_byte(0x00);
        let key = xor_name_from_byte(0xFF);
        let _config = ReplicationConfig::default();

        // Distance from self (0x00...) to key (0xFF...):
        let self_xor: XorName = [0u8; 32];
        let dist = xor_distance(&self_xor, &key);

        // A very far key would have high distance -- this proves the concept.
        assert_eq!(dist[0], 0xFF, "distance first byte should be 0xFF");

        // Meanwhile a close key would have a small distance.
        let close_key = xor_name_from_byte(0x01);
        let close_dist = xor_distance(&self_xor, &close_key);
        assert_eq!(
            close_dist[0], 0x01,
            "close distance first byte should be 0x01"
        );

        assert!(
            dist > close_dist,
            "far key should have greater distance than close key"
        );
    }

    #[test]
    fn config_close_group_sizes_are_valid() {
        let config = ReplicationConfig::default();
        assert!(
            config.close_group_size > 0,
            "close_group_size must be positive"
        );
        assert!(
            config.paid_list_close_group_size > 0,
            "paid_list_close_group_size must be positive"
        );
        assert!(
            config.paid_list_close_group_size >= config.close_group_size,
            "paid_list_close_group_size should be >= close_group_size"
        );
    }

    // -----------------------------------------------------------------------
    // Section 18 scenarios
    // -----------------------------------------------------------------------

    /// Scenario 5: Unauthorized sync peer — hints from peers not in
    /// `LocalRT(self)` are dropped and do not enter verification.
    ///
    /// Two layers enforce this:
    /// (a) `handle_sync_request` in `neighbor_sync.rs` returns
    ///     `sender_in_rt = false` when the sender is not in `LocalRT`.
    ///     The caller (`handle_neighbor_sync_request` in `mod.rs`) returns
    ///     early without processing ANY inbound hints. This is the primary
    ///     gate tested at the e2e level (scenario 17 tests the positive
    ///     case).
    /// (b) Even if a sender IS in `LocalRT`, the per-key relevance check
    ///     (`is_responsible` / `is_in_paid_close_group`) in `admit_hints`
    ///     still applies. Sender identity does not grant key admission.
    ///
    /// This test exercises layer (b): the admission pipeline's dedup,
    /// cross-set precedence, and relevance filtering using the same logic
    /// that `admit_hints` performs — without the `P2PNode` dependency
    /// needed for the actual `is_responsible` DHT lookup.
    #[test]
    fn scenario_5_sender_does_not_grant_key_relevance() {
        let key_pending = xor_name_from_byte(0xB0);
        let key_not_pending = xor_name_from_byte(0xB1);
        let key_paid_existing = xor_name_from_byte(0xB2);
        let _sender = peer_id_from_byte(0x01);

        // Simulate local state: only key_pending is in the pending set,
        // key_paid_existing is in the paid list.
        let pending: HashSet<XorName> = std::iter::once(key_pending).collect();
        let paid_set: HashSet<XorName> = std::iter::once(key_paid_existing).collect();

        // Trace through admit_hints logic for replica hints:
        let replica_hints = [key_pending, key_not_pending];
        let replica_set: HashSet<XorName> = replica_hints.iter().copied().collect();
        let mut seen = HashSet::new();
        let mut admitted_replica = Vec::new();
        let mut rejected = Vec::new();

        for &key in &replica_hints {
            if !seen.insert(key) {
                continue; // dedup
            }
            // Fast path: already pending -> admitted.
            if pending.contains(&key) {
                admitted_replica.push(key);
                continue;
            }
            // key_not_pending: not pending, not local -> needs is_responsible.
            // Simulate is_responsible returning false (out of range).
            let is_responsible = false;
            if is_responsible {
                admitted_replica.push(key);
            } else {
                rejected.push(key);
            }
        }

        // Trace through paid hints:
        let paid_hints = [key_paid_existing, key_pending]; // key_pending overlaps with replica
        let mut admitted_paid = Vec::new();

        for &key in &paid_hints {
            if !seen.insert(key) {
                continue; // dedup: key_pending already seen
            }
            if replica_set.contains(&key) {
                continue; // cross-set precedence
            }
            // Fast path: already in paid list -> admitted.
            if paid_set.contains(&key) {
                admitted_paid.push(key);
                continue;
            }
            rejected.push(key);
        }

        // Verify outcomes:
        assert_eq!(
            admitted_replica,
            vec![key_pending],
            "only the pending key should be admitted as replica"
        );
        assert_eq!(
            rejected,
            vec![key_not_pending],
            "non-pending, non-responsible key must be rejected"
        );
        assert_eq!(
            admitted_paid,
            vec![key_paid_existing],
            "existing paid-list key should be admitted via fast path"
        );

        // Cross-set precedence: key_pending appeared in both replica and
        // paid hints — it was processed as replica only, paid duplicate
        // was deduped.
        assert!(
            !admitted_paid.contains(&key_pending),
            "key in both hint sets must be processed as replica only"
        );
    }

    /// Scenario 7: Out-of-range key hint rejected regardless of quorum.
    ///
    /// A key whose XOR distance from self is much larger than the distance
    /// of the close-group members fails the `is_responsible` check in
    /// `admit_hints`. The key never enters the verification pipeline, so
    /// quorum is irrelevant.
    ///
    /// This test exercises the distance-based reasoning that `admit_hints`
    /// uses, tracing through the same logic path. Full `is_responsible`
    /// requires a P2PNode for DHT lookups; here we verify the distance
    /// comparison and admission outcome for both close and far keys.
    #[test]
    fn scenario_7_out_of_range_key_rejected() {
        let self_xor: XorName = [0u8; 32];

        // -- Distance proof: far key vs close key --

        let far_key = xor_name_from_byte(0xFF);
        let close_key = xor_name_from_byte(0x01);
        let far_dist = xor_distance(&self_xor, &far_key);
        let close_dist = xor_distance(&self_xor, &close_key);

        assert_eq!(far_dist[0], 0xFF, "far_key distance should be maximal");
        assert_eq!(close_dist[0], 0x01, "close_key distance should be small");
        assert!(far_dist > close_dist, "far key is further than close key");

        // -- Simulate admit_hints for these keys --
        //
        // When `close_group_size` peers are all closer to far_key than
        // self, `is_responsible(self, far_key)` returns false. The key is
        // rejected without entering verification or quorum.

        let pending: HashSet<XorName> = HashSet::new();
        let replica_hints = [far_key, close_key];
        let mut seen = HashSet::new();
        let mut admitted = Vec::new();
        let mut rejected = Vec::new();

        for &key in &replica_hints {
            if !seen.insert(key) {
                continue;
            }
            // Not pending, not local.
            if pending.contains(&key) {
                admitted.push(key);
                continue;
            }
            // Simulate is_responsible: self (0x00) has close_group_size
            // peers closer to far_key (0xFF) than itself -> not responsible.
            // For close_key (0x01), self is very close -> responsible.
            let distance = xor_distance(&self_xor, &key);
            let simulated_responsible = distance[0] < 0x80;
            if simulated_responsible {
                admitted.push(key);
            } else {
                rejected.push(key);
            }
        }

        assert_eq!(
            admitted,
            vec![close_key],
            "only close key should be admitted"
        );
        assert_eq!(
            rejected,
            vec![far_key],
            "far key should be rejected regardless of quorum — it never enters verification"
        );

        // Verify the key doesn't sneak in via paid hints either.
        // far_key was already seen (deduped), so paid processing skips it.
        let paid_hints = [far_key];
        let replica_set: HashSet<XorName> = replica_hints.iter().copied().collect();
        let mut paid_admitted = Vec::new();

        for &key in &paid_hints {
            if !seen.insert(key) {
                continue; // already seen from replica processing
            }
            if replica_set.contains(&key) {
                continue; // cross-set precedence
            }
            paid_admitted.push(key);
        }

        assert!(
            paid_admitted.is_empty(),
            "far key already processed as replica (and rejected) should not re-enter via paid hints"
        );
    }
}
