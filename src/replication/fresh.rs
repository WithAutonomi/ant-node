//! Fresh replication (Section 6.1) — PoP-validated push.
//!
//! Fresh replication is the first-write propagation path. When a node stores
//! a new record with a valid proof-of-payment (PoP):
//!
//! 1. `CloseGroup(K)` peers receive `FreshOffer` carrying the full record + `PoP`.
//! 2. `PaidCloseGroup(K)` peers (minus close group) receive `PaidNotify` with key + `PoP`.
//!
//! Receivers validate the `PoP`, verify responsibility, and store/track accordingly.

use crate::client::{compute_address, XorName};
use crate::replication::paid_list::PaidForList;
use crate::replication::params::{CLOSE_GROUP_SIZE, PAID_LIST_CLOSE_GROUP_SIZE};
use crate::replication::protocol::{
    FreshOfferRequest, FreshOfferResponse, PaidNotifyRequest, PaidNotifyResponse,
};
use crate::replication::routing;
use crate::storage::DiskStorage;
use std::collections::HashSet;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// PoP validation (placeholder — full EVM verification in Phase 10)
// ---------------------------------------------------------------------------

/// Validate proof-of-payment bytes.
///
/// Current implementation: basic non-empty check.
/// Full EVM verification will be integrated in Phase 10 (`EigenTrust`).
fn validate_proof_of_payment(pop: &[u8]) -> bool {
    !pop.is_empty()
}

// ---------------------------------------------------------------------------
// Incoming message handlers (receiver side)
// ---------------------------------------------------------------------------

/// Handle an incoming `FreshOffer` from a peer (Section 6.1 receiver side).
///
/// Validates `PoP`, checks responsibility, verifies content address,
/// and stores the record locally.
///
/// **Caller responsibility:** on `Accepted`, add the key to the `PaidForList`.
/// This split exists because `PaidForList` is behind a sync lock that cannot
/// be held across the async storage I/O.
///
/// # Arguments
///
/// * `self_id` - This node's peer ID
/// * `self_xor` - This node's XOR name
/// * `request` - The incoming fresh offer request
/// * `local_rt` - Local routing table (peers excluding self)
/// * `storage` - Disk storage for persisting the record
pub async fn handle_fresh_offer(
    self_id: &str,
    self_xor: &XorName,
    request: &FreshOfferRequest,
    local_rt: &[(String, XorName)],
    storage: &DiskStorage,
) -> FreshOfferResponse {
    let key_hex = hex::encode(request.key);

    // Step 1: Validate PoP
    if !validate_proof_of_payment(&request.proof_of_payment) {
        debug!("FreshOffer rejected for {key_hex}: invalid PoP");
        return FreshOfferResponse::Rejected {
            key: request.key,
            reason: "invalid proof of payment".to_string(),
        };
    }

    // Step 2: Check IsResponsible(self, K) in SelfInclusiveRT
    if !routing::is_responsible(self_id, self_xor, &request.key, local_rt) {
        debug!("FreshOffer rejected for {key_hex}: not responsible");
        return FreshOfferResponse::Rejected {
            key: request.key,
            reason: "not responsible for key".to_string(),
        };
    }

    // Step 3: Verify content address — SHA256(content) must equal key
    let computed = compute_address(&request.content);
    if computed != request.key {
        debug!("FreshOffer rejected for {key_hex}: content address mismatch");
        return FreshOfferResponse::Rejected {
            key: request.key,
            reason: "content address mismatch".to_string(),
        };
    }

    // Step 4: Store record to disk
    match storage.put(&request.key, &request.content).await {
        Ok(_) => {
            debug!(
                "FreshOffer stored {key_hex} ({} bytes)",
                request.content.len()
            );
        }
        Err(e) => {
            warn!("FreshOffer storage failed for {key_hex}: {e}");
            return FreshOfferResponse::Rejected {
                key: request.key,
                reason: format!("storage failed: {e}"),
            };
        }
    }

    FreshOfferResponse::Accepted { key: request.key }
}

/// Handle an incoming `PaidNotify` from a peer (Section 7.3 receiver side).
///
/// Validates `PoP`, checks paid-close-group membership, and adds the key
/// to the `PaidForList`. No record fetch is performed.
///
/// # Arguments
///
/// * `self_id` - This node's peer ID
/// * `self_xor` - This node's XOR name
/// * `request` - The incoming paid notify request
/// * `local_rt` - Local routing table (peers excluding self)
/// * `paid_list` - Paid-for list to update
pub fn handle_paid_notify(
    self_id: &str,
    self_xor: &XorName,
    request: &PaidNotifyRequest,
    local_rt: &[(String, XorName)],
    paid_list: &mut PaidForList,
) -> PaidNotifyResponse {
    let key_hex = hex::encode(request.key);

    // Step 1: Validate PoP
    if !validate_proof_of_payment(&request.proof_of_payment) {
        debug!("PaidNotify rejected for {key_hex}: invalid PoP");
        return PaidNotifyResponse::Rejected { key: request.key };
    }

    // Step 2: Check is_in_paid_close_group(self, K)
    if !routing::is_in_paid_close_group(self_id, self_xor, &request.key, local_rt) {
        debug!("PaidNotify rejected for {key_hex}: not in paid close group");
        return PaidNotifyResponse::Rejected { key: request.key };
    }

    // Step 3: Add to PaidForList
    let was_new = paid_list.add(request.key);
    if was_new {
        debug!("PaidNotify: added {key_hex} to PaidForList");
    } else {
        debug!("PaidNotify: {key_hex} already in PaidForList");
    }

    PaidNotifyResponse::Accepted { key: request.key }
}

// ---------------------------------------------------------------------------
// Outbound replication planning (sender side)
// ---------------------------------------------------------------------------

/// Planned outbound messages for fresh replication after storing a new record.
#[derive(Debug)]
pub struct FreshReplicationPlan {
    /// Peers to send `FreshOffer` to (`CloseGroup(K)` excluding self).
    pub offer_targets: Vec<String>,
    /// Peers to send `PaidNotify` to (`PaidCloseGroup(K)` excluding self
    /// and peers already in `offer_targets`).
    pub notify_only_targets: Vec<String>,
}

/// Compute fresh replication targets for a newly stored key (Section 6.1 sender side).
///
/// Returns which peers should receive `FreshOffer` (close group) and which
/// should receive `PaidNotify` only (wider paid-close-group members).
///
/// Peers in `offer_targets` already receive the `PoP` via `FreshOffer`, so they
/// are excluded from `notify_only_targets` to avoid redundant messages.
///
/// # Arguments
///
/// * `self_id` - This node's peer ID
/// * `self_xor` - This node's XOR name
/// * `key` - The key being replicated
/// * `local_rt` - Local routing table (peers excluding self)
#[must_use]
pub fn plan_fresh_replication(
    self_id: &str,
    self_xor: &XorName,
    key: &XorName,
    local_rt: &[(String, XorName)],
) -> FreshReplicationPlan {
    // Step 1: Build SelfInclusiveRT and compute CloseGroup(K)
    let mut self_inclusive: Vec<(String, XorName)> = local_rt.to_vec();
    self_inclusive.push((self_id.to_string(), *self_xor));

    let close = routing::close_group(key, &self_inclusive, CLOSE_GROUP_SIZE);
    let offer_targets: Vec<String> = close
        .iter()
        .filter(|(id, _)| id != self_id)
        .map(|(id, _)| id.clone())
        .collect();

    let offer_set: HashSet<&str> = offer_targets.iter().map(String::as_str).collect();

    // Step 2: Compute PaidCloseGroup(K) excluding self and offer targets
    let paid = routing::close_group(key, &self_inclusive, PAID_LIST_CLOSE_GROUP_SIZE);
    let notify_only_targets: Vec<String> = paid
        .iter()
        .filter(|(id, _)| id != self_id && !offer_set.contains(id.as_str()))
        .map(|(id, _)| id.clone())
        .collect();

    FreshReplicationPlan {
        offer_targets,
        notify_only_targets,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::storage::DiskStorageConfig;
    use tempfile::TempDir;

    /// Create a test `DiskStorage` backed by a temp directory.
    async fn test_storage() -> (DiskStorage, TempDir) {
        let dir = TempDir::new().expect("create temp dir");
        let config = DiskStorageConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: false,
            max_chunks: 0,
        };
        let storage = DiskStorage::new(config).await.expect("create storage");
        (storage, dir)
    }

    /// XOR complement — maximally distant from the input.
    fn xor_complement(xor: &XorName) -> XorName {
        let mut result = *xor;
        for b in &mut result {
            *b ^= 0xFF;
        }
        result
    }

    /// Create N peers with XOR names very close to `near` (tiny perturbations).
    fn make_peers_near(near: &XorName, n: u8) -> Vec<(String, XorName)> {
        (1..=n)
            .map(|i| {
                let mut xor = *near;
                xor[31] ^= i; // small perturbation in last byte
                (format!("peer_{i}"), xor)
            })
            .collect()
    }

    /// Create N peers with XOR names at varying distances from origin [0x00; 32].
    fn make_peers_spread(n: u8) -> Vec<(String, XorName)> {
        (1..=n)
            .map(|i| {
                let mut xor = [0x00; 32];
                xor[0] = i;
                (format!("peer_{i}"), xor)
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // handle_fresh_offer tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_fresh_offer_accepted() {
        let (storage, _dir) = test_storage().await;

        let content = b"accepted test content";
        let key = compute_address(content);
        // Place self at the exact key position — closest possible
        let self_xor = key;
        // Place peers far from key so self is in close group
        let peers = make_peers_near(&xor_complement(&key), 10);

        let request = FreshOfferRequest {
            key,
            content: content.to_vec(),
            proof_of_payment: vec![1, 2, 3],
        };

        let response = handle_fresh_offer("self", &self_xor, &request, &peers, &storage).await;

        assert!(
            matches!(response, FreshOfferResponse::Accepted { .. }),
            "expected Accepted, got: {response:?}"
        );
        assert!(storage.exists(&key));
    }

    #[tokio::test]
    async fn test_fresh_offer_invalid_pop() {
        let (storage, _dir) = test_storage().await;

        let content = b"invalid pop test";
        let key = compute_address(content);
        let self_xor = key;
        let peers = make_peers_near(&xor_complement(&key), 3);

        let request = FreshOfferRequest {
            key,
            content: content.to_vec(),
            proof_of_payment: vec![], // empty = invalid
        };

        let response = handle_fresh_offer("self", &self_xor, &request, &peers, &storage).await;

        if let FreshOfferResponse::Rejected { reason, .. } = response {
            assert!(reason.contains("proof of payment"));
        } else {
            panic!("expected Rejected, got: {response:?}");
        }
        assert!(!storage.exists(&key));
    }

    #[tokio::test]
    async fn test_fresh_offer_not_responsible() {
        let (storage, _dir) = test_storage().await;

        let content = b"not responsible test";
        let key = compute_address(content);
        // Place self maximally far from key
        let self_xor = xor_complement(&key);
        // Place 10 peers very close to key — all closer than self
        let peers = make_peers_near(&key, 10);

        let request = FreshOfferRequest {
            key,
            content: content.to_vec(),
            proof_of_payment: vec![1],
        };

        let response = handle_fresh_offer("self", &self_xor, &request, &peers, &storage).await;

        if let FreshOfferResponse::Rejected { reason, .. } = response {
            assert!(reason.contains("not responsible"));
        } else {
            panic!("expected Rejected for not responsible, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_fresh_offer_address_mismatch() {
        let (storage, _dir) = test_storage().await;

        let content = b"address mismatch test";
        let wrong_key = [0xAA; 32]; // does not match SHA256(content)
                                    // Place self at wrong_key so it passes responsibility check
        let self_xor = wrong_key;
        // Place peers far from wrong_key
        let peers = make_peers_near(&xor_complement(&wrong_key), 3);

        let request = FreshOfferRequest {
            key: wrong_key,
            content: content.to_vec(),
            proof_of_payment: vec![1],
        };

        let response = handle_fresh_offer("self", &self_xor, &request, &peers, &storage).await;

        if let FreshOfferResponse::Rejected { reason, .. } = response {
            assert!(reason.contains("address mismatch"));
        } else {
            panic!("expected Rejected for address mismatch, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_fresh_offer_idempotent() {
        let (storage, _dir) = test_storage().await;

        let content = b"idempotent test";
        let key = compute_address(content);
        let self_xor = key;
        let peers = make_peers_near(&xor_complement(&key), 5);

        let request = FreshOfferRequest {
            key,
            content: content.to_vec(),
            proof_of_payment: vec![1],
        };

        // First offer — should succeed
        let resp1 = handle_fresh_offer("self", &self_xor, &request, &peers, &storage).await;
        assert!(matches!(resp1, FreshOfferResponse::Accepted { .. }));

        // Second offer — should also succeed (storage.put is idempotent)
        let resp2 = handle_fresh_offer("self", &self_xor, &request, &peers, &storage).await;
        assert!(matches!(resp2, FreshOfferResponse::Accepted { .. }));
    }

    // -----------------------------------------------------------------------
    // handle_paid_notify tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_paid_notify_accepted() {
        let dir = TempDir::new().expect("temp dir");
        let mut paid_list = PaidForList::load(dir.path()).expect("load");

        let key = [0x01; 32];
        // Place self close to key — will be in PaidCloseGroup
        let self_xor = key;
        let peers = make_peers_near(&xor_complement(&key), 5);

        let request = PaidNotifyRequest {
            key,
            proof_of_payment: vec![1, 2, 3],
        };

        let response = handle_paid_notify("self", &self_xor, &request, &peers, &mut paid_list);

        assert!(
            matches!(response, PaidNotifyResponse::Accepted { .. }),
            "expected Accepted, got: {response:?}"
        );
        assert!(paid_list.contains(&key));
    }

    #[test]
    fn test_paid_notify_invalid_pop() {
        let dir = TempDir::new().expect("temp dir");
        let mut paid_list = PaidForList::load(dir.path()).expect("load");

        let key = [0x01; 32];
        let self_xor = key;
        let peers = make_peers_near(&xor_complement(&key), 3);

        let request = PaidNotifyRequest {
            key,
            proof_of_payment: vec![], // empty = invalid
        };

        let response = handle_paid_notify("self", &self_xor, &request, &peers, &mut paid_list);

        assert!(matches!(response, PaidNotifyResponse::Rejected { .. }));
        assert!(!paid_list.contains(&key));
    }

    #[test]
    fn test_paid_notify_not_in_paid_close_group() {
        let dir = TempDir::new().expect("temp dir");
        let mut paid_list = PaidForList::load(dir.path()).expect("load");

        let key = [0x00; 32];
        // Place self maximally far
        let self_xor = [0xFF; 32];
        // Create 25 peers close to key — self won't be in PAID_LIST_CLOSE_GROUP_SIZE(20)
        let peers = make_peers_near(&key, 25);

        let request = PaidNotifyRequest {
            key,
            proof_of_payment: vec![1],
        };

        let response = handle_paid_notify("self", &self_xor, &request, &peers, &mut paid_list);

        assert!(matches!(response, PaidNotifyResponse::Rejected { .. }));
    }

    #[test]
    fn test_paid_notify_idempotent() {
        let dir = TempDir::new().expect("temp dir");
        let mut paid_list = PaidForList::load(dir.path()).expect("load");

        let key = [0x01; 32];
        let self_xor = key;
        let peers = make_peers_near(&xor_complement(&key), 3);

        let request = PaidNotifyRequest {
            key,
            proof_of_payment: vec![1],
        };

        // First notify
        let resp1 = handle_paid_notify("self", &self_xor, &request, &peers, &mut paid_list);
        assert!(matches!(resp1, PaidNotifyResponse::Accepted { .. }));

        // Second notify — idempotent
        let resp2 = handle_paid_notify("self", &self_xor, &request, &peers, &mut paid_list);
        assert!(matches!(resp2, PaidNotifyResponse::Accepted { .. }));
    }

    // -----------------------------------------------------------------------
    // plan_fresh_replication tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_plan_excludes_self() {
        let key = [0x00; 32];
        let self_xor = key; // self is closest to key
        let peers = make_peers_spread(25);

        let plan = plan_fresh_replication("self", &self_xor, &key, &peers);

        assert!(!plan.offer_targets.contains(&"self".to_string()));
        assert!(!plan.notify_only_targets.contains(&"self".to_string()));
    }

    #[test]
    fn test_plan_no_overlap_between_offer_and_notify() {
        let key = [0x00; 32];
        let self_xor = key;
        let peers = make_peers_spread(25);

        let plan = plan_fresh_replication("self", &self_xor, &key, &peers);

        let offer_set: HashSet<String> = plan.offer_targets.iter().cloned().collect();
        for notify in &plan.notify_only_targets {
            assert!(
                !offer_set.contains(notify),
                "overlap found: {notify} appears in both targets"
            );
        }
    }

    #[test]
    fn test_plan_offer_targets_bounded_by_close_group() {
        let key = [0x00; 32];
        let self_xor = key;
        let peers = make_peers_spread(25);

        let plan = plan_fresh_replication("self", &self_xor, &key, &peers);

        // Offer targets = CloseGroup(K) minus self
        // Self is in close group, so offer_targets.len() <= CLOSE_GROUP_SIZE - 1
        assert!(plan.offer_targets.len() < CLOSE_GROUP_SIZE);
    }

    #[test]
    fn test_plan_total_targets_bounded() {
        let key = [0x00; 32];
        let self_xor = key;
        let peers = make_peers_spread(25);

        let plan = plan_fresh_replication("self", &self_xor, &key, &peers);

        let total = plan.offer_targets.len() + plan.notify_only_targets.len();
        // Total targets = PaidCloseGroup(K) minus self
        assert!(total < PAID_LIST_CLOSE_GROUP_SIZE);
    }

    #[test]
    fn test_plan_small_network() {
        let key = [0x00; 32];
        let self_xor = key;
        let peers = make_peers_spread(3); // only 3 peers

        let plan = plan_fresh_replication("self", &self_xor, &key, &peers);

        // All 3 peers should be offer targets (total nodes < CLOSE_GROUP_SIZE)
        assert_eq!(plan.offer_targets.len(), 3);
        // No notify-only since all peers are already in close group
        assert!(plan.notify_only_targets.is_empty());
    }

    #[test]
    fn test_plan_empty_network() {
        let key = [0x00; 32];
        let self_xor = key;
        let peers: Vec<(String, XorName)> = vec![];

        let plan = plan_fresh_replication("self", &self_xor, &key, &peers);

        assert!(plan.offer_targets.is_empty());
        assert!(plan.notify_only_targets.is_empty());
    }

    #[test]
    fn test_plan_self_not_closest() {
        let key = [0x00; 32];
        // Self is far from key
        let self_xor = [0xFF; 32];
        let peers = make_peers_spread(25);

        let plan = plan_fresh_replication("self", &self_xor, &key, &peers);

        // Self might not be in close group at all, so all CLOSE_GROUP_SIZE
        // closest peers are offer targets
        assert!(plan.offer_targets.len() <= CLOSE_GROUP_SIZE);
        assert!(!plan.offer_targets.contains(&"self".to_string()));
    }
}
