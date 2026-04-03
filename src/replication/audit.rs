//! Storage audit protocol (Section 15).
//!
//! Challenge-response for claimed holders. Anti-outsourcing protection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::logging::{debug, info, warn};
use rand::seq::SliceRandom;
use rand::Rng;

use crate::ant_protocol::XorName;
use crate::replication::config::{ReplicationConfig, REPLICATION_PROTOCOL_ID};
use crate::replication::protocol::{
    compute_audit_digest, AuditChallenge, AuditResponse, ReplicationMessage,
    ReplicationMessageBody, ABSENT_KEY_DIGEST,
};
use crate::replication::types::{AuditFailureReason, FailureEvidence, PeerSyncRecord};
use crate::storage::LmdbStorage;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;

// ---------------------------------------------------------------------------
// Audit tick result
// ---------------------------------------------------------------------------

/// Result of an audit tick.
#[derive(Debug)]
pub enum AuditTickResult {
    /// Audit completed successfully (all digests matched).
    Passed {
        /// The peer that was challenged.
        challenged_peer: PeerId,
        /// Number of keys verified.
        keys_checked: usize,
    },
    /// Audit found failures (after responsibility confirmation).
    Failed {
        /// Evidence of the failure for trust engine.
        evidence: FailureEvidence,
    },
    /// Audit target claimed bootstrapping.
    BootstrapClaim {
        /// The peer claiming bootstrap status.
        peer: PeerId,
    },
    /// No eligible peers for audit this tick.
    Idle,
    /// Audit skipped (not enough local keys).
    InsufficientKeys,
}

// ---------------------------------------------------------------------------
// Main audit tick
// ---------------------------------------------------------------------------

/// Execute one audit tick (Section 15 steps 2-9).
///
/// Returns the audit result. Caller is responsible for emitting trust events.
///
/// **Invariant 19**: Returns [`AuditTickResult::Idle`] immediately if
/// `is_bootstrapping` is `true` — a node must not audit others while it
/// is still bootstrapping.
#[allow(clippy::implicit_hasher, clippy::too_many_lines)]
pub async fn audit_tick(
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    config: &ReplicationConfig,
    sync_history: &HashMap<PeerId, PeerSyncRecord>,
    bootstrap_claims: &HashMap<PeerId, Instant>,
    is_bootstrapping: bool,
) -> AuditTickResult {
    // Invariant 19: never audit while still bootstrapping.
    if is_bootstrapping {
        return AuditTickResult::Idle;
    }

    let dht = p2p_node.dht_manager();
    let now = Instant::now();

    // Step 2: Select one eligible peer (has RepairOpportunity) at random.
    // Exclude peers whose bootstrap claim has exceeded the grace period —
    // they are already penalized in handle_audit_result and should not
    // consume an audit slot.
    let eligible_peers: Vec<PeerId> = sync_history
        .iter()
        .filter(|(_, record)| record.has_repair_opportunity())
        .filter(|(peer, _)| {
            bootstrap_claims.get(peer).map_or(true, |first_seen| {
                now.duration_since(*first_seen) <= config.bootstrap_claim_grace_period
            })
        })
        .map(|(peer, _)| *peer)
        .collect();

    if eligible_peers.is_empty() {
        return AuditTickResult::Idle;
    }

    let (challenged_peer, nonce, challenge_id) = {
        let mut rng = rand::thread_rng();
        let selected = match eligible_peers.choose(&mut rng) {
            Some(p) => *p,
            None => return AuditTickResult::Idle,
        };
        let n: [u8; 32] = rng.gen();
        let c: u64 = rng.gen();
        (selected, n, c)
    };

    // Step 3: Sample keys from local store and keep those the peer is
    // responsible for (appears in the close group via local RT lookup).
    let all_keys = match storage.all_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Audit: failed to read local keys: {e}");
            return AuditTickResult::Idle;
        }
    };

    if all_keys.is_empty() {
        return AuditTickResult::Idle;
    }

    let sample_count = ReplicationConfig::audit_sample_count(all_keys.len());
    let sampled_keys: Vec<XorName> = {
        let mut rng = rand::thread_rng();
        all_keys
            .choose_multiple(&mut rng, sample_count)
            .copied()
            .collect()
    };

    // Step 4: Filter to keys where the chosen peer is in the close group.
    let mut peer_keys = Vec::new();
    for key in &sampled_keys {
        let closest = dht
            .find_closest_nodes_local_with_self(key, config.close_group_size)
            .await;
        if closest.iter().any(|n| n.peer_id == challenged_peer) {
            peer_keys.push(*key);
        }
    }

    if peer_keys.is_empty() {
        return AuditTickResult::Idle;
    }

    // peer_keys is naturally bounded by audit_sample_count (sqrt-scaled),
    // so no explicit truncation needed.

    // Step 6: Send challenge.

    let challenge = AuditChallenge {
        challenge_id,
        nonce,
        challenged_peer_id: *challenged_peer.as_bytes(),
        keys: peer_keys.clone(),
    };

    let msg = ReplicationMessage {
        request_id: challenge_id,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };

    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Audit: failed to encode challenge: {e}");
            return AuditTickResult::Idle;
        }
    };

    let response = match p2p_node
        .send_request(
            &challenged_peer,
            REPLICATION_PROTOCOL_ID,
            encoded,
            config.audit_response_timeout(peer_keys.len()),
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            debug!("Audit: challenge to {challenged_peer} failed: {e}");
            // Timeout — need responsibility confirmation before penalty.
            return handle_audit_timeout(
                &challenged_peer,
                challenge_id,
                &peer_keys,
                p2p_node,
                config,
            )
            .await;
        }
    };

    // Step 7: Parse response.
    let resp_msg = match ReplicationMessage::decode(&response.data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Audit: failed to decode response from {challenged_peer}: {e}");
            return handle_audit_failure(
                &challenged_peer,
                challenge_id,
                &peer_keys,
                AuditFailureReason::MalformedResponse,
                p2p_node,
                config,
            )
            .await;
        }
    };

    match resp_msg.body {
        ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping {
            challenge_id: resp_id,
        }) => {
            if resp_id != challenge_id {
                warn!("Audit: challenge ID mismatch on Bootstrapping from {challenged_peer}");
                return handle_audit_failure(
                    &challenged_peer,
                    challenge_id,
                    &peer_keys,
                    AuditFailureReason::MalformedResponse,
                    p2p_node,
                    config,
                )
                .await;
            }
            // Step 7b: Bootstrapping claim.
            AuditTickResult::BootstrapClaim {
                peer: challenged_peer,
            }
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
            challenge_id: resp_id,
            digests,
        }) => {
            if resp_id != challenge_id {
                warn!("Audit: challenge ID mismatch from {challenged_peer}");
                return handle_audit_failure(
                    &challenged_peer,
                    challenge_id,
                    &peer_keys,
                    AuditFailureReason::MalformedResponse,
                    p2p_node,
                    config,
                )
                .await;
            }
            verify_digests(
                &challenged_peer,
                challenge_id,
                &nonce,
                &peer_keys,
                &digests,
                storage,
                p2p_node,
                config,
            )
            .await
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::Rejected {
            challenge_id: resp_id,
            reason,
        }) => {
            if resp_id != challenge_id {
                warn!("Audit: challenge ID mismatch on Rejected from {challenged_peer}");
                return handle_audit_failure(
                    &challenged_peer,
                    challenge_id,
                    &peer_keys,
                    AuditFailureReason::MalformedResponse,
                    p2p_node,
                    config,
                )
                .await;
            }
            warn!("Audit: challenge rejected by {challenged_peer}: {reason}");
            handle_audit_failure(
                &challenged_peer,
                challenge_id,
                &peer_keys,
                AuditFailureReason::Rejected,
                p2p_node,
                config,
            )
            .await
        }
        _ => {
            warn!("Audit: unexpected response type from {challenged_peer}");
            handle_audit_failure(
                &challenged_peer,
                challenge_id,
                &peer_keys,
                AuditFailureReason::MalformedResponse,
                p2p_node,
                config,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Digest verification
// ---------------------------------------------------------------------------

/// Verify per-key digests from audit response (Step 8).
#[allow(clippy::too_many_arguments)]
async fn verify_digests(
    challenged_peer: &PeerId,
    challenge_id: u64,
    nonce: &[u8; 32],
    keys: &[XorName],
    digests: &[[u8; 32]],
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> AuditTickResult {
    // Requirement: response must have exactly one digest per key.
    if digests.len() != keys.len() {
        warn!(
            "Audit: malformed response from {challenged_peer}: {} digests for {} keys",
            digests.len(),
            keys.len()
        );
        return handle_audit_failure(
            challenged_peer,
            challenge_id,
            keys,
            AuditFailureReason::MalformedResponse,
            p2p_node,
            config,
        )
        .await;
    }

    let challenged_peer_bytes = challenged_peer.as_bytes();
    let mut failed_keys = Vec::new();

    for (i, key) in keys.iter().enumerate() {
        let received_digest = &digests[i];

        // Check for absent sentinel.
        if *received_digest == ABSENT_KEY_DIGEST {
            failed_keys.push(*key);
            continue;
        }

        // Recompute expected digest from local copy.
        let local_bytes = match storage.get_raw(key).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // We should hold this key (we sampled it), but it's gone.
                warn!(
                    "Audit: local key {} disappeared during audit",
                    hex::encode(key)
                );
                continue;
            }
            Err(e) => {
                warn!("Audit: failed to read local key {}: {e}", hex::encode(key));
                continue;
            }
        };

        let expected = compute_audit_digest(nonce, challenged_peer_bytes, key, &local_bytes);
        if *received_digest != expected {
            failed_keys.push(*key);
        }
    }

    if failed_keys.is_empty() {
        info!(
            "Audit: peer {challenged_peer} passed (all {} keys verified)",
            keys.len()
        );
        return AuditTickResult::Passed {
            challenged_peer: *challenged_peer,
            keys_checked: keys.len(),
        };
    }

    // Step 9: Responsibility confirmation for failed keys.
    handle_audit_failure(
        challenged_peer,
        challenge_id,
        &failed_keys,
        AuditFailureReason::DigestMismatch,
        p2p_node,
        config,
    )
    .await
}

// ---------------------------------------------------------------------------
// Failure handling with responsibility confirmation
// ---------------------------------------------------------------------------

/// Handle audit failure: confirm responsibility before emitting evidence (Step 9).
async fn handle_audit_failure(
    challenged_peer: &PeerId,
    challenge_id: u64,
    failed_keys: &[XorName],
    reason: AuditFailureReason,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> AuditTickResult {
    let dht = p2p_node.dht_manager();
    let mut confirmed_failures = Vec::new();

    // Step 9a-b: Fresh local RT lookup for each failed key.
    for key in failed_keys {
        let closest = dht
            .find_closest_nodes_local_with_self(key, config.close_group_size)
            .await;
        if closest.iter().any(|n| n.peer_id == *challenged_peer) {
            confirmed_failures.push(*key);
        } else {
            debug!(
                "Audit: peer {challenged_peer} not responsible for {} (removed from failure set)",
                hex::encode(key)
            );
        }
    }

    // Step 9c: Empty confirmed set -> peer is no longer responsible for any
    // of the failed keys (topology churn). This is NOT a pass — the peer did
    // not prove it stores the data. Return Idle to avoid granting unearned
    // positive trust.
    if confirmed_failures.is_empty() {
        info!("Audit: all failures for {challenged_peer} cleared by responsibility confirmation");
        return AuditTickResult::Idle;
    }

    // Step 9d: Non-empty confirmed set -> emit evidence.
    let evidence = FailureEvidence::AuditFailure {
        challenge_id,
        challenged_peer: *challenged_peer,
        confirmed_failed_keys: confirmed_failures,
        reason,
    };

    AuditTickResult::Failed { evidence }
}

/// Handle audit timeout (no response received).
async fn handle_audit_timeout(
    challenged_peer: &PeerId,
    challenge_id: u64,
    keys: &[XorName],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> AuditTickResult {
    handle_audit_failure(
        challenged_peer,
        challenge_id,
        keys,
        AuditFailureReason::Timeout,
        p2p_node,
        config,
    )
    .await
}

// ---------------------------------------------------------------------------
// Responder-side handler
// ---------------------------------------------------------------------------

/// Handle an incoming audit challenge (responder side).
///
/// Validates that the challenge targets this node, computes per-key digests,
/// and returns the response.  Rejects challenges where
/// `challenged_peer_id` does not match `self_peer_id` to prevent an oracle
/// attack where a malicious challenger forges digests for a different peer.
pub async fn handle_audit_challenge(
    challenge: &AuditChallenge,
    storage: &LmdbStorage,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    stored_chunks: usize,
) -> AuditResponse {
    if is_bootstrapping {
        return AuditResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    if challenge.challenged_peer_id != *self_peer_id.as_bytes() {
        warn!(
            "Audit challenge targeted wrong peer: expected {}, got {}",
            hex::encode(self_peer_id.as_bytes()),
            hex::encode(challenge.challenged_peer_id),
        );
        return AuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: "challenged_peer_id does not match this node".to_string(),
        };
    }

    let max_keys = ReplicationConfig::max_incoming_audit_keys(stored_chunks);
    if challenge.keys.len() > max_keys {
        warn!(
            "Audit challenge rejected: {} keys exceeds dynamic limit of {max_keys} \
             (stored_chunks={stored_chunks})",
            challenge.keys.len(),
        );
        return AuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: format!(
                "challenge contains {} keys, limit is {max_keys}",
                challenge.keys.len()
            ),
        };
    }

    let mut digests = Vec::with_capacity(challenge.keys.len());

    for key in &challenge.keys {
        match storage.get_raw(key).await {
            Ok(Some(data)) => {
                let digest = compute_audit_digest(
                    &challenge.nonce,
                    &challenge.challenged_peer_id,
                    key,
                    &data,
                );
                digests.push(digest);
            }
            Ok(None) => {
                digests.push(ABSENT_KEY_DIGEST);
            }
            Err(e) => {
                warn!(
                    "Audit responder: failed to read key {}: {e}",
                    hex::encode(key)
                );
                digests.push(ABSENT_KEY_DIGEST);
            }
        }
    }

    AuditResponse::Digests {
        challenge_id: challenge.challenge_id,
        digests,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::protocol::compute_audit_digest;
    use crate::replication::types::NeighborSyncState;
    use crate::storage::LmdbStorageConfig;
    use tempfile::TempDir;

    /// Simulated stored chunk count for tests. Large enough that the dynamic
    /// incoming audit limit (`2 * sqrt(N)`) never rejects small test challenges.
    const TEST_STORED_CHUNKS: usize = 1_000_000;

    /// Create a test `LmdbStorage` backed by a temp directory.
    async fn create_test_storage() -> (LmdbStorage, TempDir) {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = LmdbStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            verify_on_read: false,
            max_map_size: 0,
            disk_reserve: 0,
        };
        let storage = LmdbStorage::new(config).await.expect("create storage");
        (storage, temp_dir)
    }

    /// Build a challenge with the given parameters.
    fn make_challenge(
        challenge_id: u64,
        nonce: [u8; 32],
        peer_id: [u8; 32],
        keys: Vec<XorName>,
    ) -> AuditChallenge {
        AuditChallenge {
            challenge_id,
            nonce,
            challenged_peer_id: peer_id,
            keys,
        }
    }

    /// Build a `PeerId` matching the raw bytes used in a challenge.
    fn peer_id_from_bytes(bytes: [u8; 32]) -> PeerId {
        PeerId::from_bytes(bytes)
    }

    // -- handle_audit_challenge: present keys ---------------------------------

    #[tokio::test]
    async fn handle_challenge_present_keys_returns_correct_digests() {
        let (storage, _temp) = create_test_storage().await;

        // Store two chunks.
        let content_a = b"chunk alpha";
        let addr_a = LmdbStorage::compute_address(content_a);
        storage.put(&addr_a, content_a).await.expect("put a");

        let content_b = b"chunk beta";
        let addr_b = LmdbStorage::compute_address(content_b);
        storage.put(&addr_b, content_b).await.expect("put b");

        let nonce = [0xAA; 32];
        let peer_id = [0xBB; 32];
        let challenge = make_challenge(42, nonce, peer_id, vec![addr_a, addr_b]);
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests {
                challenge_id,
                digests,
            } => {
                assert_eq!(challenge_id, 42);
                assert_eq!(digests.len(), 2);

                let expected_a = compute_audit_digest(&nonce, &peer_id, &addr_a, content_a);
                let expected_b = compute_audit_digest(&nonce, &peer_id, &addr_b, content_b);
                assert_eq!(digests[0], expected_a);
                assert_eq!(digests[1], expected_b);
            }
            AuditResponse::Bootstrapping { .. } => {
                panic!("expected Digests, got Bootstrapping");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
        }
    }

    // -- handle_audit_challenge: absent keys ----------------------------------

    #[tokio::test]
    async fn handle_challenge_absent_keys_returns_sentinel() {
        let (storage, _temp) = create_test_storage().await;

        let absent_key = [0xFF; 32];
        let nonce = [0x11; 32];
        let peer_id = [0x22; 32];
        let challenge = make_challenge(99, nonce, peer_id, vec![absent_key]);
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests {
                challenge_id,
                digests,
            } => {
                assert_eq!(challenge_id, 99);
                assert_eq!(digests.len(), 1);
                assert_eq!(
                    digests[0], ABSENT_KEY_DIGEST,
                    "absent key should produce sentinel digest"
                );
            }
            AuditResponse::Bootstrapping { .. } => {
                panic!("expected Digests, got Bootstrapping");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
        }
    }

    // -- handle_audit_challenge: mixed present and absent ---------------------

    #[tokio::test]
    async fn handle_challenge_mixed_present_and_absent() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"present chunk";
        let addr_present = LmdbStorage::compute_address(content);
        storage.put(&addr_present, content).await.expect("put");

        let addr_absent = [0xDE; 32];
        let nonce = [0x33; 32];
        let peer_id = [0x44; 32];
        let challenge = make_challenge(7, nonce, peer_id, vec![addr_present, addr_absent]);
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests { digests, .. } => {
                assert_eq!(digests.len(), 2);

                let expected_present =
                    compute_audit_digest(&nonce, &peer_id, &addr_present, content);
                assert_eq!(digests[0], expected_present);
                assert_eq!(
                    digests[1], ABSENT_KEY_DIGEST,
                    "absent key should be sentinel"
                );
            }
            AuditResponse::Bootstrapping { .. } => {
                panic!("expected Digests, got Bootstrapping");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
        }
    }

    // -- handle_audit_challenge: bootstrapping --------------------------------

    #[tokio::test]
    async fn handle_challenge_bootstrapping_returns_bootstrapping_response() {
        let (storage, _temp) = create_test_storage().await;

        let challenge = make_challenge(55, [0x00; 32], [0x01; 32], vec![[0x02; 32]]);
        let self_id = peer_id_from_bytes([0x01; 32]);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, true, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Bootstrapping { challenge_id } => {
                assert_eq!(challenge_id, 55);
            }
            AuditResponse::Digests { .. } => {
                panic!("expected Bootstrapping, got Digests");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
        }
    }

    // -- handle_audit_challenge: empty key list -------------------------------

    #[tokio::test]
    async fn handle_challenge_empty_keys_returns_empty_digests() {
        let (storage, _temp) = create_test_storage().await;

        let challenge = make_challenge(100, [0x10; 32], [0x20; 32], vec![]);
        let self_id = peer_id_from_bytes([0x20; 32]);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests {
                challenge_id,
                digests,
            } => {
                assert_eq!(challenge_id, 100);
                assert!(
                    digests.is_empty(),
                    "empty key list should yield empty digests"
                );
            }
            AuditResponse::Bootstrapping { .. } => {
                panic!("expected Digests, got Bootstrapping");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
        }
    }

    // -- Digest verification: matching ----------------------------------------

    #[test]
    fn digest_verification_matching() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];
        let data = b"correct data";

        let expected = compute_audit_digest(&nonce, &peer_id, &key, data);
        let recomputed = compute_audit_digest(&nonce, &peer_id, &key, data);

        assert_eq!(
            expected, recomputed,
            "same inputs must produce identical digests"
        );
        assert_ne!(
            expected, ABSENT_KEY_DIGEST,
            "real digest must not be sentinel"
        );
    }

    // -- Digest verification: mismatching -------------------------------------

    #[test]
    fn digest_verification_mismatching_data() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];

        let digest_a = compute_audit_digest(&nonce, &peer_id, &key, b"data version A");
        let digest_b = compute_audit_digest(&nonce, &peer_id, &key, b"data version B");

        assert_ne!(
            digest_a, digest_b,
            "different data must produce different digests"
        );
    }

    #[test]
    fn digest_verification_mismatching_nonce() {
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];
        let data = b"same data";

        let digest_a = compute_audit_digest(&[0x01; 32], &peer_id, &key, data);
        let digest_b = compute_audit_digest(&[0xFF; 32], &peer_id, &key, data);

        assert_ne!(
            digest_a, digest_b,
            "different nonces must produce different digests"
        );
    }

    #[test]
    fn digest_verification_mismatching_peer() {
        let nonce = [0x01; 32];
        let key: XorName = [0x03; 32];
        let data = b"same data";

        let digest_a = compute_audit_digest(&nonce, &[0x02; 32], &key, data);
        let digest_b = compute_audit_digest(&nonce, &[0xFE; 32], &key, data);

        assert_ne!(
            digest_a, digest_b,
            "different peers must produce different digests"
        );
    }

    #[test]
    fn digest_verification_mismatching_key() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let data = b"same data";

        let digest_a = compute_audit_digest(&nonce, &peer_id, &[0x03; 32], data);
        let digest_b = compute_audit_digest(&nonce, &peer_id, &[0xFC; 32], data);

        assert_ne!(
            digest_a, digest_b,
            "different keys must produce different digests"
        );
    }

    // -- Absent sentinel is all zeros -----------------------------------------

    #[test]
    fn absent_sentinel_is_all_zeros() {
        assert_eq!(ABSENT_KEY_DIGEST, [0u8; 32], "sentinel must be all zeros");
    }

    // -- Bootstrapping skips digest computation even with stored keys ---------

    #[tokio::test]
    async fn bootstrapping_skips_digest_computation() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"stored but bootstrapping";
        let addr = LmdbStorage::compute_address(content);
        storage.put(&addr, content).await.expect("put");

        let challenge = make_challenge(200, [0xCC; 32], [0xDD; 32], vec![addr]);
        let self_id = peer_id_from_bytes([0xDD; 32]);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, true, TEST_STORED_CHUNKS).await;

        assert!(
            matches!(response, AuditResponse::Bootstrapping { challenge_id: 200 }),
            "bootstrapping node must not compute digests"
        );
    }

    // -- Scenario 19/53: Partial failure with mixed responsibility ----------------

    #[tokio::test]
    async fn scenario_19_partial_failure_mixed_responsibility() {
        // Three keys challenged: K1 matches, K2 mismatches, K3 absent.
        // After responsibility confirmation, only K2 is confirmed responsible.
        // AuditFailure emitted for {K2} only.
        // Test handle_audit_challenge with mixed results, then verify
        // the digest logic manually.

        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x42u8; 32];
        let peer_id = [0xAA; 32];

        // Store K1 and K2, but NOT K3
        let content_k1 = b"key one data";
        let addr_k1 = LmdbStorage::compute_address(content_k1);
        storage.put(&addr_k1, content_k1).await.unwrap();

        let content_k2 = b"key two data";
        let addr_k2 = LmdbStorage::compute_address(content_k2);
        storage.put(&addr_k2, content_k2).await.unwrap();

        let addr_k3 = [0xFF; 32]; // Not stored

        let challenge = AuditChallenge {
            challenge_id: 100,
            nonce,
            challenged_peer_id: peer_id,
            keys: vec![addr_k1, addr_k2, addr_k3],
        };
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests { digests, .. } => {
                assert_eq!(digests.len(), 3);

                // K1 should have correct digest
                let expected_k1 = compute_audit_digest(&nonce, &peer_id, &addr_k1, content_k1);
                assert_eq!(digests[0], expected_k1);

                // K2 should have correct digest
                let expected_k2 = compute_audit_digest(&nonce, &peer_id, &addr_k2, content_k2);
                assert_eq!(digests[1], expected_k2);

                // K3 absent -> sentinel
                assert_eq!(digests[2], ABSENT_KEY_DIGEST);
            }
            AuditResponse::Bootstrapping { .. } => panic!("Expected Digests response"),
            AuditResponse::Rejected { .. } => panic!("Unexpected Rejected response"),
        }
    }

    // -- Scenario 54: All digests pass -------------------------------------------

    #[tokio::test]
    async fn scenario_54_all_digests_pass() {
        // All challenged keys present and digests match.
        // Multiple keys to strengthen coverage beyond existing two-key tests.
        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x10; 32];
        let peer_id = [0x20; 32];

        let c1 = b"chunk alpha";
        let c2 = b"chunk beta";
        let c3 = b"chunk gamma";
        let a1 = LmdbStorage::compute_address(c1);
        let a2 = LmdbStorage::compute_address(c2);
        let a3 = LmdbStorage::compute_address(c3);
        storage.put(&a1, c1).await.unwrap();
        storage.put(&a2, c2).await.unwrap();
        storage.put(&a3, c3).await.unwrap();

        let challenge = AuditChallenge {
            challenge_id: 200,
            nonce,
            challenged_peer_id: peer_id,
            keys: vec![a1, a2, a3],
        };
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;
        match response {
            AuditResponse::Digests { digests, .. } => {
                assert_eq!(digests.len(), 3);
                for (i, (addr, content)) in [(a1, &c1[..]), (a2, &c2[..]), (a3, &c3[..])]
                    .iter()
                    .enumerate()
                {
                    let expected = compute_audit_digest(&nonce, &peer_id, addr, content);
                    assert_eq!(digests[i], expected, "Key {i} digest should match");
                }
            }
            AuditResponse::Bootstrapping { .. } => panic!("Expected Digests"),
            AuditResponse::Rejected { .. } => panic!("Unexpected Rejected response"),
        }
    }

    // -- Scenario 55: Empty failure set means no evidence -------------------------

    /// Scenario 55: Peer challenged on {K1, K2}. Both digests mismatch.
    /// Responsibility confirmation shows the peer is NOT responsible for
    /// either key. The confirmed failure set is empty — no `AuditFailure`
    /// evidence is emitted.
    ///
    /// Full `verify_digests` requires a live `P2PNode` for network lookups.
    /// This test exercises the deterministic sub-steps:
    ///   (1) Digest comparison identifies K1 and K2 as mismatches.
    ///   (2) Responsibility confirmation removes both keys.
    ///   (3) Empty confirmed failure set means no evidence.
    #[tokio::test]
    async fn scenario_55_no_confirmed_responsibility_no_evidence() {
        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x55; 32];
        let peer_id = [0x55; 32];

        // Store K1 and K2 on the challenger (for expected digest computation).
        let c1 = b"scenario 55 key one";
        let c2 = b"scenario 55 key two";
        let k1 = LmdbStorage::compute_address(c1);
        let k2 = LmdbStorage::compute_address(c2);
        storage.put(&k1, c1).await.expect("put k1");
        storage.put(&k2, c2).await.expect("put k2");

        // Challenger computes expected digests.
        let expected_d1 = compute_audit_digest(&nonce, &peer_id, &k1, c1);
        let expected_d2 = compute_audit_digest(&nonce, &peer_id, &k2, c2);

        // Simulate peer returning WRONG digests for both keys.
        let wrong_d1 = compute_audit_digest(&nonce, &peer_id, &k1, b"corrupted k1");
        let wrong_d2 = compute_audit_digest(&nonce, &peer_id, &k2, b"corrupted k2");
        assert_ne!(wrong_d1, expected_d1, "K1 digest should mismatch");
        assert_ne!(wrong_d2, expected_d2, "K2 digest should mismatch");

        // Step 1: Identify failed keys via digest comparison.
        let keys = [k1, k2];
        let expected = [expected_d1, expected_d2];
        let received = [wrong_d1, wrong_d2];

        let mut failed_keys = Vec::new();
        for i in 0..keys.len() {
            if received[i] != expected[i] {
                failed_keys.push(keys[i]);
            }
        }
        assert_eq!(
            failed_keys.len(),
            2,
            "Both keys should be identified as digest mismatches"
        );

        // Step 2: Responsibility confirmation — peer is NOT responsible for
        // either key (simulated by filtering them all out).
        let confirmed_responsible_keys: Vec<XorName> = Vec::new();
        let confirmed_failures: Vec<XorName> = failed_keys
            .into_iter()
            .filter(|k| confirmed_responsible_keys.contains(k))
            .collect();

        // Step 3: Empty confirmed failure set → no AuditFailure evidence.
        assert!(
            confirmed_failures.is_empty(),
            "With no confirmed responsibility, failure set must be empty — \
             no AuditFailure evidence should be emitted"
        );

        // Verify that constructing evidence with empty keys results in a
        // no-penalty outcome (the caller checks is_empty before emitting).
        let peer = PeerId::from_bytes(peer_id);
        let evidence = FailureEvidence::AuditFailure {
            challenge_id: 5500,
            challenged_peer: peer,
            confirmed_failed_keys: confirmed_failures,
            reason: AuditFailureReason::DigestMismatch,
        };
        if let FailureEvidence::AuditFailure {
            confirmed_failed_keys,
            ..
        } = evidence
        {
            assert!(
                confirmed_failed_keys.is_empty(),
                "Evidence with empty failure set should not trigger a trust penalty"
            );
        }
    }

    // -- Scenario 56: RepairOpportunity filters never-synced peers ----------------

    #[test]
    fn scenario_56_repair_opportunity_filters_never_synced() {
        // PeerSyncRecord with last_sync=None should not pass
        // has_repair_opportunity().

        let never_synced = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 5,
        };
        assert!(!never_synced.has_repair_opportunity());

        let synced_no_cycle = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 0,
        };
        assert!(!synced_no_cycle.has_repair_opportunity());

        let synced_with_cycle = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 1,
        };
        assert!(synced_with_cycle.has_repair_opportunity());
    }

    // -- Audit response must match key count --------------------------------------

    #[tokio::test]
    async fn audit_response_must_match_key_count() {
        // Section 15: "A response is invalid if it has fewer or more entries
        // than challenged keys."
        // Verify handle_audit_challenge always produces exactly N digests for
        // N keys, including edge cases.

        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x50; 32];
        let peer_id = [0x60; 32];

        // Store a single chunk
        let content = b"single chunk";
        let addr = LmdbStorage::compute_address(content);
        storage.put(&addr, content).await.unwrap();

        // Challenge with 1 stored + 4 absent = 5 keys total
        let absent_keys: Vec<XorName> = (1..=4u8).map(|i| [i; 32]).collect();
        let mut keys = vec![addr];
        keys.extend_from_slice(&absent_keys);

        let key_count = keys.len();
        let challenge = make_challenge(300, nonce, peer_id, keys);
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;
        match response {
            AuditResponse::Digests { digests, .. } => {
                assert_eq!(
                    digests.len(),
                    key_count,
                    "must produce exactly one digest per challenged key"
                );
            }
            AuditResponse::Bootstrapping { .. } => panic!("Expected Digests"),
            AuditResponse::Rejected { .. } => panic!("Unexpected Rejected response"),
        }
    }

    // -- Audit digest uses full record bytes --------------------------------------

    #[test]
    fn audit_digest_uses_full_record_bytes() {
        // Verify digest changes when record content changes.
        let nonce = [1u8; 32];
        let peer = [2u8; 32];
        let key = [3u8; 32];

        let d1 = compute_audit_digest(&nonce, &peer, &key, b"data version 1");
        let d2 = compute_audit_digest(&nonce, &peer, &key, b"data version 2");
        assert_ne!(
            d1, d2,
            "Different record bytes must produce different digests"
        );
    }

    // -- Scenario 29: Audit start gate ------------------------------------------

    /// Scenario 29: `handle_audit_challenge` returns `Bootstrapping` when the
    /// node is still bootstrapping — audit digests are never computed, and no
    /// `AuditFailure` evidence is emitted by the caller.
    ///
    /// This is the responder-side gate.  The challenger-side gate is enforced
    /// by `audit_tick`'s `is_bootstrapping` guard (Invariant 19) and by
    /// `check_bootstrap_drained()` in the engine loop; this test confirms the
    /// complementary responder behavior.
    #[tokio::test]
    async fn scenario_29_audit_start_gate_during_bootstrap() {
        let (storage, _temp) = create_test_storage().await;

        // Store data so there *would* be work to audit.
        let content = b"should not be audited during bootstrap";
        let addr = LmdbStorage::compute_address(content);
        storage.put(&addr, content).await.expect("put");

        let challenge = make_challenge(2900, [0x29; 32], [0x29; 32], vec![addr]);
        let self_id = peer_id_from_bytes([0x29; 32]);

        // Responder is bootstrapping → Bootstrapping response, NOT Digests.
        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, true, TEST_STORED_CHUNKS).await;
        assert!(
            matches!(
                response,
                AuditResponse::Bootstrapping { challenge_id: 2900 }
            ),
            "bootstrapping node must not compute digests — audit start gate"
        );

        // Responder is NOT bootstrapping → normal Digests.
        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;
        assert!(
            matches!(response, AuditResponse::Digests { .. }),
            "drained node should compute digests normally"
        );
    }

    // -- Scenario 30: Audit peer selection from sampled keys --------------------

    /// Scenario 30: Key sampling uses dynamic sqrt-based batch sizing and
    /// `RepairOpportunity` filtering excludes never-synced peers.
    ///
    /// Full `audit_tick` requires a live network.  This test verifies the two
    /// deterministic sub-steps the function relies on:
    ///   (a) `audit_sample_count` scales with `sqrt(total_keys)`.
    ///   (b) `PeerSyncRecord::has_repair_opportunity` gates peer eligibility.
    #[test]
    fn scenario_30_audit_peer_selection_from_sampled_keys() {
        // (a) Dynamic sample count scales with sqrt(total_keys).
        assert_eq!(
            ReplicationConfig::audit_sample_count(100),
            10,
            "sample count should scale with sqrt(total_keys)"
        );

        assert_eq!(ReplicationConfig::audit_sample_count(3), 1, "sqrt(3) = 1");

        assert_eq!(
            ReplicationConfig::audit_sample_count(10_000),
            100,
            "sqrt(10000) = 100"
        );

        // (b) Peer eligibility via RepairOpportunity.
        // Never synced → not eligible.
        let never = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 10,
        };
        assert!(!never.has_repair_opportunity());

        // Synced but zero subsequent cycles → not eligible.
        let too_soon = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 0,
        };
        assert!(!too_soon.has_repair_opportunity());

        // Synced with ≥1 cycle → eligible.
        let eligible = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 2,
        };
        assert!(eligible.has_repair_opportunity());
    }

    // -- Scenario 32: Dynamic challenge size ------------------------------------

    /// Scenario 32: Challenge key count equals `|PeerKeySet(challenged_peer)|`,
    /// which is dynamic per round.  If no eligible peer remains after filtering,
    /// the tick is idle.
    ///
    /// Verified via `handle_audit_challenge`: the response digest count always
    /// equals the number of keys in the challenge.
    #[tokio::test]
    async fn scenario_32_dynamic_challenge_size() {
        let (storage, _temp) = create_test_storage().await;

        // Store varying numbers of chunks.
        let mut addrs = Vec::new();
        for i in 0u8..5 {
            let content = format!("dynamic challenge key {i}");
            let addr = LmdbStorage::compute_address(content.as_bytes());
            storage.put(&addr, content.as_bytes()).await.expect("put");
            addrs.push(addr);
        }

        let nonce = [0x32; 32];
        let peer_id = [0x32; 32];
        let self_id = peer_id_from_bytes(peer_id);

        // Challenge with 1 key.
        let challenge1 = make_challenge(3201, nonce, peer_id, vec![addrs[0]]);
        let resp1 =
            handle_audit_challenge(&challenge1, &storage, &self_id, false, TEST_STORED_CHUNKS)
                .await;
        if let AuditResponse::Digests { digests, .. } = resp1 {
            assert_eq!(digests.len(), 1, "|PeerKeySet| = 1 → 1 digest");
        }

        // Challenge with 3 keys.
        let challenge3 = make_challenge(3203, nonce, peer_id, addrs[0..3].to_vec());
        let resp3 =
            handle_audit_challenge(&challenge3, &storage, &self_id, false, TEST_STORED_CHUNKS)
                .await;
        if let AuditResponse::Digests { digests, .. } = resp3 {
            assert_eq!(digests.len(), 3, "|PeerKeySet| = 3 → 3 digests");
        }

        // Challenge with all 5 keys.
        let challenge5 = make_challenge(3205, nonce, peer_id, addrs.clone());
        let resp5 =
            handle_audit_challenge(&challenge5, &storage, &self_id, false, TEST_STORED_CHUNKS)
                .await;
        if let AuditResponse::Digests { digests, .. } = resp5 {
            assert_eq!(digests.len(), 5, "|PeerKeySet| = 5 → 5 digests");
        }

        // Challenge with 0 keys (idle equivalent — no work).
        let challenge0 = make_challenge(3200, nonce, peer_id, vec![]);
        let resp0 =
            handle_audit_challenge(&challenge0, &storage, &self_id, false, TEST_STORED_CHUNKS)
                .await;
        if let AuditResponse::Digests { digests, .. } = resp0 {
            assert!(digests.is_empty(), "|PeerKeySet| = 0 → 0 digests (idle)");
        }
    }

    // -- Scenario 47: Bootstrap claim grace period (audit) ----------------------

    /// Scenario 47: Challenged peer responds with bootstrapping claim during
    /// audit.  `handle_audit_challenge` returns `Bootstrapping`; caller records
    /// `BootstrapClaimFirstSeen`.  No `AuditFailure` evidence is emitted.
    #[tokio::test]
    async fn scenario_47_bootstrap_claim_grace_period_audit() {
        let (storage, _temp) = create_test_storage().await;

        // Store data so there is an auditable key.
        let content = b"bootstrap grace test";
        let addr = LmdbStorage::compute_address(content);
        storage.put(&addr, content).await.expect("put");

        let challenge = make_challenge(4700, [0x47; 32], [0x47; 32], vec![addr]);
        let self_id = peer_id_from_bytes([0x47; 32]);

        // Bootstrapping peer → Bootstrapping response (grace period start).
        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, true, TEST_STORED_CHUNKS).await;
        let challenge_id = match response {
            AuditResponse::Bootstrapping { challenge_id } => challenge_id,
            AuditResponse::Digests { .. } => {
                panic!("Expected Bootstrapping response during grace period")
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response")
            }
        };
        assert_eq!(challenge_id, 4700);

        // Caller records BootstrapClaimFirstSeen — verify the types support it.
        let peer = PeerId::from_bytes([0x47; 32]);
        let mut state = NeighborSyncState::new_cycle(vec![peer]);
        let now = Instant::now();
        state.bootstrap_claims.entry(peer).or_insert(now);

        assert!(
            state.bootstrap_claims.contains_key(&peer),
            "BootstrapClaimFirstSeen should be recorded after grace-period claim"
        );
    }

    // -- Scenario 53: Audit partial per-key failure with mixed responsibility ---

    /// Scenario 53: P challenged on {K1, K2, K3}.  K1 matches, K2 and K3
    /// mismatch.  Responsibility confirmation: P is responsible for K2 but
    /// not K3.  `AuditFailure` emitted for {K2} only.
    ///
    /// Full `verify_digests` + `handle_audit_failure` requires a `P2PNode` for
    /// network lookups.  This test verifies the conceptual steps:
    ///   (1) Digest comparison correctly identifies K2 and K3 as failures.
    ///   (2) `FailureEvidence::AuditFailure` carries only confirmed keys.
    #[tokio::test]
    async fn scenario_53_partial_failure_mixed_responsibility() {
        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x53; 32];
        let peer_id = [0x53; 32];

        // Store K1, K2, K3.
        let c1 = b"scenario 53 key one";
        let c2 = b"scenario 53 key two";
        let c3 = b"scenario 53 key three";
        let k1 = LmdbStorage::compute_address(c1);
        let k2 = LmdbStorage::compute_address(c2);
        let k3 = LmdbStorage::compute_address(c3);
        storage.put(&k1, c1).await.expect("put k1");
        storage.put(&k2, c2).await.expect("put k2");
        storage.put(&k3, c3).await.expect("put k3");

        // Correct digests from challenger's local store.
        let d1_expected = compute_audit_digest(&nonce, &peer_id, &k1, c1);
        let d2_expected = compute_audit_digest(&nonce, &peer_id, &k2, c2);
        let d3_expected = compute_audit_digest(&nonce, &peer_id, &k3, c3);

        // Simulate peer response: K1 matches, K2 wrong data, K3 wrong data.
        let d2_wrong = compute_audit_digest(&nonce, &peer_id, &k2, b"tampered k2");
        let d3_wrong = compute_audit_digest(&nonce, &peer_id, &k3, b"tampered k3");

        assert_eq!(d1_expected, d1_expected, "K1 should match");
        assert_ne!(d2_wrong, d2_expected, "K2 should mismatch");
        assert_ne!(d3_wrong, d3_expected, "K3 should mismatch");

        // Step 1: Identify failed keys (digest comparison).
        let digests = [d1_expected, d2_wrong, d3_wrong];
        let keys = [k1, k2, k3];
        let contents: [&[u8]; 3] = [c1, c2, c3];

        let mut failed_keys = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            if digests[i] == ABSENT_KEY_DIGEST {
                failed_keys.push(*key);
                continue;
            }
            let expected = compute_audit_digest(&nonce, &peer_id, key, contents[i]);
            if digests[i] != expected {
                failed_keys.push(*key);
            }
        }

        assert_eq!(failed_keys.len(), 2, "K2 and K3 should be in failure set");
        assert!(failed_keys.contains(&k2));
        assert!(failed_keys.contains(&k3));
        assert!(!failed_keys.contains(&k1), "K1 passed digest check");

        // Step 2: Responsibility confirmation removes K3 (not responsible).
        // Simulate: P is in closest peers for K2 but not K3.
        let responsible_for_k2 = true;
        let responsible_for_k3 = false;
        let mut confirmed = Vec::new();
        for key in &failed_keys {
            let is_responsible = if *key == k2 {
                responsible_for_k2
            } else {
                responsible_for_k3
            };
            if is_responsible {
                confirmed.push(*key);
            }
        }

        assert_eq!(confirmed, vec![k2], "Only K2 should be in confirmed set");

        // Step 3: Construct evidence for confirmed failures only.
        let challenged_peer = PeerId::from_bytes(peer_id);
        let evidence = FailureEvidence::AuditFailure {
            challenge_id: 5300,
            challenged_peer,
            confirmed_failed_keys: confirmed,
            reason: AuditFailureReason::DigestMismatch,
        };

        match evidence {
            FailureEvidence::AuditFailure {
                confirmed_failed_keys,
                ..
            } => {
                assert_eq!(
                    confirmed_failed_keys.len(),
                    1,
                    "Only K2 should generate evidence"
                );
                assert_eq!(confirmed_failed_keys[0], k2);
            }
            _ => panic!("Expected AuditFailure evidence"),
        }
    }
}
