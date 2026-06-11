//! Replication E2E tests.
//!
//! Tests the replication subsystem behaviors from Section 18 of
//! `REPLICATION_DESIGN.md` against a live multi-node testnet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::TestHarness;
use ant_node::client::compute_address;
use ant_node::replication::config::REPLICATION_PROTOCOL_ID;
use ant_node::replication::protocol::{
    compute_audit_digest, AuditChallenge, AuditResponse, FetchRequest, FetchResponse,
    FreshReplicationOffer, FreshReplicationResponse, NeighborSyncRequest, ReplicationMessage,
    ReplicationMessageBody, VerificationRequest, ABSENT_KEY_DIGEST,
};
use ant_node::replication::pruning;
use ant_node::replication::scheduling::ReplicationQueues;
use ant_node::replication::types::{NeighborSyncState, RepairProofs};
use ant_node::ReplicationConfig;
use saorsa_core::identity::PeerId;
use saorsa_core::{P2PNode, TrustEvent};
use serial_test::serial;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Maximum time to wait for replication propagation in tests.
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(15);
/// Interval between propagation poll checks.
const PROPAGATION_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Send a replication request via saorsa-core's request-response mechanism
/// and decode the response.
///
/// Uses `send_request` which wraps the payload in a `RequestResponseEnvelope`
/// with the `/rr/` topic prefix. The replication handler recognises this
/// pattern and routes the response back via `send_response`.
async fn send_replication_request(
    sender: &P2PNode,
    target: &PeerId,
    msg: ReplicationMessage,
    timeout: Duration,
) -> ReplicationMessage {
    let encoded = msg.encode().expect("encode replication request");
    let response = sender
        .send_request(target, REPLICATION_PROTOCOL_ID, encoded, timeout)
        .await
        .expect("send_request");
    ReplicationMessage::decode(&response.data).expect("decode replication response")
}

fn prune_test_config(close_group_size: usize) -> ReplicationConfig {
    ReplicationConfig {
        close_group_size,
        quorum_threshold: 1,
        paid_list_close_group_size: 1,
        prune_hysteresis_duration: Duration::ZERO,
        ..ReplicationConfig::default()
    }
}

fn node_index_for_peer(harness: &TestHarness, peer: &PeerId) -> Option<usize> {
    (0..harness.node_count()).find(|idx| {
        harness
            .test_node(*idx)
            .and_then(|node| node.p2p_node.as_ref())
            .is_some_and(|p2p| p2p.peer_id() == peer)
    })
}

async fn find_remote_prune_candidate(
    harness: &TestHarness,
    pruner_idx: usize,
    close_group_size: usize,
    label: &str,
) -> (Vec<u8>, [u8; 32], Vec<PeerId>) {
    let pruner = harness.test_node(pruner_idx).expect("pruner");
    let pruner_p2p = pruner.p2p_node.as_ref().expect("pruner p2p");
    let pruner_peer = *pruner_p2p.peer_id();

    for attempt in 0..10_000usize {
        let content = format!("prune-confirmation-{label}-{attempt}").into_bytes();
        let address = compute_address(&content);
        let closest = pruner_p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(&address, close_group_size)
            .await;
        if closest.len() != close_group_size {
            continue;
        }

        let target_peers: Vec<PeerId> = closest.iter().map(|node| node.peer_id).collect();
        if target_peers.contains(&pruner_peer) {
            continue;
        }
        if target_peers
            .iter()
            .all(|peer| node_index_for_peer(harness, peer).is_some())
        {
            return (content, address, target_peers);
        }
    }

    panic!("failed to find a {close_group_size}-peer prune candidate outside pruner {pruner_idx}");
}

async fn store_record_on_peer(
    harness: &TestHarness,
    peer: &PeerId,
    address: &[u8; 32],
    content: &[u8],
) {
    let idx = node_index_for_peer(harness, peer).expect("target peer should be in test harness");
    let protocol = harness
        .test_node(idx)
        .expect("target node")
        .ant_protocol
        .as_ref()
        .expect("target protocol");
    protocol.storage().put(address, content).await.expect("put");
}

async fn store_record_on_peers(
    harness: &TestHarness,
    peers: &[PeerId],
    address: &[u8; 32],
    content: &[u8],
) {
    for peer in peers {
        store_record_on_peer(harness, peer, address, content).await;
    }
}

async fn record_repair_proofs_for_peers(
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    peers: &[PeerId],
    key: &[u8; 32],
    hinted_at_epoch: u64,
) {
    let close_peers: HashSet<PeerId> = p2p_node
        .dht_manager()
        .find_closest_nodes_local_with_self(key, config.close_group_size)
        .await
        .iter()
        .map(|node| node.peer_id)
        .collect();
    let mut proofs = repair_proofs.write().await;
    for peer in peers {
        assert!(
            proofs.record_replica_hint_sent(*peer, *key, &close_peers, hinted_at_epoch),
            "test target should be in close group for repair-proof recording"
        );
    }
    drop(proofs);
}

/// Fresh write happy path (Section 18 #1).
///
/// Store a chunk on a node that has a `ReplicationEngine`, manually call
/// `replicate_fresh`, then check that at least one other node in the
/// close group received it via their storage.
#[tokio::test]
#[serial]
async fn test_fresh_replication_propagates_to_close_group() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    // Pick a non-bootstrap node with replication engine
    let source_idx = 3; // first regular node
    let source = harness.test_node(source_idx).expect("source node");
    let source_protocol = source.ant_protocol.as_ref().expect("protocol");
    let source_storage = source_protocol.storage();

    // Create and store a chunk
    let content = b"hello replication world";
    let address = compute_address(content);
    source_storage.put(&address, content).await.expect("put");

    // Pre-populate payment cache on ALL nodes so receivers accept the offer
    // (bypasses EVM verification, which is unavailable without Anvil).
    for i in 0..harness.node_count() {
        if let Some(node) = harness.test_node(i) {
            if let Some(protocol) = &node.ant_protocol {
                protocol.payment_verifier().cache_insert(address);
            }
        }
    }

    // Trigger fresh replication with a dummy PoP
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Poll until replication propagates (or timeout).
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    let mut found_on_other = false;
    while tokio::time::Instant::now() < deadline {
        for i in 0..harness.node_count() {
            if i == source_idx {
                continue;
            }
            if let Some(node) = harness.test_node(i) {
                if let Some(protocol) = &node.ant_protocol {
                    if protocol.storage().exists(&address).unwrap_or(false) {
                        found_on_other = true;
                    }
                }
            }
        }
        if found_on_other {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }
    assert!(
        found_on_other,
        "Chunk should have replicated to at least one other node"
    );

    harness.teardown().await.expect("teardown");
}

/// `PaidForList` persistence (Section 18 #43).
///
/// Insert a key into the `PaidList`, verify it persists by reopening the
/// list from the same data directory.
#[tokio::test]
#[serial]
async fn test_paid_list_persistence() {
    let mut harness = TestHarness::setup_minimal().await.expect("setup");

    let key = [0xAA; 32];
    let data_dir = {
        let node = harness.test_node(3).expect("node");
        let dir = node.data_dir.clone();

        // Insert into paid list
        if let Some(ref engine) = node.replication_engine {
            engine.paid_list().insert(&key).await.expect("insert");
            assert!(engine.paid_list().contains(&key).expect("contains"));
        }
        dir
    };

    // Shut down the replication engine so the LMDB env is released
    {
        let node = harness.network_mut().node_mut(3).expect("node");
        if let Some(ref mut engine) = node.replication_engine {
            engine.shutdown().await;
        }
        node.replication_engine = None;
        node.replication_shutdown = None;
    }

    // Reopen the paid list from the same directory to verify persistence
    let paid_list2 = ant_node::replication::paid_list::PaidList::new(&data_dir)
        .await
        .expect("reopen");
    assert!(paid_list2.contains(&key).expect("contains after reopen"));

    harness.teardown().await.expect("teardown");
}

/// Verification request/response (Section 18 #6, #27).
///
/// Send a verification request to a node and check that it returns proper
/// per-key presence results for both stored and missing keys.
#[tokio::test]
#[serial]
async fn test_verification_request_returns_presence() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");
    let storage_a = protocol_a.storage();

    // Store a chunk on node A
    let content = b"verification test data";
    let address = compute_address(content);
    storage_a.put(&address, content).await.expect("put");

    // Also create a key that doesn't exist
    let missing_key = [0xBB; 32];

    // Build verification request from B to A
    let request = VerificationRequest {
        keys: vec![address, missing_key],
        paid_list_check_indices: vec![],
    };
    let msg = ReplicationMessage {
        request_id: 42,
        body: ReplicationMessageBody::VerificationRequest(request),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
        assert_eq!(resp.results.len(), 2);
        assert!(resp.results[0].present, "First key should be present");
        assert!(!resp.results[1].present, "Second key should be absent");
    } else {
        panic!("Expected VerificationResponse");
    }

    harness.teardown().await.expect("teardown");
}

/// Fetch request/response happy path.
///
/// Store a chunk on node A, send a `FetchRequest` from node B, and verify
/// the response contains the correct data.
#[tokio::test]
#[serial]
async fn test_fetch_request_returns_record() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");

    // Store chunk on A
    let content = b"fetch me please";
    let address = compute_address(content);
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    // Send fetch request from B to A
    let request = FetchRequest { key: address };
    let msg = ReplicationMessage {
        request_id: 99,
        body: ReplicationMessageBody::FetchRequest(request),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::FetchResponse(FetchResponse::Success { key, data }) =
        resp_msg.body
    {
        assert_eq!(key, address);
        assert_eq!(data, content);
    } else {
        panic!("Expected FetchResponse::Success");
    }

    harness.teardown().await.expect("teardown");
}

/// Audit challenge/response (Section 18 #54).
///
/// Store a chunk on a node, send an audit challenge, and verify the
/// returned digest matches our local computation.
#[tokio::test]
#[serial]
async fn test_audit_challenge_returns_correct_digest() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");

    // Store chunk on A
    let content = b"audit test data";
    let address = compute_address(content);
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    let peer_a = *p2p_a.peer_id();
    let nonce = [0x42u8; 32];

    // Send audit challenge from B to A
    let challenge = AuditChallenge {
        challenge_id: 1234,
        nonce,
        challenged_peer_id: *peer_a.as_bytes(),
        keys: vec![address],
    };
    let msg = ReplicationMessage {
        request_id: 1234,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
        challenge_id,
        digests,
    }) = resp_msg.body
    {
        assert_eq!(challenge_id, 1234);
        assert_eq!(digests.len(), 1);

        // Verify digest matches our local computation
        let expected = compute_audit_digest(&nonce, peer_a.as_bytes(), &address, content);
        assert_eq!(digests[0], expected);
    } else {
        panic!("Expected AuditResponse::Digests");
    }

    harness.teardown().await.expect("teardown");
}

/// Audit absent key returns sentinel (Section 18 #54 variant).
///
/// Challenge a node with a key it does NOT hold and verify the digest
/// is the [`ABSENT_KEY_DIGEST`] sentinel.
#[tokio::test]
#[serial]
async fn test_audit_absent_key_returns_sentinel() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let peer_a = *p2p_a.peer_id();

    // Challenge with a key that A does NOT hold
    let missing_key = [0xDD; 32];
    let nonce = [0x11u8; 32];

    let challenge = AuditChallenge {
        challenge_id: 5678,
        nonce,
        challenged_peer_id: *peer_a.as_bytes(),
        keys: vec![missing_key],
    };
    let msg = ReplicationMessage {
        request_id: 5678,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::AuditResponse(AuditResponse::Digests { digests, .. }) =
        resp_msg.body
    {
        assert_eq!(digests.len(), 1);
        assert_eq!(
            digests[0], ABSENT_KEY_DIGEST,
            "Absent key should return sentinel digest"
        );
    } else {
        panic!("Expected AuditResponse::Digests");
    }

    harness.teardown().await.expect("teardown");
}

/// Prune pass requires remote storage proofs before deleting local records.
///
/// This drives `run_prune_pass` against live nodes so prune-confirmation audits
/// travel over the real replication request/response path.
#[tokio::test]
#[serial]
async fn test_prune_pass_requires_remote_confirmation_before_delete() {
    const HINT_EPOCH: u64 = 7;
    const CURRENT_EPOCH: u64 = HINT_EPOCH + 1;

    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let pruner_idx = 3;
    let close_group_size = 2;
    let config = prune_test_config(close_group_size);
    let sync_state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![])));
    let repair_proofs = Arc::new(RwLock::new(RepairProofs::new()));

    let pruner = harness.test_node(pruner_idx).expect("pruner");
    let pruner_p2p = Arc::clone(pruner.p2p_node.as_ref().expect("pruner p2p"));
    let pruner_protocol = pruner.ant_protocol.as_ref().expect("pruner protocol");
    let pruner_storage = pruner_protocol.storage();
    let pruner_paid_list = Arc::clone(
        pruner
            .replication_engine
            .as_ref()
            .expect("pruner replication engine")
            .paid_list(),
    );
    let pruner_peer = *pruner_p2p.peer_id();

    // Even with all target peers storing the record, pruning must be blocked
    // while remote prune audits are not allowed during bootstrap/drain.
    let (gate_content, gate_address, gate_targets) =
        find_remote_prune_candidate(&harness, pruner_idx, close_group_size, "bootstrap-gate").await;
    pruner_storage
        .put(&gate_address, &gate_content)
        .await
        .expect("put gate record on pruner");
    store_record_on_peers(&harness, &gate_targets, &gate_address, &gate_content).await;
    record_repair_proofs_for_peers(
        &repair_proofs,
        &pruner_p2p,
        &config,
        &gate_targets,
        &gate_address,
        HINT_EPOCH,
    )
    .await;

    let blocked = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        current_sync_epoch: CURRENT_EPOCH,
        allow_remote_prune_audits: false,
    })
    .await;
    assert_eq!(blocked.records_pruned, 0);
    assert!(
        pruner_storage.exists(&gate_address).expect("exists"),
        "record must not be pruned before remote audits are allowed"
    );

    let confirmed = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        current_sync_epoch: CURRENT_EPOCH,
        allow_remote_prune_audits: true,
    })
    .await;
    assert_eq!(confirmed.records_pruned, 1);
    assert!(
        !pruner_storage.exists(&gate_address).expect("exists"),
        "record should be pruned after all target peers prove storage"
    );

    // If any current close-group peer lacks the record, the prune pass must
    // retain the local copy until that peer can prove it stores the bytes.
    let (missing_content, missing_address, missing_targets) =
        find_remote_prune_candidate(&harness, pruner_idx, close_group_size, "missing-proof").await;
    pruner_storage
        .put(&missing_address, &missing_content)
        .await
        .expect("put missing-proof record on pruner");
    store_record_on_peer(
        &harness,
        &missing_targets[0],
        &missing_address,
        &missing_content,
    )
    .await;
    record_repair_proofs_for_peers(
        &repair_proofs,
        &pruner_p2p,
        &config,
        &missing_targets,
        &missing_address,
        HINT_EPOCH,
    )
    .await;

    let incomplete = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        current_sync_epoch: CURRENT_EPOCH,
        allow_remote_prune_audits: true,
    })
    .await;
    assert_eq!(incomplete.records_pruned, 0);
    assert!(
        pruner_storage.exists(&missing_address).expect("exists"),
        "record must remain local while any target peer lacks proof"
    );

    store_record_on_peers(
        &harness,
        &missing_targets,
        &missing_address,
        &missing_content,
    )
    .await;

    let complete = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        current_sync_epoch: CURRENT_EPOCH,
        allow_remote_prune_audits: true,
    })
    .await;
    assert_eq!(complete.records_pruned, 1);
    assert!(
        !pruner_storage.exists(&missing_address).expect("exists"),
        "record should prune once every current target peer proves storage"
    );

    harness.teardown().await.expect("teardown");
}

/// Fetch not-found returns `NotFound`.
///
/// Request a key that does not exist on the target node and verify
/// the response is `FetchResponse::NotFound`.
#[tokio::test]
#[serial]
async fn test_fetch_not_found() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let peer_a = *p2p_a.peer_id();

    let missing_key = [0xEE; 32];
    let request = FetchRequest { key: missing_key };
    let msg = ReplicationMessage {
        request_id: 77,
        body: ReplicationMessageBody::FetchRequest(request),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    assert!(
        matches!(
            resp_msg.body,
            ReplicationMessageBody::FetchResponse(FetchResponse::NotFound { .. })
        ),
        "Expected FetchResponse::NotFound"
    );

    harness.teardown().await.expect("teardown");
}

/// Verification with paid-list check.
///
/// Store a chunk AND add it to the paid list on node A, then send a
/// verification request with `paid_list_check_indices` and confirm the
/// response reports both presence and paid status.
#[tokio::test]
#[serial]
async fn test_verification_with_paid_list_check() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");

    // Store a chunk AND add to paid list on node A
    let content = b"paid test data";
    let address = compute_address(content);
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    if let Some(ref engine) = node_a.replication_engine {
        engine
            .paid_list()
            .insert(&address)
            .await
            .expect("paid_list insert");
    }

    // Send verification with paid-list check for index 0
    let request = VerificationRequest {
        keys: vec![address],
        paid_list_check_indices: vec![0],
    };
    let msg = ReplicationMessage {
        request_id: 55,
        body: ReplicationMessageBody::VerificationRequest(request),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
        assert_eq!(resp.results.len(), 1);
        assert!(resp.results[0].present, "Key should be present");
        assert_eq!(
            resp.results[0].paid,
            Some(true),
            "Key should be in PaidForList"
        );
    } else {
        panic!("Expected VerificationResponse");
    }

    harness.teardown().await.expect("teardown");
}

/// Fresh write with empty `PoP` rejected (Section 18 #2).
///
/// Send a `FreshReplicationOffer` with an empty `proof_of_payment` and
/// verify the receiver rejects it without storing the chunk.
#[tokio::test]
#[serial]
async fn test_fresh_offer_with_empty_pop_rejected() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    let content = b"invalid pop test";
    let address = ant_node::client::compute_address(content);

    // Send fresh offer with EMPTY PoP
    let offer = FreshReplicationOffer {
        key: address,
        data: content.to_vec(),
        proof_of_payment: vec![], // Empty!
    };
    let msg = ReplicationMessage {
        request_id: 1000,
        body: ReplicationMessageBody::FreshReplicationOffer(offer),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    match resp_msg.body {
        ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
            reason,
            ..
        }) => {
            assert!(
                reason.contains("proof of payment") || reason.contains("Missing"),
                "Should mention missing PoP, got: {reason}"
            );
        }
        other => panic!("Expected Rejected, got: {other:?}"),
    }

    // Verify chunk was NOT stored
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol");
    assert!(
        !protocol_a.storage().exists(&address).unwrap_or(false),
        "Chunk should not be stored with empty PoP"
    );

    harness.teardown().await.expect("teardown");
}

/// Fresh write with a key that does not match the supplied bytes is rejected
/// before payment verification, matching the direct PUT handler.
#[tokio::test]
#[serial]
async fn test_fresh_offer_with_mismatched_content_address_rejected() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    let content = b"mismatched fresh offer content";
    let actual_address = compute_address(content);
    let mut wrong_address = actual_address;
    wrong_address[0] ^= 0xFF;

    let offer = FreshReplicationOffer {
        key: wrong_address,
        data: content.to_vec(),
        proof_of_payment: vec![0x01; 64],
    };
    let msg = ReplicationMessage {
        request_id: 1001,
        body: ReplicationMessageBody::FreshReplicationOffer(offer),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    match resp_msg.body {
        ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
            reason,
            ..
        }) => {
            assert!(
                reason.contains("Content address mismatch"),
                "Should mention content address mismatch, got: {reason}"
            );
        }
        other => panic!("Expected Rejected, got: {other:?}"),
    }

    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol");
    assert!(
        !protocol_a.storage().exists(&wrong_address).unwrap_or(false),
        "Chunk should not be stored under the wrong address"
    );
    assert!(
        !protocol_a
            .storage()
            .exists(&actual_address)
            .unwrap_or(false),
        "Chunk should not be stored under the actual address after rejected offer"
    );

    harness.teardown().await.expect("teardown");
}

/// Neighbor sync request returns a sync response (Section 18 #5/#37).
///
/// Send a `NeighborSyncRequest` from one node to another and verify we
/// receive a well-formed `NeighborSyncResponse`.
#[tokio::test]
#[serial]
async fn test_neighbor_sync_request_returns_hints() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    // Store something on A so it has hints to share
    let content = b"sync test data";
    let address = ant_node::client::compute_address(content);
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol");
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    // Send sync request
    let request = NeighborSyncRequest {
        replica_hints: vec![],
        paid_hints: vec![],
        bootstrapping: false,
    };
    let msg = ReplicationMessage {
        request_id: 2000,
        body: ReplicationMessageBody::NeighborSyncRequest(request),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    match resp_msg.body {
        ReplicationMessageBody::NeighborSyncResponse(resp) => {
            // Node A should return a sync response (may or may not contain hints
            // depending on whether B is in A's close group for any keys)
            assert!(!resp.bootstrapping, "Node A shouldn't claim bootstrapping");
            // The response is valid -- that's the main assertion
        }
        other => panic!("Expected NeighborSyncResponse, got: {other:?}"),
    }

    harness.teardown().await.expect("teardown");
}

/// Audit challenge with multiple keys, some present and some absent
/// (Section 18 #11).
///
/// Challenge a node with three keys (two stored, one missing) and verify
/// per-key digest correctness.
#[tokio::test]
#[serial]
async fn test_audit_challenge_multi_key() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");

    // Store four chunks on A so the dynamic audit key limit (2 * sqrt(4) = 4)
    // accommodates our 3-key challenge.  Only c1 and c2 are challenged; c3
    // and c4 just raise the stored-chunk count.
    let c1 = b"audit multi key 1";
    let c2 = b"audit multi key 2";
    let c3 = b"audit multi key 3 (padding)";
    let c4 = b"audit multi key 4 (padding)";
    let a1 = ant_node::client::compute_address(c1);
    let a2 = ant_node::client::compute_address(c2);
    let a3 = ant_node::client::compute_address(c3);
    let a4 = ant_node::client::compute_address(c4);
    protocol_a.storage().put(&a1, c1).await.expect("put 1");
    protocol_a.storage().put(&a2, c2).await.expect("put 2");
    protocol_a.storage().put(&a3, c3).await.expect("put 3");
    protocol_a.storage().put(&a4, c4).await.expect("put 4");

    let absent_key = [0xCC; 32];
    let peer_a = *p2p_a.peer_id();
    let nonce = [0x55; 32];

    let challenge = AuditChallenge {
        challenge_id: 3000,
        nonce,
        challenged_peer_id: *peer_a.as_bytes(),
        keys: vec![a1, absent_key, a2],
    };
    let msg = ReplicationMessage {
        request_id: 3000,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
        challenge_id,
        digests,
    }) = resp_msg.body
    {
        assert_eq!(challenge_id, 3000);
        assert_eq!(digests.len(), 3);

        // Key 1 -- correct digest
        let expected_1 = compute_audit_digest(&nonce, peer_a.as_bytes(), &a1, c1);
        assert_eq!(digests[0], expected_1, "First key digest should match");

        // Key 2 -- absent sentinel
        assert_eq!(
            digests[1], ABSENT_KEY_DIGEST,
            "Absent key should be sentinel"
        );

        // Key 3 -- correct digest
        let expected_2 = compute_audit_digest(&nonce, peer_a.as_bytes(), &a2, c2);
        assert_eq!(digests[2], expected_2, "Third key digest should match");
    } else {
        panic!("Expected AuditResponse::Digests");
    }

    harness.teardown().await.expect("teardown");
}

/// Fetch returns `NotFound` for a zeroed-out key (variant of the basic
/// not-found test).
///
/// Request a key that is all zeros -- not a valid content address -- and
/// verify the response is `FetchResponse::NotFound`.
#[tokio::test]
#[serial]
async fn test_fetch_returns_error_for_corrupt_key() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let peer_a = *p2p_a.peer_id();

    let fake_key = [0x00; 32];
    let request = FetchRequest { key: fake_key };
    let msg = ReplicationMessage {
        request_id: 4000,
        body: ReplicationMessageBody::FetchRequest(request),
    };
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    assert!(
        matches!(
            resp_msg.body,
            ReplicationMessageBody::FetchResponse(FetchResponse::NotFound { .. })
        ),
        "Expected NotFound for non-existent key"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #1/#24: Fresh replication stores + PaidNotify
// =========================================================================

/// Fresh replication stores chunk on remote peer AND updates their `PaidForList`
/// (Section 18 #1 + #24 combined).
///
/// Store a chunk on node A, call `replicate_fresh`, wait for propagation, then
/// verify at least one remote node has the chunk in both storage and `PaidForList`.
#[tokio::test]
#[serial]
async fn scenario_1_and_24_fresh_replication_stores_and_propagates_paid_list() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let source_idx = 3;
    let source = harness.test_node(source_idx).expect("source");
    let protocol = source.ant_protocol.as_ref().expect("protocol");
    let storage = protocol.storage();

    let content = b"scenario 3 quorum pass test";
    let address = compute_address(content);
    storage.put(&address, content).await.expect("put");

    // Pre-populate payment cache on ALL nodes so receivers accept the offer
    // (bypasses EVM verification, which is unavailable without Anvil).
    for i in 0..harness.node_count() {
        if let Some(node) = harness.test_node(i) {
            if let Some(p) = &node.ant_protocol {
                p.payment_verifier().cache_insert(address);
            }
        }
    }

    // Trigger fresh replication (sends FreshReplicationOffer + PaidNotify)
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Poll until replication propagates (or timeout).
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    let mut stored_elsewhere = false;
    let mut paid_listed_elsewhere = false;
    loop {
        for i in 0..harness.node_count() {
            if i == source_idx {
                continue;
            }
            if let Some(node) = harness.test_node(i) {
                if let Some(p) = &node.ant_protocol {
                    if p.storage().exists(&address).unwrap_or(false) {
                        stored_elsewhere = true;
                    }
                }
                if let Some(ref engine) = node.replication_engine {
                    if engine.paid_list().contains(&address).unwrap_or(false) {
                        paid_listed_elsewhere = true;
                    }
                }
            }
        }
        if (stored_elsewhere && paid_listed_elsewhere) || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }
    assert!(
        stored_elsewhere,
        "Chunk should be stored on at least one other node"
    );
    assert!(
        paid_listed_elsewhere,
        "Key should be in PaidForList on at least one other node"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #9: Fetch retry with alternate source
// =========================================================================

/// When a fetch fails, the queue rotates to the next untried source
/// (Section 18 #9).
///
/// Tested via direct `ReplicationQueues` manipulation since we cannot
/// deterministically trigger network failures in e2e.
#[tokio::test]
#[serial]
async fn scenario_9_fetch_retry_uses_alternate_source() {
    let mut queues = ReplicationQueues::new();
    let key = [0x09; 32];
    let distance = [0x01; 32];
    let source_a = PeerId::from_bytes([0xA0; 32]);
    let source_b = PeerId::from_bytes([0xB0; 32]);

    // Enqueue with two sources
    queues.enqueue_fetch(key, distance, vec![source_a, source_b]);
    let candidate = queues.dequeue_fetch().expect("dequeue");

    // Start in-flight with first source
    queues.start_fetch(key, source_a, candidate.sources);

    // First source fails -> retry should give source_b
    let next = queues.retry_fetch(&key);
    assert_eq!(next, Some(source_b), "Should retry with alternate source");

    // Second source fails -> no more sources
    let exhausted = queues.retry_fetch(&key);
    assert!(exhausted.is_none(), "No more sources available");
}

// =========================================================================
// Section 18, Scenario #10: Fetch retry exhaustion
// =========================================================================

/// When all sources fail, the fetch is exhausted and can be completed
/// (Section 18 #10).
#[tokio::test]
#[serial]
async fn scenario_10_fetch_retry_exhaustion() {
    let mut queues = ReplicationQueues::new();
    let key = [0x10; 32];
    let distance = [0x01; 32];
    let source = PeerId::from_bytes([0xC0; 32]);

    // Single source
    queues.enqueue_fetch(key, distance, vec![source]);
    let _candidate = queues.dequeue_fetch().expect("dequeue");
    queues.start_fetch(key, source, vec![source]);

    // Source fails -> no alternates -> exhausted
    let next = queues.retry_fetch(&key);
    assert!(next.is_none(), "Single source exhausted");

    // Complete the fetch (abandon)
    let entry = queues.complete_fetch(&key);
    assert!(entry.is_some(), "Should have in-flight entry to complete");
    assert_eq!(queues.in_flight_count(), 0);
}

// =========================================================================
// Section 18, Scenario #11: Repeated failures -> trust penalty
// =========================================================================

/// Multiple application failures from a peer decrease its trust score
/// (Section 18 #11).
#[tokio::test]
#[serial]
async fn scenario_11_repeated_failures_decrease_trust() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_b = *p2p_b.peer_id();

    // Get initial trust score for node B (should be neutral ~0.5)
    let initial_trust = p2p_a.peer_trust(&peer_b);

    // Report multiple application failures
    let failure_count = 5;
    let failure_weight = 3.0;
    for _ in 0..failure_count {
        p2p_a
            .report_trust_event(&peer_b, TrustEvent::ApplicationFailure(failure_weight))
            .await;
    }

    let final_trust = p2p_a.peer_trust(&peer_b);
    assert!(
        final_trust < initial_trust,
        "Trust should decrease after repeated failures: {initial_trust} -> {final_trust}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #12: Bootstrap quorum aggregation
// =========================================================================

/// A bootstrapping node queries multiple peers and discovers that a key
/// meets the multi-peer presence threshold (Section 18 #12).
///
/// Store a chunk on nodes 0-3 (4 holders), then have node 4 send
/// verification requests to all holders. The querying node should receive
/// enough presence confirmations to meet the quorum threshold.
#[tokio::test]
#[serial]
async fn scenario_12_bootstrap_quorum_aggregation() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let content = b"bootstrap quorum test";
    let address = compute_address(content);

    // Store chunk + paid-list entry on nodes 0-3 (4 holders)
    let holder_count = 4;
    for idx in 0..holder_count {
        let node = harness.test_node(idx).expect("node");
        let protocol = node.ant_protocol.as_ref().expect("protocol");
        protocol
            .storage()
            .put(&address, content)
            .await
            .expect("put");
        if let Some(ref engine) = node.replication_engine {
            engine
                .paid_list()
                .insert(&address)
                .await
                .expect("paid insert");
        }
    }

    // Node 4 acts as the bootstrapping node: query each holder for presence
    let querier = harness.test_node(4).expect("querier");
    let p2p_q = querier.p2p_node.as_ref().expect("p2p");

    let mut presence_confirmations = 0u32;
    let mut paid_confirmations = 0u32;
    for idx in 0..holder_count {
        let target = harness.test_node(idx).expect("target");
        let peer = *target.p2p_node.as_ref().expect("p2p").peer_id();

        let request = VerificationRequest {
            keys: vec![address],
            paid_list_check_indices: vec![0],
        };
        let msg = ReplicationMessage {
            request_id: 1200 + idx as u64,
            body: ReplicationMessageBody::VerificationRequest(request),
        };

        let resp_msg = send_replication_request(p2p_q, &peer, msg, Duration::from_secs(10)).await;
        if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
            if let Some(result) = resp.results.first() {
                if result.present {
                    presence_confirmations += 1;
                }
                if result.paid == Some(true) {
                    paid_confirmations += 1;
                }
            }
        }
    }

    // Quorum threshold is floor(CLOSE_GROUP_SIZE/2)+1 = 4, but dynamic
    // QuorumNeeded uses min(4, floor(|targets|/2)+1). With 4 targets:
    // min(4, 3) = 3. Require at least 3 confirmations.
    let min_quorum = 3;
    assert!(
        presence_confirmations >= min_quorum,
        "Bootstrap node should receive enough presence confirmations for quorum: \
         got {presence_confirmations}, need {min_quorum}"
    );
    assert!(
        paid_confirmations >= min_quorum,
        "Bootstrap node should receive enough paid-list confirmations: \
         got {paid_confirmations}, need {min_quorum}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #14: Coverage under backlog
// =========================================================================

/// Under load, neighbor-sync hint construction covers the full local
/// inventory: when node A stores multiple chunks and node B sends a
/// `NeighborSyncRequest`, A's response hints include all locally stored
/// keys that B should hold (Section 18 #14).
#[tokio::test]
#[serial]
async fn scenario_14_sync_hints_cover_all_local_keys() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");
    let storage_a = protocol_a.storage();

    // Store multiple chunks on node A (simulating backlog)
    let chunk_count = 10u8;
    let mut addresses = Vec::new();
    for i in 0..chunk_count {
        let content = format!("backlog test chunk {i}");
        let address = compute_address(content.as_bytes());
        storage_a
            .put(&address, content.as_bytes())
            .await
            .expect("put");
        addresses.push(address);
    }

    // Verify the local inventory is complete
    let all_keys = storage_a.all_keys().await.expect("all_keys");
    assert_eq!(
        all_keys.len(),
        addresses.len(),
        "all_keys should cover every stored chunk"
    );

    // Send a NeighborSyncRequest from B to A and inspect the response hints.
    let request = NeighborSyncRequest {
        replica_hints: vec![],
        paid_hints: vec![],
        bootstrapping: false,
    };
    let msg = ReplicationMessage {
        request_id: 1400,
        body: ReplicationMessageBody::NeighborSyncRequest(request),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    let hints = match resp_msg.body {
        ReplicationMessageBody::NeighborSyncResponse(resp) => resp.replica_hints,
        other => panic!("Expected NeighborSyncResponse, got: {other:?}"),
    };

    // Node A builds replica hints for B based on B's close-group membership.
    // In a 5-node network every node is close to every key, so the hints
    // should include ALL locally stored keys.
    for addr in &addresses {
        assert!(
            hints.contains(addr),
            "Sync response hints should include stored key {addr:?}; \
             got {} hints total",
            hints.len()
        );
    }

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #15: Partition and heal
// =========================================================================

/// Partition and heal: data and paid-list authorization survive a network
/// partition. After the partition, remaining nodes can still confirm
/// paid-list status via verification requests, enabling recovery
/// (Section 18 #15).
#[tokio::test]
#[serial]
async fn scenario_15_partition_and_heal() {
    let mut harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let content = b"partition test data";
    let address = compute_address(content);

    // Store chunk + paid-list entry on nodes 3 AND 4
    for idx in [3, 4] {
        let node = harness.test_node(idx).expect("node");
        let protocol = node.ant_protocol.as_ref().expect("protocol");
        protocol
            .storage()
            .put(&address, content)
            .await
            .expect("put");
        if let Some(ref engine) = node.replication_engine {
            engine
                .paid_list()
                .insert(&address)
                .await
                .expect("paid insert");
        }
    }

    // "Partition": shut down node 4 (simulates peer loss)
    harness.shutdown_node(4).await.expect("shutdown");

    // Data should still exist on node 3
    let node3 = harness.test_node(3).expect("node3 after partition");
    let protocol3 = node3.ant_protocol.as_ref().expect("protocol");
    assert!(
        protocol3.storage().exists(&address).expect("exists"),
        "Data should survive partition on remaining node"
    );

    // Paid-list authorization still confirmable: query remaining nodes
    // (0,1,2,3) from node 0. Node 3 should confirm paid status.
    let querier = harness.test_node(0).expect("querier");
    let p2p_q = querier.p2p_node.as_ref().expect("p2p");

    let node3_peer = *node3.p2p_node.as_ref().expect("p2p").peer_id();
    let request = VerificationRequest {
        keys: vec![address],
        paid_list_check_indices: vec![0],
    };
    let msg = ReplicationMessage {
        request_id: 1500,
        body: ReplicationMessageBody::VerificationRequest(request),
    };

    let resp_msg = send_replication_request(p2p_q, &node3_peer, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
        let result = resp.results.first().expect("should have a result");
        assert!(
            result.present,
            "Node 3 should still report chunk as present after partition"
        );
        assert_eq!(
            result.paid,
            Some(true),
            "Node 3 should still confirm paid-list status — this enables recovery \
             when paid-list authorization survives the partition"
        );
    } else {
        panic!("Expected VerificationResponse");
    }

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #17: Admission asymmetry
// =========================================================================

/// When sender IS in receiver's `LocalRT`, sync is bidirectional: the
/// receiver sends outbound hints AND accepts inbound hints. This test
/// verifies the outbound direction: after warmup (all nodes in each
/// other's RT), node A stores data, node B sends sync, and A's response
/// includes replica hints for its stored keys (Section 18 #17).
///
/// The inbound admission guard (dropping hints from non-RT senders) is
/// tested in the unit-level `admission.rs` tests.
#[tokio::test]
#[serial]
async fn scenario_17_bidirectional_sync_when_sender_in_rt() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    // Store data on node A so it has something to hint about
    let content = b"admission asymmetry test";
    let address = compute_address(content);
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol");
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    // B sends sync request with a hint for a fabricated key
    let inbound_hint = [0x17; 32];
    let request = NeighborSyncRequest {
        replica_hints: vec![inbound_hint],
        paid_hints: vec![],
        bootstrapping: false,
    };
    let msg = ReplicationMessage {
        request_id: 1700,
        body: ReplicationMessageBody::NeighborSyncRequest(request),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    match resp_msg.body {
        ReplicationMessageBody::NeighborSyncResponse(resp) => {
            assert!(!resp.bootstrapping, "Node A should not claim bootstrapping");

            // A should send outbound hints back to B — in a 5-node network
            // after warmup, B is in A's close group for all keys, so A's
            // stored key should appear in the replica hints.
            assert!(
                resp.replica_hints.contains(&address),
                "When sender is in receiver's RT, receiver should send outbound \
                 replica hints. Expected address {address:?} in hints, got {} hints.",
                resp.replica_hints.len()
            );
        }
        other => panic!("Expected NeighborSyncResponse, got: {other:?}"),
    }

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #21: Paid-list majority confirmation
// =========================================================================

/// Paid-list status is confirmed by querying multiple peers via verification
/// requests (Section 18 #21).
///
/// Insert a key into the paid lists of 4 out of 5 nodes, then query each
/// from the remaining node and verify a majority confirms paid status.
#[tokio::test]
#[serial]
async fn scenario_21_paid_list_majority_from_multiple_peers() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let key = [0x21; 32];

    // Add key to paid lists on nodes 0,1,2,3 (4 of 5 nodes)
    let populated_count = 4;
    for idx in 0..populated_count {
        if let Some(node) = harness.test_node(idx) {
            if let Some(ref engine) = node.replication_engine {
                engine.paid_list().insert(&key).await.expect("paid insert");
            }
        }
    }

    // Node 4 queries nodes 0..3 for paid-list status via verification
    let querier = harness.test_node(4).expect("querier");
    let p2p_q = querier.p2p_node.as_ref().expect("p2p");

    let mut paid_confirmations = 0u32;
    for idx in 0..populated_count {
        let target = harness.test_node(idx).expect("target");
        let target_p2p = target.p2p_node.as_ref().expect("target_p2p");
        let peer = *target_p2p.peer_id();

        let request = VerificationRequest {
            keys: vec![key],
            paid_list_check_indices: vec![0],
        };
        let msg = ReplicationMessage {
            request_id: 2100 + idx as u64,
            body: ReplicationMessageBody::VerificationRequest(request),
        };

        let resp_msg = send_replication_request(p2p_q, &peer, msg, Duration::from_secs(10)).await;
        if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
            if resp.results.first().and_then(|r| r.paid) == Some(true) {
                paid_confirmations += 1;
            }
        }
    }

    // Should have at least 3 confirmations (we added to 4 nodes)
    let min_confirmations = 3;
    assert!(
        paid_confirmations >= min_confirmations,
        "Should get paid confirmations from multiple peers, got {paid_confirmations}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #24: Fresh replication paid-list propagation
// =========================================================================

/// After fresh replication, `PaidNotify` propagates to remote nodes' paid
/// lists (Section 18 #24).
#[tokio::test]
#[serial]
async fn scenario_24_fresh_replication_propagates_paid_notify() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let source_idx = 3;
    let source = harness.test_node(source_idx).expect("source");
    let protocol = source.ant_protocol.as_ref().expect("protocol");

    let content = b"paid notify propagation test";
    let address = compute_address(content);
    protocol
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    // Pre-populate payment cache on ALL nodes so receivers accept the offer
    // and PaidNotify (bypasses EVM verification, unavailable without Anvil).
    for i in 0..harness.node_count() {
        if let Some(node) = harness.test_node(i) {
            if let Some(p) = &node.ant_protocol {
                p.payment_verifier().cache_insert(address);
            }
        }
    }

    // Trigger fresh replication (includes PaidNotify to PaidCloseGroup)
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Poll until PaidNotify propagates (or timeout).
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    let mut paid_count;
    loop {
        paid_count = 0u32;
        for i in 0..harness.node_count() {
            if i == source_idx {
                continue;
            }
            if let Some(node) = harness.test_node(i) {
                if let Some(ref engine) = node.replication_engine {
                    if engine.paid_list().contains(&address).unwrap_or(false) {
                        paid_count += 1;
                    }
                }
            }
        }
        if paid_count >= 1 || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }

    // At least one other node should have received the PaidNotify
    // (PaidCloseGroup is up to 20, but in a 5-node network all peers are close)
    assert!(
        paid_count >= 1,
        "PaidNotify should propagate to at least 1 other node, got {paid_count}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #25: Convergence repair
// =========================================================================

/// Paid-list convergence: a majority of queried peers confirm paid status
/// for a key added to a subset of nodes (Section 18 #25).
#[tokio::test]
#[serial]
async fn scenario_25_paid_list_convergence_via_verification() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let key = [0x25; 32];

    // Add to paid list on nodes 0,1,2 (majority of 5)
    let populated_count = 3;
    for idx in 0..populated_count {
        if let Some(node) = harness.test_node(idx) {
            if let Some(ref engine) = node.replication_engine {
                engine.paid_list().insert(&key).await.expect("insert");
            }
        }
    }

    // Node 4 queries nodes 0,1,2 for paid-list status
    let querier = harness.test_node(4).expect("querier");
    let p2p_q = querier.p2p_node.as_ref().expect("p2p");

    let mut confirmations = 0u32;
    for idx in 0..populated_count {
        let target = harness.test_node(idx).expect("target");
        let peer = *target.p2p_node.as_ref().expect("p2p").peer_id();

        let request = VerificationRequest {
            keys: vec![key],
            paid_list_check_indices: vec![0],
        };
        let msg = ReplicationMessage {
            request_id: 2500 + idx as u64,
            body: ReplicationMessageBody::VerificationRequest(request),
        };

        let resp_msg = send_replication_request(p2p_q, &peer, msg, Duration::from_secs(10)).await;
        if let ReplicationMessageBody::VerificationResponse(v) = resp_msg.body {
            if v.results.first().and_then(|r| r.paid) == Some(true) {
                confirmations += 1;
            }
        }
    }

    let min_confirmations = 2;
    assert!(
        confirmations >= min_confirmations,
        "Majority of queried peers should confirm paid status, got {confirmations}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #43: Paid-list persistence across restart
// =========================================================================

/// `PaidForList` survives restart: keys inserted before shutdown are found
/// when the list is reopened from the same data directory (Section 18 #43).
#[tokio::test]
#[serial]
async fn scenario_43_paid_list_persists_across_restart() {
    let mut harness = TestHarness::setup_minimal().await.expect("setup");

    let data_dir = {
        let node = harness.test_node(3).expect("node");
        let dir = node.data_dir.clone();
        let key = [0x44; 32];

        // Insert into paid list
        if let Some(ref engine) = node.replication_engine {
            engine.paid_list().insert(&key).await.expect("insert");
        }
        dir
    };

    // Shut down the replication engine so the LMDB env is released
    {
        let node = harness.network_mut().node_mut(3).expect("node");
        if let Some(ref mut engine) = node.replication_engine {
            engine.shutdown().await;
        }
        node.replication_engine = None;
        node.replication_shutdown = None;
    }

    // Simulate restart: reopen PaidList from same directory
    let key = [0x44; 32];
    let paid_list2 = ant_node::replication::paid_list::PaidList::new(&data_dir)
        .await
        .expect("reopen");

    assert!(
        paid_list2.contains(&key).expect("contains"),
        "PaidForList should survive restart (cold-start recovery)"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #45: Unrecoverable when paid-list lost
// =========================================================================

/// If `PaidForList` is lost AND no quorum exists, the key is unrecoverable.
/// A fresh `PaidList` in a different directory does NOT contain previously-paid
/// keys (Section 18 #45).
#[tokio::test]
#[serial]
async fn scenario_45_unrecoverable_when_paid_list_lost() {
    let harness = TestHarness::setup_minimal().await.expect("setup");

    let key = [0x45; 32];

    // Insert into node 3's paid list
    let node = harness.test_node(3).expect("node");
    if let Some(ref engine) = node.replication_engine {
        engine.paid_list().insert(&key).await.expect("insert");
    }

    // Create a fresh PaidList in a different directory (simulating data loss)
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fresh_paid_list = ant_node::replication::paid_list::PaidList::new(temp_dir.path())
        .await
        .expect("fresh paid list");

    assert!(
        !fresh_paid_list.contains(&key).expect("contains"),
        "Key should NOT be found in a fresh (lost) PaidForList"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Late-joiner bootstrap replication
// =========================================================================

/// A new node joining an existing network replicates all chunks it is
/// responsible for during bootstrap.
///
/// This is the critical "late joiner" scenario: the network already holds
/// data, a fresh node appears, and the replication subsystem must ensure
/// the new node converges to hold every chunk whose close group includes
/// it.
///
/// Flow:
/// 1. Start a 5-node network and warm up DHT.
/// 2. Store several chunks on existing nodes, pre-populate payment caches.
/// 3. Trigger fresh replication so chunks spread across close groups.
/// 4. Add a 6th node via `add_node()` (starts, bootstraps, replication
///    engine finishes bootstrap).
/// 5. Allow time for neighbor-sync and fetch workers to propagate chunks.
/// 6. For each chunk whose close group (according to the new node's DHT)
///    includes the new node, verify the chunk exists in the new node's
///    storage.
#[tokio::test]
#[serial]
async fn test_late_joiner_replicates_responsible_chunks() {
    const REPLICATION_SETTLE_TIMEOUT: Duration = Duration::from_secs(90);
    const SETTLE_POLL_INTERVAL: Duration = Duration::from_millis(500);

    let mut harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    // ------------------------------------------------------------------
    // Step 1: Store chunks on the existing 5-node network
    // ------------------------------------------------------------------
    let chunk_count = 10;
    let mut chunks: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(chunk_count);

    for i in 0..chunk_count {
        let content = format!("late-joiner-test-chunk-{i}").into_bytes();
        let address = compute_address(&content);
        chunks.push((address, content));
    }

    // Store each chunk on node 2 and pre-populate payment caches on ALL
    // existing nodes so fresh replication offers are accepted.
    let source_idx = 2;
    {
        let source = harness.test_node(source_idx).expect("source node");
        let storage = source.ant_protocol.as_ref().expect("protocol").storage();
        for (address, content) in &chunks {
            storage.put(address, content).await.expect("put");
        }
    }

    for (address, _) in &chunks {
        for i in 0..harness.node_count() {
            if let Some(node) = harness.test_node(i) {
                if let Some(protocol) = &node.ant_protocol {
                    protocol.payment_verifier().cache_insert(*address);
                }
            }
        }
    }

    // Trigger fresh replication for each chunk so they spread to close groups.
    let dummy_pop = [0x01u8; 64];
    {
        let source = harness.test_node(source_idx).expect("source node");
        if let Some(ref engine) = source.replication_engine {
            for (address, content) in &chunks {
                engine.replicate_fresh(address, content, &dummy_pop).await;
            }
        }
    }

    // Wait for replication to settle across the existing network.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ------------------------------------------------------------------
    // Step 2: Add a new (6th) node
    // ------------------------------------------------------------------
    let new_idx = harness.add_node().await.expect("add_node");

    // Pre-populate payment caches on the new node so it accepts fetched chunks.
    {
        let new_node = harness.test_node(new_idx).expect("new node");
        let protocol = new_node.ant_protocol.as_ref().expect("protocol");
        for (address, _) in &chunks {
            protocol.payment_verifier().cache_insert(*address);
        }
    }

    // ------------------------------------------------------------------
    // Step 3: Wait for replication to propagate to the new node
    // ------------------------------------------------------------------
    // The replication subsystem discovers missing chunks via neighbor-sync
    // and fetches them. Give it time to complete.
    let new_node = harness.test_node(new_idx).expect("new node");
    let new_p2p = new_node.p2p_node.as_ref().expect("p2p");
    let new_peer_id = *new_p2p.peer_id();
    let new_storage = new_node.ant_protocol.as_ref().expect("protocol").storage();
    let close_group_size = ant_node::CLOSE_GROUP_SIZE;

    // Determine which chunks the new node should be responsible for.
    let mut responsible_chunks: Vec<[u8; 32]> = Vec::new();
    for (address, _) in &chunks {
        let closest = new_p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(address, close_group_size)
            .await;
        if closest.iter().any(|n| n.peer_id == new_peer_id) {
            responsible_chunks.push(*address);
        }
    }

    // The new node should be responsible for at least some chunks in a
    // 6-node network with CLOSE_GROUP_SIZE=7 (it should be responsible
    // for all of them since 6 < 7, but be defensive).
    assert!(
        !responsible_chunks.is_empty(),
        "New node should be in the close group for at least some chunks"
    );

    // Poll until all responsible chunks are present in the new node's storage.
    let deadline = tokio::time::Instant::now() + REPLICATION_SETTLE_TIMEOUT;
    let mut all_present = false;
    while tokio::time::Instant::now() < deadline {
        let mut count = 0;
        for address in &responsible_chunks {
            if new_storage.exists(address).unwrap_or(false) {
                count += 1;
            }
        }
        if count == responsible_chunks.len() {
            all_present = true;
            break;
        }
        tokio::time::sleep(SETTLE_POLL_INTERVAL).await;
    }

    // ------------------------------------------------------------------
    // Step 4: Verify
    // ------------------------------------------------------------------
    if !all_present {
        let mut missing = Vec::new();
        for address in &responsible_chunks {
            if !new_storage.exists(address).unwrap_or(false) {
                missing.push(hex::encode(address));
            }
        }
        panic!(
            "New node is missing {}/{} responsible chunks after {REPLICATION_SETTLE_TIMEOUT:?}: [{}]",
            missing.len(),
            responsible_chunks.len(),
            missing.join(", "),
        );
    }

    // Verify the data content is correct, not just presence.
    for (address, content) in &chunks {
        if responsible_chunks.contains(address) {
            let stored = new_storage
                .get(address)
                .await
                .expect("get should succeed")
                .expect("chunk should exist");
            assert_eq!(
                &stored,
                content,
                "Stored chunk content should match original for key {}",
                hex::encode(address),
            );
        }
    }

    harness.teardown().await.expect("teardown");
}
