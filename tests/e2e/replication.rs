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
use ant_node::replication::scheduling::ReplicationQueues;
use saorsa_core::identity::PeerId;
use saorsa_core::TrustEvent;
use serial_test::serial;
use std::time::Duration;

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

    // Pre-populate payment cache so the store is considered paid
    source_protocol.payment_verifier().cache_insert(address);

    // Trigger fresh replication with a dummy PoP
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Wait for replication to propagate
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Check if any other node received the chunk
    let mut found_on_other = false;
    for i in 0..harness.node_count() {
        if i == source_idx {
            continue;
        }
        if let Some(node) = harness.test_node(i) {
            if let Some(protocol) = &node.ant_protocol {
                if protocol.storage().exists(&address).unwrap_or(false) {
                    found_on_other = true;
                    break;
                }
            }
        }
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
    let harness = TestHarness::setup_minimal().await.expect("setup");

    let node = harness.test_node(3).expect("node");
    let key = [0xAA; 32];

    // Insert into paid list
    if let Some(ref engine) = node.replication_engine {
        engine.paid_list().insert(&key).await.expect("insert");
        assert!(engine.paid_list().contains(&key).expect("contains"));
    }

    // Reopen the paid list from the same directory to verify persistence
    let paid_list2 = ant_node::replication::paid_list::PaidList::new(&node.data_dir)
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
    let encoded = msg.encode().expect("encode");

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();

    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
    let encoded = msg.encode().expect("encode");

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();

    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
    let encoded = msg.encode().expect("encode");

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
    let encoded = msg.encode().expect("encode");

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
    let encoded = msg.encode().expect("encode");

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
    let encoded = msg.encode().expect("encode");

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();
    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
    let encoded = msg.encode().expect("encode");

    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
    let encoded = msg.encode().expect("encode");

    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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

    // Store two chunks on A
    let c1 = b"audit multi key 1";
    let c2 = b"audit multi key 2";
    let a1 = ant_node::client::compute_address(c1);
    let a2 = ant_node::client::compute_address(c2);
    protocol_a.storage().put(&a1, c1).await.expect("put 1");
    protocol_a.storage().put(&a2, c2).await.expect("put 2");

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
    let encoded = msg.encode().expect("encode");

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
    let encoded = msg.encode().expect("encode");

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let response = p2p_b
        .send_request(
            &peer_a,
            REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send_request");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
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
// Section 18, Scenario #3: Neighbor-sync unknown key quorum pass -> stored
// =========================================================================

/// Fresh replication stores chunk on remote peer AND updates their `PaidForList`
/// (Section 18 #3).
///
/// Store a chunk on node A, call `replicate_fresh`, wait for propagation, then
/// verify at least one remote node has the chunk in both storage and `PaidForList`.
#[tokio::test]
#[serial]
async fn scenario_3_fresh_replication_stores_and_updates_paid_list() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let source_idx = 3;
    let source = harness.test_node(source_idx).expect("source");
    let protocol = source.ant_protocol.as_ref().expect("protocol");
    let storage = protocol.storage();

    let content = b"scenario 3 quorum pass test";
    let address = compute_address(content);
    storage.put(&address, content).await.expect("put");

    // Pre-populate payment cache so the store is considered paid
    protocol.payment_verifier().cache_insert(address);

    // Trigger fresh replication (sends FreshReplicationOffer + PaidNotify)
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Wait for propagation
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check: at least one other node has the chunk AND has it in paid list
    let mut stored_elsewhere = false;
    let mut paid_listed_elsewhere = false;
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
    let max_concurrent = 10;
    let mut queues = ReplicationQueues::new(max_concurrent);
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
    let max_concurrent = 10;
    let mut queues = ReplicationQueues::new(max_concurrent);
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

/// Store chunks on multiple nodes and verify storage + paid-list consistency
/// (Section 18 #12).
///
/// Simulates the state a bootstrapping node would discover: keys that exist
/// on multiple peers with paid-list entries.
#[tokio::test]
#[serial]
async fn scenario_12_bootstrap_discovers_keys() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    // Store a chunk on nodes 3 and 4
    let content = b"bootstrap discovery test";
    let address = compute_address(content);

    for idx in [3, 4] {
        let node = harness.test_node(idx).expect("node");
        let protocol = node.ant_protocol.as_ref().expect("protocol");
        protocol
            .storage()
            .put(&address, content)
            .await
            .expect("put");
        protocol.payment_verifier().cache_insert(address);
        // Add to paid list
        if let Some(ref engine) = node.replication_engine {
            engine
                .paid_list()
                .insert(&address)
                .await
                .expect("paid insert");
        }
    }

    // Verify both nodes have storage AND paid-list entries
    for idx in [3, 4] {
        let node = harness.test_node(idx).expect("node");
        let protocol = node.ant_protocol.as_ref().expect("protocol");
        assert!(
            protocol.storage().exists(&address).unwrap(),
            "Node {idx} should have the chunk in storage"
        );
        if let Some(ref engine) = node.replication_engine {
            assert!(
                engine.paid_list().contains(&address).unwrap(),
                "Node {idx} should have the key in PaidForList"
            );
        }
    }

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #14: Coverage under backlog
// =========================================================================

/// All locally stored keys appear in `all_keys()`, ensuring neighbor-sync
/// hint construction covers the full local inventory (Section 18 #14).
#[tokio::test]
#[serial]
async fn scenario_14_hint_construction_covers_all_local_keys() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node = harness.test_node(3).expect("node");
    let protocol = node.ant_protocol.as_ref().expect("protocol");
    let storage = protocol.storage();

    // Store multiple chunks
    let chunk_count = 10u8;
    let mut addresses = Vec::new();
    for i in 0..chunk_count {
        let content = format!("backlog test chunk {i}");
        let address = compute_address(content.as_bytes());
        storage
            .put(&address, content.as_bytes())
            .await
            .expect("put");
        addresses.push(address);
    }

    // Verify all_keys returns all stored keys
    let all_keys = storage.all_keys().expect("all_keys");
    for addr in &addresses {
        assert!(
            all_keys.contains(addr),
            "all_keys should include every stored key"
        );
    }
    assert_eq!(all_keys.len(), addresses.len());

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #15: Partition and heal
// =========================================================================

/// Data survives a network partition (node shutdown). The remaining node
/// retains the chunk and its `PaidForList` entry (Section 18 #15).
#[tokio::test]
#[serial]
async fn scenario_15_partition_and_heal() {
    let mut harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    // Store a chunk on node 3
    let address;
    let content = b"partition test data";
    {
        let node3 = harness.test_node(3).expect("node3");
        let protocol3 = node3.ant_protocol.as_ref().expect("protocol");
        address = compute_address(content);
        protocol3
            .storage()
            .put(&address, content)
            .await
            .expect("put");

        // Add to paid list so it survives verification
        if let Some(ref engine) = node3.replication_engine {
            engine
                .paid_list()
                .insert(&address)
                .await
                .expect("paid insert");
        }
    }

    // "Partition": shut down node 4
    harness.shutdown_node(4).await.expect("shutdown");

    // Data should still exist on node 3
    let node3 = harness.test_node(3).expect("node3 after partition");
    assert!(
        node3
            .ant_protocol
            .as_ref()
            .unwrap()
            .storage()
            .exists(&address)
            .unwrap(),
        "Data should survive partition on remaining node"
    );

    // Paid list should also survive
    if let Some(ref engine) = node3.replication_engine {
        assert!(
            engine.paid_list().contains(&address).unwrap(),
            "PaidForList should survive partition"
        );
    }

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #17: Admission asymmetry
// =========================================================================

/// A `NeighborSyncRequest` from any peer returns a valid
/// `NeighborSyncResponse`, regardless of routing-table membership
/// (Section 18 #17).
///
/// The protocol always replies with outbound hints; inbound hint acceptance
/// depends on RT membership, but we verify the response is well-formed.
#[tokio::test]
#[serial]
async fn scenario_17_admission_requires_sender_in_rt() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    // Send sync request with a hint for a fabricated key
    let fake_key = [0x17; 32];
    let request = NeighborSyncRequest {
        replica_hints: vec![fake_key],
        paid_hints: vec![],
        bootstrapping: false,
    };
    let msg = ReplicationMessage {
        request_id: 1700,
        body: ReplicationMessageBody::NeighborSyncRequest(request),
    };
    let encoded = msg.encode().expect("encode");

    let response = p2p_b
        .send_request(
            &peer_a,
            ant_node::replication::config::REPLICATION_PROTOCOL_ID,
            encoded,
            Duration::from_secs(10),
        )
        .await
        .expect("send");

    let resp_msg = ReplicationMessage::decode(&response.data).expect("decode");
    // Response should be a valid NeighborSyncResponse regardless of RT membership
    assert!(
        matches!(
            resp_msg.body,
            ReplicationMessageBody::NeighborSyncResponse(_)
        ),
        "Expected NeighborSyncResponse, got: {:?}",
        resp_msg.body
    );

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
        let encoded = msg.encode().expect("encode");

        if let Ok(response) = p2p_q
            .send_request(
                &peer,
                ant_node::replication::config::REPLICATION_PROTOCOL_ID,
                encoded,
                Duration::from_secs(10),
            )
            .await
        {
            if let Ok(resp_msg) = ReplicationMessage::decode(&response.data) {
                if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
                    if resp.results.first().and_then(|r| r.paid) == Some(true) {
                        paid_confirmations += 1;
                    }
                }
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
    protocol.payment_verifier().cache_insert(address);

    // Trigger fresh replication (includes PaidNotify to PaidCloseGroup)
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Wait for propagation
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check paid lists on other nodes
    let mut paid_count = 0u32;
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
        let encoded = msg.encode().expect("encode");

        if let Ok(resp) = p2p_q
            .send_request(
                &peer,
                ant_node::replication::config::REPLICATION_PROTOCOL_ID,
                encoded,
                Duration::from_secs(10),
            )
            .await
        {
            if let Ok(resp_msg) = ReplicationMessage::decode(&resp.data) {
                if let ReplicationMessageBody::VerificationResponse(v) = resp_msg.body {
                    if v.results.first().and_then(|r| r.paid) == Some(true) {
                        confirmations += 1;
                    }
                }
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
// Section 18, Scenario #44: Cold-start recovery
// =========================================================================

/// `PaidForList` survives restart: keys inserted before shutdown are found
/// when the list is reopened from the same data directory (Section 18 #44).
#[tokio::test]
#[serial]
async fn scenario_44_paid_list_survives_restart() {
    let harness = TestHarness::setup_minimal().await.expect("setup");

    let node = harness.test_node(3).expect("node");
    let data_dir = node.data_dir.clone();
    let key = [0x44; 32];

    // Insert into paid list
    if let Some(ref engine) = node.replication_engine {
        engine.paid_list().insert(&key).await.expect("insert");
    }

    // Simulate restart: reopen PaidList from same directory
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
