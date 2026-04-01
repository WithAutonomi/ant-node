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
