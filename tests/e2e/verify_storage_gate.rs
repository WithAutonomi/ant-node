//! Verification driver for the replica-hint storage-admission gate.
//!
//! Drives a live multi-node testnet to observe, at the wire protocol, whether
//! a replica hint can make a node store a key it carries no storage
//! responsibility for.
//!
//! The attack this exercises: key K is already in the target's `PaidForList`
//! (validity settled — that is what an attacker's first, paid hint achieves).
//! A second message re-advertises K as a *replica* hint. Before the fix, the
//! `Replica` arm of the paid-list fast path went straight to a presence probe
//! and fetch, never asking whether this node was inside
//! `storage_admission_width` for K.
//!
//! Both scenarios run against the same network so the negative and the
//! positive control share routing state.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::TestNetworkConfig;
use super::TestHarness;
use ant_node::client::compute_address;
use ant_node::replication::config::{storage_admission_width, REPLICATION_PROTOCOL_ID};
use ant_node::replication::protocol::{
    NeighborSyncRequest, ReplicationMessage, ReplicationMessageBody,
};
use ant_node::ReplicationConfig;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use serial_test::serial;
use std::time::Duration;

/// Nodes in the driver network. Must exceed `storage_admission_width` (9) so
/// that a rank-10+ band exists at all; every node still falls inside the
/// 20-wide paid close group, which is exactly the vulnerable population.
const GATE_NODE_COUNT: usize = 12;
/// Production close group size, so `storage_admission_width` is the real 9.
const GATE_CLOSE_GROUP_SIZE: usize = 7;
/// Target node driven by both scenarios.
const TARGET_INDEX: usize = 5;
/// Peer used to send the crafted hint (must be in the target's routing table).
const ADVERTISER_INDEX: usize = 6;
/// Node used to host the chunk bytes so a fetch could succeed if attempted.
const HOLDER_SEARCH_LIMIT: usize = 10_000;
/// How long to wait for the target's verification cycle to act on the hint.
const CYCLE_OBSERVATION_WINDOW: Duration = Duration::from_secs(12);
/// Poll interval while observing the target's storage.
const OBSERVATION_POLL: Duration = Duration::from_millis(200);
/// Wire timeout for the crafted sync request.
const SYNC_SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Request id for the crafted paid hint (message 1 of the attack).
const CRAFTED_PAID_REQUEST_ID: u64 = 909_090;
/// Request id for the crafted replica hint (message 2 of the attack).
const CRAFTED_REPLICA_REQUEST_ID: u64 = 909_091;
/// Paid close group narrowed for the far-key probe, so that a key outside the
/// target's storage-admission group is outside its paid group too. At the
/// production width (20) every node on a 12-node network is in every paid
/// group, which would make "outside both gates" unrepresentable here.
const FAR_KEY_PAID_GROUP: usize = 2;

fn gate_config() -> ReplicationConfig {
    ReplicationConfig {
        close_group_size: GATE_CLOSE_GROUP_SIZE,
        ..ReplicationConfig::default()
    }
}

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

/// Find a key whose `width`-wide storage-admission group either excludes
/// (`want_responsible = false`) or includes (`true`) the target, from the
/// target's own DHT view. Shared with the fetch-recheck driver.
pub async fn find_key_for_target(
    harness: &TestHarness,
    target_idx: usize,
    width: usize,
    want_responsible: bool,
    label: &str,
) -> (Vec<u8>, [u8; 32]) {
    let target = harness.test_node(target_idx).expect("target node");
    let target_p2p = target.p2p_node.as_ref().expect("target p2p");
    let target_peer = *target_p2p.peer_id();

    for attempt in 0..HOLDER_SEARCH_LIMIT {
        let content = format!("gate-{label}-{attempt}").into_bytes();
        let address = compute_address(&content);
        let admission_group = target_p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(&address, width)
            .await;
        let is_responsible = admission_group
            .iter()
            .any(|node| node.peer_id == target_peer);
        if is_responsible == want_responsible {
            return (content, address);
        }
    }
    panic!("no key found for target {target_idx} with responsible={want_responsible}");
}

/// Seed the target's paid list with `address`, host the bytes on every other
/// node so a fetch would succeed, then send the target a replica hint for it.
/// Returns whether the target's storage holds the key at the end of the
/// observation window.
async fn drive_replica_hint(harness: &TestHarness, content: &[u8], address: [u8; 32]) -> bool {
    let target = harness.test_node(TARGET_INDEX).expect("target");
    let target_p2p = target.p2p_node.as_ref().expect("target p2p");
    let target_peer = *target_p2p.peer_id();
    let target_storage = target
        .ant_protocol
        .as_ref()
        .expect("target protocol")
        .storage();

    // Validity is already settled for this key: this is the state an
    // attacker's first (paid) hint leaves behind.
    target
        .replication_engine
        .as_ref()
        .expect("target engine")
        .paid_list()
        .insert(&address)
        .await
        .expect("seed target paid list");

    // Host the bytes everywhere else so that a fetch, if the target attempts
    // one, finds a willing source. A negative result then means the target
    // *declined*, not that it failed to find the data.
    for idx in 0..harness.node_count() {
        if idx == TARGET_INDEX {
            continue;
        }
        if let Some(node) = harness.test_node(idx) {
            if let Some(protocol) = node.ant_protocol.as_ref() {
                let _ = protocol.storage().put(&address, content).await;
                protocol.payment_verifier().cache_insert(address);
            }
        }
    }

    assert!(
        !target_storage.exists(&address).unwrap_or(true),
        "target must not already hold the key before the hint"
    );

    let advertiser = harness.test_node(ADVERTISER_INDEX).expect("advertiser");
    let advertiser_p2p = advertiser.p2p_node.as_ref().expect("advertiser p2p");

    // Message 1 — paid hint. The target is inside the 20-wide paid close
    // group, so this is admitted and lands in pending_verify as PaidOnly.
    // This is what opens the escalation window: a lone replica hint for an
    // out-of-range key is simply rejected at admission.
    let paid_msg = ReplicationMessage {
        request_id: CRAFTED_PAID_REQUEST_ID,
        body: ReplicationMessageBody::NeighborSyncRequest(NeighborSyncRequest {
            replica_hints: vec![],
            paid_hints: vec![address],
            bootstrapping: false,
            commitment: None,
        }),
    };
    let resp =
        send_replication_request(advertiser_p2p, &target_peer, paid_msg, SYNC_SEND_TIMEOUT).await;
    assert!(
        matches!(resp.body, ReplicationMessageBody::NeighborSyncResponse(_)),
        "target accepted the paid hint: {resp:?}"
    );

    // Message 2 — the same key, now advertised as a replica hint. The key is
    // already in pending_verify, so admission's already-pending fast path
    // skips the storage-admission check and the entry escalates to Replica.
    let replica_msg = ReplicationMessage {
        request_id: CRAFTED_REPLICA_REQUEST_ID,
        body: ReplicationMessageBody::NeighborSyncRequest(NeighborSyncRequest {
            replica_hints: vec![address],
            paid_hints: vec![],
            bootstrapping: false,
            commitment: None,
        }),
    };
    let resp =
        send_replication_request(advertiser_p2p, &target_peer, replica_msg, SYNC_SEND_TIMEOUT)
            .await;
    assert!(
        matches!(resp.body, ReplicationMessageBody::NeighborSyncResponse(_)),
        "target accepted the crafted replica hint: {resp:?}"
    );

    // Observe: does the target fetch and store the key?
    let deadline = tokio::time::Instant::now() + CYCLE_OBSERVATION_WINDOW;
    while tokio::time::Instant::now() < deadline {
        if target_storage.exists(&address).unwrap_or(false) {
            return true;
        }
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    target_storage.exists(&address).unwrap_or(false)
}

#[tokio::test]
#[serial]
async fn replica_hint_storage_gate_observed_on_live_network() {
    let config = TestNetworkConfig {
        node_count: GATE_NODE_COUNT,
        replication_config: Some(gate_config()),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("setup gate network");
    harness.warmup_dht().await.expect("warmup");

    // -- Scenario A (the attack): target is NOT in the storage-admission
    //    group for this key, but a replica hint advertises it anyway.
    let (content_out, key_out) = find_key_for_target(
        &harness,
        TARGET_INDEX,
        storage_admission_width(GATE_CLOSE_GROUP_SIZE),
        false,
        "out",
    )
    .await;
    let stored_out = drive_replica_hint(&harness, &content_out, key_out).await;

    // -- Scenario B (positive control): target IS in the storage-admission
    //    group. Legitimate replica repair must still happen.
    let (content_in, key_in) = find_key_for_target(
        &harness,
        TARGET_INDEX,
        storage_admission_width(GATE_CLOSE_GROUP_SIZE),
        true,
        "in",
    )
    .await;
    let stored_in = drive_replica_hint(&harness, &content_in, key_in).await;

    println!("GATE-RESULT out_of_range_stored={stored_out} in_range_stored={stored_in}");

    assert!(
        !stored_out,
        "SECURITY: replica hint made the target store a key it is not \
         storage-responsible for (key {})",
        hex::encode(key_out)
    );
    assert!(
        stored_in,
        "REGRESSION: legitimate replica repair did not happen for a key the \
         target IS storage-responsible for (key {})",
        hex::encode(key_in)
    );

    harness.teardown().await.expect("teardown");
}

/// Probe: under the unified admission gate, a key that is out of range for
/// *both* the paid group and storage admission must be rejected outright, and
/// the label the sender picks must not change that.
///
/// This is the "does mislabeling buy anything" question. With one gate, a
/// replica hint and a paid hint for the same far key should reach the same
/// verdict.
#[tokio::test]
#[serial]
async fn far_key_rejected_under_either_label() {
    let config = TestNetworkConfig {
        node_count: GATE_NODE_COUNT,
        replication_config: Some(ReplicationConfig {
            close_group_size: GATE_CLOSE_GROUP_SIZE,
            paid_list_close_group_size: FAR_KEY_PAID_GROUP,
            ..ReplicationConfig::default()
        }),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("setup far-key network");
    harness.warmup_dht().await.expect("warmup");

    let target = harness.test_node(TARGET_INDEX).expect("target");
    let target_p2p = target.p2p_node.as_ref().expect("target p2p");
    let target_peer = *target_p2p.peer_id();
    let target_storage = target.ant_protocol.as_ref().expect("protocol").storage();

    // A key the target is not responsible for and not in the (narrowed) paid
    // group for. Deliberately NOT seeded into the paid list: nothing should
    // make this key relevant.
    let (content, address) = find_key_for_target(
        &harness,
        TARGET_INDEX,
        storage_admission_width(GATE_CLOSE_GROUP_SIZE),
        false,
        "far",
    )
    .await;
    for idx in 0..harness.node_count() {
        if idx == TARGET_INDEX {
            continue;
        }
        if let Some(node) = harness.test_node(idx) {
            if let Some(protocol) = node.ant_protocol.as_ref() {
                let _ = protocol.storage().put(&address, &content).await;
            }
        }
    }

    let advertiser = harness.test_node(ADVERTISER_INDEX).expect("advertiser");
    let advertiser_p2p = advertiser.p2p_node.as_ref().expect("advertiser p2p");

    for (label, req) in [
        (
            "paid",
            NeighborSyncRequest {
                replica_hints: vec![],
                paid_hints: vec![address],
                bootstrapping: false,
                commitment: None,
            },
        ),
        (
            "replica",
            NeighborSyncRequest {
                replica_hints: vec![address],
                paid_hints: vec![],
                bootstrapping: false,
                commitment: None,
            },
        ),
    ] {
        let msg = ReplicationMessage {
            request_id: CRAFTED_PAID_REQUEST_ID,
            body: ReplicationMessageBody::NeighborSyncRequest(req),
        };
        let resp =
            send_replication_request(advertiser_p2p, &target_peer, msg, SYNC_SEND_TIMEOUT).await;
        assert!(
            matches!(resp.body, ReplicationMessageBody::NeighborSyncResponse(_)),
            "{label} hint accepted at the wire"
        );
    }

    let deadline = tokio::time::Instant::now() + CYCLE_OBSERVATION_WINDOW;
    while tokio::time::Instant::now() < deadline {
        assert!(
            !target_storage.exists(&address).unwrap_or(false),
            "far key stored despite being outside both gates"
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }

    println!("PROBE-RESULT far_key_stored=false (both labels rejected)");
    harness.teardown().await.expect("teardown");
}
