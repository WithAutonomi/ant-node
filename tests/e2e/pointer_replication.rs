//! Pointer replication across real nodes (ADR-0016).
//!
//! Each test runs a live network whose nodes carry the same pointer service and
//! replication engine a production node does, over real QUIC. Payment is
//! pre-marked in each node's verifier cache — the chain is not what is under
//! test here — but every other check a node makes runs for real: signatures,
//! responsibility, the merge rule, quorum and the capability gate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::{TestNetworkConfig, TestNode};
use super::TestHarness;
use ant_node::ant_protocol::chunk::{
    ChunkMessage, ChunkMessageBody, PointerPutRequest, PointerPutResponse,
};
use ant_node::pointer::PointerStore;
use ant_node::replication::pointer::{PointerFreshWrite, PointerReplication};
use ant_node::ReplicationConfig;
use ant_protocol::pointer::{Pointer, PointerState, PointerTarget, PointerTargetKind};
use bytes::Bytes;
use saorsa_core::identity::PeerId;
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};
use serial_test::serial;
use std::sync::Arc;
use std::time::Duration;

/// How long to wait for replication to reach a node.
const SETTLE: Duration = Duration::from_secs(30);

/// How often to look while waiting.
const POLL: Duration = Duration::from_millis(200);

/// A proof the receivers never parse: the state is pre-marked as paid in each
/// verifier's cache, so verification answers from the cache.
const DUMMY_PROOF: [u8; 64] = [0x01; 64];

fn owner() -> (MlDsaPublicKey, MlDsaSecretKey) {
    ml_dsa_65().generate_keypair().expect("keypair")
}

fn signed(pk: &MlDsaPublicKey, sk: &MlDsaSecretKey, counter: u64, target: u8) -> Pointer {
    Pointer::sign(
        sk,
        pk,
        counter,
        PointerTarget::new(PointerTargetKind::Chunk, [target; 32]),
    )
    .expect("sign")
}

fn store(node: &TestNode) -> PointerStore {
    node.ant_protocol
        .as_ref()
        .expect("protocol")
        .pointer_service()
        .expect("pointer service")
        .store()
        .clone()
}

fn replication(node: &TestNode) -> &Arc<PointerReplication> {
    node.replication_engine
        .as_ref()
        .expect("engine")
        .pointer_replication()
        .expect("pointer replication")
}

fn peer(node: &TestNode) -> PeerId {
    *node.p2p_node.as_ref().expect("p2p").peer_id()
}

fn held(node: &TestNode, record: &Pointer) -> Option<PointerState> {
    store(node).state(&record.address())
}

fn holds(node: &TestNode, record: &Pointer) -> bool {
    held(node, record).is_some_and(|state| state.state_id == record.state_id())
}

/// Mark `record`'s state as paid on every node, as a settled payment would.
fn mark_paid(harness: &TestHarness, record: &Pointer) {
    for i in 0..harness.node_count() {
        if let Some(protocol) = harness.test_node(i).and_then(|n| n.ant_protocol.as_ref()) {
            protocol
                .payment_verifier()
                .cache_insert_pointer(record.address(), record.state_id());
        }
    }
}

/// Every node's index, except `except`.
fn others(harness: &TestHarness, except: &[usize]) -> Vec<usize> {
    (0..harness.node_count())
        .filter(|i| !except.contains(i))
        .collect()
}

/// Wait until `node` holds exactly `record`'s state.
async fn wait_for(harness: &TestHarness, index: usize, record: &Pointer) -> bool {
    let deadline = tokio::time::Instant::now() + SETTLE;
    while tokio::time::Instant::now() < deadline {
        if harness
            .test_node(index)
            .is_some_and(|node| holds(node, record))
        {
            return true;
        }
        tokio::time::sleep(POLL).await;
    }
    false
}

/// Send a paid pointer PUT to one node through its request handler, as a
/// client's PUT arrives, and return its answer.
async fn put(node: &TestNode, record: &Pointer) -> PointerPutResponse {
    let message = ChunkMessage {
        request_id: 1,
        body: ChunkMessageBody::PointerPutRequest(PointerPutRequest::with_payment(
            Bytes::from(record.to_bytes()),
            DUMMY_PROOF.to_vec(),
        )),
    };
    let reply = node
        .ant_protocol
        .as_ref()
        .expect("protocol")
        .try_handle_request(&message.encode().expect("encode"))
        .await
        .expect("handle")
        .expect("answered");
    match ChunkMessage::decode(&reply).expect("decode").body {
        ChunkMessageBody::PointerPutResponse(response) => response,
        other => panic!("expected a pointer PUT response, got {other:?}"),
    }
}

/// Have every node in `from` push its hints to every node in `to`, so each
/// learns the others understand pointers and hears what they hold.
async fn exchange_hints(harness: &TestHarness, from: &[usize], to: &[usize]) {
    let targets: Vec<PeerId> = to
        .iter()
        .filter_map(|i| harness.test_node(*i).map(peer))
        .collect();
    for i in from {
        let node = harness.test_node(*i).expect("node");
        let own = peer(node);
        let peers: Vec<PeerId> = targets.iter().copied().filter(|p| *p != own).collect();
        replication(node).push_hints(&peers).await;
    }
    // One-way messages: give them a moment to land.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// A client's paid PUT reaches one node, and replication carries it to every
/// other member of the close group: the node that accepted it offers it on,
/// with the proof, and each receiver verifies and stores it.
#[tokio::test]
#[serial]
async fn a_paid_put_to_one_node_reaches_its_whole_close_group() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let record = signed(&pk, &sk, 0, 1);
    mark_paid(&harness, &record);

    let entry = 3;
    match put(harness.test_node(entry).expect("node"), &record).await {
        PointerPutResponse::Success { state_id, .. } => assert_eq!(state_id, record.state_id()),
        other => panic!("the entry node refused the PUT: {other:?}"),
    }

    // In a five-node network every node is in every close group.
    for i in others(&harness, &[entry]) {
        assert!(
            wait_for(&harness, i, &record).await,
            "node {i} never received the pointer"
        );
    }

    harness.teardown().await.expect("teardown");
}

/// An update written to one node replaces the old state on every node.
#[tokio::test]
#[serial]
async fn an_update_replicates_and_replaces_the_old_state_everywhere() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let created = signed(&pk, &sk, 0, 1);
    let updated = signed(&pk, &sk, 4, 2);
    mark_paid(&harness, &created);
    mark_paid(&harness, &updated);

    put(harness.test_node(2).expect("node"), &created).await;
    for i in 0..harness.node_count() {
        assert!(
            wait_for(&harness, i, &created).await,
            "node {i} lacks the create"
        );
    }
    put(harness.test_node(4).expect("node"), &updated).await;
    for i in 0..harness.node_count() {
        assert!(
            wait_for(&harness, i, &updated).await,
            "node {i} still holds the old state"
        );
    }

    harness.teardown().await.expect("teardown");
}

/// A node that missed an update is brought level by neighbour sync: the
/// holders hint the newer state, it asks the group which state each holds,
/// adopts the one a quorum hold, and fetches it from one of them.
#[tokio::test]
#[serial]
async fn a_node_that_missed_an_update_is_repaired_by_neighbour_sync() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let created = signed(&pk, &sk, 0, 1);
    let missed = signed(&pk, &sk, 3, 2);
    let lagging = 4;
    let current = others(&harness, &[lagging]);

    // Everyone holds the create; everyone but the laggard holds the update,
    // written straight into their stores so nothing replicates it.
    for i in 0..harness.node_count() {
        store(harness.test_node(i).expect("node"))
            .put_bytes(&created.to_bytes())
            .await
            .expect("put");
    }
    for i in &current {
        store(harness.test_node(*i).expect("node"))
            .put_bytes(&missed.to_bytes())
            .await
            .expect("put");
    }
    assert!(holds(harness.test_node(lagging).expect("node"), &created));

    // Nothing but hints reaches the laggard: no fresh write carries the
    // update, so holding it afterwards means it was repaired. The engine's
    // own verification loop runs too; driving a round here only saves waiting.
    exchange_hints(&harness, &current, &[lagging]).await;
    replication(harness.test_node(lagging).expect("node"))
        .verify_due()
        .await;

    assert!(
        wait_for(&harness, lagging, &missed).await,
        "the lagging node never caught up"
    );

    harness.teardown().await.expect("teardown");
}

/// A node that joins after a pointer was written obtains it, with nothing but
/// the engine's own loops: its bootstrap sync reaches its neighbours, they
/// push their hints back, and it verifies and fetches.
#[tokio::test]
#[serial]
async fn a_node_that_joins_later_obtains_the_existing_pointers() {
    let mut harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let record = signed(&pk, &sk, 2, 1);
    for i in 0..harness.node_count() {
        store(harness.test_node(i).expect("node"))
            .put_bytes(&record.to_bytes())
            .await
            .expect("put");
    }

    let joined = harness.add_node().await.expect("add node");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut obtained = false;
    while tokio::time::Instant::now() < deadline {
        if harness
            .test_node(joined)
            .is_some_and(|node| holds(node, &record))
        {
            obtained = true;
            break;
        }
        // Stand in for the periodic timer, which runs every ten minutes.
        for i in 0..harness.node_count() {
            if let Some(engine) = harness
                .test_node(i)
                .and_then(|n| n.replication_engine.as_ref())
            {
                engine.trigger_neighbor_sync();
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(obtained, "the joining node never obtained the pointer");

    harness.teardown().await.expect("teardown");
}

/// A newer state that only one node holds is not adopted by the rest, however
/// well signed: one peer's word is not the network's. It is exactly what an
/// owner who got one node to store an unpaid state would try.
#[tokio::test]
#[serial]
async fn a_state_only_one_node_holds_is_not_adopted() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let agreed = signed(&pk, &sk, 1, 1);
    let lone = signed(&pk, &sk, 9, 9);
    let lone_holder = 0;
    for i in 0..harness.node_count() {
        store(harness.test_node(i).expect("node"))
            .put_bytes(&agreed.to_bytes())
            .await
            .expect("put");
    }
    store(harness.test_node(lone_holder).expect("node"))
        .put_bytes(&lone.to_bytes())
        .await
        .expect("put");

    let rest = others(&harness, &[lone_holder]);
    let everyone: Vec<usize> = (0..harness.node_count()).collect();
    exchange_hints(&harness, &everyone, &everyone).await;
    for i in &rest {
        replication(harness.test_node(*i).expect("node"))
            .verify_due()
            .await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    let lone_peer = peer(harness.test_node(lone_holder).expect("node"));
    for i in &rest {
        let node = harness.test_node(*i).expect("node");
        // The lone holder's hints did arrive, so what follows is the quorum
        // refusing, not a hint that never came.
        assert!(
            replication(node).is_capable(&lone_peer),
            "node {i} never heard from the lone holder"
        );
        assert!(
            holds(node, &agreed),
            "node {i} adopted a state only one node holds"
        );
    }

    harness.teardown().await.expect("teardown");
}

/// A fresh offer whose state was never paid for is refused by every receiver.
#[tokio::test]
#[serial]
async fn a_fresh_offer_that_was_not_paid_for_is_refused() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let unpaid = signed(&pk, &sk, 0, 1);
    let source = 3;
    let node = harness.test_node(source).expect("node");
    store(node)
        .put_bytes(&unpaid.to_bytes())
        .await
        .expect("put");
    replication(node)
        .replicate_fresh(PointerFreshWrite {
            record: unpaid.to_bytes(),
            payment_proof: DUMMY_PROOF.to_vec(),
        })
        .await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    for i in others(&harness, &[source]) {
        assert!(
            held(harness.test_node(i).expect("node"), &unpaid).is_none(),
            "node {i} stored an unpaid pointer"
        );
    }

    harness.teardown().await.expect("teardown");
}

/// Some minutes after offering a fresh state, the offering node asks each
/// close-group member for it. A member that cannot produce it is penalised,
/// and one that can is not.
#[tokio::test]
#[serial]
async fn the_possession_check_penalises_only_a_member_that_dropped_the_record() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let record = signed(&pk, &sk, 0, 1);
    let checker = 3;
    let dropper = 1;
    let keeper = 2;
    for i in 0..harness.node_count() {
        store(harness.test_node(i).expect("node"))
            .put_bytes(&record.to_bytes())
            .await
            .expect("put");
    }
    store(harness.test_node(dropper).expect("node"))
        .delete(&record.address())
        .await
        .expect("delete");

    // The checker only asks peers that understand pointers.
    let everyone: Vec<usize> = (0..harness.node_count()).collect();
    exchange_hints(&harness, &everyone, &[checker]).await;

    let checker_node = harness.test_node(checker).expect("node");
    let checker_p2p = checker_node.p2p_node.as_ref().expect("p2p");
    let dropper_peer = peer(harness.test_node(dropper).expect("node"));
    let keeper_peer = peer(harness.test_node(keeper).expect("node"));
    let dropper_before = checker_p2p.peer_trust(&dropper_peer);
    let keeper_before = checker_p2p.peer_trust(&keeper_peer);

    replication(checker_node)
        .check_possession(record.state(), &[dropper_peer, keeper_peer])
        .await;

    assert!(
        checker_p2p.peer_trust(&dropper_peer) < dropper_before,
        "the member that dropped the record was not penalised"
    );
    assert!(
        checker_p2p.peer_trust(&keeper_peer) >= keeper_before,
        "the member that holds the record was penalised"
    );

    harness.teardown().await.expect("teardown");
}

/// A network whose close group is two nodes, so that in five nodes some node
/// is always outside the retention width (two plus the margin of two) for any
/// address, with no pruning hysteresis.
fn prune_network(paid_width: usize) -> TestNetworkConfig {
    TestNetworkConfig {
        replication_config: Some(ReplicationConfig {
            close_group_size: 2,
            // The quorum may not exceed the group.
            quorum_threshold: 2,
            paid_list_close_group_size: paid_width,
            prune_hysteresis_duration: Duration::ZERO,
            ..ReplicationConfig::default()
        }),
        ..TestNetworkConfig::minimal()
    }
}

/// The node, out of five, that is outside the retention width for `record`.
async fn out_of_range_node(harness: &TestHarness, record: &Pointer) -> usize {
    let view = harness.test_node(0).expect("node");
    let p2p = view.p2p_node.as_ref().expect("p2p");
    let inside: Vec<PeerId> = p2p
        .dht_manager()
        .find_closest_nodes_local_with_self(&record.address(), 4)
        .await
        .into_iter()
        .map(|node| node.peer_id)
        .collect();
    (0..harness.node_count())
        .find(|i| {
            harness
                .test_node(*i)
                .is_some_and(|node| !inside.contains(&peer(node)))
        })
        .expect("one node is outside a width of four in five")
}

/// Pruning deletes a record the node is no longer responsible for once the
/// current close group prove they hold it, and keeps it while they do not.
#[tokio::test]
#[serial]
async fn pruning_deletes_only_once_the_close_group_proves_it_holds_the_record() {
    // A paid width no five-node network can complete, so deletion needs the
    // close group's proof rather than taking the far-away fast path.
    let harness = TestHarness::setup_with_config(prune_network(20))
        .await
        .expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let record = signed(&pk, &sk, 1, 1);
    let pruner = out_of_range_node(&harness, &record).await;
    store(harness.test_node(pruner).expect("node"))
        .put_bytes(&record.to_bytes())
        .await
        .expect("put");

    // Nobody else holds it yet: nothing proves it is safe to drop.
    let everyone: Vec<usize> = (0..harness.node_count()).collect();
    exchange_hints(&harness, &everyone, &[pruner]).await;
    let pruning = replication(harness.test_node(pruner).expect("node"));
    pruning.prune_pass(true).await;
    assert!(
        holds(harness.test_node(pruner).expect("node"), &record),
        "the only copy was pruned"
    );

    // Once the rest hold it, the close group proves it and the pruner drops it.
    for i in others(&harness, &[pruner]) {
        store(harness.test_node(i).expect("node"))
            .put_bytes(&record.to_bytes())
            .await
            .expect("put");
    }
    pruning.prune_pass(true).await;
    assert!(
        held(harness.test_node(pruner).expect("node"), &record).is_none(),
        "the record was not pruned though the close group holds it"
    );

    harness.teardown().await.expect("teardown");
}

/// A node outside even a complete paid-width group drops the record without
/// asking anyone, as a chunk is.
#[tokio::test]
#[serial]
async fn a_node_far_outside_the_group_prunes_without_asking() {
    let harness = TestHarness::setup_with_config(prune_network(3))
        .await
        .expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (pk, sk) = owner();
    let record = signed(&pk, &sk, 1, 1);
    let pruner = out_of_range_node(&harness, &record).await;
    store(harness.test_node(pruner).expect("node"))
        .put_bytes(&record.to_bytes())
        .await
        .expect("put");

    replication(harness.test_node(pruner).expect("node"))
        .prune_pass(false)
        .await;
    assert!(
        held(harness.test_node(pruner).expect("node"), &record).is_none(),
        "a far-away record was kept"
    );

    harness.teardown().await.expect("teardown");
}
