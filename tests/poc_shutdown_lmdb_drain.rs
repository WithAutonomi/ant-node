//! Regression test for the LMDB drain guarantee of
//! [`ant_node::ReplicationEngine::shutdown`].
//!
//! ## The vulnerability (pre-fix)
//!
//! Engine tasks race their work against the shutdown `CancellationToken` in
//! `select!`. Dropping the losing future does **not** cancel a
//! `tokio::task::spawn_blocking` LMDB transaction it was awaiting — the
//! closure keeps running on the blocking pool and owns a cloned heed `Env`.
//! `shutdown()` had nothing to wait on for those detached closures (fetch
//! `storage.put`, prune `storage.delete` / `paid_list.remove_batch`,
//! verification `paid_list.insert`), so it could return while the
//! environment was still open. Reopening the same LMDB file with the old
//! `Env` alive in-process is undefined behavior.
//!
//! ## The fix
//!
//! `LmdbStorage` and `PaidList` track their blocking tasks in a
//! `TaskTracker`; `shutdown()` awaits `wait_idle()` on both after draining
//! its own tasks. This test parks a chunk-store write inside its blocking
//! closure, drops the awaiter (the exact leak shape), and asserts that
//! `shutdown()` blocks until the write finishes — then proves both LMDB
//! environments reopen cleanly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use ant_node::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig,
};
use ant_node::replication::paid_list::PaidList;
use ant_node::storage::{LmdbStorage, LmdbStorageConfig};
use ant_node::{ReplicationConfig, ReplicationEngine};
use evmlib::{Network as EvmNetwork, RewardsAddress};
use rand::Rng;
use saorsa_core::identity::NodeIdentity;
use saorsa_core::{NodeConfig as CoreNodeConfig, P2PNode};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// E2E test port range (CLAUDE.md): tests must stay inside 20000-60000,
/// away from production ant-node's 10000-10999.
const TEST_PORT_RANGE_MIN: u16 = 20_000;
/// Upper bound (exclusive) of the E2E test port range.
const TEST_PORT_RANGE_MAX: u16 = 60_000;
/// Attempts to bind a random test port before giving up (mirrors the
/// transient port-bind retry in the e2e testnet harness).
const PORT_BIND_ATTEMPTS: usize = 4;
/// Short probe proving `shutdown()` is still waiting on the parked LMDB op.
const SHUTDOWN_BLOCKED_PROBE: Duration = Duration::from_millis(300);
/// Generous ceiling for `shutdown()` to finish once the op is released.
const SHUTDOWN_COMPLETE_TIMEOUT: Duration = Duration::from_secs(30);
/// Payment cache capacity for the test verifier.
const TEST_PAYMENT_CACHE_CAPACITY: usize = 1000;
/// Rewards address for the test verifier.
const TEST_REWARDS_ADDRESS: [u8; 20] = [0x01; 20];

/// Create and start a loopback P2P node on a random port in the test range.
async fn start_p2p_node(identity: &Arc<NodeIdentity>) -> Arc<P2PNode> {
    let mut last_err = String::new();
    for _ in 0..PORT_BIND_ATTEMPTS {
        let port = rand::thread_rng().gen_range(TEST_PORT_RANGE_MIN..TEST_PORT_RANGE_MAX);
        let mut config = CoreNodeConfig::builder()
            .port(port)
            .ipv6(false)
            .local(true)
            .build()
            .expect("build core config");
        config.node_identity = Some(Arc::clone(identity));
        match P2PNode::new(config).await {
            Ok(node) => {
                node.start().await.expect("start p2p node");
                return Arc::new(node);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    panic!("failed to create P2P node after {PORT_BIND_ATTEMPTS} attempts: {last_err}");
}

/// A blocking LMDB write whose awaiter was dropped must delay `shutdown()`
/// until it commits, after which both LMDB environments reopen cleanly.
// Holding the gate's write guard across awaits is the point of the test:
// it parks the blocking closure while we probe shutdown().
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn shutdown_waits_for_detached_lmdb_op_and_envs_reopen() {
    let temp_dir = tempfile::TempDir::new().expect("create temp dir");
    let root_dir = temp_dir.path().to_path_buf();

    // The chunk store the engine will hold (and whose env we reopen below).
    let storage = Arc::new(
        LmdbStorage::new(LmdbStorageConfig {
            root_dir: root_dir.clone(),
            ..LmdbStorageConfig::test_default()
        })
        .await
        .expect("create storage"),
    );

    let identity = Arc::new(NodeIdentity::generate().expect("generate identity"));
    let replication_config = ReplicationConfig::default();
    let payment_verifier = Arc::new(PaymentVerifier::new(PaymentVerifierConfig {
        evm: EvmVerifierConfig {
            network: EvmNetwork::ArbitrumSepoliaTest,
        },
        cache_capacity: TEST_PAYMENT_CACHE_CAPACITY,
        close_group_size: replication_config.close_group_size,
        local_rewards_address: RewardsAddress::new(TEST_REWARDS_ADDRESS),
        price_floor: PriceFloorConfig::default(),
    }));

    let p2p = start_p2p_node(&identity).await;

    let (_fresh_tx, fresh_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut engine = ReplicationEngine::new(
        replication_config,
        Arc::clone(&p2p),
        Arc::clone(&storage),
        payment_verifier,
        identity,
        &root_dir,
        fresh_rx,
        CancellationToken::new(),
    )
    .await
    .expect("create engine");
    engine.start(p2p.dht_manager().subscribe_events()).await;

    // Park a put's blocking closure on the test gate, then drop its awaiter
    // mid-flight — the exact shape of a select! losing to the shutdown token
    // while `storage.put()` awaits `spawn_blocking`.
    let content = b"held-open write must block engine shutdown";
    let address = LmdbStorage::compute_address(content);
    let gate = storage.test_put_gate();
    let parked = gate.write();
    tokio::select! {
        biased;
        res = storage.put(&address, content) => {
            panic!("put must be parked on the test gate, got {res:?}")
        }
        () = std::future::ready(()) => {}
    }

    {
        let shutdown_fut = engine.shutdown();
        tokio::pin!(shutdown_fut);

        // shutdown() must not return while the blocking op is still running.
        let blocked = tokio::time::timeout(SHUTDOWN_BLOCKED_PROBE, shutdown_fut.as_mut()).await;
        assert!(
            blocked.is_err(),
            "shutdown() returned while an LMDB blocking op was in flight"
        );

        // Release the write; shutdown must now run to completion.
        drop(parked);
        tokio::time::timeout(SHUTDOWN_COMPLETE_TIMEOUT, shutdown_fut)
            .await
            .expect("shutdown after releasing the parked op");
    }

    // The detached write committed before shutdown returned.
    assert!(storage.exists(&address).expect("exists after shutdown"));

    // Release every reference the test still holds. Per the shutdown
    // contract, no engine-spawned work holds the storage or paid list any
    // more, so these drops close both environments.
    drop(engine);
    p2p.shutdown().await.expect("p2p shutdown");
    drop(p2p);
    drop(gate);
    drop(storage);

    // Both LMDB environments reopen cleanly from the same directory.
    let reopened = LmdbStorage::new(LmdbStorageConfig {
        root_dir: root_dir.clone(),
        ..LmdbStorageConfig::test_default()
    })
    .await
    .expect("reopen chunk store");
    let read_back = reopened.get(&address).await.expect("get after reopen");
    assert_eq!(read_back, Some(content.to_vec()));

    let paid_list = PaidList::new(&root_dir).await.expect("reopen paid list");
    assert_eq!(paid_list.count().expect("paid list count"), 0);
}
