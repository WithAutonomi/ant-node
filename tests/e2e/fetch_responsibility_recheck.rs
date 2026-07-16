//! Per-attempt storage-responsibility recheck at the point of download.
//!
//! The replication design (`types.rs`, `admission.rs`) promises that storage
//! responsibility is decided against LIVE routing state at the point of
//! download. The responsibility check in the verification cycle is only a
//! pre-filter: a key can wait in the nearest-first fetch queue while topology
//! churn moves this node out of the storage-admission group, and before the
//! per-attempt recheck in `execute_single_fetch` the worker would download
//! and store it anyway.
//!
//! Why this test does not shift live topology: peer IDs are randomly
//! derived, saorsa-core admits new routing-table entries only from real
//! network interactions (no injection API), and the promotion→dequeue window
//! is milliseconds — real churn cannot be timed into it deterministically.
//! Instead, the test-only `enqueue_fetch_for_test` seam places a verified
//! fetch candidate directly into the fetch queue for a key the target — per
//! its own live routing view — carries no storage responsibility for. That
//! is exactly the state the staleness bug leaves behind: a fetch-queue entry
//! whose promotion-time responsibility answer no longer matches live routing
//! state. The only gate between that entry and a disk write is the
//! per-attempt recheck.
//!
//! Bootstrap-drain accounting is not directly observable here (the harness
//! finishes bootstrap before tests run); the unit tests on
//! `apply_fetch_result` pin `NoLongerResponsible` to the same terminal arm
//! as `Stored`, which is the path that shrinks the bootstrap pending set.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::TestNetworkConfig;
use super::verify_storage_gate::find_key_for_target;
use super::TestHarness;
use ant_node::replication::config::storage_admission_width;
use ant_node::ReplicationConfig;
use serial_test::serial;
use std::time::Duration;

/// Nodes in the driver network. Must exceed `storage_admission_width` (9) so
/// that keys outside the target's admission group exist at all.
const RECHECK_NODE_COUNT: usize = 12;
/// Production close group size, so `storage_admission_width` is the real 9.
const RECHECK_CLOSE_GROUP_SIZE: usize = 7;
/// Node whose fetch pipeline is driven by both scenarios.
const TARGET_INDEX: usize = 5;
/// Node hosting the chunk bytes so a fetch, if attempted, succeeds.
const HOLDER_INDEX: usize = 6;
/// How long to wait for the target's fetch worker to resolve a candidate.
const OBSERVATION_WINDOW: Duration = Duration::from_secs(12);
/// Poll interval while observing the target's storage and fetch pipeline.
const OBSERVATION_POLL: Duration = Duration::from_millis(200);

fn recheck_config() -> ReplicationConfig {
    ReplicationConfig {
        close_group_size: RECHECK_CLOSE_GROUP_SIZE,
        ..ReplicationConfig::default()
    }
}

/// Scenario A (the bug): a fetch-queue candidate for a key the target is not
/// storage-responsible for must be declined at download time — never stored,
/// and terminally removed from the fetch pipeline (no stall, no verification
/// requeue). Scenario B (positive control): the same seam and the same
/// holder, for a key the target IS responsible for, must fetch and store —
/// proving the seam drives the real worker and executor.
#[tokio::test]
#[serial]
async fn stale_fetch_candidate_is_declined_at_download_time() {
    let config = TestNetworkConfig {
        node_count: RECHECK_NODE_COUNT,
        replication_config: Some(recheck_config()),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("setup recheck network");
    harness.warmup_dht().await.expect("warmup");

    let width = storage_admission_width(RECHECK_CLOSE_GROUP_SIZE);
    let (content_out, key_out) =
        find_key_for_target(&harness, TARGET_INDEX, width, false, "stale").await;
    let (content_in, key_in) =
        find_key_for_target(&harness, TARGET_INDEX, width, true, "live").await;

    let target = harness.test_node(TARGET_INDEX).expect("target");
    let target_storage = target
        .ant_protocol
        .as_ref()
        .expect("target protocol")
        .storage();
    let target_engine = target.replication_engine.as_ref().expect("target engine");

    // Host both chunks on the holder so a negative result means the target
    // *declined* the download, not that no source could serve it.
    let holder = harness.test_node(HOLDER_INDEX).expect("holder");
    let holder_peer = *holder.p2p_node.as_ref().expect("holder p2p").peer_id();
    let holder_storage = holder
        .ant_protocol
        .as_ref()
        .expect("holder protocol")
        .storage();
    holder_storage
        .put(&key_out, &content_out)
        .await
        .expect("host stale-candidate chunk");
    holder_storage
        .put(&key_in, &content_in)
        .await
        .expect("host control chunk");

    assert!(
        !target_storage.exists(&key_out).unwrap_or(true),
        "target must not hold the stale-candidate key before the test"
    );
    assert!(
        !target_storage.exists(&key_in).unwrap_or(true),
        "target must not hold the control key before the test"
    );

    // -- Scenario A: stale candidate. The seam models a promotion decision
    //    whose responsibility answer no longer matches live routing state.
    assert!(
        target_engine
            .enqueue_fetch_for_test(key_out, vec![holder_peer])
            .await,
        "stale candidate must enqueue"
    );

    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while target_engine
        .fetch_pipeline_contains_for_test(&key_out)
        .await
    {
        assert!(
            !target_storage.exists(&key_out).unwrap_or(false),
            "CHURN BUG: stale fetch candidate was downloaded and stored for a \
             key outside the target's storage-admission group (key {})",
            hex::encode(key_out)
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "stale candidate did not leave the fetch pipeline terminally — \
             a key stuck here would stall bootstrap drain (key {})",
            hex::encode(key_out)
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    // The store happens before a fetch resolves, so pipeline-exit without a
    // stored chunk is conclusive: the download was declined.
    assert!(
        !target_storage.exists(&key_out).unwrap_or(true),
        "CHURN BUG: stale fetch candidate was downloaded and stored (key {})",
        hex::encode(key_out)
    );

    // -- Scenario B: positive control through the identical path.
    assert!(
        target_engine
            .enqueue_fetch_for_test(key_in, vec![holder_peer])
            .await,
        "control candidate must enqueue"
    );

    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while !target_storage.exists(&key_in).unwrap_or(false) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "REGRESSION: fetch for a key the target IS storage-responsible \
             for did not store within the window (key {})",
            hex::encode(key_in)
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while target_engine
        .fetch_pipeline_contains_for_test(&key_in)
        .await
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "control candidate should leave the fetch pipeline after storing"
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }

    println!("RECHECK-RESULT stale_stored=false control_stored=true");
    harness.teardown().await.expect("teardown");
}
