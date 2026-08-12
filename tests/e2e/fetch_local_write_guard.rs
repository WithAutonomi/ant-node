//! A node that cannot write does not spend anyone else's bandwidth.
//!
//! `execute_single_fetch` rechecks storage *responsibility* at download time,
//! and now rechecks local possession and local capacity there too. The unit
//! tests on `apply_fetch_result` pin what the queue does with the resulting
//! `AlreadyHeld` / `LocalWriteFailed` outcomes; what they cannot show is the
//! part that matters for egress — that a node which cannot use the bytes does
//! not ask for them in the first place.
//!
//! (`LocalWriteFailed` also covers a `put` that fails *after* a round trip, so
//! the variant does not mean "no bytes moved". What the pre-check adds is that
//! the refusal happens before any holder is contacted, and what the
//! classification adds is that no *further* holder is contacted.)
//!
//! Both scenarios are observed through the holder's `chunks_retrieved` counter.
//! Only `LmdbStorage::get` increments it — the replication fetch responder and
//! the client GET handler; audits read through `get_raw` and leave it alone.
//! It is not keyed by chunk or requester, so it is an "it served something"
//! signal rather than an exact per-key one; on a freshly built testnet with no
//! other traffic to the holder, a delta means it served this fetch.
//!
//! Two gaps this file deliberately does not close, because neither is
//! constructible without adding test-only hooks to `LmdbStorage`:
//!
//! - **Ordering.** Possession is checked before capacity so a full node still
//!   accepts a key it already holds, matching `put`. Proving it needs a node
//!   that both holds the key and refuses writes, and `disk_reserve` is fixed at
//!   construction — seeding such a node fails. The ordering rests on inspection
//!   and on the `FetchResult::AlreadyHeld` doc comment.
//! - **Post-round-trip classification.** Nothing here forces `put` to fail
//!   *after* the bytes arrive, so reverting that one arm to `SourceFailed`
//!   would still pass. The pre-check fires first in every reachable local
//!   failure mode this harness can build.
//!
//! Why this matters in bytes: before the capacity gate, a write-blocked node
//! pulled the whole chunk first, and the failure was then classified as the
//! source's, so the worker walked to the next verified holder and every one of
//! them re-uploaded the same chunk into the same full store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::TestNetworkConfig;
use super::verify_storage_gate::find_key_for_target;
use super::TestHarness;
use ant_node::replication::config::storage_admission_width;
use ant_node::ReplicationConfig;
use serial_test::serial;
use std::collections::HashMap;
use std::time::Duration;

/// Above `storage_admission_width` (9), so a key the target is *not*
/// responsible for can exist — otherwise every node is responsible for
/// everything and `find_key_for_target` has nothing to choose between.
const NODE_COUNT: usize = 12;
/// Production close-group size, so the admission width is the real 9.
const CLOSE_GROUP_SIZE: usize = 7;
const TARGET_INDEX: usize = 5;
const HOLDER_INDEX: usize = 6;
/// Far above any real free space, so the target's capacity check always
/// refuses — the same `Insufficient disk space` error a full partition raises,
/// through the same `check_disk_space_cached` call `put` makes.
const IMPOSSIBLE_DISK_RESERVE: u64 = u64::MAX / 2;
const OBSERVATION_WINDOW: Duration = Duration::from_secs(15);
const OBSERVATION_POLL: Duration = Duration::from_millis(200);

/// A node whose storage cannot accept a write must not dial for the chunk.
#[tokio::test]
#[serial]
async fn write_blocked_node_does_not_dial() {
    let mut storage_disk_reserve_overrides = HashMap::new();
    storage_disk_reserve_overrides.insert(TARGET_INDEX, IMPOSSIBLE_DISK_RESERVE);
    let config = TestNetworkConfig {
        node_count: NODE_COUNT,
        storage_disk_reserve_overrides,
        replication_config: Some(ReplicationConfig {
            close_group_size: CLOSE_GROUP_SIZE,
            ..ReplicationConfig::default()
        }),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("setup write-blocked network");
    harness.warmup_dht().await.expect("warmup");

    let width = storage_admission_width(CLOSE_GROUP_SIZE);
    let (content, key) = find_key_for_target(&harness, TARGET_INDEX, width, true, "blocked").await;

    let target = harness.test_node(TARGET_INDEX).expect("target");
    let target_storage = target
        .ant_protocol
        .as_ref()
        .expect("target protocol")
        .storage();
    let target_engine = target.replication_engine.as_ref().expect("target engine");
    let holder = harness.test_node(HOLDER_INDEX).expect("holder");
    let holder_peer = *holder.p2p_node.as_ref().expect("holder p2p").peer_id();
    let holder_storage = holder
        .ant_protocol
        .as_ref()
        .expect("holder protocol")
        .storage();

    // The holder can serve it, so a zero below means the target declined to
    // ask — not that nobody could answer.
    holder_storage
        .put(&key, &content)
        .await
        .expect("host the chunk");
    // Establish the precondition through the public write path, which runs the
    // same capacity check the fetch pre-check calls.
    let probe = b"local-write-guard-precondition-probe".to_vec();
    let probe_address = ant_node::client::compute_address(&probe);
    assert!(
        target_storage.put(&probe_address, &probe).await.is_err(),
        "the target's storage must be refusing writes, or this test proves nothing"
    );

    let served_before = holder_storage.stats().chunks_retrieved;
    assert!(
        target_engine
            .enqueue_fetch_for_test(key, vec![holder_peer])
            .await,
        "candidate must enqueue"
    );

    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while target_engine.fetch_pipeline_contains_for_test(&key).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the candidate never resolved; a key stuck in the fetch pipeline \
             would stall bootstrap drain (key {})",
            hex::encode(key)
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    let served = holder_storage.stats().chunks_retrieved - served_before;
    println!("LOCAL-WRITE-GUARD-RESULT served_by_holder={served}");

    assert_eq!(
        served, 0,
        "a node whose storage cannot accept a write pulled {served} chunk(s) \
         from the holder. The bytes could never have been stored, and the old \
         classification treated the failure as the source's for retry-selection \
         purposes, so the worker walked to every remaining holder and each \
         re-sent the same chunk into the same full store."
    );
    assert!(
        !target_storage.exists(&key).unwrap_or(true),
        "the target cannot have stored a chunk its storage refuses to write"
    );

    harness.teardown().await.expect("teardown");
}

/// A node that already holds the key must not dial for it either.
#[tokio::test]
#[serial]
async fn already_held_key_is_not_fetched_again() {
    let config = TestNetworkConfig {
        node_count: NODE_COUNT,
        replication_config: Some(ReplicationConfig {
            close_group_size: CLOSE_GROUP_SIZE,
            ..ReplicationConfig::default()
        }),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("setup possession-recheck network");
    harness.warmup_dht().await.expect("warmup");

    let width = storage_admission_width(CLOSE_GROUP_SIZE);
    let (held_content, held_key) =
        find_key_for_target(&harness, TARGET_INDEX, width, true, "held").await;
    let (missing_content, missing_key) =
        find_key_for_target(&harness, TARGET_INDEX, width, true, "missing").await;

    let target = harness.test_node(TARGET_INDEX).expect("target");
    let target_storage = target
        .ant_protocol
        .as_ref()
        .expect("target protocol")
        .storage();
    let target_engine = target.replication_engine.as_ref().expect("target engine");
    let holder = harness.test_node(HOLDER_INDEX).expect("holder");
    let holder_peer = *holder.p2p_node.as_ref().expect("holder p2p").peer_id();
    let holder_storage = holder
        .ant_protocol
        .as_ref()
        .expect("holder protocol")
        .storage();

    holder_storage
        .put(&held_key, &held_content)
        .await
        .expect("host held key");
    holder_storage
        .put(&missing_key, &missing_content)
        .await
        .expect("host control key");
    target_storage
        .put(&held_key, &held_content)
        .await
        .expect("target already holds the key");

    let served_before = holder_storage.stats().chunks_retrieved;
    assert!(
        target_engine
            .enqueue_fetch_for_test(held_key, vec![holder_peer])
            .await,
        "held-key candidate must enqueue"
    );
    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while target_engine
        .fetch_pipeline_contains_for_test(&held_key)
        .await
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a candidate for an already-held key must leave the fetch pipeline"
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let held_serves = holder_storage.stats().chunks_retrieved - served_before;

    // Positive control: same seam, same holder, a key the target genuinely
    // lacks. Without this the assertion above could pass on a broken pipeline.
    let served_before = holder_storage.stats().chunks_retrieved;
    assert!(
        target_engine
            .enqueue_fetch_for_test(missing_key, vec![holder_peer])
            .await,
        "control candidate must enqueue"
    );
    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while !target_storage.exists(&missing_key).unwrap_or(false) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "REGRESSION: a key the target does not hold was not fetched — the \
             possession recheck must not decline genuine work"
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    let control_serves = holder_storage.stats().chunks_retrieved - served_before;

    println!("POSSESSION-RESULT held_serves={held_serves} control_serves={control_serves}");

    assert_eq!(
        held_serves, 0,
        "the target pulled {held_serves} chunk(s) for a key it already had"
    );
    assert!(
        control_serves >= 1,
        "the holder served nothing for a key the target lacks, so the \
         zero-serve assertion above proves nothing"
    );

    harness.teardown().await.expect("teardown");
}
