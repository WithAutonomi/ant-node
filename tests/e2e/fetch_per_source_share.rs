//! A fetching node keeps no more of its fetches in flight to one answering
//! holder than that holder will admit from it.
//!
//! A fetch responder admits two outstanding requests per requesting peer and
//! refuses a third. Before busy replies it answered that third with nothing
//! at all, and it still does when it cannot send a busy reply, so a requester
//! that sends more than two at once to one holder can lose the rest to its own
//! fetch timeout. The fetch
//! worker used to do exactly that: it ran one fetch per slot and sent every one
//! to the first verified holder of its key, so a node whose queued keys shared
//! one holder had all of them outstanding there at once.
//!
//! The observation is made on the requester, which is what the scheduler
//! governs, and made deterministic by holding the holder's work in place: the
//! holder's test-only serve gate holds every fetch request it admits before
//! serving it, so whatever the requester sends stays outstanding for as long as
//! the test looks at it, however fast the host serves a chunk. Every node runs
//! eight fetch slots, more than one holder's share on any host. With the
//! per-source limit removed the requester holds all eight in flight to the one
//! holder and this test fails. Both hooks are per engine, so no other node or
//! test is affected.
//!
//! The limit is a share of a holder that answers. A holder whose requests go
//! unanswered has no share to keep within, and keeping its keys at two per
//! fetch timeout would drain them four times more slowly than before the limit.
//! The second test closes the holder's gate for good, with a short fetch
//! timeout, and checks that once the first requests time out the requester
//! sends past the share and the keys leave its fetch pipeline in a bounded time.
//!
//! Both tests tear the network down with the holder's gate still closed and
//! requests held at it, which the holder's engine shutdown must release.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::TestNetworkConfig;
use super::verify_storage_gate::find_key_for_target;
use super::TestHarness;
use ant_node::client::XorName;
use ant_node::replication::config::storage_admission_width;
use ant_node::{ReplicationConfig, ReplicationEngine};
use saorsa_core::identity::PeerId;
use serial_test::serial;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::time::Instant as TokioInstant;

/// Above `storage_admission_width` (9), so the network has a real close group.
const NODE_COUNT: usize = 12;
/// Production close-group size.
const CLOSE_GROUP_SIZE: usize = 7;
/// Node whose fetch worker is observed.
const REQUESTER_INDEX: usize = 5;
/// The one node hosting every chunk.
const HOLDER_INDEX: usize = 6;
/// More keys than fetch slots, all held by the one holder.
const KEY_COUNT: usize = 12;
/// Fetch slots per node, above the per-source share on every host.
const FETCH_CONCURRENCY: usize = 8;
/// The responder's per-peer fetch share.
const PER_SOURCE_SHARE: usize = 2;
/// How long the requester's fetch pipeline must stay empty before the test
/// starts, so earlier traffic cannot occupy its slots.
const QUIET_FOR: Duration = Duration::from_secs(1);
/// Upper bound on waiting for that quiet period.
const QUIET_DEADLINE: Duration = Duration::from_secs(30);
/// How long the requester is observed with the gate closed. Far below the 30 s
/// fetch timeout, so no held request times out and frees its slot early.
const OBSERVATION_WINDOW: Duration = Duration::from_secs(3);
const OBSERVATION_POLL: Duration = Duration::from_millis(50);
/// The silent-holder test's fetch timeout, short so silence is seen in seconds.
const SILENT_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Keys held only by the silent holder: two fetch slots' worth.
const SILENT_KEY_COUNT: usize = 16;
/// The longest the silent holder's keys may take to leave the requester's
/// fetch pipeline: four fetch timeouts. This scheduler takes three, one more
/// than fetching as before the limit, to see the silence; keeping the holder
/// at its share would take eight (sixteen keys, two per timeout). The exact
/// three waves are checked without timing in the scheduler's unit tests.
const SILENT_DRAIN_LIMIT: Duration = Duration::from_secs(20);
/// The longest tearing the network down may take with requests still held at
/// the holder's closed serve gate. Without the release at engine shutdown it
/// waits for them for ever.
const TEARDOWN_LIMIT: Duration = Duration::from_secs(120);

#[tokio::test]
#[serial]
async fn requester_keeps_at_most_its_share_in_flight_to_one_holder() {
    let max_in_flight = max_in_flight_to_one_holder().await;
    assert!(
        max_in_flight <= PER_SOURCE_SHARE,
        "the requester had {max_in_flight} fetches outstanding at one holder, which \
         admits {PER_SOURCE_SHARE} from it and answers the rest with nothing"
    );
    assert_eq!(
        max_in_flight, PER_SOURCE_SHARE,
        "the requester never filled the holder's share, so the run says nothing \
         about the limit: the worker did not dispatch"
    );
}

#[tokio::test]
#[serial]
async fn a_holder_that_stops_answering_is_fetched_from_past_its_share() {
    let harness = start_network(SILENT_FETCH_TIMEOUT).await;
    let chunks = chunks_for_requester(&harness, "silent-holder", SILENT_KEY_COUNT).await;
    let keys: HashSet<XorName> = chunks.iter().map(|(_, key)| *key).collect();

    let requester = harness.test_node(REQUESTER_INDEX).expect("requester");
    let requester_engine = requester
        .replication_engine
        .as_ref()
        .expect("requester engine");
    let holder = harness.test_node(HOLDER_INDEX).expect("holder");
    let holder_peer = *holder.p2p_node.as_ref().expect("holder p2p").peer_id();
    let holder_engine = holder.replication_engine.as_ref().expect("holder engine");

    wait_until_fetch_pipeline_is_quiet(requester_engine).await;

    // The holder answers none of these fetches, ever: it holds the ones it
    // admits, and refuses the rest without even a busy reply.
    holder_engine.close_fetch_serve_gate_for_test();
    holder_engine.turn_off_fetch_busy_replies_for_test();
    let started = Instant::now();
    for key in &keys {
        assert!(
            requester_engine
                .enqueue_fetch_for_test(*key, vec![holder_peer])
                .await,
            "every key must be queued for the silent holder alone"
        );
    }

    let mut max_in_flight_to_holder = 0;
    let drained_after = loop {
        let snapshot = requester_engine.fetch_pipeline_snapshot_for_test().await;
        let in_flight_to_holder = snapshot
            .in_flight
            .iter()
            .filter(|(key, source)| keys.contains(key) && *source == holder_peer)
            .count();
        max_in_flight_to_holder = max_in_flight_to_holder.max(in_flight_to_holder);
        let pending = snapshot
            .queued
            .iter()
            .chain(snapshot.in_flight.iter().map(|(key, _)| key))
            .filter(|key| keys.contains(*key))
            .count();
        if pending == 0 {
            break started.elapsed();
        }
        assert!(
            started.elapsed() < SILENT_DRAIN_LIMIT,
            "{pending} of {SILENT_KEY_COUNT} keys held only by a silent holder were still \
             in the fetch pipeline after {SILENT_DRAIN_LIMIT:?}"
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    };
    println!(
        "SILENT-HOLDER-RESULT drained_after={drained_after:?} \
         max_in_flight_to_holder={max_in_flight_to_holder} timeout={SILENT_FETCH_TIMEOUT:?}"
    );

    teardown_with_the_gate_closed(harness).await;
    assert!(
        drained_after < SILENT_DRAIN_LIMIT,
        "the silent holder's keys took {drained_after:?} to leave the fetch pipeline"
    );
    assert!(
        max_in_flight_to_holder > PER_SOURCE_SHARE,
        "the requester kept a holder that answers nothing at its share of \
         {PER_SOURCE_SHARE}, which drains that holder's keys at two per timeout"
    );
}

/// Build the network with `fetch_request_timeout` and warm its DHT.
async fn start_network(fetch_request_timeout: Duration) -> TestHarness {
    let config = TestNetworkConfig {
        node_count: NODE_COUNT,
        replication_config: Some(ReplicationConfig {
            close_group_size: CLOSE_GROUP_SIZE,
            fetch_request_timeout,
            ..ReplicationConfig::default()
        }),
        fetch_concurrency: Some(FETCH_CONCURRENCY),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("setup per-source share network");
    harness.warmup_dht().await.expect("warmup");
    harness
}

/// `count` distinct chunks the requester is responsible for storing.
async fn chunks_for_requester(
    harness: &TestHarness,
    label: &str,
    count: usize,
) -> Vec<(Vec<u8>, XorName)> {
    let width = storage_admission_width(CLOSE_GROUP_SIZE);
    let mut chunks = Vec::with_capacity(count);
    for index in 0..count {
        let label = format!("{label}-{index}");
        chunks.push(find_key_for_target(harness, REQUESTER_INDEX, width, true, &label).await);
    }
    let keys: HashSet<&XorName> = chunks.iter().map(|(_, key)| key).collect();
    assert_eq!(keys.len(), count, "every key must be distinct");
    chunks
}

/// Build the network, direct twelve keys at one holder while that holder holds
/// what it admits, and return the most fetches the requester had in flight to
/// it.
async fn max_in_flight_to_one_holder() -> usize {
    let harness = start_network(ReplicationConfig::default().fetch_request_timeout).await;
    let chunks = chunks_for_requester(&harness, "per-source-share", KEY_COUNT).await;
    let keys: HashSet<XorName> = chunks.iter().map(|(_, key)| *key).collect();

    let requester = harness.test_node(REQUESTER_INDEX).expect("requester");
    let requester_engine = requester
        .replication_engine
        .as_ref()
        .expect("requester engine");
    let holder = harness.test_node(HOLDER_INDEX).expect("holder");
    let holder_peer = *holder.p2p_node.as_ref().expect("holder p2p").peer_id();
    let holder_engine = holder.replication_engine.as_ref().expect("holder engine");
    let holder_storage = holder
        .ant_protocol
        .as_ref()
        .expect("holder protocol")
        .storage();

    // Start from an idle requester, so its fetch slots are all free.
    wait_until_fetch_pipeline_is_quiet(requester_engine).await;

    // Hold every fetch the holder admits, then make the chunks available.
    holder_engine.close_fetch_serve_gate_for_test();
    for (content, key) in &chunks {
        holder_storage.put(key, content).await.expect("host chunk");
    }
    let before = requester_engine.fetch_pipeline_snapshot_for_test().await;
    let unrelated: Vec<XorName> = before
        .queued
        .iter()
        .chain(before.in_flight.iter().map(|(key, _)| key))
        .filter(|key| !keys.contains(*key))
        .copied()
        .collect();
    assert!(
        unrelated.is_empty(),
        "unrelated fetch work could occupy the requester's slots: {unrelated:?}"
    );
    for key in &keys {
        // A replica hint may already have queued the key; either way it is
        // headed to the one holder.
        let _ = requester_engine
            .enqueue_fetch_for_test(*key, vec![holder_peer])
            .await;
    }

    let max_in_flight_to_holder =
        observe_max_in_flight_to(requester_engine, &keys, &holder_peer).await;
    println!(
        "PER-SOURCE-SHARE-RESULT max_in_flight_to_holder={max_in_flight_to_holder} \
         concurrency={FETCH_CONCURRENCY} keys={KEY_COUNT}"
    );

    teardown_with_the_gate_closed(harness).await;
    max_in_flight_to_holder
}

/// Tear the network down while the holder's serve gate is still closed.
async fn teardown_with_the_gate_closed(harness: TestHarness) {
    let torn_down = tokio::time::timeout(TEARDOWN_LIMIT, harness.teardown()).await;
    assert!(
        matches!(torn_down, Ok(Ok(()))),
        "teardown with requests held at a closed serve gate did not finish within \
         {TEARDOWN_LIMIT:?}: {torn_down:?}"
    );
}

/// Wait until `engine` has nothing queued or in flight for fetch, continuously
/// for [`QUIET_FOR`].
async fn wait_until_fetch_pipeline_is_quiet(engine: &ReplicationEngine) {
    let deadline = TokioInstant::now() + QUIET_DEADLINE;
    let mut quiet_since = TokioInstant::now();
    loop {
        let snapshot = engine.fetch_pipeline_snapshot_for_test().await;
        let now = TokioInstant::now();
        if !snapshot.queued.is_empty() || !snapshot.in_flight.is_empty() {
            quiet_since = now;
        } else if now.duration_since(quiet_since) >= QUIET_FOR {
            return;
        }
        assert!(
            now < deadline,
            "the requester's fetch pipeline never went quiet: {snapshot:?}"
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
}

/// The most of `keys` that `engine` had in flight to `holder` at once over
/// [`OBSERVATION_WINDOW`], failing if any other fetch work appears.
async fn observe_max_in_flight_to(
    engine: &ReplicationEngine,
    keys: &HashSet<XorName>,
    holder: &PeerId,
) -> usize {
    let deadline = TokioInstant::now() + OBSERVATION_WINDOW;
    let mut max_in_flight = 0;
    while TokioInstant::now() < deadline {
        let snapshot = engine.fetch_pipeline_snapshot_for_test().await;
        let unrelated: Vec<&XorName> = snapshot
            .queued
            .iter()
            .chain(snapshot.in_flight.iter().map(|(key, _)| key))
            .filter(|key| !keys.contains(*key))
            .collect();
        assert!(
            unrelated.is_empty(),
            "unrelated fetch work appeared during the observation: {unrelated:?}"
        );
        let to_holder = snapshot
            .in_flight
            .iter()
            .filter(|(key, source)| keys.contains(key) && source == holder)
            .count();
        max_in_flight = max_in_flight.max(to_holder);
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    max_in_flight
}
