//! Opt-in measurement, not a pass/fail gate: how long one node takes to fetch
//! a batch of chunks whose holders it over-asks, and what that costs the
//! holders in the requester's trust table.
//!
//! The requester fetches every chunk with the same three holders in the same
//! order, so its fetch worker, one slot per hardware thread, sends more than a
//! holder's two-request share to the first holder at once. That is the
//! over-share the busy reply answers. The file uses only test hooks that exist
//! on `main` too, so the same file measures a build without the busy reply and
//! a build with it.
//!
//! A second measurement, [`fetch_busy_ab_pool`], has every requester stay
//! within its share, as #252 makes them, and fills the first holder's
//! twelve-slot pool instead: the refusals that remain after #252.
//!
//! Run with `ANT_FETCH_BUSY_AB=1 cargo test --test e2e --features test-utils
//! fetch_busy_ab -- --nocapture --test-threads=1`. Without the variable both
//! return at once. The pool measurement uses the test-only fetch serve gate,
//! which a build without the busy reply needs patched in to compare.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::TestNetworkConfig;
use super::TestHarness;
use ant_node::client::compute_address;
use ant_node::ReplicationConfig;
use serial_test::serial;
use std::time::{Duration, Instant};

const REQUESTER_INDEX: usize = 4;
const HOLDER_INDICES: [usize; 3] = [1, 2, 3];
const CHUNKS: usize = 48;
const CHUNK_LEN: usize = 256 * 1024;
const FILL_DEADLINE: Duration = Duration::from_mins(15);
const POLL: Duration = Duration::from_millis(100);

#[tokio::test]
#[serial]
async fn fetch_busy_ab() {
    if std::env::var("ANT_FETCH_BUSY_AB").is_err() {
        return;
    }
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let holders: Vec<_> = HOLDER_INDICES
        .iter()
        .map(|&i| {
            *harness
                .test_node(i)
                .and_then(|n| n.p2p_node.as_ref())
                .expect("holder p2p")
                .peer_id()
        })
        .collect();

    let mut keys = Vec::with_capacity(CHUNKS);
    for c in 0..CHUNKS {
        let content: Vec<u8> = (0..CHUNK_LEN)
            .map(|i| u8::try_from((i * 31 + c * 7) % 251).unwrap())
            .collect();
        let key = compute_address(&content);
        for &h in &HOLDER_INDICES {
            harness
                .test_node(h)
                .and_then(|n| n.ant_protocol.as_ref())
                .expect("holder protocol")
                .storage()
                .put(&key, &content)
                .await
                .expect("put");
        }
        keys.push(key);
    }

    let requester = harness.test_node(REQUESTER_INDEX).expect("requester");
    let p2p = requester.p2p_node.as_ref().expect("requester p2p");
    let engine = requester
        .replication_engine
        .as_ref()
        .expect("requester engine");
    let storage = requester
        .ant_protocol
        .as_ref()
        .expect("requester protocol")
        .storage();

    let trust_before: Vec<f64> = holders.iter().map(|h| p2p.peer_trust(h)).collect();
    let started = Instant::now();
    let mut enqueued = 0usize;
    for key in &keys {
        if engine.enqueue_fetch_for_test(*key, holders.clone()).await {
            enqueued += 1;
        }
    }

    let mut stored = 0usize;
    while started.elapsed() < FILL_DEADLINE {
        stored = 0;
        for key in &keys {
            if storage.exists(key).unwrap_or(false) {
                stored += 1;
            }
        }
        if stored == CHUNKS {
            break;
        }
        tokio::time::sleep(POLL).await;
    }
    let elapsed = started.elapsed();
    let trust_after: Vec<f64> = holders.iter().map(|h| p2p.peer_trust(h)).collect();

    println!(
        "FETCH_BUSY_AB slots={} chunks={CHUNKS} enqueued={enqueued} stored={stored} \
         elapsed_ms={} trust_before={trust_before:?} trust_after={trust_after:?}",
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
        elapsed.as_millis(),
    );

    harness.teardown().await.expect("teardown");
}

/// Nodes in the pool measurement's network.
const POOL_NODES: usize = 25;
/// A close group this wide makes every node responsible for every key, so
/// each requester stores what it fetches.
const POOL_CLOSE_GROUP: usize = 24;
/// The holders, in the source order every chunk uses.
const POOL_HOLDERS: [usize; 5] = [3, 4, 5, 6, 7];
/// Chunks per requester: its per-peer share, so it never over-asks a holder.
const POOL_KEYS_PER_REQUESTER: usize = 2;
const POOL_CHUNK_LEN: usize = 64 * 1024;
/// How long the first holder keeps its pool full, once it is full, before it
/// serves what it holds.
const POOL_GATE_HOLD: Duration = Duration::from_secs(2);
/// A holder's fetch admission pool: `FETCH_RESPONDER_MAX_OUTSTANDING`.
const POOL_SLOTS: usize = 12;
/// Bound on reaching the precondition before measuring.
const POOL_SETUP_DEADLINE: Duration = Duration::from_secs(60);

#[tokio::test]
#[serial]
async fn fetch_busy_ab_pool() {
    if std::env::var("ANT_FETCH_BUSY_AB").is_err() {
        return;
    }
    let config = TestNetworkConfig {
        node_count: POOL_NODES,
        replication_config: Some(ReplicationConfig {
            close_group_size: POOL_CLOSE_GROUP,
            ..ReplicationConfig::default()
        }),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config).await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let holders: Vec<_> = POOL_HOLDERS
        .iter()
        .map(|&i| {
            *harness
                .test_node(i)
                .and_then(|n| n.p2p_node.as_ref())
                .expect("holder p2p")
                .peer_id()
        })
        .collect();
    let requesters: Vec<usize> = (0..POOL_NODES)
        .filter(|i| !POOL_HOLDERS.contains(i))
        .collect();

    let mut keys_by_requester = Vec::with_capacity(requesters.len());
    for (r, _) in requesters.iter().enumerate() {
        let mut keys = Vec::with_capacity(POOL_KEYS_PER_REQUESTER);
        for k in 0..POOL_KEYS_PER_REQUESTER {
            let content: Vec<u8> = (0..POOL_CHUNK_LEN)
                .map(|i| u8::try_from((i * 13 + r * 101 + k * 7) % 251).unwrap())
                .collect();
            let key = compute_address(&content);
            for &h in &POOL_HOLDERS {
                harness
                    .test_node(h)
                    .and_then(|n| n.ant_protocol.as_ref())
                    .expect("holder protocol")
                    .storage()
                    .put(&key, &content)
                    .await
                    .expect("put");
            }
            keys.push(key);
        }
        keys_by_requester.push(keys);
    }

    let first_holder = POOL_HOLDERS
        .first()
        .and_then(|&i| harness.test_node(i))
        .and_then(|n| n.replication_engine.as_ref())
        .expect("first holder engine");
    first_holder.close_fetch_serve_gate_for_test();

    let trust_of = |i: usize| -> Vec<f64> {
        let p2p = harness
            .test_node(i)
            .and_then(|n| n.p2p_node.as_ref())
            .expect("requester p2p");
        holders.iter().map(|h| p2p.peer_trust(h)).collect()
    };
    let trust_before: Vec<Vec<f64>> = requesters.iter().map(|&i| trust_of(i)).collect();

    let total = requesters.len() * POOL_KEYS_PER_REQUESTER;
    let refusals_before = first_holder.fetch_pool_full_refusals_for_test();
    let started = Instant::now();
    let mut enqueued = 0usize;
    for (&i, keys) in requesters.iter().zip(&keys_by_requester) {
        let engine = harness
            .test_node(i)
            .and_then(|n| n.replication_engine.as_ref())
            .expect("requester engine");
        for key in keys {
            if engine.enqueue_fetch_for_test(*key, holders.clone()).await {
                enqueued += 1;
            }
        }
    }
    assert_eq!(
        enqueued, total,
        "every key must be queued for the measurement"
    );

    // The measurement is only about a full pool: wait until the first holder
    // holds a whole pool's worth, keep it full, and require that it refused
    // the rest before letting it serve.
    let setup_deadline = Instant::now() + POOL_SETUP_DEADLINE;
    while first_holder.fetch_admitted_for_test() < POOL_SLOTS {
        assert!(
            Instant::now() < setup_deadline,
            "the first holder never filled its pool: {} admitted",
            first_holder.fetch_admitted_for_test()
        );
        tokio::time::sleep(POLL).await;
    }
    tokio::time::sleep(POOL_GATE_HOLD).await;
    let refused_while_full = first_holder
        .fetch_pool_full_refusals_for_test()
        .saturating_sub(refusals_before);
    assert!(
        refused_while_full > 0,
        "the first holder refused nothing for a full pool while it was full"
    );
    first_holder.open_fetch_serve_gate_for_test();
    let mut stored = 0usize;
    while started.elapsed() < FILL_DEADLINE {
        stored = 0;
        for (&i, keys) in requesters.iter().zip(&keys_by_requester) {
            let storage = harness
                .test_node(i)
                .and_then(|n| n.ant_protocol.as_ref())
                .expect("requester protocol")
                .storage();
            for key in keys {
                if storage.exists(key).unwrap_or(false) {
                    stored += 1;
                }
            }
        }
        if stored == total {
            break;
        }
        tokio::time::sleep(POLL).await;
    }
    let elapsed = started.elapsed();

    // Trust lost per holder, summed over requesters. Each connection-timeout
    // charge from a neutral 0.5 costs about 0.06.
    let trust_after: Vec<Vec<f64>> = requesters.iter().map(|&i| trust_of(i)).collect();
    let drops = |h: usize| {
        trust_before
            .iter()
            .zip(&trust_after)
            .filter_map(move |(b, a)| Some(b.get(h)? - a.get(h)?))
    };
    let lost: Vec<f64> = (0..holders.len())
        .map(|h| drops(h).map(|d| d.max(0.0)).sum())
        .collect();
    let charged: Vec<usize> = (0..holders.len())
        .map(|h| drops(h).filter(|d| *d > 0.0).count())
        .collect();

    println!(
        "FETCH_BUSY_AB_POOL requesters={} keys={total} enqueued={enqueued} stored={stored} \
         refused_while_full={refused_while_full} elapsed_ms={} \
         requesters_charging_each_holder={charged:?} trust_lost_per_holder={lost:?}",
        requesters.len(),
        elapsed.as_millis(),
    );

    harness.teardown().await.expect("teardown");
}
