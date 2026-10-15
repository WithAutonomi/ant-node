//! A fetch responder answers `Busy` to a refused request that asked for it,
//! stays silent to one that did not, and a requester takes a busy answer
//! without charging the holder.
//!
//! The unit tests pin the wire format, the limiter, the wait and the queue
//! transitions. What they cannot show is the whole path between two real
//! nodes: the capability trailer surviving the transport, admission refusing
//! past the per-peer share, the reply riding the request/response channel
//! back, and the requester's fetch worker acting on it.
//!
//! The holder's fetch serve gate makes every case deterministic. With the gate
//! closed, an admitted request is held before it is served, keeping its share,
//! so of three concurrent requests from one peer exactly two are admitted and
//! exactly one is refused, whatever order they arrive in.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::TestHarness;
use ant_node::client::compute_address;
use ant_node::replication::config::REPLICATION_PROTOCOL_ID;
use ant_node::replication::fetch_busy::{FETCH_BUSY_WAIT_MAX, FETCH_BUSY_WAIT_MIN};
use ant_node::replication::protocol::{
    FetchRequest, FetchResponse, ReplicationMessage, ReplicationMessageBody,
};
use futures::stream::{FuturesUnordered, StreamExt};
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use serial_test::serial;
use std::time::{Duration, Instant};

const HOLDER_INDEX: usize = 3;
const REQUESTER_INDEX: usize = 4;
/// Requests admitted per requesting peer: the responder's per-peer share.
const SHARE: usize = 2;
/// Long enough that a held request is never timed out before the test opens
/// the gate; a timeout would charge the holder and spoil the trust checks.
const HELD_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a request that should be refused silently is given.
const SILENCE_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound on how long anything that must happen promptly may take.
const PROMPTLY: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(50);
const CHUNK_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Success,
    Busy,
    Silent,
    Other,
}

async fn fetch(
    sender: &P2PNode,
    holder: &PeerId,
    key: [u8; 32],
    busy_reply: bool,
    timeout: Duration,
) -> Answer {
    let msg = ReplicationMessage {
        request_id: rand_request_id(),
        body: ReplicationMessageBody::FetchRequest(FetchRequest { key, busy_reply }),
    };
    let Ok(response) = sender
        .send_request(
            holder,
            REPLICATION_PROTOCOL_ID,
            msg.encode().expect("encode"),
            timeout,
        )
        .await
    else {
        return Answer::Silent;
    };
    match ReplicationMessage::decode(&response.data).map(|m| m.body) {
        Ok(ReplicationMessageBody::FetchResponse(FetchResponse::Success { key: k, .. }))
            if k == key =>
        {
            Answer::Success
        }
        Ok(ReplicationMessageBody::FetchResponse(FetchResponse::Busy { key: k })) if k == key => {
            Answer::Busy
        }
        _ => Answer::Other,
    }
}

fn rand_request_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(9_000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

struct Setup {
    harness: TestHarness,
    key: [u8; 32],
    holder: PeerId,
}

async fn setup() -> Setup {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");
    let holder_node = harness.test_node(HOLDER_INDEX).expect("holder");
    let content: Vec<u8> = (0..CHUNK_LEN)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let key = compute_address(&content);
    holder_node
        .ant_protocol
        .as_ref()
        .expect("holder protocol")
        .storage()
        .put(&key, &content)
        .await
        .expect("put");
    let holder = *holder_node.p2p_node.as_ref().expect("holder p2p").peer_id();
    holder_node
        .replication_engine
        .as_ref()
        .expect("holder engine")
        .close_fetch_serve_gate_for_test();
    Setup {
        harness,
        key,
        holder,
    }
}

fn open_gate(harness: &TestHarness) {
    harness
        .test_node(HOLDER_INDEX)
        .and_then(|n| n.replication_engine.as_ref())
        .expect("holder engine")
        .open_fetch_serve_gate_for_test();
}

/// Of `SHARE + 1` concurrent requests that ask for busy replies, the one the
/// holder refuses is answered `Busy` at once, the held ones are served once
/// the gate opens, and a request that does not ask is refused silently. (The
/// per-peer and global busy allowances are pinned exactly by the limiter's
/// unit tests; over a real network their timing is not controllable.)
#[tokio::test]
#[serial]
async fn a_refused_fetch_is_answered_busy_only_when_it_asks() {
    let Setup {
        harness,
        key,
        holder,
    } = setup().await;
    let requester = harness
        .test_node(REQUESTER_INDEX)
        .and_then(|n| n.p2p_node.as_ref())
        .expect("requester p2p");

    let mut pending: FuturesUnordered<_> = (0..=SHARE)
        .map(|_| fetch(requester, &holder, key, true, HELD_TIMEOUT))
        .collect();
    let started = Instant::now();
    let first = tokio::time::timeout(PROMPTLY, pending.next())
        .await
        .expect("the refused request is answered promptly")
        .expect("a request");
    assert_eq!(first, Answer::Busy, "the refused request is told busy");
    assert!(started.elapsed() < PROMPTLY);

    // The share is still held, so a request that does not ask for busy
    // replies is refused, and silently, exactly as before busy replies.
    assert_eq!(
        fetch(requester, &holder, key, false, SILENCE_TIMEOUT).await,
        Answer::Silent
    );

    open_gate(&harness);
    let rest: Vec<Answer> = tokio::time::timeout(PROMPTLY, pending.collect())
        .await
        .expect("held requests are served once the gate opens");
    assert_eq!(rest, vec![Answer::Success; SHARE]);

    harness.teardown().await.expect("teardown");
}

/// The requester's own fetch worker, refused by a holder whose share is full,
/// gets a busy answer, puts that holder last for later fetches, waits before
/// giving the key up, and charges the holder nothing. Before busy replies the
/// same refusal was silent and cost the holder a connection-timeout trust
/// event at the requester.
#[tokio::test]
#[serial]
async fn the_requester_takes_a_busy_answer_without_charging_the_holder() {
    let Setup {
        harness,
        key,
        holder,
    } = setup().await;
    let requester_node = harness.test_node(REQUESTER_INDEX).expect("requester");
    let requester = requester_node.p2p_node.as_ref().expect("requester p2p");
    let engine = requester_node
        .replication_engine
        .as_ref()
        .expect("requester engine");
    let trust_before = requester.peer_trust(&holder);

    // Fill this requester's share at the holder: two held, one told busy.
    let mut held: FuturesUnordered<_> = (0..=SHARE)
        .map(|_| fetch(requester, &holder, key, true, HELD_TIMEOUT))
        .collect();
    let first = tokio::time::timeout(PROMPTLY, held.next())
        .await
        .expect("the refused request is answered promptly")
        .expect("a request");
    assert_eq!(first, Answer::Busy);
    assert!(!engine.fetch_source_cooling_for_test(&holder));

    // Trust is sampled throughout, so a charge cannot hide behind a later
    // unrelated success: any dip below the starting value fails.
    let mut lowest_trust = trust_before;
    let sample = |lowest: &mut f64| *lowest = lowest.min(requester.peer_trust(&holder));

    // The fetch worker's request is refused too, and told busy.
    assert!(engine.enqueue_fetch_for_test(key, vec![holder]).await);
    let deadline = Instant::now() + PROMPTLY;
    while !engine.fetch_source_cooling_for_test(&holder) {
        assert!(
            Instant::now() < deadline,
            "the fetch worker never recorded the busy answer"
        );
        sample(&mut lowest_trust);
        tokio::time::sleep(POLL).await;
    }

    // The attempt holds its slot through the busy wait, then gives the key up
    // (its only source refused), exactly as a timeout would have, sooner. The
    // wait is timed from when the busy answer was recorded, just before it
    // starts, to when this fetch attempt is first seen gone, watched with the
    // gate still closed so nothing else delays the observation.
    let busy_at = engine
        .fetch_source_last_busy_for_test(&holder)
        .expect("the busy answer was recorded");
    let deadline = Instant::now() + FETCH_BUSY_WAIT_MAX + PROMPTLY;
    while engine.fetch_queued_or_in_flight_for_test(&key).await {
        assert!(
            Instant::now() < deadline,
            "the fetch attempt outlived its busy wait"
        );
        sample(&mut lowest_trust);
        tokio::time::sleep(POLL).await;
    }
    let attempt_lasted = busy_at.elapsed();
    assert!(
        attempt_lasted >= FETCH_BUSY_WAIT_MIN,
        "the key was given up {attempt_lasted:?} after the busy answer, before the busy wait"
    );

    open_gate(&harness);
    let rest: Vec<Answer> = tokio::time::timeout(PROMPTLY, held.collect())
        .await
        .expect("held requests are served once the gate opens");
    assert_eq!(rest, vec![Answer::Success; SHARE]);
    sample(&mut lowest_trust);
    assert!(
        lowest_trust >= trust_before,
        "a busy answer must not cost the holder trust: {trust_before} fell to {lowest_trust}"
    );

    harness.teardown().await.expect("teardown");
}
