//! A fetch responder answers `Busy` to a refused request that asked for it,
//! stays silent to one that did not, and a requester takes a busy answer
//! without charging the holder, until the holder has answered busy past its
//! neutral allowance without serving.
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
use ant_node::replication::config::{FETCH_REQUEST_TIMEOUT, REPLICATION_PROTOCOL_ID};
use ant_node::replication::fetch_busy::{
    FETCH_BUSY_NEUTRAL_ALLOWANCE, FETCH_BUSY_WAIT_MAX, FETCH_BUSY_WAIT_MIN,
};
use ant_node::replication::protocol::{
    FetchRequest, FetchResponse, ReplicationMessage, ReplicationMessageBody,
};
use futures::stream::{FuturesUnordered, StreamExt};
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use serial_test::serial;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// Just over the holder's per-peer busy reply interval of one a second, so
/// each of the requester's refused fetches is answered busy, not silently.
const BUSY_REPLY_SPACING: Duration = Duration::from_millis(1_100);

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
    static NEXT: AtomicU64 = AtomicU64::new(9_000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

struct Setup {
    harness: TestHarness,
    key: [u8; 32],
    holder: PeerId,
}

/// A network whose holder has its fetch serve gate closed, and the holder.
async fn gated_holder() -> (TestHarness, PeerId) {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");
    let holder_node = harness.test_node(HOLDER_INDEX).expect("holder");
    let holder = *holder_node.p2p_node.as_ref().expect("holder p2p").peer_id();
    holder_node
        .replication_engine
        .as_ref()
        .expect("holder engine")
        .close_fetch_serve_gate_for_test();
    (harness, holder)
}

/// Put a chunk made from `seed` straight into the holder's store.
async fn put_on_holder(harness: &TestHarness, seed: usize) -> [u8; 32] {
    let content: Vec<u8> = (0..CHUNK_LEN)
        .map(|i| u8::try_from((i + seed * 7) % 251).unwrap())
        .collect();
    let key = compute_address(&content);
    harness
        .test_node(HOLDER_INDEX)
        .and_then(|n| n.ant_protocol.as_ref())
        .expect("holder protocol")
        .storage()
        .put(&key, &content)
        .await
        .expect("put");
    key
}

async fn setup() -> Setup {
    let (harness, holder) = gated_holder().await;
    let key = put_on_holder(&harness, 0).await;
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

/// A holder that keeps answering busy, across many keys and without serving,
/// costs it nothing at the requester's fetch worker for
/// `FETCH_BUSY_NEUTRAL_ALLOWANCE` answers in a row. The next is charged, as its
/// silence would have been, once that attempt's fetch timeout has run out.
/// Serving the requester once then clears what the holder owes.
///
/// The holder stores nothing until the end. A chunk put straight into its
/// store has no payment behind it, so once replication starts, about a minute
/// in, the holder's replica hint for it is rejected and charged, and this test
/// runs longer than that.
#[tokio::test]
#[serial]
async fn a_holder_that_keeps_answering_busy_is_charged_past_its_allowance() {
    let (harness, holder) = gated_holder().await;
    let requester_node = harness.test_node(REQUESTER_INDEX).expect("requester");
    let requester = requester_node.p2p_node.as_ref().expect("requester p2p");
    let engine = requester_node
        .replication_engine
        .as_ref()
        .expect("requester engine");
    let trust_before = requester.peer_trust(&holder);

    // Fill this requester's share at the holder, so the holder refuses every
    // fetch the worker sends it. Each attempt below runs to its end before the
    // next starts, so the held requests must outlast all of them: a timeout
    // would charge the holder. They are never answered. The gate stays closed
    // for longer than the holder's fetch timeout, so once it opens the holder
    // sheds them as stale.
    let held_key = compute_address(b"held");
    let held_timeout = (BUSY_REPLY_SPACING + FETCH_BUSY_WAIT_MAX + PROMPTLY)
        * (FETCH_BUSY_NEUTRAL_ALLOWANCE + 1)
        + FETCH_REQUEST_TIMEOUT;
    let mut held: FuturesUnordered<_> = (0..=SHARE)
        .map(|_| fetch(requester, &holder, held_key, true, held_timeout))
        .collect();
    let first = tokio::time::timeout(PROMPTLY, held.next())
        .await
        .expect("the refused request is answered promptly")
        .expect("a request");
    assert_eq!(first, Answer::Busy);

    // Busy answers from the worker, each for a new key, until the holder has
    // used up its allowance: the allowance belongs to the holder, not to a key.
    // Each attempt runs to its end before the next key is queued, so any
    // charge would come from the attempt just made.
    let mut next_key = 0u32;
    let mut lowest_trust = trust_before;
    loop {
        let owed = engine.fetch_source_unserved_busy_for_test(&holder);
        if owed >= FETCH_BUSY_NEUTRAL_ALLOWANCE {
            break;
        }
        tokio::time::sleep(BUSY_REPLY_SPACING).await;
        let other_key = compute_address(&next_key.to_le_bytes());
        next_key += 1;
        assert!(engine.enqueue_fetch_for_test(other_key, vec![holder]).await);
        let deadline = Instant::now() + FETCH_REQUEST_TIMEOUT + PROMPTLY;
        while engine.fetch_queued_or_in_flight_for_test(&other_key).await {
            lowest_trust = lowest_trust.min(requester.peer_trust(&holder));
            assert!(
                Instant::now() < deadline,
                "the attempt after {owed} busy answers never ended"
            );
            tokio::time::sleep(POLL).await;
        }
        lowest_trust = lowest_trust.min(requester.peer_trust(&holder));
        assert!(
            engine.fetch_source_unserved_busy_for_test(&holder) > owed,
            "the attempt after {owed} busy answers was not answered busy"
        );
        assert!(
            lowest_trust >= trust_before,
            "a busy answer within the allowance cost the holder trust: \
             {trust_before} fell to {lowest_trust}"
        );
    }
    assert_eq!(
        engine.fetch_source_unserved_busy_for_test(&holder),
        FETCH_BUSY_NEUTRAL_ALLOWANCE
    );

    // The next answer is past the allowance. Its attempt holds its slot until
    // its fetch timeout runs out, costing nothing meanwhile, and the holder is
    // charged only as it ends.
    tokio::time::sleep(BUSY_REPLY_SPACING).await;
    let last_key = compute_address(&next_key.to_le_bytes());
    assert!(engine.enqueue_fetch_for_test(last_key, vec![holder]).await);
    let deadline = Instant::now() + PROMPTLY;
    while engine.fetch_source_unserved_busy_for_test(&holder) <= FETCH_BUSY_NEUTRAL_ALLOWANCE {
        assert!(
            Instant::now() < deadline,
            "the answer past the allowance never came"
        );
        tokio::time::sleep(POLL).await;
    }
    let answered_at = Instant::now();
    // The answer was seen within `PROMPTLY` of the request, so the attempt
    // holds its slot, uncharged, for at least the rest: still well past any
    // busy wait.
    let not_before = FETCH_REQUEST_TIMEOUT.saturating_sub(PROMPTLY);
    let deadline = answered_at + FETCH_REQUEST_TIMEOUT + PROMPTLY;
    while engine.fetch_queued_or_in_flight_for_test(&last_key).await {
        if answered_at.elapsed() < not_before {
            lowest_trust = lowest_trust.min(requester.peer_trust(&holder));
        }
        assert!(
            Instant::now() < deadline,
            "the attempt past the allowance never ended"
        );
        tokio::time::sleep(POLL).await;
    }
    let attempt_lasted = answered_at.elapsed();
    assert!(
        attempt_lasted >= not_before,
        "the attempt past the allowance ended {attempt_lasted:?} after its answer, \
         before its fetch timeout"
    );
    assert!(
        lowest_trust >= trust_before,
        "the answer past the allowance was charged before its attempt ended: \
         {trust_before} fell to {lowest_trust}"
    );
    let trust_after = requester.peer_trust(&holder);
    assert!(
        trust_after < trust_before,
        "the answer past the allowance was not charged: trust stayed {trust_after}"
    );
    drop(held);

    // Serving once clears what the holder owes. The chunk is new, so the
    // requester cannot already hold it, and it is fetched only after the
    // holder has shed the held requests and so has room for it.
    let fresh_key = put_on_holder(&harness, 1).await;
    open_gate(&harness);
    let holder_engine = harness
        .test_node(HOLDER_INDEX)
        .and_then(|n| n.replication_engine.as_ref())
        .expect("holder engine");
    let deadline = Instant::now() + PROMPTLY;
    while holder_engine.fetch_admitted_for_test() > 0 {
        assert!(
            Instant::now() < deadline,
            "the holder never let go of the held requests"
        );
        tokio::time::sleep(POLL).await;
    }
    assert!(engine.enqueue_fetch_for_test(fresh_key, vec![holder]).await);
    let deadline = Instant::now() + PROMPTLY;
    while engine.fetch_source_unserved_busy_for_test(&holder) > 0 {
        assert!(
            Instant::now() < deadline,
            "serving the requester did not clear what the holder owes"
        );
        tokio::time::sleep(POLL).await;
    }

    harness.teardown().await.expect("teardown");
}
