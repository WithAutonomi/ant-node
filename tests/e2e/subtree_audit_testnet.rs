//! Local-testnet end-to-end tests for the gossip-triggered contiguous-subtree
//! storage audit (ADR-0002).
//!
//! These spin a real multi-node testnet and drive the SHIPPED audit over the
//! live wire (real `handle_subtree_challenge` responder + `run_subtree_audit`
//! auditor + real LMDB storage), via the test-only `audit_peer_now` /
//! `rebuild_commitment_now` engine hooks. They prove the two outcomes that
//! matter for a testnet:
//!
//!   1. HONEST: an honest node that holds its committed data passes the audit
//!      (no false-positive eviction).
//!   2. ADVERSARY: a node that deletes the bytes it committed to fails the audit
//!      (a confirmed failure that, once eviction is re-enabled, evicts it) while
//!      honest nodes are unaffected.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::TestHarness;
use ant_node::replication::audit::AuditTickResult;
use serial_test::serial;

/// Store the same `n` chunks on both `a` (the audited holder) and `b` (the
/// auditor — NOT because verification needs them: round 2 demands the bytes
/// from `a` itself, so `b` could hold nothing; storing them just makes `b` a
/// realistic co-holder of the keyspace), make `a` commit to them,
/// then deterministically seed `b`'s cache with `a`'s commitment (simulating
/// "b received a's gossip" without depending on neighbor-sync timing — that
/// propagation is covered by the dedicated neighbor-sync tests). After this,
/// `b.audit_peer_now(a)` pins `a`'s real commitment and runs the audit over the
/// live wire against `a`'s real responder.
async fn commit_and_seed(
    harness: &TestHarness,
    a_idx: usize,
    b_idx: usize,
    n: usize,
) -> Vec<[u8; 32]> {
    let a = harness.test_node(a_idx).expect("node a");
    let b = harness.test_node(b_idx).expect("node b");
    let a_store = a.ant_protocol.as_ref().expect("a protocol").storage();
    let b_store = b.ant_protocol.as_ref().expect("b protocol").storage();

    // Store identical chunks on A and B. Content-addressed: addr == BLAKE3(bytes).
    let mut addrs = Vec::with_capacity(n);
    for i in 0..n {
        let content = format!("subtree-audit-testnet-chunk-{i}").into_bytes();
        let address = *blake3::hash(&content).as_bytes();
        a_store.put(&address, &content).await.expect("put on a");
        b_store.put(&address, &content).await.expect("put on b");
        addrs.push(address);
    }

    // A commits to its current key set.
    let a_engine = a.replication_engine.as_ref().expect("a engine");
    a_engine
        .rebuild_commitment_now()
        .await
        .expect("a rebuild commitment");

    // Grab A's freshly built commitment and seed it into B's cache so B can pin
    // it (deterministic; no gossip-timing flake).
    let a_peer = *a.p2p_node.as_ref().expect("a p2p").peer_id();
    let a_commitment = a_engine
        .commitment_state()
        .current()
        .expect("a has a current commitment")
        .commitment()
        .clone();
    let b_engine = b.replication_engine.as_ref().expect("b engine");
    b_engine
        .inject_peer_commitment_for_test(&a_peer, a_commitment)
        .await;
    addrs
}

/// HONEST: a node holding its committed data passes the subtree audit.
#[tokio::test]
#[serial]
async fn honest_node_passes_subtree_audit() {
    let harness = TestHarness::setup_small().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (a_idx, b_idx) = (3, 4);
    commit_and_seed(&harness, a_idx, b_idx, 64).await;

    let a_peer = *harness
        .test_node(a_idx)
        .expect("a")
        .p2p_node
        .as_ref()
        .expect("a p2p")
        .peer_id();
    let b_engine = harness
        .test_node(b_idx)
        .expect("b")
        .replication_engine
        .as_ref()
        .expect("b engine");

    // Honest holder: B holds the chunks so it byte-verifies the proof → Passed.
    let result = b_engine.audit_peer_now(&a_peer).await;
    assert!(
        matches!(result, AuditTickResult::Passed { keys_checked, .. } if keys_checked >= 1),
        "honest node must pass with at least one byte-verified leaf, got {result:?}"
    );

    harness.teardown().await.expect("teardown");
}

/// ADVERSARY: a node that deletes the bytes it committed to FAILS the audit,
/// while honest peers are unaffected.
#[tokio::test]
#[serial]
async fn data_deleting_node_fails_subtree_audit() {
    let harness = TestHarness::setup_small().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (a_idx, b_idx) = (5, 6);
    let addrs = commit_and_seed(&harness, a_idx, b_idx, 64).await;

    // A is now committed-and-gossiped. The adversary deletes ALL the bytes it
    // committed to (keeps the gossiped commitment — the classic "claim storage,
    // hold nothing" attack). It does NOT rebuild its commitment, so it still
    // advertises the now-unbacked root.
    let a_store = harness
        .test_node(a_idx)
        .expect("a")
        .ant_protocol
        .as_ref()
        .expect("a protocol")
        .storage();
    for addr in &addrs {
        a_store.delete(addr).await.expect("delete on adversary");
    }

    let a_peer = *harness
        .test_node(a_idx)
        .expect("a")
        .p2p_node
        .as_ref()
        .expect("a p2p")
        .peer_id();
    let b_engine = harness
        .test_node(b_idx)
        .expect("b")
        .replication_engine
        .as_ref()
        .expect("b engine");

    let result = b_engine.audit_peer_now(&a_peer).await;
    // The adversary can no longer produce the subtree's bytes, so its responder
    // rejects ("missing bytes for committed key") → a confirmed Failed. (It must
    // NOT be Passed; Idle would mean B couldn't reach the audit, also a failure
    // of the test setup.)
    assert!(
        matches!(result, AuditTickResult::Failed { .. }),
        "a node that deleted its committed data must FAIL the audit, got {result:?}"
    );

    harness.teardown().await.expect("teardown");
}

/// NO FALSE POSITIVE: auditing an honest node repeatedly (different nonces)
/// never produces a confirmed failure.
#[tokio::test]
#[serial]
async fn honest_node_never_false_fails_across_repeated_audits() {
    let harness = TestHarness::setup_small().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let (a_idx, b_idx) = (7, 8);
    commit_and_seed(&harness, a_idx, b_idx, 100).await;

    let a_peer = *harness
        .test_node(a_idx)
        .expect("a")
        .p2p_node
        .as_ref()
        .expect("a p2p")
        .peer_id();
    let b_engine = harness
        .test_node(b_idx)
        .expect("b")
        .replication_engine
        .as_ref()
        .expect("b engine");

    // Each audit uses a fresh random nonce (different selected subtree). None may
    // ever be a confirmed Failed for an honest holder.
    for round in 0..8 {
        let result = b_engine.audit_peer_now(&a_peer).await;
        assert!(
            !matches!(result, AuditTickResult::Failed { .. }),
            "honest node false-failed on round {round}: {result:?}"
        );
    }

    harness.teardown().await.expect("teardown");
}
