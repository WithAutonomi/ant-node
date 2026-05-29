//! Live responder-handler integration tests for the v12 storage-bound
//! audit (`notes/security-findings-2026-05-22/proposal-gossip-audit-v12.md`).
//!
//! The pure-verifier gates are covered by `poc_commitment_audit_attacks`
//! and the unit tests in `commitment_audit.rs` / `commitment_state.rs`.
//! This file fills the gap flagged in the prod-readiness review: the
//! *live* responder control-flow branches in
//! `audit::handle_audit_challenge_with_commitment` — the function the
//! network actually calls — were not exercised end-to-end. These tests
//! drive that real entry point against a real `LmdbStorage` + a real
//! `ResponderCommitmentState` and assert on the exact `AuditResponse`
//! variant produced.
//!
//! Each test is written to FAIL if the defence it covers is removed —
//! see the `// FLIPS IF:` note on each. They are not tautologies: the
//! responder is the production code path, not a reimplementation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use ant_node::replication::audit::{
    handle_audit_challenge, handle_audit_challenge_with_commitment,
};
use ant_node::replication::commitment::commitment_hash;
use ant_node::replication::commitment_state::{BuiltCommitment, ResponderCommitmentState};
use ant_node::replication::protocol::{AuditChallenge, AuditResponse};
use ant_node::storage::{LmdbStorage, LmdbStorageConfig};
use saorsa_core::identity::PeerId;
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn test_storage() -> (LmdbStorage, TempDir) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let config = LmdbStorageConfig {
        root_dir: temp_dir.path().to_path_buf(),
        ..LmdbStorageConfig::test_default()
    };
    let storage = LmdbStorage::new(config).await.expect("create storage");
    (storage, temp_dir)
}

fn keypair() -> (MlDsaPublicKey, MlDsaSecretKey) {
    ml_dsa_65().generate_keypair().unwrap()
}

/// Deterministic chunk content for index `i` (>= MIN size so the store
/// accepts it; content-addressed so the address is BLAKE3(content)).
fn chunk_content(i: u8) -> Vec<u8> {
    // 1 KiB of deterministic bytes keyed by i.
    (0..1024u32).map(|n| (n as u8) ^ i).collect()
}

/// A responder identity bound to a freshly-built commitment over the
/// given chunk indices, with those chunks actually stored in `storage`.
struct Responder {
    peer_id: PeerId,
    peer_id_bytes: [u8; 32],
    state: Arc<ResponderCommitmentState>,
}

impl Responder {
    /// Build a responder that has stored `indices` and committed to them.
    async fn new(storage: &LmdbStorage, indices: &[u8]) -> Self {
        let (pk, sk) = keypair();
        // Gate 2c: peer_id == BLAKE3(pubkey_bytes), matching production
        // saorsa-core identity derivation.
        let peer_id_bytes = *blake3::hash(&pk.to_bytes()).as_bytes();
        let peer_id = PeerId::from_bytes(peer_id_bytes);

        // Store the real chunks and commit to (address, address) entries
        // (content-addressed: bytes_hash == address).
        let mut entries = Vec::new();
        for &i in indices {
            let content = chunk_content(i);
            let addr = LmdbStorage::compute_address(&content);
            storage.put(&addr, &content).await.expect("put chunk");
            entries.push((addr, addr));
        }
        let built =
            BuiltCommitment::build(entries, &peer_id_bytes, &sk, &pk.to_bytes()).expect("build");
        let state = Arc::new(ResponderCommitmentState::new());
        state.rotate(built);

        Self {
            peer_id,
            peer_id_bytes,
            state,
        }
    }

    fn current_hash(&self) -> [u8; 32] {
        self.state.current().unwrap().hash()
    }

    fn address(i: u8) -> [u8; 32] {
        LmdbStorage::compute_address(&chunk_content(i))
    }
}

fn pinned_challenge(
    responder: &Responder,
    keys: Vec<[u8; 32]>,
    pin: Option<[u8; 32]>,
) -> AuditChallenge {
    AuditChallenge {
        challenge_id: 42,
        nonce: [0x11; 32],
        challenged_peer_id: responder.peer_id_bytes,
        keys,
        expected_commitment_hash: pin,
    }
}

// ---------------------------------------------------------------------------
// 1. Pinned challenge, honest responder -> CommitmentBound answer
// ---------------------------------------------------------------------------

/// Baseline: a pinned challenge to a responder that holds the committed
/// bytes yields a `CommitmentBound` response that hashes to the pin.
/// This anchors the other tests — it proves the handler's happy path is
/// reachable so the failure-path assertions are meaningful (not passing
/// because the handler errors out for an unrelated reason).
#[tokio::test]
async fn pinned_honest_responder_answers_commitment_bound() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    let challenge = pinned_challenge(
        &r,
        vec![Responder::address(1), Responder::address(3)],
        Some(pin),
    );

    let resp = handle_audit_challenge_with_commitment(
        &challenge,
        &storage,
        &r.peer_id,
        /* is_bootstrapping */ false,
        /* stored_chunks */ 4,
        Some(&r.state),
    )
    .await;

    match resp {
        AuditResponse::CommitmentBound {
            challenge_id,
            commitment,
            ..
        } => {
            assert_eq!(challenge_id, 42);
            // The answered commitment must hash to the pin.
            assert_eq!(commitment_hash(&commitment), Some(pin));
        }
        other => panic!("expected CommitmentBound, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. Pinned challenge, but the responder cannot answer the pin
//    (rotated past / never had it) -> Rejected "unknown commitment hash"
// ---------------------------------------------------------------------------

/// A pinned challenge whose hash the responder's state does not contain
/// is rejected with "unknown commitment hash" (the §5 signal the auditor
/// uses for conditional invalidation), NOT silently answered against a
/// different commitment.
///
/// FLIPS IF: the responder ignored the pin and answered against its
/// current commitment regardless — the auditor's pin contract (§4) would
/// be void and a lazy node could answer any challenge with any tree.
#[tokio::test]
async fn pinned_unknown_hash_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    // Pin a hash the responder never committed to.
    let bogus_pin = [0x99u8; 32];
    let challenge = pinned_challenge(&r, vec![Responder::address(1)], Some(bogus_pin));

    let resp = handle_audit_challenge_with_commitment(
        &challenge,
        &storage,
        &r.peer_id,
        false,
        4,
        Some(&r.state),
    )
    .await;

    match resp {
        AuditResponse::Rejected { reason, .. } => {
            assert!(
                reason.contains("unknown commitment hash"),
                "expected unknown-commitment-hash rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(unknown commitment hash), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 3. Pinned challenge for a key the commitment does not cover
//    -> Rejected "key not in commitment"
// ---------------------------------------------------------------------------

/// The auditor pins the responder's real commitment but challenges a key
/// that commitment never covered (responder rotated between gossip and
/// audit). The responder rejects with "key not in commitment" — a benign
/// signal the auditor treats as Idle, not a storage-loss penalty.
///
/// FLIPS IF: the responder fabricated a proof for an uncommitted key, or
/// answered with a malformed `CommitmentBound` the auditor would penalise.
#[tokio::test]
async fn pinned_key_not_in_commitment_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    // key(9) is a valid content address we also store, but it is NOT in
    // the committed set {1,2,3,4}.
    let extra = chunk_content(9);
    let extra_addr = LmdbStorage::compute_address(&extra);
    storage.put(&extra_addr, &extra).await.unwrap();
    let challenge = pinned_challenge(&r, vec![extra_addr], Some(pin));

    let resp = handle_audit_challenge_with_commitment(
        &challenge,
        &storage,
        &r.peer_id,
        false,
        5,
        Some(&r.state),
    )
    .await;

    match resp {
        AuditResponse::Rejected { reason, .. } => {
            assert!(
                reason.contains("key not in commitment"),
                "expected key-not-in-commitment rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(key not in commitment), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Pinned challenge for a committed key whose bytes the responder has
//    since deleted -> Rejected "missing bytes for committed key"
// ---------------------------------------------------------------------------

/// The lazy/chunk-deleter case: the responder committed to a key, the
/// auditor pins that commitment and challenges the key, but the responder
/// has dropped the actual bytes. The responder cannot fabricate a valid
/// per-key digest (it is bound to the bytes), so it rejects with the
/// distinct "missing bytes for committed key" reason — which the auditor
/// treats as real storage loss and penalises (codex round-12).
///
/// FLIPS IF: the responder could answer a committed key without holding
/// the bytes — exactly the Finding-1 storage-binding hole this PR closes.
#[tokio::test]
async fn pinned_committed_key_with_missing_bytes_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    // Delete the bytes for committed key(2) AFTER committing.
    let addr2 = Responder::address(2);
    storage.delete(&addr2).await.expect("delete chunk");
    let challenge = pinned_challenge(&r, vec![addr2], Some(pin));

    let resp = handle_audit_challenge_with_commitment(
        &challenge,
        &storage,
        &r.peer_id,
        false,
        3,
        Some(&r.state),
    )
    .await;

    match resp {
        AuditResponse::Rejected { reason, .. } => {
            assert!(
                reason.contains("missing bytes for committed key"),
                "expected missing-bytes rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(missing bytes), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. Bootstrapping responder under a pinned challenge -> Bootstrapping
// ---------------------------------------------------------------------------

/// A responder that is still bootstrapping answers `Bootstrapping`, not a
/// commitment proof — it must not be penalised for not yet holding data.
/// (The §3 shield + 24h bootstrap-claim grace covers abuse of this on the
/// auditor side; here we assert the responder reports it honestly.)
#[tokio::test]
async fn bootstrapping_responder_reports_bootstrapping() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    let challenge = pinned_challenge(&r, vec![Responder::address(1)], Some(pin));

    let resp = handle_audit_challenge_with_commitment(
        &challenge,
        &storage,
        &r.peer_id,
        /* is_bootstrapping */ true,
        4,
        Some(&r.state),
    )
    .await;

    assert!(
        matches!(resp, AuditResponse::Bootstrapping { challenge_id: 42 }),
        "expected Bootstrapping, got {resp:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. Legacy (unpinned) challenge still works via the plain-digest path
// ---------------------------------------------------------------------------

/// Backward-compat: an unpinned challenge (no commitment hash) is answered
/// with plain `Digests` — the legacy path remains available so a node can
/// challenge peers it hasn't yet received a commitment from during rollout.
///
/// FLIPS IF: the commitment-bound path had become mandatory and broke
/// mixed-version networks.
#[tokio::test]
async fn unpinned_challenge_answers_with_digests() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let challenge = pinned_challenge(&r, vec![Responder::address(1), Responder::address(2)], None);

    // Legacy entry point (no commitment_state) — the network's
    // pre-commitment path.
    let resp = handle_audit_challenge(&challenge, &storage, &r.peer_id, false, 4).await;

    match resp {
        AuditResponse::Digests {
            challenge_id,
            digests,
        } => {
            assert_eq!(challenge_id, 42);
            assert_eq!(digests.len(), 2, "one digest per challenged key");
        }
        other => panic!("expected Digests, got {other:?}"),
    }
}
