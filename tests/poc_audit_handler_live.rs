//! Live responder-handler integration tests for the gossip-triggered
//! contiguous-subtree storage audit (ADR-0002).
//!
//! The pure proof maths are covered by the unit tests in
//! `src/replication/subtree.rs`, and the end-to-end attack composition by
//! `poc_commitment_audit_attacks`. This file fills the remaining gap: the
//! *live* responder control-flow branches in
//! [`ant_node::replication::storage_commitment_audit::handle_subtree_challenge`] — the function the
//! network actually calls — driven against a real `LmdbStorage` and a real
//! `ResponderCommitmentState`, asserting on the exact `SubtreeAuditResponse`
//! variant produced.
//!
//! Each test is written to FAIL if the defence it covers is removed — see the
//! `// FLIPS IF:` note on each. They are not tautologies: the responder under
//! test is the production code path, not a reimplementation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use ant_node::replication::commitment_state::{BuiltCommitment, ResponderCommitmentState};
use ant_node::replication::config::MAX_BYTE_CHALLENGE_KEYS;
use ant_node::replication::protocol::{
    SubtreeAuditChallenge, SubtreeAuditResponse, SubtreeByteChallenge, SubtreeByteItem,
    SubtreeByteResponse,
};
use ant_node::replication::storage_commitment_audit::{
    handle_subtree_byte_challenge, handle_subtree_challenge,
};
use ant_node::replication::subtree::{verify_subtree_proof, StructureVerdict};
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

/// Deterministic chunk content for index `i` (>= store MIN size). Distinct per
/// index so each address is distinct.
fn chunk_content(i: u8) -> Vec<u8> {
    (0..1024u32).map(|n| (n as u8) ^ i).collect()
}

/// A responder identity bound to a freshly-built commitment over the given
/// chunk indices, with those chunks actually stored in `storage`.
struct Responder {
    peer_id: PeerId,
    peer_id_bytes: [u8; 32],
    state: Arc<ResponderCommitmentState>,
}

impl Responder {
    /// Build a responder that has stored `indices` and committed to them.
    /// The committed leaf binds `(address, BLAKE3(content))`; the responder
    /// reads bytes by address at audit time and rehashes them.
    async fn new(storage: &LmdbStorage, indices: &[u8]) -> Self {
        let (pk, sk) = keypair();
        // Production identity derivation: peer_id == BLAKE3(pubkey_bytes).
        let peer_id_bytes = *blake3::hash(&pk.to_bytes()).as_bytes();
        let peer_id = PeerId::from_bytes(peer_id_bytes);

        let mut entries = Vec::new();
        for &i in indices {
            let content = chunk_content(i);
            let addr = LmdbStorage::compute_address(&content);
            storage.put(&addr, &content).await.expect("put chunk");
            let bytes_hash = *blake3::hash(&content).as_bytes();
            entries.push((addr, bytes_hash));
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

fn challenge_for(responder: &Responder, pin: [u8; 32], nonce: [u8; 32]) -> SubtreeAuditChallenge {
    SubtreeAuditChallenge {
        challenge_id: 42,
        nonce,
        challenged_peer_id: responder.peer_id_bytes,
        expected_commitment_hash: pin,
    }
}

// ---------------------------------------------------------------------------
// 1. Honest responder, pinned to its gossiped commitment -> Proof
// ---------------------------------------------------------------------------

/// Baseline: a challenge pinned to the responder's retained commitment, with
/// all committed bytes present, yields a `Proof` whose commitment matches the
/// pin and whose subtree proof passes `verify_subtree_proof`. Anchors the
/// failure-path tests — it proves the happy path is reachable, so a Rejected in
/// another test is the defence firing, not an unrelated error.
#[tokio::test]
async fn honest_responder_answers_with_valid_proof() {
    let (storage, _t) = test_storage().await;
    // Enough leaves to exercise a real (non-whole-tree) subtree selection.
    let indices: Vec<u8> = (1..=64u8).collect();
    let r = Responder::new(&storage, &indices).await;
    let pin = r.current_hash();
    let nonce = [0x11u8; 32];
    let challenge = challenge_for(&r, pin, nonce);

    let resp =
        handle_subtree_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state)).await;

    match resp {
        SubtreeAuditResponse::Proof {
            challenge_id,
            commitment,
            proof,
        } => {
            assert_eq!(challenge_id, 42);
            // The answered commitment is the pinned one.
            assert_eq!(
                ant_node::replication::commitment::commitment_hash(&commitment),
                Some(pin),
            );
            // And the proof structurally verifies under the nonce + commitment.
            assert_eq!(
                verify_subtree_proof(&proof, &nonce, &commitment),
                StructureVerdict::Valid,
                "honest responder's proof must verify"
            );
        }
        other => panic!("expected Proof, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. Bootstrapping responder -> Bootstrapping (never penalised)
// ---------------------------------------------------------------------------

/// A responder still bootstrapping answers `Bootstrapping`, not a proof — it
/// must not be penalised for not yet holding data.
///
/// FLIPS IF: the bootstrap shortcut were removed and a bootstrapping node tried
/// (and failed) to build a proof, exposing fresh nodes to audit penalties.
#[tokio::test]
async fn bootstrapping_responder_reports_bootstrapping() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    let challenge = challenge_for(&r, pin, [0x11u8; 32]);

    let resp = handle_subtree_challenge(
        &challenge,
        &storage,
        &r.peer_id,
        /* is_bootstrapping */ true,
        Some(&r.state),
    )
    .await;

    assert!(
        matches!(
            resp,
            SubtreeAuditResponse::Bootstrapping { challenge_id: 42 }
        ),
        "expected Bootstrapping, got {resp:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. Challenge targeting the wrong peer -> Rejected
// ---------------------------------------------------------------------------

/// A challenge whose `challenged_peer_id` is not this node is rejected — a node
/// must only answer audits addressed to it (so an attacker can't make node A
/// answer for node B's committed tree).
///
/// FLIPS IF: the target-peer check were dropped and a node answered challenges
/// addressed to anyone.
#[tokio::test]
async fn wrong_target_peer_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    let mut challenge = challenge_for(&r, pin, [0x11u8; 32]);
    // Address the challenge to a different peer.
    challenge.challenged_peer_id = [0x99u8; 32];

    let resp =
        handle_subtree_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state)).await;

    match resp {
        SubtreeAuditResponse::Rejected {
            challenge_id,
            reason,
            ..
        } => {
            assert_eq!(challenge_id, 42);
            assert!(
                reason.contains("does not match this node"),
                "expected wrong-peer rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(wrong peer), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Pinned hash the responder does not retain -> Rejected "unknown commitment"
// ---------------------------------------------------------------------------

/// A challenge pinned to a commitment hash the responder's state does not
/// contain is rejected with "unknown commitment hash", NOT silently answered
/// against the current commitment. Since the auditor only pins a hash the peer
/// just gossiped, this rejection is the auditor's confirmed-failure signal.
///
/// FLIPS IF: the responder ignored the pin and answered against its current
/// commitment regardless — the pin contract would be void and a lazy node could
/// answer any challenge with any tree.
#[tokio::test]
async fn unknown_pinned_hash_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    // A hash the responder never built/retained.
    let bogus_pin = [0x99u8; 32];
    let challenge = challenge_for(&r, bogus_pin, [0x11u8; 32]);

    let resp =
        handle_subtree_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state)).await;

    match resp {
        SubtreeAuditResponse::Rejected { reason, .. } => {
            assert!(
                reason.contains("unknown commitment hash"),
                "expected unknown-commitment-hash rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(unknown commitment hash), got {other:?}"),
    }
}

/// No commitment state at all (e.g. before the first rotation during rollout)
/// is likewise rejected — there is nothing to answer the pin against.
#[tokio::test]
async fn missing_commitment_state_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    let challenge = challenge_for(&r, pin, [0x11u8; 32]);

    // Pass None for commitment_state.
    let resp = handle_subtree_challenge(&challenge, &storage, &r.peer_id, false, None).await;

    assert!(
        matches!(resp, SubtreeAuditResponse::Rejected { .. }),
        "expected Rejected when no commitment state, got {resp:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Committed key whose bytes were deleted -> Rejected "missing bytes..."
// ---------------------------------------------------------------------------

/// The chunk-deleter case: the responder committed to a key, the auditor pins
/// that commitment, but the responder has since dropped the actual bytes for a
/// key the nonce-selected subtree covers. It cannot fabricate the leaf (the
/// nonced hash is bound to the bytes), so it rejects with the distinct "missing
/// bytes for committed key" reason — which the auditor treats as real storage
/// loss and penalises.
///
/// To guarantee the deleted key falls inside the selected subtree, we delete
/// EVERY committed chunk's bytes, so whichever leaves the nonce selects, at
/// least one is missing.
///
/// FLIPS IF: the responder could answer a committed key without holding the
/// bytes — exactly the storage-binding hole the subtree audit closes.
#[tokio::test]
async fn committed_key_with_missing_bytes_is_rejected() {
    let (storage, _t) = test_storage().await;
    let indices: Vec<u8> = (1..=32u8).collect();
    let r = Responder::new(&storage, &indices).await;
    let pin = r.current_hash();

    // Drop the bytes for every committed chunk AFTER committing, so any selected
    // subtree contains at least one key whose bytes are gone.
    for &i in &indices {
        let addr = Responder::address(i);
        storage.delete(&addr).await.expect("delete chunk");
    }

    let challenge = challenge_for(&r, pin, [0x11u8; 32]);
    let resp =
        handle_subtree_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state)).await;

    match resp {
        SubtreeAuditResponse::Rejected { reason, .. } => {
            assert!(
                reason.contains("missing bytes for committed key"),
                "expected missing-bytes rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(missing bytes), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 6. Round 2 (byte challenge): honest serve + oversize-request rejection
// ---------------------------------------------------------------------------

/// Round-2 happy path: a byte challenge pinned to the responder's retained
/// commitment, for keys it committed to and still stores, returns `Items` with
/// the ORIGINAL bytes (`Present`) for every requested key.
///
/// FLIPS IF: the responder stops serving original bytes for committed keys —
/// the auditor would then see byte-verification failures for honest nodes.
#[tokio::test]
async fn byte_challenge_serves_original_bytes_for_committed_keys() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();

    let keys = vec![Responder::address(1), Responder::address(2)];
    let challenge = SubtreeByteChallenge {
        challenge_id: 43,
        nonce: [0x22u8; 32],
        challenged_peer_id: r.peer_id_bytes,
        expected_commitment_hash: pin,
        keys: keys.clone(),
    };

    let resp =
        handle_subtree_byte_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;

    match resp {
        SubtreeByteResponse::Items {
            challenge_id,
            items,
        } => {
            assert_eq!(challenge_id, 43);
            assert_eq!(items.len(), keys.len(), "one item per requested key");
            for (item, (i, key)) in items.iter().zip([1u8, 2].into_iter().zip(keys)) {
                match item {
                    SubtreeByteItem::Present { key: k, bytes } => {
                        assert_eq!(*k, key);
                        assert_eq!(*bytes, chunk_content(i), "must serve the ORIGINAL bytes");
                    }
                    other @ SubtreeByteItem::Absent { .. } => {
                        panic!("expected Present for stored committed key, got {other:?}")
                    }
                }
            }
        }
        other => panic!("expected Items, got {other:?}"),
    }
}

/// A byte challenge requesting more than `MAX_BYTE_CHALLENGE_KEYS` keys is
/// rejected up front: an honest auditor batches its sample to that cap so the
/// worst-case response (all chunks at max size) fits the replication wire cap;
/// anything larger is a forged/over-size request the responder must not try to
/// serve (the response could not encode, and reading the chunks first would be
/// disk-read amplification).
///
/// FLIPS IF: the per-challenge key cap is removed from the responder.
#[tokio::test]
async fn oversize_byte_challenge_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();

    let keys: Vec<[u8; 32]> = (0..=MAX_BYTE_CHALLENGE_KEYS)
        .map(|i| [u8::try_from(i % 251).unwrap_or(0); 32])
        .collect();
    assert!(keys.len() > MAX_BYTE_CHALLENGE_KEYS);
    let challenge = SubtreeByteChallenge {
        challenge_id: 44,
        nonce: [0x33u8; 32],
        challenged_peer_id: r.peer_id_bytes,
        expected_commitment_hash: pin,
        keys,
    };

    let resp =
        handle_subtree_byte_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;

    match resp {
        SubtreeByteResponse::Rejected { reason, .. } => {
            assert!(
                reason.contains("max"),
                "expected per-challenge key-cap rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(oversize), got {other:?}"),
    }
}
