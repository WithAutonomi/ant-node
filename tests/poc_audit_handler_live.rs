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
use ant_node::replication::config::MAX_SLICE_OPENINGS;
use ant_node::replication::protocol::{
    SubtreeAuditChallenge, SubtreeAuditResponse, SubtreeSliceChallenge, SubtreeSliceItem,
    SubtreeSliceOpening, SubtreeSliceResponse,
};
use ant_node::replication::slice::{nonced_block_root, verify_block_slice, verify_nonced_block};
use ant_node::replication::storage_commitment_audit::{
    handle_subtree_challenge, handle_subtree_challenge_measured, handle_subtree_slice_challenge,
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
// 5b. Partial round-1 work is charged even when the response is a rejection
// ---------------------------------------------------------------------------

/// A successful proof reports exactly the chunk content it read and hashed.
/// Anchors the rejection case below: it fixes what the measurement means.
#[tokio::test]
async fn round1_proof_reports_the_content_it_read() {
    let (storage, _t) = test_storage().await;
    let indices: Vec<u8> = (1..=64u8).collect();
    let r = Responder::new(&storage, &indices).await;
    let challenge = challenge_for(&r, r.current_hash(), [0x11u8; 32]);

    let work =
        handle_subtree_challenge_measured(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;

    let SubtreeAuditResponse::Proof { ref proof, .. } = work.response else {
        panic!("expected Proof, got {:?}", work.response);
    };
    let from_proof: i64 = proof
        .leaves
        .iter()
        .map(|leaf| i64::from(leaf.content_len))
        .sum();
    assert_eq!(
        work.content_bytes, from_proof,
        "reported work must equal the content the proof covers"
    );
    assert!(work.content_bytes > 0, "a real proof reads real bytes");
}

/// Regression (dirvine, PR #181): round 1 reads and hashes leaf by leaf, so a
/// commitment holding ONE unreadable key still costs a full run of reads and
/// keyed-BLAKE3 passes over every leaf before it — and then rejects.
///
/// The responder used to charge its work budget only on the `Proof` arm, so
/// that run was free. An attacker who found such a commitment could replay
/// subtrees over it indefinitely at no cost, and the per-peer cooldown does not
/// help because it is escapable by rotating identity — the responder-wide budget
/// is the only bound that applies to this, so it has to see the work.
///
/// FLIPS IF: the accounting goes back to charging only successful proofs.
#[tokio::test]
async fn rejected_round1_still_reports_the_work_it_spent() {
    let (storage, _t) = test_storage().await;
    let indices: Vec<u8> = (1..=64u8).collect();
    let r = Responder::new(&storage, &indices).await;
    let pin = r.current_hash();

    // Find a nonce whose selected subtree spans more than one leaf, then delete
    // the bytes behind its LAST leaf only. Everything before it is readable, so
    // the responder does real work and then hits the hole.
    let challenge = challenge_for(&r, pin, [0x11u8; 32]);
    let baseline =
        handle_subtree_challenge_measured(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;
    let SubtreeAuditResponse::Proof { ref proof, .. } = baseline.response else {
        panic!("expected a baseline Proof, got {:?}", baseline.response);
    };
    assert!(
        proof.leaves.len() > 1,
        "need a multi-leaf subtree for partial work to exist; got {}",
        proof.leaves.len()
    );
    let last_leaf = proof.leaves.last().expect("non-empty");
    let (last, deleted_len) = (last_leaf.key, i64::from(last_leaf.content_len));
    let baseline_bytes = baseline.content_bytes;
    storage.delete(&last).await.expect("delete last leaf chunk");

    let work =
        handle_subtree_challenge_measured(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;

    match work.response {
        SubtreeAuditResponse::Rejected { ref reason, .. } => {
            assert!(
                reason.contains("missing bytes for committed key"),
                "expected the missing-bytes rejection, got: {reason}"
            );
        }
        ref other => panic!("expected Rejected(missing bytes), got {other:?}"),
    }
    assert!(
        work.content_bytes > 0,
        "the leaves read before the hole must be charged, not written off"
    );
    // Everything except the deleted leaf was read, so the charge is the
    // baseline minus that one leaf.
    assert_eq!(
        work.content_bytes,
        baseline_bytes - deleted_len,
        "charge must cover exactly the leaves actually read"
    );
}

// ---------------------------------------------------------------------------
// 6. Round 2 (slice challenge): honest open + oversize-request rejection
// ---------------------------------------------------------------------------

/// Round-2 happy path: a slice challenge pinned to the responder's retained
/// commitment, for keys it committed to and still stores, returns `Items` with a
/// `Present` verified opening for every requested key. The opening is fully
/// verified here — the Bao slice decodes against the chunk address to the real
/// block, and the nonced opening folds to the honest nonced root — so this FAILS
/// if the responder produces a malformed or non-possessing proof.
///
/// FLIPS IF: the responder stops opening valid slices for committed keys — the
/// auditor would then see verification failures for honest nodes.
#[tokio::test]
async fn slice_challenge_opens_valid_blocks_for_committed_keys() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    let nonce = [0x22u8; 32];

    let openings = vec![
        SubtreeSliceOpening {
            key: Responder::address(1),
            block_index: 0,
        },
        SubtreeSliceOpening {
            key: Responder::address(2),
            block_index: 0,
        },
    ];
    let challenge = SubtreeSliceChallenge {
        challenge_id: 43,
        nonce,
        challenged_peer_id: r.peer_id_bytes,
        expected_commitment_hash: pin,
        openings: openings.clone(),
    };

    let resp =
        handle_subtree_slice_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;

    match resp {
        SubtreeSliceResponse::Items {
            challenge_id,
            items,
        } => {
            assert_eq!(challenge_id, 43);
            assert_eq!(
                items.len(),
                openings.len(),
                "one item per requested opening"
            );
            for (item, (i, opening)) in items.iter().zip([1u8, 2].into_iter().zip(openings)) {
                match item {
                    SubtreeSliceItem::Present {
                        key: k,
                        block_index,
                        bao_slice,
                        nonced_siblings,
                    } => {
                        assert_eq!(*k, opening.key);
                        assert_eq!(*block_index, 0);
                        let content = chunk_content(i);
                        let bytes_hash = *blake3::hash(&content).as_bytes();
                        // Chain 1: the Bao slice decodes against the address to
                        // the real block (a 1024-byte chunk is a single block).
                        let block =
                            verify_block_slice(bao_slice, &bytes_hash, content.len() as u64, 0)
                                .expect("bao slice must verify against the chunk address");
                        assert_eq!(block, content, "opened block must be the ORIGINAL bytes");
                        // Chain 2: the nonced opening folds to the honest nonced
                        // root over the real content under this audit's nonce.
                        let root =
                            nonced_block_root(&nonce, &r.peer_id_bytes, &opening.key, &content);
                        assert!(
                            verify_nonced_block(
                                &nonce,
                                &r.peer_id_bytes,
                                &opening.key,
                                0,
                                &block,
                                nonced_siblings,
                                &root,
                                ant_node::replication::slice::block_count(content.len() as u64),
                            ),
                            "nonced opening must fold to the honest nonced root"
                        );
                    }
                    other @ SubtreeSliceItem::Absent { .. } => {
                        panic!("expected Present for stored committed key, got {other:?}")
                    }
                }
            }
        }
        other => panic!("expected Items, got {other:?}"),
    }
}

/// Coalescing at the live responder boundary: a challenge carrying DUPLICATE and
/// interleaved openings for the same `(key, block_index)` returns one `Present`
/// item per DISTINCT opening, not one per raw opening. This is the contract that
/// lets `serve_committed_key_openings` (via `ChunkOpener`) read and hash each
/// committed chunk once instead of re-reading it per repeated opening, so a
/// forged auditor cannot amplify responder disk/CPU work by repeating openings
/// while staying under the total-openings cap.
///
/// FLIPS IF: the responder stops deduplicating openings (item count would grow
/// with the raw request) or drops/duplicates a distinct identity.
#[tokio::test]
async fn slice_challenge_coalesces_duplicate_and_interleaved_openings() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();
    let nonce = [0x55u8; 32];

    let k1 = Responder::address(1);
    let k2 = Responder::address(2);
    // Five raw openings, interleaved, over only TWO distinct (key, block) pairs.
    let openings = vec![
        SubtreeSliceOpening {
            key: k1,
            block_index: 0,
        },
        SubtreeSliceOpening {
            key: k2,
            block_index: 0,
        },
        SubtreeSliceOpening {
            key: k1,
            block_index: 0,
        },
        SubtreeSliceOpening {
            key: k2,
            block_index: 0,
        },
        SubtreeSliceOpening {
            key: k1,
            block_index: 0,
        },
    ];
    assert!(openings.len() <= MAX_SLICE_OPENINGS);
    let challenge = SubtreeSliceChallenge {
        challenge_id: 46,
        nonce,
        challenged_peer_id: r.peer_id_bytes,
        expected_commitment_hash: pin,
        openings,
    };

    let resp =
        handle_subtree_slice_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;

    match resp {
        SubtreeSliceResponse::Items {
            challenge_id,
            items,
        } => {
            assert_eq!(challenge_id, 46);
            // Coalesced: one item per DISTINCT (key, block_index), not per raw opening.
            assert_eq!(
                items.len(),
                2,
                "duplicate openings must not multiply response items"
            );
            let mut seen: Vec<([u8; 32], u32)> = Vec::new();
            for item in &items {
                match item {
                    SubtreeSliceItem::Present {
                        key, block_index, ..
                    } => {
                        assert!(
                            !seen.contains(&(*key, *block_index)),
                            "each (key, block) identity must appear at most once"
                        );
                        seen.push((*key, *block_index));
                    }
                    other @ SubtreeSliceItem::Absent { .. } => {
                        panic!("expected Present for a stored committed key, got {other:?}")
                    }
                }
            }
            seen.sort_unstable();
            let mut want = vec![(k1, 0u32), (k2, 0u32)];
            want.sort_unstable();
            assert_eq!(
                seen, want,
                "both distinct openings must be served exactly once, order-independent"
            );
        }
        other => panic!("expected Items, got {other:?}"),
    }
}

/// Multi-block coverage: open a DEEP block of a genuinely large (multi-block)
/// chunk end-to-end through the live handler. The single-block happy-path test
/// above cannot exercise the Bao parent-hash chain or the multi-level nonced
/// tree; this one does — it stores a ~100 KB chunk (98 blocks), opens block 50,
/// and verifies both chains against that exact block.
///
/// FLIPS IF: the Bao slice or nonced opening for a non-trivial tree is malformed
/// (e.g. wrong offset, wrong sibling ordering).
#[tokio::test]
async fn slice_challenge_opens_a_deep_block_of_a_large_chunk() {
    use ant_node::replication::commitment::commitment_hash;
    use ant_node::replication::slice::block_count;

    let (storage, _t) = test_storage().await;

    // One large chunk: ~100 KB => 98 one-KiB blocks.
    let content: Vec<u8> = (0..100_000u32)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let addr = LmdbStorage::compute_address(&content);
    storage.put(&addr, &content).await.expect("put chunk");
    let bytes_hash = *blake3::hash(&content).as_bytes();

    let (pk, sk) = keypair();
    let peer_id_bytes = *blake3::hash(&pk.to_bytes()).as_bytes();
    let peer_id = PeerId::from_bytes(peer_id_bytes);
    let built = BuiltCommitment::build(
        vec![(addr, bytes_hash)],
        &peer_id_bytes,
        &sk,
        &pk.to_bytes(),
    )
    .expect("build");
    let pin = commitment_hash(built.commitment()).unwrap();
    let state = Arc::new(ResponderCommitmentState::new());
    state.rotate(built);

    let count = block_count(content.len() as u64);
    assert!(
        count > 64,
        "test needs a genuinely multi-block chunk, got {count} blocks"
    );
    let block_index = 50u32;
    let nonce = [0x5Au8; 32];
    let challenge = SubtreeSliceChallenge {
        challenge_id: 77,
        nonce,
        challenged_peer_id: peer_id_bytes,
        expected_commitment_hash: pin,
        openings: vec![SubtreeSliceOpening {
            key: addr,
            block_index,
        }],
    };

    let resp =
        handle_subtree_slice_challenge(&challenge, &storage, &peer_id, false, Some(&state)).await;

    let SubtreeSliceResponse::Items { items, .. } = resp else {
        panic!("expected Items, got {resp:?}");
    };
    let Some(SubtreeSliceItem::Present {
        block_index: bi,
        bao_slice,
        nonced_siblings,
        ..
    }) = items.first()
    else {
        panic!("expected a single Present opening, got {items:?}");
    };
    assert_eq!(*bi, block_index);

    // Chain 1: the Bao slice decodes against the address to exactly block 50.
    let block = verify_block_slice(bao_slice, &bytes_hash, content.len() as u64, block_index)
        .expect("deep-block bao slice must verify");
    let start = block_index as usize * 1024;
    assert_eq!(
        block,
        content[start..start + 1024],
        "opened block must be block 50's bytes"
    );

    // Chain 2: the nonced opening folds up the multi-level tree to the honest root.
    let root = nonced_block_root(&nonce, &peer_id_bytes, &addr, &content);
    assert!(
        verify_nonced_block(
            &nonce,
            &peer_id_bytes,
            &addr,
            block_index,
            &block,
            nonced_siblings,
            &root,
            ant_node::replication::slice::block_count(content.len() as u64)
        ),
        "deep-block nonced opening must fold to the honest root"
    );
    // And the proof is genuinely small — a slice, not the whole 100 KB chunk.
    assert!(
        bao_slice.len() < content.len() / 4,
        "the slice ({} bytes) must be far smaller than the chunk ({} bytes)",
        bao_slice.len(),
        content.len()
    );
}

/// A slice challenge requesting more than `MAX_SLICE_OPENINGS` openings is
/// rejected up front: an honest auditor opens at most that many blocks; anything
/// larger is a forged/over-size request the responder must not try to serve
/// (each opening forces a full chunk read to build its proof — disk-read
/// amplification).
///
/// FLIPS IF: the per-challenge openings cap is removed from the responder.
#[tokio::test]
async fn oversize_slice_challenge_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();

    let openings: Vec<SubtreeSliceOpening> = (0..=MAX_SLICE_OPENINGS)
        .map(|i| SubtreeSliceOpening {
            key: [u8::try_from(i % 251).unwrap_or(0); 32],
            block_index: 0,
        })
        .collect();
    assert!(openings.len() > MAX_SLICE_OPENINGS);
    let challenge = SubtreeSliceChallenge {
        challenge_id: 44,
        nonce: [0x33u8; 32],
        challenged_peer_id: r.peer_id_bytes,
        expected_commitment_hash: pin,
        openings,
    };

    let resp =
        handle_subtree_slice_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;

    match resp {
        SubtreeSliceResponse::Rejected { reason, .. } => {
            assert!(
                reason.contains("max"),
                "expected per-challenge openings-cap rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(oversize), got {other:?}"),
    }
}

/// A slice challenge spanning more DISTINCT keys than the honest spot-check sample
/// is rejected even when it stays under the total-openings cap. Coalescing saves
/// work only when keys repeat, so a forged auditor could otherwise force a full
/// chunk read per distinct key (up to ~40 MiB) without exceeding `MAX_SLICE_OPENINGS`.
///
/// FLIPS IF: the distinct-key cap is removed from the responder.
#[tokio::test]
async fn slice_challenge_with_too_many_distinct_keys_is_rejected() {
    let (storage, _t) = test_storage().await;
    let r = Responder::new(&storage, &[1, 2, 3, 4]).await;
    let pin = r.current_hash();

    // 6 distinct keys × 1 opening = 6 openings: under MAX_SLICE_OPENINGS (10) but
    // over the honest BYTE_SPOTCHECK_MAX (5) distinct-key sample.
    let openings: Vec<SubtreeSliceOpening> = (0..6u8)
        .map(|i| SubtreeSliceOpening {
            key: [i + 1; 32],
            block_index: 0,
        })
        .collect();
    assert!(openings.len() <= MAX_SLICE_OPENINGS);
    let challenge = SubtreeSliceChallenge {
        challenge_id: 45,
        nonce: [0x44u8; 32],
        challenged_peer_id: r.peer_id_bytes,
        expected_commitment_hash: pin,
        openings,
    };

    let resp =
        handle_subtree_slice_challenge(&challenge, &storage, &r.peer_id, false, Some(&r.state))
            .await;

    match resp {
        SubtreeSliceResponse::Rejected { reason, .. } => {
            assert!(
                reason.contains("distinct keys"),
                "expected distinct-key rejection, got: {reason}"
            );
        }
        other => panic!("expected Rejected(distinct keys), got {other:?}"),
    }
}
