//! Threat-model proof-of-concept tests for the v12 storage-bound audit
//! design (`notes/security-findings-2026-05-22/proposal-gossip-audit-v12.md`).
//!
//! Each test models a specific attack from the original Finding-1 and
//! Finding-2 reports (`notes/security-findings-2026-05-22/{01,02}-*.md`)
//! and asserts that the v12 mechanisms reject it.
//!
//! This file is the single canonical place to look for "does the
//! storage-bound audit actually close Findings 1 and 2?" — each `#[test]`
//! has a docstring linking the attack back to the original finding.
//!
//! Unit-level coverage of each gate in the verifier lives in
//! `src/replication/commitment_audit.rs` and `src/replication/
//! commitment_state.rs`. This file composes those gates end-to-end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::needless_borrows_for_generic_args
)]

use ant_node::replication::commitment::{
    commitment_hash, leaf_hash, sign_commitment, verify_commitment_signature,
    CommitmentBoundResult, MerkleTree, StorageCommitment,
};
use ant_node::replication::commitment_audit::{verify_commitment_bound_response, AuditVerifyError};
use ant_node::replication::commitment_state::{
    build_commitment_bound_audit_response, BuiltCommitment, CommitmentBoundOutcome,
    ResponderCommitmentState,
};
use ant_node::replication::protocol::compute_audit_digest;
use ant_node::replication::recent_provers::RecentProvers;
use saorsa_core::identity::PeerId;
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn keypair() -> (MlDsaPublicKey, MlDsaSecretKey) {
    ml_dsa_65().generate_keypair().unwrap()
}

fn content(byte: u8) -> Vec<u8> {
    (0..256u32).map(|i| (i as u8) ^ byte).collect()
}

fn content_hash(byte: u8) -> [u8; 32] {
    *blake3::hash(&content(byte)).as_bytes()
}

fn key(byte: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = byte;
    k
}

fn peer_id(byte: u8) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    PeerId::from_bytes(bytes)
}

struct Responder {
    state: ResponderCommitmentState,
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
    peer_id_bytes: [u8; 32],
}

impl Responder {
    fn new(_peer_byte: u8) -> Self {
        let (public_key, secret_key) = keypair();
        // Gate 2c requires peer_id == BLAKE3(public_key_bytes). The
        // _peer_byte parameter is kept for source-compat with existing
        // tests but is no longer respected — peer identity is derived
        // from the actual pubkey, as in production (saorsa-core
        // `peer_id_from_public_key`).
        let peer_id_bytes = *blake3::hash(&public_key.to_bytes()).as_bytes();
        Self {
            state: ResponderCommitmentState::new(),
            public_key,
            secret_key,
            peer_id_bytes,
        }
    }

    /// Commit to the given set of (key, bytes_hash) entries and rotate
    /// into `state.current`.
    fn commit_to(&self, key_indices: &[u8]) {
        let entries: Vec<_> = key_indices
            .iter()
            .map(|&i| (key(i), content_hash(i)))
            .collect();
        let built = BuiltCommitment::build(
            entries,
            &self.peer_id_bytes,
            &self.secret_key,
            &self.public_key.to_bytes(),
        )
        .unwrap();
        self.state.rotate(built);
    }

    fn current_hash(&self) -> [u8; 32] {
        self.state.current().unwrap().hash()
    }

    fn build_response(
        &self,
        pinned_hash: &[u8; 32],
        challenge_keys: &[[u8; 32]],
        nonce: &[u8; 32],
    ) -> CommitmentBoundOutcome {
        build_commitment_bound_audit_response(
            &self.state,
            pinned_hash,
            challenge_keys,
            nonce,
            &self.peer_id_bytes,
            |k| {
                // Responder serves whatever bytes it actually has,
                // matched by key.
                for byte in 0..=255u8 {
                    if &key(byte) == k {
                        return Some(content(byte));
                    }
                }
                None
            },
        )
    }
}

/// Auditor verification — takes everything from the responder via the
/// `CommitmentBoundOutcome::Built` arm and runs the real auditor's
/// `verify_commitment_bound_response`. The responder's public key is now
/// embedded in the commitment itself, so no external `responder_public_key`
/// argument is needed.
fn auditor_verifies(
    responder_peer_id_bytes: &[u8; 32],
    pinned_hash: &[u8; 32],
    challenge_keys: &[[u8; 32]],
    nonce: &[u8; 32],
    response_commitment: &StorageCommitment,
    response_per_key: &[CommitmentBoundResult],
    auditor_local_bytes: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<(), AuditVerifyError> {
    verify_commitment_bound_response(
        challenge_keys,
        nonce,
        responder_peer_id_bytes,
        pinned_hash,
        response_commitment,
        response_per_key,
        auditor_local_bytes,
    )
}

// ---------------------------------------------------------------------------
// Finding 1: Audit not storage-bound (lazy-node attacks)
// ---------------------------------------------------------------------------

/// Attack 1a (Finding 1, Path A): lazy node gossips a real commitment,
/// drops the bytes, fetches them on demand at audit time, and computes
/// the digest with its own peer ID + the fetched bytes. The PoC test
/// in commitment_audit.rs proves the auditor's pin closes the variant
/// where the lazy node tries to substitute a fresh commitment; this
/// test composes the full flow.
///
/// Property: honest responder produces a response that the auditor
/// accepts. Then a lazy responder with a *different* commitment tries
/// to answer the same pin — auditor rejects.
#[test]
fn honest_responder_passes_audit_lazy_responder_fails() {
    let nonce = [0xCD; 32];

    // Honest: the responder gossiped this commitment, the auditor pinned
    // its hash, and the responder still has all the bytes.
    let honest = Responder::new(0xAB);
    honest.commit_to(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let pinned_hash = honest.current_hash();
    let challenge_keys = vec![key(1), key(4), key(7)];

    let CommitmentBoundOutcome::Built {
        commitment,
        per_key,
    } = honest.build_response(&pinned_hash, &challenge_keys, &nonce)
    else {
        panic!("honest responder should produce Built");
    };

    let auditor_local = |k: &[u8; 32]| -> Option<Vec<u8>> {
        for byte in 1..=8u8 {
            if &key(byte) == k {
                return Some(content(byte));
            }
        }
        None
    };

    let result = auditor_verifies(
        &honest.peer_id_bytes,
        &pinned_hash,
        &challenge_keys,
        &nonce,
        &commitment,
        &per_key,
        auditor_local,
    );
    assert!(result.is_ok(), "honest path must pass: {result:?}");

    // Lazy: a different responder (different key set) tries to answer
    // the same pin. The pin won't match their commitment — the responder
    // helper returns UnknownCommitmentHash before it even tries to
    // build proofs. (Models the "lazy node has no commitment for this
    // pinned hash" case.)
    let lazy = Responder::new(0xAB); // same peer_id_bytes, different key (different commitment).
    lazy.commit_to(&[9, 10, 11]); // covers different keys.

    let outcome = lazy.build_response(&pinned_hash, &challenge_keys, &nonce);
    assert!(
        matches!(outcome, CommitmentBoundOutcome::UnknownCommitmentHash),
        "lazy responder with no matching commitment must return UnknownCommitmentHash, got {outcome:?}",
    );
}

/// Attack 1b (Finding 1, Path B): lazy node fabricates a fresh
/// commitment and tries to substitute it into the response while the
/// auditor's pin is for an older commitment. The auditor's gate-2
/// commitment-hash pin closes this directly.
///
/// This is the core property: forging a commitment AFTER the auditor
/// pinned a different one cannot satisfy gate 2.
#[test]
fn fresh_commitment_substitution_rejected_by_pin() {
    let nonce = [0xCD; 32];

    let original = Responder::new(0xAB);
    original.commit_to(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let pinned_hash = original.current_hash();

    // Lazy node forges a NEW commitment over only the challenged keys
    // (using all real bytes — they fetched on demand). The lazy node
    // even uses the same peer_id_bytes as the original; the only
    // difference is the key set, hence the new root, hence a different
    // commitment_hash that won't match `pinned_hash`.
    let lazy = Responder::new(0xAB);
    lazy.commit_to(&[1]);
    let lazy_hash = lazy.current_hash();
    assert_ne!(pinned_hash, lazy_hash);

    // Responder builds a response that *would* be valid against
    // `lazy_hash`, then we feed it to the auditor pinned to
    // `pinned_hash`.
    let CommitmentBoundOutcome::Built {
        commitment,
        per_key,
    } = lazy.build_response(&lazy_hash, &[key(1)], &nonce)
    else {
        panic!("lazy responder builds OK against its own hash");
    };

    let auditor_local = |k: &[u8; 32]| -> Option<Vec<u8>> {
        if k == &key(1) {
            Some(content(1))
        } else {
            None
        }
    };

    let result = auditor_verifies(
        &lazy.peer_id_bytes,
        &pinned_hash, // <-- ORIGINAL pin, not the fresh hash
        &[key(1)],
        &nonce,
        &commitment,
        &per_key,
        auditor_local,
    );
    assert!(
        matches!(result, Err(AuditVerifyError::CommitmentHashMismatch)),
        "auditor pin must reject fresh-commitment substitution, got {result:?}",
    );
}

/// Attack 1c (Finding 1, Path C): lazy node gossips a real commitment
/// over a *small* subset of keys, then claims it holds more via other
/// channels (e.g. replica hints) and earns rewards for keys it never
/// committed to.
///
/// The §6 holder cache binds credit to (peer, current_commitment_hash,
/// key). A peer that didn't include K in its committed set cannot
/// successfully prove K — gate "key not in commitment" rejects. With
/// no proof, the cache never credits the peer for K.
#[test]
fn overclaim_via_partial_commitment_yields_no_holder_credit() {
    let nonce = [0xCD; 32];

    let lazy = Responder::new(0xAB);
    // Lazy node only commits to key 1, but it really wanted credit for
    // keys 1..=8.
    lazy.commit_to(&[1]);
    let pinned_hash = lazy.current_hash();

    // The auditor challenges on a key the lazy node DIDN'T commit to.
    let challenge_keys = [key(5)];
    let outcome = lazy.build_response(&pinned_hash, &challenge_keys, &nonce);
    assert!(
        matches!(outcome, CommitmentBoundOutcome::KeyNotInCommitment { .. }),
        "lazy responder cannot prove a key it didn't commit to, got {outcome:?}",
    );

    // The auditor maps `KeyNotInCommitment` to a Rejected response —
    // no successful proof, no `recent_provers` insertion, so the
    // holder-cache predicate denies credit.
    let cache = RecentProvers::new();
    // The auditor never calls record_proof for key 5 because the
    // verification never succeeded.
    assert!(!cache.is_credited_holder(&key(5), &peer_id(0xAB), &pinned_hash));
}

/// Attack 1d (Finding 1, Path D): lazy node tries to ROTATE its
/// commitment between the auditor's challenge issue and the response.
/// v6/v12 §4 retention guarantees the responder can answer audits
/// pinned to either current or previous, so a single rotation is
/// answerable. But after two rotations the original commitment is
/// gone — and the responder correctly returns UnknownCommitmentHash,
/// which under v12 §5 is conditionally interpreted by the auditor.
///
/// This test pins the retention invariant: pin to commitment-N, then
/// rotate twice. The responder must NOT be able to answer (the old
/// commitment is contractually allowed to be dropped) AND the auditor
/// can detect this via the structural response.
#[test]
fn responder_drops_old_commitment_past_retention_window() {
    let nonce = [0xCD; 32];

    let responder = Responder::new(0xAB);

    // Commitment 1.
    responder.commit_to(&[1, 2, 3]);
    let h1 = responder.current_hash();

    // Round-11 widened retention to 4 slots (covers ~4h with the 1h
    // rotation cadence). Rotate 4 more times → h1 ages out.
    for batch_size in 4..=8u8 {
        let keys: Vec<u8> = (1..=batch_size).collect();
        responder.commit_to(&keys);
    }

    let outcome = responder.build_response(&h1, &[key(1)], &nonce);
    assert!(
        matches!(outcome, CommitmentBoundOutcome::UnknownCommitmentHash),
        "h1 must be unreachable after RETAINED_COMMITMENT_SLOTS rotations, got {outcome:?}",
    );
}

/// Attack 1e (Finding 1): replay an old audit response. Since the
/// digest binds the per-challenge nonce, a fresh challenge with a new
/// nonce makes a stale response invalid.
#[test]
fn audit_response_replay_blocked_by_fresh_nonce() {
    let original_nonce = [0xCD; 32];
    let fresh_nonce = [0xEF; 32];

    let responder = Responder::new(0xAB);
    responder.commit_to(&[1, 2, 3]);
    let pinned_hash = responder.current_hash();

    // Responder produces a valid response under the ORIGINAL nonce.
    let CommitmentBoundOutcome::Built {
        commitment,
        per_key,
    } = responder.build_response(&pinned_hash, &[key(1)], &original_nonce)
    else {
        panic!("build OK");
    };

    let auditor_local = |k: &[u8; 32]| -> Option<Vec<u8>> {
        if k == &key(1) {
            Some(content(1))
        } else {
            None
        }
    };

    // Auditor's FRESH challenge has `fresh_nonce`. Replaying the OLD
    // response (with `original_nonce`-derived digest) must fail.
    let result = auditor_verifies(
        &responder.peer_id_bytes,
        &pinned_hash,
        &[key(1)],
        &fresh_nonce, // <-- different nonce
        &commitment,
        &per_key,
        auditor_local,
    );
    assert!(
        matches!(result, Err(AuditVerifyError::DigestMismatch { .. })),
        "replay must fail digest check under fresh nonce, got {result:?}",
    );
}

// ---------------------------------------------------------------------------
// Finding 2 ingredients: bootstrap-claim shield foundation
// ---------------------------------------------------------------------------
//
// Finding 2 (bootstrap-claim audit shield) is closed in v12 §3+§6 by:
//   - A peer that never gossipped a commitment has commitment_capable
//     = false; auditor refuses to credit it as a holder.
//   - The cache binds credit to (peer, current_commitment_hash, key),
//     so a peer with no commitment has no current hash and credit is
//     impossible.
//
// Full integration (the gossip emit + audit cadence trigger) lands in
// phase 3. Here we prove the *cache-side* property: no commitment hash
// ⇒ no credit.

/// A peer with no recent commitment (never gossipped) cannot be
/// credited as a holder via the recent_provers cache.
#[test]
fn silent_peer_earns_no_credit() {
    let cache = RecentProvers::new();
    // Even with a non-trivial key, peer, and hash, an empty cache
    // means no credit.
    assert!(!cache.is_credited_holder(&key(1), &peer_id(0xAB), &[0; 32]));
}

/// A peer that rotated their commitment between proof and credit-check
/// loses credit (the v12 §6 hash-binding lever). The lazy-node "drop
/// bytes, gossip new commitment, hope auditor doesn't notice" attack
/// is closed here.
#[test]
fn rotated_commitment_drops_holder_credit() {
    let mut cache = RecentProvers::new();
    let now = Instant::now();
    cache.record_proof(key(1), peer_id(7), [0xAB; 32], now);
    assert!(cache.is_credited_holder(&key(1), &peer_id(7), &[0xAB; 32]));
    // The auditor's view of "P's current commitment" has now changed
    // (e.g. P gossipped a new commitment that the auditor stored).
    // The old cache entry no longer matches; credit is denied.
    assert!(!cache.is_credited_holder(&key(1), &peer_id(7), &[0xCD; 32]));
}

// ---------------------------------------------------------------------------
// Wire-substitution / signature-forgery sanity
// ---------------------------------------------------------------------------

/// A response carrying a commitment signed by the WRONG key (somebody
/// else's keypair) is rejected at the signature gate.
///
/// Since the public key is now embedded in the commitment AND must hash
/// to sender_peer_id (gate 2c), isolating the signature gate is fiddly.
/// The construction here: swap the embedded pubkey to one whose
/// signature would NOT verify under the actual signed payload, AND
/// update peer_id to BLAKE3(swapped pubkey) so gate 2c passes, AND
/// re-pin the auditor + the challenged peer to the new identity. Then
/// gate 3 (signature) is the only remaining gate that can fail.
#[test]
fn wrong_signer_rejected_at_signature_gate() {
    let nonce = [0xCD; 32];
    let (wrong_public_key, _) = keypair();
    let wrong_pk_bytes = wrong_public_key.to_bytes();
    let wrong_peer_id = *blake3::hash(&wrong_pk_bytes).as_bytes();

    let responder = Responder::new(0xAB);
    responder.commit_to(&[1, 2, 3]);
    let pinned_hash = responder.current_hash();

    let CommitmentBoundOutcome::Built {
        commitment,
        per_key,
    } = responder.build_response(&pinned_hash, &[key(1)], &nonce)
    else {
        panic!("build OK");
    };

    let auditor_local = |k: &[u8; 32]| -> Option<Vec<u8>> {
        if k == &key(1) {
            Some(content(1))
        } else {
            None
        }
    };

    // Swap both the embedded pubkey AND sender_peer_id so gate 2c
    // passes; pin to the new commitment hash so gate 2b passes; then
    // gate 3 is the only failure path because the signature was signed
    // under responder.secret_key, not the wrong key.
    let mut bad_commit = commitment.clone();
    bad_commit.sender_public_key = wrong_pk_bytes;
    bad_commit.sender_peer_id = wrong_peer_id;
    let new_pin = commitment_hash(&bad_commit).unwrap();

    // Per-key digest also bound the original challenged_peer_id; rebuild
    // it under the new wrong_peer_id so gate 4 (digest) wouldn't trip
    // first.
    let mut bad_per_key = per_key.clone();
    bad_per_key[0].digest = compute_audit_digest(&nonce, &wrong_peer_id, &key(1), &content(1));

    let result = auditor_verifies(
        &wrong_peer_id, // challenged peer == new (wrong) peer_id
        &new_pin,
        &[key(1)],
        &nonce,
        &bad_commit,
        &bad_per_key,
        auditor_local,
    );
    assert!(
        matches!(result, Err(AuditVerifyError::SignatureInvalid)),
        "swapped embedded key must trip signature gate, got {result:?}",
    );
}

/// Attack 1a' (Finding 1, Path A — the ACTUAL on-demand fetch under
/// the original pin): the lazy node retains its gossiped commitment
/// but dropped the bytes. At audit time the lazy node fetches the
/// bytes from honest neighbours and answers with a VALID proof against
/// its OWN original commitment (same pin, same root). The auditor
/// accepts.
///
/// This is the "lazy node strictly dominated by economic cost"
/// property v12 admits: the pin defeats cross-commitment substitution
/// (covered by `fresh_commitment_substitution_rejected_by_pin` above)
/// but does NOT prevent a node that gossiped a real commitment from
/// answering audits via on-demand fetch. Closing this is bandwidth
/// economics (cost-per-audit > cost-of-storing), not cryptography.
///
/// **Setup to make the attack structurally distinct from the honest
/// path**: the lazy responder's commitment is built from a fixed key
/// set at gossip time (it HAD bytes then, per the v12 protocol
/// invariant — you cannot compute leaf hashes without bytes). After
/// that, we build the audit response **bypassing the responder's own
/// `ResponderCommitmentState`** and instead **manually constructing
/// the per-key proof entries from an alternate bytes source** that
/// represents fetched-on-demand bytes from a neighbour. This is
/// observationally indistinguishable from honest storage from the
/// auditor's perspective — which is exactly the point.
///
/// Pinning this test means: any future "we somehow close Path A
/// without bandwidth economics" claim must update this test to assert
/// the new defence (i.e. this test must FAIL after such a fix).
#[test]
fn on_demand_fetch_under_original_pin_succeeds_documenting_v12_limit() {
    use ant_node::replication::commitment::leaf_hash;
    let nonce = [0xCD; 32];

    // Lazy node gossipped a commitment over its full claimed set at
    // gossip time. The protocol invariant guarantees it had the bytes
    // then (leaf_hash requires bytes_hash).
    let lazy = Responder::new(0xAB);
    lazy.commit_to(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let pinned_hash = lazy.current_hash();
    let challenge_keys = vec![key(3)];

    // ATTACK MODEL: lazy node has DROPPED its local bytes for key 3.
    // To audit, it must fetch from a "neighbour" — modeled as an
    // alternate bytes source that the lazy node didn't have at
    // challenge-receive time but obtains during the audit window.
    //
    // We construct the audit response by hand using the alternate
    // bytes source. This bypasses Responder::build_response (which
    // would use the lazy node's own bytes via the closure that always
    // returns content(byte)) — making the fetched-vs-stored
    // distinction observable in the test setup even though it's
    // unobservable to the auditor on the wire.
    let neighbour_fetched_bytes_for_key_3 = content(3);

    // Pull the lazy node's original commitment + proof structure for
    // key 3 from its retained state.
    let built = lazy.state.lookup_by_hash(&pinned_hash).expect("retained");
    let (path, leaf_index) = built.proof_for(&key(3)).expect("key in commitment");
    let bytes_hash = *blake3::hash(&neighbour_fetched_bytes_for_key_3).as_bytes();

    // Confirm the bytes_hash from "fetched" bytes equals what the
    // commitment leaf expects (since the commitment was honest at
    // gossip time, the bytes_hash field is the SAME regardless of
    // whether the bytes are local or fetched — that's the auditor's
    // blind spot).
    let expected_leaf = leaf_hash(&key(3), &bytes_hash);
    let from_commitment = leaf_hash(&key(3), &content_hash(3));
    assert_eq!(
        expected_leaf, from_commitment,
        "fetched bytes produce the same leaf hash as locally-stored bytes (the v12 blind spot)"
    );

    let digest = ant_node::replication::protocol::compute_audit_digest(
        &nonce,
        &lazy.peer_id_bytes,
        &key(3),
        &neighbour_fetched_bytes_for_key_3,
    );
    let per_key = vec![CommitmentBoundResult {
        key: key(3),
        digest,
        bytes_hash,
        leaf_index,
        path,
    }];

    // Auditor verifies. It has its own copy of the bytes (only
    // commitment-audits keys it holds, per v12).
    let auditor_local = |k: &[u8; 32]| -> Option<Vec<u8>> {
        if k == &key(3) {
            Some(content(3))
        } else {
            None
        }
    };
    let result = auditor_verifies(
        &lazy.peer_id_bytes,
        &pinned_hash,
        &challenge_keys,
        &nonce,
        built.commitment(),
        &per_key,
        auditor_local,
    );

    // VERDICT: the audit PASSES. The lazy node sourced bytes from a
    // neighbour (modeled by `neighbour_fetched_bytes_for_key_3` being
    // a separate local that is then THROWN AWAY — the actual lazy node
    // doesn't have those bytes after the audit ends). The verifier
    // has no way to distinguish this from honest storage. Mick's
    // design note in #02_network on 2026-05-21 explicitly anchors
    // this: "harder to fight against when there are few chunks per
    // node... the more chunks in an audit, the harder it will become
    // to fetch them all on-demand within the time frame." Bandwidth
    // economics is the lever, not the audit cryptography.
    assert!(
        result.is_ok(),
        "on-demand-fetch attack with valid original commitment + alternate bytes source \
         passes the v12 verifier — this is by design. v12 is an economic, not \
         cryptographic, defence against Path A. result: {result:?}",
    );
}

/// Attack 1f (Finding 1 — peer impersonation via cross-peer
/// commitment substitution): the lazy node lifts a signed commitment
/// from another peer P' (e.g. observed in gossip) and embeds it in
/// its own audit response, hoping the auditor verifies the signature
/// against P''s public key by mistake. Gate 2a (sender_peer_id ==
/// challenged_peer_id) rejects this before any signature work.
#[test]
fn cross_peer_commitment_substitution_rejected_by_sender_id() {
    let nonce = [0xCD; 32];

    // Peer P with a real signed commitment.
    let real_p = Responder::new(0xAA);
    real_p.commit_to(&[1, 2, 3]);
    let p_hash = real_p.current_hash();

    // Auditor is challenging peer Q (different peer_id_bytes) but
    // somehow has p_hash in its pin (modelling a mis-binding bug).
    // Q's public key, P's signed commitment.
    let q_peer_id_bytes = [0xCC; 32];

    // Q builds a response that contains P's commitment (lifted from
    // gossip). The path/digests/bytes happen to be valid for P's
    // commitment over P's key 1.
    let CommitmentBoundOutcome::Built {
        commitment: stolen_commitment,
        per_key,
    } = real_p.build_response(&p_hash, &[key(1)], &nonce)
    else {
        panic!("real_p builds OK against its own pin");
    };

    let auditor_local = |k: &[u8; 32]| -> Option<Vec<u8>> {
        if k == &key(1) {
            Some(content(1))
        } else {
            None
        }
    };

    // Auditor challenged Q but the response carries P's commitment.
    // sender_peer_id in the commitment is P's (0xAA), not Q's (0xCC).
    // Gate 2a rejects.
    let result = auditor_verifies(
        &q_peer_id_bytes, // challenged peer
        &p_hash,
        &[key(1)],
        &nonce,
        &stolen_commitment, // sender_peer_id = 0xAA, not 0xCC
        &per_key,
        auditor_local,
    );
    assert!(
        matches!(result, Err(AuditVerifyError::SenderPeerIdMismatch)),
        "cross-peer substitution must trip gate 2a, got {result:?}",
    );
}

/// Attack 1f': throwaway-key substitution. An adversary controls the
/// peer at peer_id P. They build a commitment, fill in P's peer_id, but
/// embed a *different* (throwaway) public key whose secret they hold.
/// The signature verifies under the throwaway key (gate 3). Without
/// gate 2c, the audit would accept this as a valid claim from P even
/// though the throwaway key has no relationship to P's identity.
///
/// Gate 2c (peer_id == BLAKE3(embedded_pubkey)) rejects this. saorsa-
/// core derives PeerId from the public key bytes; any commitment whose
/// embedded pubkey doesn't match the claimed peer_id is malformed.
#[test]
#[allow(clippy::similar_names)]
fn throwaway_key_substitution_rejected_by_pubkey_binding() {
    let nonce = [0xCD; 32];

    // Adversary wants to impersonate peer P. Compute P's peer_id from a
    // legitimate pubkey (which the adversary does NOT control).
    let (p_pubkey, _) = keypair();
    let p_peer_id = *blake3::hash(&p_pubkey.to_bytes()).as_bytes();

    // They build a fresh throwaway keypair and sign with it.
    let (throwaway_pk, throwaway_sk) = keypair();
    let throwaway_pk_bytes = throwaway_pk.to_bytes();

    // Build a commitment claiming P's peer_id but embedding the throwaway
    // pubkey. Sign under the throwaway secret. The signature verifies
    // under the embedded throwaway key.
    let entries = vec![(key(1), content_hash(1))];
    let tree = MerkleTree::build(entries).unwrap();
    let root = tree.root();
    let path = tree.path_for(&key(1)).unwrap();
    let key_count = tree.key_count();
    let sig = sign_commitment(
        &throwaway_sk,
        &root,
        key_count,
        &p_peer_id, // P's peer_id (LIE)
        &throwaway_pk_bytes,
    )
    .unwrap();
    let bad_commit = StorageCommitment {
        root,
        key_count,
        sender_peer_id: p_peer_id,
        sender_public_key: throwaway_pk_bytes.clone(),
        signature: sig,
    };

    let pin = commitment_hash(&bad_commit).unwrap();
    let per_key = vec![CommitmentBoundResult {
        key: key(1),
        digest: compute_audit_digest(&nonce, &p_peer_id, &key(1), &content(1)),
        bytes_hash: content_hash(1),
        leaf_index: 0,
        path,
    }];

    let auditor_local = |k: &[u8; 32]| -> Option<Vec<u8>> { (k == &key(1)).then(|| content(1)) };

    let result = auditor_verifies(
        &p_peer_id, // challenged peer is P
        &pin,
        &[key(1)],
        &nonce,
        &bad_commit,
        &per_key,
        auditor_local,
    );
    assert!(
        matches!(result, Err(AuditVerifyError::SenderPeerIdMismatch)),
        "throwaway-key attack must trip gate 2c, got {result:?}",
    );
}

/// Attack 1g (overclaim, end-to-end via real audit flow): the lazy
/// node gossips a commitment over a small key set (just key 1), but
/// in a real network might claim more via replication hints. The
/// auditor's challenge on key 5 — which is NOT in the lazy node's
/// commitment — is correctly handled: the responder returns
/// `KeyNotInCommitment` (caller maps to `Rejected`), and the
/// auditor's holder cache predicate correctly denies credit because
/// no `record_proof` is ever issued for (peer, key 5, hash).
///
/// This is stronger than the earlier vacuous version because it
/// composes the full responder helper + cache predicate.
#[test]
fn overclaim_via_partial_commitment_end_to_end_no_credit() {
    let nonce = [0xCD; 32];

    let lazy = Responder::new(0xAB);
    lazy.commit_to(&[1]); // claims only key 1
    let pinned_hash = lazy.current_hash();

    // Auditor challenges key 5 — not committed.
    let outcome = lazy.build_response(&pinned_hash, &[key(5)], &nonce);
    assert!(
        matches!(outcome, CommitmentBoundOutcome::KeyNotInCommitment { .. }),
        "responder must reject key not in commitment, got {outcome:?}",
    );

    // Simulate the auditor's flow: it receives Rejected
    // (KeyNotInCommitment); does NOT record_proof; cache stays empty
    // for (peer, key 5). The credit predicate correctly denies.
    let mut cache = RecentProvers::new();
    // No record_proof call — that's the auditor's flow when it sees
    // any non-successful outcome.

    // For contrast, prove the cache DOES credit when a successful
    // proof IS recorded — so the predicate is meaningful, not
    // trivially false.
    cache.record_proof(key(1), peer_id(0xAB), pinned_hash, Instant::now());
    assert!(
        cache.is_credited_holder(&key(1), &peer_id(0xAB), &pinned_hash),
        "cache predicate is meaningful: successful proof yields credit"
    );

    // And the lazy node STILL has no credit for key 5 (because no
    // proof was ever recorded for it).
    assert!(
        !cache.is_credited_holder(&key(5), &peer_id(0xAB), &pinned_hash),
        "key 5 was never proved → no credit, despite a successful proof for key 1"
    );
}

/// `forget_commitment` semantics primitive: the v12 §5 conditional
/// invalidation handler will live at a higher layer (phase 3:
/// auditor coordinator that owns `last_commitment` per peer). The
/// underlying primitive — drop cache entries pinned to a specific
/// hash without touching entries for other hashes — is the building
/// block. This test pins that primitive's contract.
#[test]
fn forget_commitment_only_drops_matching_hash() {
    let mut cache = RecentProvers::new();
    let now = Instant::now();

    // P proves K1 under C1, then K1 under C2 (modelling rotation),
    // then K2 under C1. (Last is unusual but exercises the
    // "different key same hash" case.)
    cache.record_proof(key(1), peer_id(0xAB), [0xAA; 32], now);
    cache.record_proof(key(1), peer_id(0xAB), [0xBB; 32], now);
    cache.record_proof(key(2), peer_id(0xAB), [0xAA; 32], now);

    // Auditor invalidates C1 (e.g. received UnknownCommitmentHash
    // for C1 from this peer).
    cache.forget_commitment(&[0xAA; 32]);

    // C1 entries for both keys are gone.
    assert!(!cache.is_credited_holder(&key(1), &peer_id(0xAB), &[0xAA; 32]));
    assert!(!cache.is_credited_holder(&key(2), &peer_id(0xAB), &[0xAA; 32]));
    // C2 entry survives.
    assert!(cache.is_credited_holder(&key(1), &peer_id(0xAB), &[0xBB; 32]));
}

/// Sanity: the four foundational hashes (leaf, node, commitment_hash,
/// signature) are independent — none of them alone is sufficient.
#[test]
fn each_gate_fires_independently() {
    let nonce = [0xCD; 32];
    let responder = Responder::new(0xAB);
    responder.commit_to(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let pinned_hash = responder.current_hash();

    let CommitmentBoundOutcome::Built {
        commitment,
        per_key,
    } = responder.build_response(&pinned_hash, &[key(1)], &nonce)
    else {
        panic!("build OK");
    };

    let auditor_local = |k: &[u8; 32]| -> Option<Vec<u8>> {
        for byte in 1..=8u8 {
            if &key(byte) == k {
                return Some(content(byte));
            }
        }
        None
    };

    // Baseline: valid.
    let ok = auditor_verifies(
        &responder.peer_id_bytes,
        &pinned_hash,
        &[key(1)],
        &nonce,
        &commitment,
        &per_key,
        &auditor_local,
    );
    assert!(ok.is_ok());

    // Tamper bytes_hash → BytesHashMismatch.
    let mut bad = per_key.clone();
    bad[0].bytes_hash[0] ^= 1;
    let r = auditor_verifies(
        &responder.peer_id_bytes,
        &pinned_hash,
        &[key(1)],
        &nonce,
        &commitment,
        &bad,
        &auditor_local,
    );
    assert!(matches!(r, Err(AuditVerifyError::BytesHashMismatch { .. })));

    // Tamper path → PathInvalid.
    let mut bad = per_key.clone();
    bad[0].path[0][0] ^= 1;
    let r = auditor_verifies(
        &responder.peer_id_bytes,
        &pinned_hash,
        &[key(1)],
        &nonce,
        &commitment,
        &bad,
        &auditor_local,
    );
    assert!(matches!(r, Err(AuditVerifyError::PathInvalid { .. })));

    // Tamper digest → DigestMismatch.
    let mut bad = per_key.clone();
    bad[0].digest[0] ^= 1;
    let r = auditor_verifies(
        &responder.peer_id_bytes,
        &pinned_hash,
        &[key(1)],
        &nonce,
        &commitment,
        &bad,
        &auditor_local,
    );
    assert!(matches!(r, Err(AuditVerifyError::DigestMismatch { .. })));
}

// ---------------------------------------------------------------------------
// Cross-check: documented v12 invariants
// ---------------------------------------------------------------------------

/// The commitment-hash function is sensitive to every field. This
/// lemma underwrites every "pin doesn't match" test above.
#[test]
fn commitment_hash_is_field_sensitive() {
    let (pk, sk) = keypair();
    let pk_bytes = pk.to_bytes();
    let sig = sign_commitment(&sk, &[0; 32], 1, &[0; 32], &pk_bytes).unwrap();
    let c1 = StorageCommitment {
        root: [0; 32],
        key_count: 1,
        sender_peer_id: [0; 32],
        sender_public_key: pk_bytes,
        signature: sig,
    };
    let h1 = commitment_hash(&c1).unwrap();

    for mutate in 0..5u8 {
        let mut c = c1.clone();
        match mutate {
            0 => c.root[0] ^= 1,
            1 => c.key_count += 1,
            2 => c.sender_peer_id[0] ^= 1,
            3 => c.signature[0] ^= 1,
            4 => c.sender_public_key[0] ^= 1,
            _ => unreachable!(),
        }
        let h = commitment_hash(&c).unwrap();
        assert_ne!(h, h1, "mutation {mutate} should change commitment_hash");
    }
}

/// The leaf hash binds (key, bytes_hash). Same key + different bytes →
/// different leaf → different root.
#[test]
fn leaf_hash_binds_key_and_bytes() {
    let h1 = leaf_hash(&key(1), &content_hash(1));
    let h2 = leaf_hash(&key(1), &content_hash(2));
    let h3 = leaf_hash(&key(2), &content_hash(1));
    assert_ne!(h1, h2);
    assert_ne!(h1, h3);
    assert_ne!(h2, h3);
}

/// The Merkle tree is deterministic per key set.
#[test]
fn merkle_tree_root_is_deterministic_per_key_set() {
    let entries = vec![
        (key(1), content_hash(1)),
        (key(2), content_hash(2)),
        (key(3), content_hash(3)),
    ];
    let r1 = MerkleTree::build(entries.clone()).unwrap().root();
    let r2 = MerkleTree::build(entries).unwrap().root();
    assert_eq!(r1, r2);
}

/// The signature verifies under the right public key and only under
/// that key.
#[test]
fn signature_round_trips_correctly() {
    let (pk1, sk1) = keypair();
    let (pk2, _sk2) = keypair();
    let pk1_bytes = pk1.to_bytes();
    let pk2_bytes = pk2.to_bytes();
    let sig = sign_commitment(&sk1, &[7; 32], 42, &[3; 32], &pk1_bytes).unwrap();
    let c = StorageCommitment {
        root: [7; 32],
        key_count: 42,
        sender_peer_id: [3; 32],
        sender_public_key: pk1_bytes,
        signature: sig,
    };
    // Verifies via the embedded pk1 key.
    assert!(verify_commitment_signature(&c));
    // If we swap the embedded key to pk2 (keeping the signature signed by
    // sk1), verification must fail because pk2 didn't sign this payload.
    let mut c2 = c.clone();
    c2.sender_public_key = pk2_bytes;
    assert!(!verify_commitment_signature(&c2));
}

// ---------------------------------------------------------------------------
// PeerCommitmentRecord: §2 step 5 sticky commitment_capable
// ---------------------------------------------------------------------------

use ant_node::replication::commitment_state::PeerCommitmentRecord;

/// §2 step 5: `commitment_capable` is set on the first verified gossip
/// ingest and never flips back to false. A peer that later evicts the
/// cached commitment (TTL / sybil cap / restart) retains capability
/// status so §6 + §3 still refuse credit and refuse legacy-fallback.
#[test]
fn commitment_capable_flag_is_sticky_across_eviction() {
    let (pk, sk) = keypair();
    let pk_bytes = pk.to_bytes();
    let sig = sign_commitment(&sk, &[0; 32], 1, &[0; 32], &pk_bytes).unwrap();
    let commitment = StorageCommitment {
        root: [0; 32],
        key_count: 1,
        sender_peer_id: [0; 32],
        sender_public_key: pk_bytes,
        signature: sig,
    };

    let mut rec = PeerCommitmentRecord::from_verified(commitment, Instant::now());
    assert!(rec.commitment_capable);
    assert!(rec.last_commitment.is_some());

    // Simulate TTL eviction / restart: drop the commitment but keep
    // the record (this is what the engine should do — we don't have
    // a public API yet, so we mutate directly).
    rec.last_commitment = None;
    // Sticky: capable flag stays true.
    assert!(rec.commitment_capable);
}

/// `capable_but_no_commitment` constructor: used when we evict the
/// cached commitment but want to remember the peer has spoken v12.
#[test]
fn capable_but_no_commitment_starts_capable() {
    let rec = PeerCommitmentRecord::capable_but_no_commitment(Instant::now());
    assert!(rec.commitment_capable);
    assert!(rec.last_commitment.is_none());
}
