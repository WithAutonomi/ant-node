//! Auditor-side verification of commitment-bound audit responses.
//!
//! Phase 2c of the v12 storage-bound audit design (`notes/security-
//! findings-2026-05-22/proposal-gossip-audit-v12.md`).
//!
//! `verify_commitment_bound_response` is a pure function: it takes the
//! commitment the auditor pinned, the response received from the
//! challenged peer, the auditor's own copy of the bytes for each
//! challenged key, the responder's ML-DSA-65 public key, and the
//! challenged peer ID — and returns either `Ok(())` (audit passed) or a
//! typed [`AuditVerifyError`] explaining which gate failed.
//!
//! The function performs the four checks specified in v12 §5:
//!
//! 1. **Structural**: `per_key.len() == challenge_keys.len()`; same
//!    order, no duplicates; each `path.len() == ceil(log2(key_count))`.
//! 2. **Commitment hash pin**: `commitment_hash(response.commitment) ==
//!    expected_commitment_hash`. Defeats fresh-commitment substitution.
//! 3. **Signature**: `verify_commitment_signature(commitment)` — using the
//!    public key embedded in the commitment itself; no external lookup.
//! 4. **Per-key**: for each challenged key K, the response's `bytes_hash`
//!    equals BLAKE3 of the auditor's local bytes for K (defeats lying
//!    about bytes), the rebuilt Merkle leaf verifies up to the
//!    commitment root via [`verify_path`] (proves the responder
//!    committed to K under this exact commitment), and the audit digest
//!    matches `BLAKE3(nonce || challenged_peer_id || K || bytes)` (the
//!    legacy audit-freshness check via the per-challenge nonce).
//!
//! The auditor only commitment-audits keys it itself holds — same
//! constraint as today's plain-digest audit (`audit.rs` step 9). The
//! `local_bytes_for` closure encapsulates that lookup.

use std::collections::HashSet;

use crate::ant_protocol::XorName;
use crate::replication::commitment::{
    commitment_hash, leaf_hash, verify_commitment_signature, verify_path, CommitmentBoundResult,
    StorageCommitment, MAX_COMMITMENT_KEY_COUNT,
};
use crate::replication::protocol::compute_audit_digest;

/// Why a commitment-bound audit response failed verification.
///
/// Each variant maps to one of the v12 §5 gates. Callers convert
/// any `Err` into a full `AUDIT_FAILURE_TRUST_WEIGHT` per-key penalty.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AuditVerifyError {
    /// `per_key.len() != challenge.keys.len()` — responder did not
    /// answer the exact challenge set.
    #[error("response covers {got} keys, expected {expected}")]
    PerKeyCountMismatch {
        /// Number of per-key entries in the response.
        got: usize,
        /// Number of keys in the challenge.
        expected: usize,
    },
    /// `per_key[i].key != challenge.keys[i]` — responder answered
    /// keys in the wrong order or substituted a different key.
    #[error("response key #{index} mismatch (got {got:?}, expected {expected:?})")]
    PerKeyOrderMismatch {
        /// Index in the challenge / response.
        index: usize,
        /// The key the responder answered.
        got: XorName,
        /// The key the auditor challenged.
        expected: XorName,
    },
    /// `per_key` contains a duplicate key — defeats responder trying to
    /// answer the same key twice in lieu of a key it doesn't have.
    #[error("response contains duplicate key {key:?}")]
    DuplicateKey {
        /// The duplicated key.
        key: XorName,
    },
    /// `commitment.key_count` exceeds [`MAX_COMMITMENT_KEY_COUNT`] —
    /// rejected before any hashing.
    #[error("commitment claims {key_count} keys, exceeds protocol max")]
    KeyCountOverProtocolMax {
        /// The claimed (rejected) key count.
        key_count: u32,
    },
    /// A `per_key[i].path` has the wrong length for the claimed
    /// `key_count` — caught before any hashing per v12 §5a.
    #[error("response key #{index} path length {got} != expected {expected}")]
    WrongPathLength {
        /// Index in the `per_key` vec.
        index: usize,
        /// The length the responder sent.
        got: usize,
        /// The expected length (`ceil(log2(key_count))`).
        expected: usize,
    },
    /// `commitment_hash(response.commitment) != expected_commitment_hash`
    /// — responder substituted a different commitment than the one the
    /// auditor pinned.
    #[error("commitment hash mismatch (expected pin)")]
    CommitmentHashMismatch,
    /// `response.commitment.sender_peer_id != challenged_peer_id` — the
    /// responder embedded another peer's signed commitment. Caught
    /// before the signature gate so callers cannot conflate keys.
    #[error("response commitment sender_peer_id mismatch (peer impersonation)")]
    SenderPeerIdMismatch,
    /// `commitment.signature` is not valid under `public_key`.
    #[error("commitment signature did not verify")]
    SignatureInvalid,
    /// A `per_key[i].bytes_hash` does not match BLAKE3 of the auditor's
    /// local bytes — responder lied about the bytes underlying the leaf.
    #[error("response key #{index} bytes_hash mismatch")]
    BytesHashMismatch {
        /// Index in the `per_key` vec.
        index: usize,
    },
    /// A `per_key[i].leaf_index >= commitment.key_count` — out-of-range
    /// leaf claim.
    #[error("response key #{index} leaf_index {leaf_index} >= key_count {key_count}")]
    LeafIndexOutOfRange {
        /// Index in the `per_key` vec.
        index: usize,
        /// The claimed leaf index.
        leaf_index: u32,
        /// The commitment's claimed key count.
        key_count: u32,
    },
    /// A `per_key[i].path` does not verify against the commitment root
    /// — the responder did not commit to this `(key, bytes_hash)` pair
    /// under this exact commitment.
    #[error("response key #{index} merkle path did not verify")]
    PathInvalid {
        /// Index in the `per_key` vec.
        index: usize,
    },
    /// A `per_key[i].digest` does not match
    /// `BLAKE3(nonce || challenged_peer_id || key || bytes)` — same
    /// per-key gate the existing plain-digest audit uses. The nonce
    /// defeats replay; the peer-id binding stops a third party forging
    /// a digest on the responder's behalf.
    #[error("response key #{index} audit digest mismatch")]
    DigestMismatch {
        /// Index in the `per_key` vec.
        index: usize,
    },
}

/// Verify a `CommitmentBound` audit response against the pin and the
/// auditor's local bytes.
///
/// `local_bytes_for` returns `Some(bytes)` for keys the auditor itself
/// holds. Per v12, the auditor only commitment-audits keys in its own
/// store; a key for which the closure returns `None` triggers
/// [`AuditVerifyError::BytesHashMismatch`] (the responder cannot prove
/// possession of bytes we don't have to compare against).
///
/// All four v12 §5 gates run before returning `Ok`. The order is chosen
/// to fail cheapest first: structural checks before any hashing,
/// commitment hash pin before signature verify, signature verify before
/// the per-key loop.
///
/// # Errors
///
/// See [`AuditVerifyError`]. Any error means the audit failed and the
/// caller should apply the standard `AUDIT_FAILURE_TRUST_WEIGHT × keys`
/// penalty.
///
/// Test-only one-shot verifier. Production uses the streaming split
/// [`verify_commitment_bound_metadata`] + [`verify_commitment_bound_per_key`]
/// to verify one chunk at a time; this whole-response variant exists only
/// for tests that build a full response and assert on the verdict. Gated
/// out of production builds.
#[cfg(any(test, feature = "test-utils"))]
#[allow(clippy::too_many_arguments)]
pub fn verify_commitment_bound_response(
    challenge_keys: &[XorName],
    challenge_nonce: &[u8; 32],
    challenged_peer_id: &[u8; 32],
    expected_commitment_hash: &[u8; 32],
    response_commitment: &StorageCommitment,
    response_per_key: &[CommitmentBoundResult],
    local_bytes_for: impl Fn(&XorName) -> Option<Vec<u8>>,
) -> Result<(), AuditVerifyError> {
    verify_commitment_bound_metadata(
        challenge_keys,
        challenged_peer_id,
        expected_commitment_hash,
        response_commitment,
        response_per_key,
    )?;
    for (i, result) in response_per_key.iter().enumerate() {
        let local_bytes =
            local_bytes_for(&result.key).ok_or(AuditVerifyError::BytesHashMismatch { index: i })?;
        verify_commitment_bound_per_key(
            i,
            challenge_nonce,
            challenged_peer_id,
            response_commitment,
            result,
            &local_bytes,
        )?;
    }
    Ok(())
}

/// Verify the metadata gates (1, 2a, 2b, 3) of a commitment-bound audit
/// response. Pure-sync, fast: structural / peer-identity / pin / signature.
///
/// Run this once per response before iterating per-key with
/// [`verify_commitment_bound_per_key`]. Split out so the auditor can stream
/// chunk bytes per-key from async storage instead of preloading them all
/// into memory (which at sqrt-scaled sample sizes and 4 MiB chunks would
/// be a remote memory-DoS vector — see codex round-5 BLOCKER #2).
///
/// # Errors
///
/// See [`AuditVerifyError`]. Returns the first gate failure encountered.
pub fn verify_commitment_bound_metadata(
    challenge_keys: &[XorName],
    challenged_peer_id: &[u8; 32],
    expected_commitment_hash: &[u8; 32],
    response_commitment: &StorageCommitment,
    response_per_key: &[CommitmentBoundResult],
) -> Result<(), AuditVerifyError> {
    // -- Gate 1: structural ---------------------------------------------------

    if response_per_key.len() != challenge_keys.len() {
        return Err(AuditVerifyError::PerKeyCountMismatch {
            got: response_per_key.len(),
            expected: challenge_keys.len(),
        });
    }

    // Key-order match: responder answers in challenge order. (Same
    // contract as today's plain-digest audit, where `digests[i]`
    // corresponds to `challenge.keys[i]`.)
    for (i, (expected, result)) in challenge_keys.iter().zip(response_per_key).enumerate() {
        if &result.key != expected {
            return Err(AuditVerifyError::PerKeyOrderMismatch {
                index: i,
                got: result.key,
                expected: *expected,
            });
        }
    }

    // Duplicate-key check (responder can't double-up answers).
    let mut seen = HashSet::with_capacity(response_per_key.len());
    for result in response_per_key {
        if !seen.insert(result.key) {
            return Err(AuditVerifyError::DuplicateKey { key: result.key });
        }
    }

    // Wire-input bounds on key_count + expected path length.
    let key_count = response_commitment.key_count;
    if key_count == 0 || key_count > MAX_COMMITMENT_KEY_COUNT {
        return Err(AuditVerifyError::KeyCountOverProtocolMax { key_count });
    }
    // verify_path will recompute this same value, but we precompute once
    // for an early structural reject before any hashing.
    let expected_path_len = key_count
        .checked_next_power_of_two()
        .map_or(usize::MAX, |n| n.trailing_zeros() as usize);
    for (i, result) in response_per_key.iter().enumerate() {
        if result.path.len() != expected_path_len {
            return Err(AuditVerifyError::WrongPathLength {
                index: i,
                got: result.path.len(),
                expected: expected_path_len,
            });
        }
    }

    // -- Gate 2a: peer-identity binding --------------------------------------
    //
    // A signed commitment from a DIFFERENT peer would have a valid
    // signature (it's a real commitment, just not from THIS peer) and
    // could pass the hash pin if the auditor's pin was accidentally
    // for the wrong peer. Catching this explicitly stops cross-peer
    // substitution as a class — the responder cannot embed someone
    // else's commitment in a response to a challenge targeting them.

    if &response_commitment.sender_peer_id != challenged_peer_id {
        return Err(AuditVerifyError::SenderPeerIdMismatch);
    }

    // -- Gate 2b: commitment hash pin ----------------------------------------

    let response_hash =
        commitment_hash(response_commitment).ok_or(AuditVerifyError::CommitmentHashMismatch)?;
    if &response_hash != expected_commitment_hash {
        return Err(AuditVerifyError::CommitmentHashMismatch);
    }

    // -- Gate 2c: peer-identity to embedded-pubkey binding ------------------
    //
    // The peer-id field on the commitment must match BLAKE3 of the embedded
    // public key — otherwise a responder could sign with a throwaway key
    // they own and lie about which identity it belongs to. saorsa-core
    // derives PeerId as `BLAKE3(pubkey_bytes)`.

    let derived_peer_id = *blake3::hash(&response_commitment.sender_public_key).as_bytes();
    if derived_peer_id != response_commitment.sender_peer_id {
        return Err(AuditVerifyError::SenderPeerIdMismatch);
    }

    // -- Gate 3: signature ---------------------------------------------------

    // Verifies against the public key embedded in the commitment itself.
    // The peer-id binding above (gate 2a) ensures that key actually belongs
    // to the challenged peer — a substituted commitment from another peer
    // would have failed there.
    if !verify_commitment_signature(response_commitment) {
        return Err(AuditVerifyError::SignatureInvalid);
    }

    Ok(())
}

/// Verify gate 4 (`bytes_hash` + path + digest) for a single per-key entry.
///
/// Call this once per challenged key in a streaming loop after running
/// [`verify_commitment_bound_metadata`] once on the response. Lets the
/// caller load one chunk at a time and drop it, bounding peak memory at
/// `MAX_CHUNK_SIZE` per challenge regardless of sample size.
///
/// # Errors
///
/// See [`AuditVerifyError`]. Returns `BytesHashMismatch`, `PathInvalid`,
/// `LeafIndexOutOfRange`, or `DigestMismatch` on failure.
pub fn verify_commitment_bound_per_key(
    index: usize,
    challenge_nonce: &[u8; 32],
    challenged_peer_id: &[u8; 32],
    response_commitment: &StorageCommitment,
    result: &CommitmentBoundResult,
    local_bytes: &[u8],
) -> Result<(), AuditVerifyError> {
    let expected_bytes_hash = *blake3::hash(local_bytes).as_bytes();
    if result.bytes_hash != expected_bytes_hash {
        return Err(AuditVerifyError::BytesHashMismatch { index });
    }

    let leaf = leaf_hash(&result.key, &result.bytes_hash);
    let key_count = response_commitment.key_count;
    if u64::from(result.leaf_index) >= u64::from(key_count) {
        return Err(AuditVerifyError::LeafIndexOutOfRange {
            index,
            leaf_index: result.leaf_index,
            key_count,
        });
    }
    if !verify_path(
        &leaf,
        &result.path,
        result.leaf_index as usize,
        key_count,
        &response_commitment.root,
    ) {
        return Err(AuditVerifyError::PathInvalid { index });
    }

    // Legacy audit digest. Defeats replay (nonce changes per
    // challenge) and third-party forging (peer ID is bound).
    let expected_digest = compute_audit_digest(
        challenge_nonce,
        challenged_peer_id,
        &result.key,
        local_bytes,
    );
    if result.digest != expected_digest {
        return Err(AuditVerifyError::DigestMismatch { index });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::commitment_state::BuiltCommitment;
    use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey};
    use std::collections::HashMap;

    fn key(byte: u8) -> XorName {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    fn content(byte: u8) -> Vec<u8> {
        // 256 bytes of deterministic content per index.
        (0..256u32)
            .map(|i| u8::try_from(i).unwrap_or(0) ^ byte)
            .collect()
    }

    fn bytes_hash(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    struct AuditFixture {
        pub built: BuiltCommitment,
        pub bytes_by_key: HashMap<XorName, Vec<u8>>,
        pub peer_id: [u8; 32],
        pub nonce: [u8; 32],
    }

    fn fixture(n: u8) -> (AuditFixture, MlDsaPublicKey) {
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let nonce = [0xCD; 32];
        let entries: Vec<_> = (1..=n)
            .map(|i| {
                let k = key(i);
                let c = content(i);
                (k, bytes_hash(&c))
            })
            .collect();
        let bytes_by_key: HashMap<_, _> = (1..=n).map(|i| (key(i), content(i))).collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk.to_bytes()).unwrap();
        let fx = AuditFixture {
            built,
            bytes_by_key,
            peer_id,
            nonce,
        };
        (fx, pk)
    }

    /// Build a valid `CommitmentBoundResponse` for the given challenge
    /// keys against `fx`. Used as the baseline; tampering tests mutate
    /// the result.
    fn build_valid_response(fx: &AuditFixture, keys: &[XorName]) -> Vec<CommitmentBoundResult> {
        keys.iter()
            .map(|k| {
                let bytes = fx.bytes_by_key.get(k).expect("auditor holds key").clone();
                let (path, leaf_index) = fx.built.proof_for(k).expect("present");
                let bh = bytes_hash(&bytes);
                let digest = compute_audit_digest(&fx.nonce, &fx.peer_id, k, &bytes);
                CommitmentBoundResult {
                    key: *k,
                    digest,
                    bytes_hash: bh,
                    leaf_index,
                    path,
                }
            })
            .collect()
    }

    fn local_lookup(fx: &AuditFixture) -> impl Fn(&XorName) -> Option<Vec<u8>> + '_ {
        |k: &XorName| fx.bytes_by_key.get(k).cloned()
    }

    #[test]
    fn valid_response_verifies() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1), key(2), key(3)];
        let per_key = build_valid_response(&fx, &keys);
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn wrong_key_count_rejected() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1), key(2), key(3)];
        let mut per_key = build_valid_response(&fx, &keys);
        per_key.pop();
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(
            result,
            Err(AuditVerifyError::PerKeyCountMismatch { .. })
        ));
    }

    #[test]
    fn wrong_key_order_rejected() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1), key(2), key(3)];
        let mut per_key = build_valid_response(&fx, &keys);
        per_key.swap(0, 2);
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(
            result,
            Err(AuditVerifyError::PerKeyOrderMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_key_rejected() {
        let (fx, _pk) = fixture(8);
        // Build keys=[k1, k1, k3] — a duplicate. Build the response
        // from this so structural+order pass but the duplicate-set
        // check fires.
        let keys = vec![key(1), key(1), key(3)];
        let per_key = build_valid_response(&fx, &keys);
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(result, Err(AuditVerifyError::DuplicateKey { .. })));
    }

    #[test]
    fn wrong_commitment_hash_pin_rejected() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1)];
        let per_key = build_valid_response(&fx, &keys);
        let mut wrong_pin = fx.built.hash();
        wrong_pin[0] ^= 0x01;
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &wrong_pin,
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(
            result,
            Err(AuditVerifyError::CommitmentHashMismatch)
        ));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1)];
        let per_key = build_valid_response(&fx, &keys);
        // Clone the commitment + flip a byte in the signature. This
        // also changes the commitment_hash, so we have to pin against
        // the new hash (this isolates the signature gate from gate 2).
        let mut bad_commit = fx.built.commitment().clone();
        bad_commit.signature[0] ^= 0xFF;
        let pin = commitment_hash(&bad_commit).unwrap();
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &pin,
            &bad_commit,
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(result, Err(AuditVerifyError::SignatureInvalid)));
    }

    #[test]
    fn wrong_bytes_hash_rejected() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1)];
        let mut per_key = build_valid_response(&fx, &keys);
        per_key[0].bytes_hash[0] ^= 0x01;
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(
            result,
            Err(AuditVerifyError::BytesHashMismatch { .. })
        ));
    }

    #[test]
    fn missing_local_bytes_rejected_as_bytes_hash_mismatch() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1)];
        let per_key = build_valid_response(&fx, &keys);
        // Auditor's local lookup says "I don't have this key" — the
        // verifier can't compare bytes and must reject.
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            |_| None,
        );
        assert!(matches!(
            result,
            Err(AuditVerifyError::BytesHashMismatch { .. })
        ));
    }

    #[test]
    fn out_of_range_leaf_index_rejected() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1)];
        let mut per_key = build_valid_response(&fx, &keys);
        per_key[0].leaf_index = 999;
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(
            result,
            Err(AuditVerifyError::LeafIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn tampered_path_rejected() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1)];
        let mut per_key = build_valid_response(&fx, &keys);
        if let Some(p) = per_key[0].path.first_mut() {
            p[0] ^= 0x01;
        }
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(result, Err(AuditVerifyError::PathInvalid { .. })));
    }

    #[test]
    fn wrong_path_length_rejected_before_hashing() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1)];
        let mut per_key = build_valid_response(&fx, &keys);
        per_key[0].path.push([0u8; 32]);
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(
            result,
            Err(AuditVerifyError::WrongPathLength { .. })
        ));
    }

    #[test]
    fn wrong_digest_rejected() {
        let (fx, _pk) = fixture(8);
        let keys = vec![key(1)];
        let mut per_key = build_valid_response(&fx, &keys);
        per_key[0].digest[0] ^= 0x01;
        let result = verify_commitment_bound_response(
            &keys,
            &fx.nonce,
            &fx.peer_id,
            &fx.built.hash(),
            fx.built.commitment(),
            &per_key,
            local_lookup(&fx),
        );
        assert!(matches!(
            result,
            Err(AuditVerifyError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn lazy_node_on_demand_fetch_attack_fails() {
        // The headline attack v12 closes: a "lazy" responder who
        // dropped the bytes but fetches them on demand at audit time.
        // To pass §5 they would need either (a) a valid path that
        // matches the local bytes_hash AND the commitment root they
        // already gossiped, OR (b) a fresh commitment they substitute
        // into the response. (a) requires them to have built the tree
        // with the real bytes at gossip time (i.e. they had them then),
        // and (b) is closed by the commitment hash pin.
        //
        // Concretely model attack (b): the lazy node received the
        // challenge, fetched bytes from a neighbour, builds a *fresh*
        // commitment over just the challenged keys, and replies with
        // that fresh commitment + valid proofs. The pin check rejects.
        let (_pk1, sk1) = ml_dsa_65().generate_keypair().unwrap();
        let (pk_lazy, sk_lazy) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk_lazy.to_bytes()).as_bytes();
        let nonce = [0xCD; 32];
        let _ = sk1;

        // Pretend the auditor previously received a commitment from the
        // lazy node over keys 1..=8.
        let original_entries: Vec<_> = (1..=8u8)
            .map(|i| {
                let k = key(i);
                let c = content(i);
                (k, bytes_hash(&c))
            })
            .collect();
        let pk_lazy_bytes = pk_lazy.to_bytes();
        let original_built =
            BuiltCommitment::build(original_entries, &peer_id, &sk_lazy, &pk_lazy_bytes).unwrap();
        let pinned_hash = original_built.hash();

        // Auditor challenges on key 3. Lazy node fetches the bytes
        // and builds a fresh commitment that includes key 3.
        let challenged_keys = vec![key(3)];

        // The lazy node fabricates a NEW commitment (different from the
        // one originally gossiped). It even includes the correct bytes
        // hash for key 3, so per-key path verification would pass
        // against the new commitment's root.
        let fresh_entries: Vec<_> = vec![(key(3), bytes_hash(&content(3)))];
        let fresh_built =
            BuiltCommitment::build(fresh_entries, &peer_id, &sk_lazy, &pk_lazy_bytes).unwrap();

        // Build a response that contains the fresh commitment + valid
        // proofs against it. Per-key entry uses the fresh tree.
        let (path, leaf_index) = fresh_built.proof_for(&key(3)).unwrap();
        let per_key = vec![CommitmentBoundResult {
            key: key(3),
            digest: compute_audit_digest(&nonce, &peer_id, &key(3), &content(3)),
            bytes_hash: bytes_hash(&content(3)),
            leaf_index,
            path,
        }];

        // Auditor's local store has key 3's bytes.
        let local = |k: &XorName| if k == &key(3) { Some(content(3)) } else { None };

        // Verify against the *original* pinned hash, response carries
        // the fresh commitment. Must fail at gate 2 (pin mismatch).
        let result = verify_commitment_bound_response(
            &challenged_keys,
            &nonce,
            &peer_id,
            &pinned_hash,
            fresh_built.commitment(),
            &per_key,
            local,
        );
        assert!(
            matches!(result, Err(AuditVerifyError::CommitmentHashMismatch)),
            "lazy-node fresh-commitment substitution must fail at pin check, got {result:?}",
        );
    }
}
