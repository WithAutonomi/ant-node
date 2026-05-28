//! Responder-side commitment builder + rotation state.
//!
//! Phase 2b of the v12 storage-bound audit design. Builds, signs, and
//! caches a [`StorageCommitment`] over the responder's currently-stored
//! key set; serves audit lookups by `expected_commitment_hash`; retains
//! the previous commitment across one rotation so an audit pinned to it
//! does not false-fail at the rotation boundary (v5/v12 §4 retention).
//!
//! Rotation strategy:
//!
//! - `rotate(new_built)` atomically replaces `current` with `new_built`
//!   and demotes the prior `current` to `previous`. The prior
//!   `previous` is dropped.
//! - `lookup(hash)` reads the in-memory map and returns an [`Arc`] to
//!   the matching `BuiltCommitment`, keeping it alive for the audit
//!   response regardless of subsequent rotation (mirrors the `ArcSwap`
//!   semantics specified in v6 §2: an in-flight reader holding its
//!   `Arc` is unaffected by a concurrent rotate).
//!
//! No persistent disk state. Trees are rebuilt from `LmdbStorage` at
//! the next rotation tick. Memory cost is bounded by
//! `2 × (key_count × ~64 bytes + signature_size)` — for 10k keys, ~1.3 MB.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use saorsa_pqc::api::sig::MlDsaSecretKey;

use crate::ant_protocol::XorName;
use crate::replication::commitment::{
    commitment_hash, sign_commitment, CommitmentError, MerkleTree, StorageCommitment,
};

/// Auditor-side per-peer commitment state.
///
/// Holds two things that together implement v10/v12 §2 step 5 and §6:
///   - `last_commitment`: the most recently received, verified, signed
///     commitment from this peer. `None` if we've evicted it (TTL,
///     sybil cap, peer-removed) or never received one.
///   - `commitment_capable`: a **sticky** boolean that flips to `true`
///     on the first successful gossip ingest and NEVER reverts. Used
///     by holder-eligibility (§6) and bootstrap-claim shield: a peer
///     that has at least once proven it speaks v12 is forever held to
///     that standard. Without stickiness, a peer could flip the flag
///     off by silencing its gossip and downgrade to the weaker legacy
///     audit path.
#[derive(Debug, Clone)]
pub struct PeerCommitmentRecord {
    /// Last verified commitment, or `None` if evicted/expired.
    pub last_commitment: Option<StorageCommitment>,
    /// Sticky: true once this peer has gossiped a valid commitment.
    /// Set on ingest. Never set back to false except by full
    /// `PeerRemoved` cleanup.
    pub commitment_capable: bool,
    /// When `last_commitment` was received. Used for TTL on the
    /// commitment itself (independent of the `commitment_capable`
    /// stickiness — losing the commitment via TTL doesn't make us
    /// forget the peer ever spoke v12).
    pub received_at: Instant,
    /// Last time we performed an ML-DSA signature verify for this
    /// peer's commitment. Used to enforce the §2 step 3 rate limit
    /// (at most one sig verify per peer per 60s).
    pub last_sig_verify_at: Instant,
}

impl PeerCommitmentRecord {
    /// Construct from a freshly-verified commitment. `commitment_capable`
    /// is set to `true` here and must remain so for the lifetime of the
    /// record.
    #[must_use]
    pub fn from_verified(commitment: StorageCommitment, now: Instant) -> Self {
        Self {
            last_commitment: Some(commitment),
            commitment_capable: true,
            received_at: now,
            last_sig_verify_at: now,
        }
    }

    /// Mark commitment-capable without storing a commitment (used when
    /// we've TTL-expired the commitment itself but want to remember the
    /// peer has spoken v12 before).
    #[must_use]
    pub fn capable_but_no_commitment(now: Instant) -> Self {
        Self {
            last_commitment: None,
            commitment_capable: true,
            received_at: now,
            last_sig_verify_at: now,
        }
    }
}

/// A fully-built commitment: signed wire blob, cached hash, Merkle tree
/// for inclusion proofs, and a sorted leaf-index lookup for the auditor's
/// `leaf_index` field.
///
/// Held inside an [`Arc`] so audit responders can grab a reference and
/// build a reply without holding the [`ResponderCommitmentState`] read
/// lock for the duration of the response.
pub struct BuiltCommitment {
    /// The signed wire blob.
    commitment: StorageCommitment,
    /// `commitment_hash(commitment)` — cached so audit lookups don't
    /// re-serialize on every match.
    cached_hash: [u8; 32],
    /// The Merkle tree behind the commitment. `path_for(key)` produces
    /// the inclusion proof; the responder's leaf-index lookup is below.
    tree: MerkleTree,
    /// `sorted_keys[i]` is the key at leaf index `i`. Sorted ascending
    /// so binary search reconstructs `leaf_index` for any key in
    /// `O(log n)`.
    sorted_keys: Vec<XorName>,
}

impl BuiltCommitment {
    /// Build a commitment over `entries = [(key, bytes_hash), ...]` and
    /// sign it with `secret_key`.
    ///
    /// `entries` does not need to be sorted (the inner [`MerkleTree`]
    /// sorts internally); `sender_peer_id` is bound into the signature
    /// and the commitment.
    ///
    /// # Errors
    ///
    /// Returns the wrapped [`CommitmentError`] on empty key sets,
    /// over-cap key counts, duplicates, or signing failures.
    pub fn build(
        entries: Vec<(XorName, [u8; 32])>,
        sender_peer_id: &[u8; 32],
        secret_key: &MlDsaSecretKey,
        sender_public_key: &[u8],
    ) -> Result<Self, CommitmentError> {
        let tree = MerkleTree::build(entries)?;
        let root = tree.root();
        let key_count = tree.key_count();
        let signature = sign_commitment(
            secret_key,
            &root,
            key_count,
            sender_peer_id,
            sender_public_key,
        )?;
        let commitment = StorageCommitment {
            root,
            key_count,
            sender_peer_id: *sender_peer_id,
            sender_public_key: sender_public_key.to_vec(),
            signature,
        };
        // `commitment_hash` only returns None on a postcard serialization
        // failure, which for our fixed-size commitment cannot occur in
        // practice (ML-DSA-65 signature is 3293 bytes). If it ever
        // somehow does, surface as a SignatureFailed so callers don't
        // need a new error variant for an unreachable case.
        let cached_hash = commitment_hash(&commitment).ok_or_else(|| {
            CommitmentError::SignatureFailed("commitment serialization failed".to_string())
        })?;
        // Recover the sorted key list from the tree (path_for uses
        // binary search internally, but we need an explicit list for
        // leaf_index lookup at audit time).
        let sorted_keys: Vec<XorName> = tree.sorted_keys();
        Ok(Self {
            commitment,
            cached_hash,
            tree,
            sorted_keys,
        })
    }

    /// The signed wire blob.
    #[must_use]
    pub fn commitment(&self) -> &StorageCommitment {
        &self.commitment
    }

    /// The cached commitment hash. Equal to
    /// [`crate::replication::commitment::commitment_hash`]
    /// `(self.commitment())`.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.cached_hash
    }

    /// Inclusion path + leaf index for `key`, if it is in this
    /// commitment. Returns `None` if `key` is not committed.
    #[must_use]
    pub fn proof_for(&self, key: &XorName) -> Option<(Vec<[u8; 32]>, u32)> {
        let idx = self.sorted_keys.binary_search(key).ok()?;
        let path = self.tree.path_for(key)?;
        // u32 cast safe because MerkleTree::build rejects > MAX_COMMITMENT_KEY_COUNT.
        let leaf_index = u32::try_from(idx).unwrap_or(u32::MAX);
        Some((path, leaf_index))
    }
}

/// Number of historical commitments retained by [`ResponderCommitmentState`].
///
/// Per v12 paragraph 4: a responder MUST retain demoted commitments long
/// enough that audits pinned to them can be answered.
///
/// Sizing: with 1h rotation interval (see `COMMITMENT_ROTATION_INTERVAL_SECS`
/// in mod.rs) and worst-case neighbor-sync cooldown of ~3h (1h cooldown +
/// batch staggering), keeping 4 slots gives ~4h of pin validity. That
/// comfortably exceeds the worst-case auditor pin lag (codex round-11
/// MAJOR #1). Memory cost: 4 × (sig + pubkey + ~64 B/key) → at 10k keys
/// per commitment, ~2.6 MB.
const RETAINED_COMMITMENT_SLOTS: usize = 4;

/// Multi-slot retention state: the current commitment plus
/// `RETAINED_COMMITMENT_SLOTS` - 1 historical ones.
///
/// Per v12 paragraph 4: a responder MUST retain demoted commitments
/// until they would no longer plausibly be pinned by any remote auditor.
/// This struct enforces that as a structural invariant — rotation is the
/// only path that drops the oldest slot.
pub struct ResponderCommitmentState {
    inner: RwLock<Inner>,
}

struct Inner {
    /// Newest-first: slots[0] is `current`, slots[1] is `previous`,
    /// slots[2..] are older retained commitments. Length is at most
    /// [`RETAINED_COMMITMENT_SLOTS`].
    slots: Vec<Arc<BuiltCommitment>>,
}

impl Default for ResponderCommitmentState {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponderCommitmentState {
    /// Empty state: no commitments yet. Audits before the first rotation
    /// see `None` lookups and the auditor falls back to the legacy plain
    /// digest path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                slots: Vec::with_capacity(RETAINED_COMMITMENT_SLOTS),
            }),
        }
    }

    /// Rotate: the new build becomes `current`; existing commitments
    /// shift down; the oldest beyond `RETAINED_COMMITMENT_SLOTS` is
    /// dropped.
    ///
    /// Invariant INV-R2 (v7 paragraph 2): demoted trees remain reachable
    /// until they age out past the retention window. Callers MUST NOT
    /// clear the retention buffer by any other mechanism.
    pub fn rotate(&self, new_current: BuiltCommitment) {
        let new_current = Arc::new(new_current);
        let mut guard = self.inner.write();
        guard.slots.insert(0, new_current);
        if guard.slots.len() > RETAINED_COMMITMENT_SLOTS {
            guard.slots.truncate(RETAINED_COMMITMENT_SLOTS);
        }
    }

    /// Look up a commitment by its hash. Returns `Some(arc)` if `hash`
    /// matches any retained slot. The returned `Arc` keeps the
    /// [`BuiltCommitment`] alive for as long as the caller holds it,
    /// even if a concurrent `rotate` ages it out of the retention buffer.
    #[must_use]
    pub fn lookup_by_hash(&self, hash: &[u8; 32]) -> Option<Arc<BuiltCommitment>> {
        let guard = self.inner.read();
        for c in &guard.slots {
            if &c.cached_hash == hash {
                return Some(Arc::clone(c));
            }
        }
        None
    }

    /// Snapshot the current commitment, if any. Used by the gossip
    /// piggyback path: emit `state.current()` on the next outbound
    /// `NeighborSyncRequest`/`Response`.
    #[must_use]
    pub fn current(&self) -> Option<Arc<BuiltCommitment>> {
        self.inner.read().slots.first().map(Arc::clone)
    }

    /// Drop every retained slot. Called when the local store has
    /// transitioned to empty: keeping the previously-advertised
    /// commitment alive would invite audit failures (we can no longer
    /// answer for any of the keys we committed to), and would leave
    /// remote auditors pinning a hash this node will never satisfy
    /// again. After clearing, the gossip piggyback path will emit
    /// `commitment: None` until a fresh rotation occurs.
    ///
    /// This is the one sanctioned escape from the "callers MUST NOT
    /// clear retention by any other mechanism" invariant — empty
    /// storage means there is nothing to retain.
    pub fn clear_all(&self) {
        self.inner.write().slots.clear();
    }

    /// Test-only: snapshot of the second-newest slot (legacy "previous").
    #[cfg(test)]
    pub(crate) fn previous(&self) -> Option<Arc<BuiltCommitment>> {
        self.inner.read().slots.get(1).map(Arc::clone)
    }
}

// ---------------------------------------------------------------------------
// Responder: commitment-bound audit handler
// ---------------------------------------------------------------------------

/// Outcome of [`build_commitment_bound_audit_response`]: either a
/// fully-built `CommitmentBound` response, or a typed rejection reason
/// the caller turns into an `AuditResponse::Rejected`.
#[derive(Debug)]
pub enum CommitmentBoundOutcome {
    /// Per-key proofs + commitment. Caller wraps in
    /// `AuditResponse::CommitmentBound`.
    Built {
        /// The commitment whose root the proofs are against.
        commitment: crate::replication::commitment::StorageCommitment,
        /// Per-key Merkle inclusion proofs, in challenge order.
        per_key: Vec<crate::replication::commitment::CommitmentBoundResult>,
    },
    /// The auditor pinned a commitment we don't recognize. Caller emits
    /// `AuditResponse::Rejected { reason: "unknown commitment hash" }`.
    /// Auditors classify this per the v12 §5 conditional-invalidation
    /// rule: only invalidate `last_commitment` if it still matches the
    /// rejected hash.
    UnknownCommitmentHash,
    /// One or more challenged keys are not in the matched commitment.
    /// The auditor only commitment-audits keys it itself holds, so this
    /// can happen if the responder rotated between the gossip the
    /// auditor saw and the audit response. Caller emits
    /// `AuditResponse::Rejected { reason: "key not in commitment" }`.
    /// (Treated as a normal Rejected by today's auditor.)
    KeyNotInCommitment {
        /// The first challenged key the matched commitment didn't cover.
        key: crate::ant_protocol::XorName,
    },
}

/// Build a `CommitmentBound` audit response for the challenged peer
/// using the given `state`.
///
/// Called by the responder when an `AuditChallenge` has
/// `expected_commitment_hash: Some(h)`. The responder looks up `h` in
/// its `ResponderCommitmentState` (current + previous), and produces a
/// per-key proof against the matched tree. Per v12 §4: the responder
/// MUST answer against the *exact* commitment whose hash matches the
/// pin — that's what `lookup_by_hash` enforces.
///
/// The caller is responsible for:
///   - Looking up record bytes for each challenged key (the per-key
///     `digest` is bound to the bytes via
///     [`compute_audit_digest`]). This module exposes `bytes_for`
///     as a closure so the caller can use whatever storage handle it
///     has without this module depending on `LmdbStorage`.
///
/// [`compute_audit_digest`]: crate::replication::protocol::compute_audit_digest
///
/// # Errors / outcome
///
/// See [`CommitmentBoundOutcome`].
pub fn build_commitment_bound_audit_response(
    state: &ResponderCommitmentState,
    expected_commitment_hash: &[u8; 32],
    challenge_keys: &[crate::ant_protocol::XorName],
    challenge_nonce: &[u8; 32],
    challenged_peer_id: &[u8; 32],
    bytes_for: impl Fn(&crate::ant_protocol::XorName) -> Option<Vec<u8>>,
) -> CommitmentBoundOutcome {
    use crate::replication::commitment::CommitmentBoundResult;
    use crate::replication::protocol::compute_audit_digest;

    let Some(built) = state.lookup_by_hash(expected_commitment_hash) else {
        return CommitmentBoundOutcome::UnknownCommitmentHash;
    };

    let mut per_key = Vec::with_capacity(challenge_keys.len());
    for key in challenge_keys {
        let Some((path, leaf_index)) = built.proof_for(key) else {
            return CommitmentBoundOutcome::KeyNotInCommitment { key: *key };
        };
        // If we don't actually have the bytes, we can't produce a
        // valid digest; treat as "key not in commitment" since the
        // commitment claims we have it but we don't.
        let Some(bytes) = bytes_for(key) else {
            return CommitmentBoundOutcome::KeyNotInCommitment { key: *key };
        };
        let bytes_hash = *blake3::hash(&bytes).as_bytes();
        let digest = compute_audit_digest(challenge_nonce, challenged_peer_id, key, &bytes);
        per_key.push(CommitmentBoundResult {
            key: *key,
            digest,
            bytes_hash,
            leaf_index,
            path,
        });
    }

    CommitmentBoundOutcome::Built {
        commitment: built.commitment().clone(),
        per_key,
    }
}

/// Pre-check a commitment-bound audit challenge: look up the pinned
/// commitment in `state` and verify every challenged key is covered by
/// it. Does NOT read any chunk bytes.
///
/// Used by the responder side to validate the challenge structurally
/// before streaming chunk bytes one at a time (which can be GiB for a
/// sqrt-scaled sample on a large store). The caller then iterates
/// `challenge_keys`, reads each chunk async, and calls
/// [`build_commitment_bound_result_for_key`] per key — bounding peak
/// memory at one chunk regardless of sample size (codex round-9 MAJOR).
///
/// Returns the matched commitment Arc on success so the caller doesn't
/// have to look it up again.
///
/// # Errors
///
/// Returns [`CommitmentBoundOutcome::UnknownCommitmentHash`] if `state`
/// has no built commitment whose hash matches `expected_commitment_hash`
/// (e.g. it was rotated past). Returns
/// [`CommitmentBoundOutcome::KeyNotInCommitment`] if any entry in
/// `challenge_keys` is absent from the matched commitment's per-key
/// proof table.
#[allow(clippy::result_large_err)]
pub fn precheck_commitment_bound_challenge(
    state: &ResponderCommitmentState,
    expected_commitment_hash: &[u8; 32],
    challenge_keys: &[crate::ant_protocol::XorName],
) -> Result<std::sync::Arc<BuiltCommitment>, CommitmentBoundOutcome> {
    let Some(built) = state.lookup_by_hash(expected_commitment_hash) else {
        return Err(CommitmentBoundOutcome::UnknownCommitmentHash);
    };
    for key in challenge_keys {
        if built.proof_for(key).is_none() {
            return Err(CommitmentBoundOutcome::KeyNotInCommitment { key: *key });
        }
    }
    Ok(built)
}

/// Build one per-key entry of a commitment-bound audit response, given
/// the pre-checked commitment and the chunk bytes for `key`.
///
/// Pairs with [`precheck_commitment_bound_challenge`] for streaming
/// (one chunk at a time) response construction. Returns `None` if
/// `key` is not in the commitment — precheck should have caught this,
/// so a None here is a programmer error.
#[must_use]
pub fn build_commitment_bound_result_for_key(
    built: &BuiltCommitment,
    key: &crate::ant_protocol::XorName,
    challenge_nonce: &[u8; 32],
    challenged_peer_id: &[u8; 32],
    bytes: &[u8],
) -> Option<crate::replication::commitment::CommitmentBoundResult> {
    use crate::replication::commitment::CommitmentBoundResult;
    use crate::replication::protocol::compute_audit_digest;

    let (path, leaf_index) = built.proof_for(key)?;
    let bytes_hash = *blake3::hash(bytes).as_bytes();
    let digest = compute_audit_digest(challenge_nonce, challenged_peer_id, key, bytes);
    Some(CommitmentBoundResult {
        key: *key,
        digest,
        bytes_hash,
        leaf_index,
        path,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::commitment::{commitment_hash, leaf_hash, verify_path};
    use saorsa_pqc::api::sig::ml_dsa_65;

    fn key(byte: u8) -> XorName {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    fn bh(byte: u8) -> [u8; 32] {
        [byte ^ 0x5A; 32]
    }

    fn keypair() -> (saorsa_pqc::api::sig::MlDsaPublicKey, MlDsaSecretKey) {
        ml_dsa_65().generate_keypair().unwrap()
    }

    #[test]
    fn built_commitment_hash_matches_global_hash() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let entries: Vec<_> = (1..=5u8).map(|i| (key(i), bh(i))).collect();
        let built = BuiltCommitment::build(entries, &[0xAB; 32], &sk, &pk_bytes).unwrap();
        let expected = commitment_hash(built.commitment()).unwrap();
        assert_eq!(built.hash(), expected);
    }

    #[test]
    fn built_commitment_proof_verifies_under_its_own_root() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let entries: Vec<_> = (1..=8u8).map(|i| (key(i), bh(i))).collect();
        let built = BuiltCommitment::build(entries.clone(), &[1; 32], &sk, &pk_bytes).unwrap();
        let root = built.commitment().root;
        let key_count = built.commitment().key_count;

        for (k, _) in &entries {
            let (path, leaf_index) = built.proof_for(k).expect("present");
            // Find the bytes_hash for this key.
            let bh_k = entries.iter().find(|(kk, _)| kk == k).unwrap().1;
            let lh = leaf_hash(k, &bh_k);
            assert!(
                verify_path(&lh, &path, leaf_index as usize, key_count, &root),
                "path verify failed for key {k:?}"
            );
        }
    }

    #[test]
    fn proof_for_absent_key_is_none() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let built = BuiltCommitment::build(
            vec![(key(1), bh(1)), (key(2), bh(2))],
            &[0; 32],
            &sk,
            &pk_bytes,
        )
        .unwrap();
        assert!(built.proof_for(&key(99)).is_none());
    }

    #[test]
    fn empty_state_returns_none() {
        let state = ResponderCommitmentState::new();
        assert!(state.current().is_none());
        assert!(state.lookup_by_hash(&[0; 32]).is_none());
    }

    #[test]
    fn rotate_promotes_and_demotes() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        // First rotation: just current, no previous.
        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        assert_eq!(state.current().unwrap().hash(), h1);
        assert!(state.previous().is_none());

        // Second rotation: c1 demoted to previous.
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        assert_eq!(state.current().unwrap().hash(), h2);
        assert_eq!(state.previous().unwrap().hash(), h1);
    }

    #[test]
    fn rotate_drops_oldest_past_retention_window() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        // RETAINED_COMMITMENT_SLOTS = 4. Insert 5 commitments; the
        // oldest should be evicted, the most recent 4 retained.
        let cs: Vec<_> = (1..=5u8)
            .map(|i| {
                BuiltCommitment::build(vec![(key(i), bh(i))], &[0; 32], &sk, &pk_bytes).unwrap()
            })
            .collect();
        let hashes: Vec<_> = cs.iter().map(BuiltCommitment::hash).collect();

        for c in cs {
            state.rotate(c);
        }

        // Newest is current.
        assert_eq!(state.current().unwrap().hash(), hashes[4]);
        // Slots 1-4 of the input (indices 1..=4) remain reachable.
        for h in hashes.iter().skip(1) {
            assert!(state.lookup_by_hash(h).is_some());
        }
        // The very first commitment (oldest) has been aged out.
        assert!(state.lookup_by_hash(&hashes[0]).is_none());
    }

    #[test]
    fn lookup_finds_current_and_previous() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();
        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c1);
        state.rotate(c2);

        assert!(state.lookup_by_hash(&h1).is_some());
        assert!(state.lookup_by_hash(&h2).is_some());
        assert!(state.lookup_by_hash(&[0xFF; 32]).is_none());
    }

    // ---------------------------------------------------------------------
    // build_commitment_bound_audit_response
    // ---------------------------------------------------------------------

    fn content(byte: u8) -> Vec<u8> {
        (0..256u32)
            .map(|i| u8::try_from(i).unwrap_or(0) ^ byte)
            .collect()
    }

    fn bytes_hash(b: &[u8]) -> [u8; 32] {
        *blake3::hash(b).as_bytes()
    }

    #[test]
    fn build_response_succeeds_for_keys_in_current_commitment() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();

        let entries: Vec<_> = (1..=5u8)
            .map(|i| (key(i), bytes_hash(&content(i))))
            .collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_bytes).unwrap();
        let h = built.hash();
        state.rotate(built);

        let bytes_lookup =
            |k: &XorName| -> Option<Vec<u8>> { (1..=5u8).find(|i| key(*i) == *k).map(content) };
        let outcome = build_commitment_bound_audit_response(
            &state,
            &h,
            &[key(1), key(3)],
            &[0xCD; 32],
            &peer_id,
            bytes_lookup,
        );
        match outcome {
            CommitmentBoundOutcome::Built {
                commitment,
                per_key,
            } => {
                assert_eq!(commitment_hash(&commitment).unwrap(), h);
                assert_eq!(per_key.len(), 2);
                assert_eq!(per_key[0].key, key(1));
                assert_eq!(per_key[1].key, key(3));
            }
            other => panic!("expected Built, got {other:?}"),
        }
    }

    #[test]
    fn build_response_unknown_commitment_hash() {
        let (_pk, sk) = keypair();
        let _ = sk;
        let state = ResponderCommitmentState::new();
        // No rotate; state has no commitment.
        let outcome = build_commitment_bound_audit_response(
            &state,
            &[0xAA; 32], // arbitrary hash, nothing matches
            &[key(1)],
            &[0; 32],
            &[0; 32],
            |_| Some(content(1)),
        );
        assert!(matches!(
            outcome,
            CommitmentBoundOutcome::UnknownCommitmentHash
        ));
    }

    #[test]
    fn build_response_falls_back_to_previous_after_rotation() {
        // INV-R2: an audit pinned to the just-demoted commitment is
        // still answerable. v5/v12 §4.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();

        let entries_c1: Vec<_> = (1..=3u8)
            .map(|i| (key(i), bytes_hash(&content(i))))
            .collect();
        let c1 = BuiltCommitment::build(entries_c1, &peer_id, &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);

        // Rotate to a new commitment (key set unchanged for simplicity).
        let entries_c2: Vec<_> = (1..=4u8)
            .map(|i| (key(i), bytes_hash(&content(i))))
            .collect();
        let c2 = BuiltCommitment::build(entries_c2, &peer_id, &sk, &pk_bytes).unwrap();
        state.rotate(c2);

        // Auditor still pinned to h1.
        let outcome = build_commitment_bound_audit_response(
            &state,
            &h1,
            &[key(1)],
            &[0; 32],
            &peer_id,
            |_| Some(content(1)),
        );
        assert!(matches!(
            outcome,
            CommitmentBoundOutcome::Built { commitment, .. }
            if commitment_hash(&commitment).unwrap() == h1
        ));
    }

    #[test]
    fn build_response_key_not_in_commitment() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();

        let entries: Vec<_> = (1..=3u8)
            .map(|i| (key(i), bytes_hash(&content(i))))
            .collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_bytes).unwrap();
        let h = built.hash();
        state.rotate(built);

        let outcome = build_commitment_bound_audit_response(
            &state,
            &h,
            &[key(99)], // not committed
            &[0; 32],
            &peer_id,
            |_| Some(content(99)),
        );
        assert!(matches!(
            outcome,
            CommitmentBoundOutcome::KeyNotInCommitment { .. }
        ));
    }

    // ---------------------------------------------------------------------
    // End-to-end: responder builds → auditor verifies
    // ---------------------------------------------------------------------

    use crate::replication::commitment_audit::verify_commitment_bound_response;

    #[test]
    fn end_to_end_responder_to_auditor_happy_path() {
        // Honest responder + honest auditor. Auditor should verify OK.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let nonce = [0xCD; 32];

        let entries: Vec<_> = (1..=8u8)
            .map(|i| (key(i), bytes_hash(&content(i))))
            .collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_bytes).unwrap();
        let h = built.hash();
        state.rotate(built);

        let bytes_lookup =
            |k: &XorName| -> Option<Vec<u8>> { (1..=8u8).find(|i| key(*i) == *k).map(content) };
        let challenge_keys = vec![key(1), key(4), key(7)];

        let CommitmentBoundOutcome::Built {
            commitment,
            per_key,
        } = build_commitment_bound_audit_response(
            &state,
            &h,
            &challenge_keys,
            &nonce,
            &peer_id,
            bytes_lookup,
        )
        else {
            panic!("expected Built");
        };

        let result = verify_commitment_bound_response(
            &challenge_keys,
            &nonce,
            &peer_id,
            &h,
            &commitment,
            &per_key,
            bytes_lookup,
        );
        // `pk` is not directly used in verify (the embedded key is) but
        // we asserted it was the signing key during build.
        assert!(result.is_ok(), "{result:?}");
    }

    // (The lazy-node fresh-commitment substitution attack is more
    // directly covered in
    // commitment_audit::tests::lazy_node_on_demand_fetch_attack_fails.
    // Removed here to keep the cross-module test surface focused on the
    // happy-path data flow.)

    #[test]
    fn clear_all_drops_every_slot() {
        // Empty-storage transition: after clear_all, the gossip path
        // must observe `current() == None` so it stops piggybacking a
        // commitment the node can no longer answer audits against.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &peer_id, &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &peer_id, &sk, &pk_bytes).unwrap();
        state.rotate(c2);

        assert!(state.current().is_some());
        assert!(state.lookup_by_hash(&h1).is_some());

        state.clear_all();

        assert!(state.current().is_none());
        assert!(state.lookup_by_hash(&h1).is_none());
    }

    #[test]
    fn lookup_arc_outlives_subsequent_rotation() {
        // INV-R2: an in-flight audit responder that grabbed an Arc must
        // be able to finish building the response even after the state
        // rotates that commitment out past the retention window.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);

        let in_flight = state.lookup_by_hash(&h1).unwrap();

        // Rotate RETAINED_COMMITMENT_SLOTS times → h1 ages out.
        for i in 2..=(u8::try_from(super::RETAINED_COMMITMENT_SLOTS).unwrap_or(0) + 1) {
            let c =
                BuiltCommitment::build(vec![(key(i), bh(i))], &[0; 32], &sk, &pk_bytes).unwrap();
            state.rotate(c);
        }
        assert!(state.lookup_by_hash(&h1).is_none());

        // But the in-flight Arc still works.
        assert_eq!(in_flight.hash(), h1);
        assert!(in_flight.proof_for(&key(1)).is_some());
    }
}
