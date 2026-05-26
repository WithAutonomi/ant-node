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

use parking_lot::RwLock;
use saorsa_pqc::api::sig::MlDsaSecretKey;

use crate::ant_protocol::XorName;
use crate::replication::commitment::{
    commitment_hash, sign_commitment, CommitmentError, MerkleTree, StorageCommitment,
};

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
    ) -> Result<Self, CommitmentError> {
        let tree = MerkleTree::build(entries)?;
        let root = tree.root();
        let key_count = tree.key_count();
        let signature = sign_commitment(secret_key, &root, key_count, sender_peer_id)?;
        let commitment = StorageCommitment {
            root,
            key_count,
            sender_peer_id: *sender_peer_id,
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
    /// [`commitment_hash`](crate::replication::commitment::commitment_hash)
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

/// Two-slot retention state: the current commitment and the immediately
/// previous one.
///
/// Per v12 §4: a responder MUST retain the just-demoted commitment until
/// the next rotation so audits pinned to it can be answered. This struct
/// enforces that as a structural invariant — rotation is the only path
/// that drops `previous`.
pub struct ResponderCommitmentState {
    inner: RwLock<Inner>,
}

struct Inner {
    current: Option<Arc<BuiltCommitment>>,
    previous: Option<Arc<BuiltCommitment>>,
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
                current: None,
                previous: None,
            }),
        }
    }

    /// Rotate: the new build becomes `current`; the prior `current`
    /// becomes `previous`; the prior `previous` is dropped.
    ///
    /// Invariant INV-R2 (v7 §2): the demoted tree is reachable until the
    /// next rotation. Callers MUST NOT clear `previous` by any other
    /// mechanism.
    pub fn rotate(&self, new_current: BuiltCommitment) {
        let new_current = Arc::new(new_current);
        let mut guard = self.inner.write();
        let previous = guard.current.take();
        guard.current = Some(new_current);
        guard.previous = previous;
    }

    /// Look up a commitment by its hash. Returns `Some(arc)` if `hash`
    /// matches either `current` or `previous`. The returned `Arc` keeps
    /// the [`BuiltCommitment`] alive for as long as the caller holds it,
    /// even if a concurrent `rotate` drops the slot.
    #[must_use]
    pub fn lookup_by_hash(&self, hash: &[u8; 32]) -> Option<Arc<BuiltCommitment>> {
        let guard = self.inner.read();
        if let Some(c) = &guard.current {
            if &c.cached_hash == hash {
                return Some(Arc::clone(c));
            }
        }
        if let Some(c) = &guard.previous {
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
        self.inner.read().current.as_ref().map(Arc::clone)
    }

    /// Test-only: snapshot of `previous`.
    #[cfg(test)]
    pub(crate) fn previous(&self) -> Option<Arc<BuiltCommitment>> {
        self.inner.read().previous.as_ref().map(Arc::clone)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        let (_pk, sk) = keypair();
        let entries: Vec<_> = (1..=5u8).map(|i| (key(i), bh(i))).collect();
        let built = BuiltCommitment::build(entries, &[0xAB; 32], &sk).unwrap();
        let expected = commitment_hash(built.commitment()).unwrap();
        assert_eq!(built.hash(), expected);
    }

    #[test]
    fn built_commitment_proof_verifies_under_its_own_root() {
        let (_pk, sk) = keypair();
        let entries: Vec<_> = (1..=8u8).map(|i| (key(i), bh(i))).collect();
        let built = BuiltCommitment::build(entries.clone(), &[1; 32], &sk).unwrap();
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
        let (_pk, sk) = keypair();
        let built =
            BuiltCommitment::build(vec![(key(1), bh(1)), (key(2), bh(2))], &[0; 32], &sk).unwrap();
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
        let (_pk, sk) = keypair();
        let state = ResponderCommitmentState::new();

        // First rotation: just current, no previous.
        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        assert_eq!(state.current().unwrap().hash(), h1);
        assert!(state.previous().is_none());

        // Second rotation: c1 demoted to previous.
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        assert_eq!(state.current().unwrap().hash(), h2);
        assert_eq!(state.previous().unwrap().hash(), h1);
    }

    #[test]
    fn rotate_drops_oldest_after_two_rotations() {
        let (_pk, sk) = keypair();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk).unwrap();
        let h1 = c1.hash();
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk).unwrap();
        let c3 = BuiltCommitment::build(vec![(key(3), bh(3))], &[0; 32], &sk).unwrap();
        let h3 = c3.hash();
        state.rotate(c1);
        state.rotate(c2);
        state.rotate(c3);

        assert_eq!(state.current().unwrap().hash(), h3);
        assert!(state.previous().is_some());
        // h1 is no longer reachable.
        assert!(state.lookup_by_hash(&h1).is_none());
    }

    #[test]
    fn lookup_finds_current_and_previous() {
        let (_pk, sk) = keypair();
        let state = ResponderCommitmentState::new();
        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk).unwrap();
        let h1 = c1.hash();
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk).unwrap();
        let h2 = c2.hash();
        state.rotate(c1);
        state.rotate(c2);

        assert!(state.lookup_by_hash(&h1).is_some());
        assert!(state.lookup_by_hash(&h2).is_some());
        assert!(state.lookup_by_hash(&[0xFF; 32]).is_none());
    }

    #[test]
    fn lookup_arc_outlives_subsequent_rotation() {
        // INV-R2: an in-flight audit responder that grabbed an Arc must
        // be able to finish building the response even after the state
        // rotates that commitment out.
        let (_pk, sk) = keypair();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);

        let in_flight = state.lookup_by_hash(&h1).unwrap();

        // Two rotations — h1 is gone from state.
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk).unwrap();
        let c3 = BuiltCommitment::build(vec![(key(3), bh(3))], &[0; 32], &sk).unwrap();
        state.rotate(c2);
        state.rotate(c3);
        assert!(state.lookup_by_hash(&h1).is_none());

        // But the in-flight Arc still works.
        assert_eq!(in_flight.hash(), h1);
        assert!(in_flight.proof_for(&key(1)).is_some());
    }
}
