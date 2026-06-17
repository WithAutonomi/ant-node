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
use std::time::{Duration, Instant};

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
    /// Last verified commitment, or `None` if evicted/expired. PRIVATE so it can
    /// only be mutated through [`Self::set_commitment`] / [`Self::clear_commitment`],
    /// which keep `cached_hash` in lockstep (codex#2 — a stray
    /// `record.last_commitment = …` would otherwise stale the cached hash). Read
    /// it via [`Self::last_commitment`].
    last_commitment: Option<StorageCommitment>,
    /// `commitment_hash(last_commitment)`, cached so the per-cycle verifier
    /// snapshot doesn't re-serialize + re-hash every peer's ~5 KiB commitment
    /// each verification round (§13). Kept in sync via [`Self::set_commitment`]
    /// / [`Self::clear_commitment`]; `None` exactly when `last_commitment` is
    /// `None`.
    cached_hash: Option<[u8; 32]>,
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
        let cached_hash = commitment_hash(&commitment);
        Self {
            last_commitment: Some(commitment),
            cached_hash,
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
            cached_hash: None,
            commitment_capable: true,
            received_at: now,
            last_sig_verify_at: now,
        }
    }

    /// The stored commitment, if any. Read-only view of the private field.
    #[must_use]
    pub fn last_commitment(&self) -> Option<&StorageCommitment> {
        self.last_commitment.as_ref()
    }

    /// The cached `commitment_hash` of the stored commitment (§13) — `None`
    /// when no commitment is held. Avoids re-serializing/re-hashing on every
    /// verifier snapshot.
    #[must_use]
    pub fn commitment_hash(&self) -> Option<[u8; 32]> {
        self.cached_hash
    }

    /// Replace the stored commitment and refresh the cached hash together, so
    /// the two never drift.
    pub fn set_commitment(&mut self, commitment: StorageCommitment, now: Instant) {
        self.cached_hash = commitment_hash(&commitment);
        self.last_commitment = Some(commitment);
        self.received_at = now;
    }

    /// Drop the stored commitment and its cached hash together.
    pub fn clear_commitment(&mut self) {
        self.last_commitment = None;
        self.cached_hash = None;
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
    /// The Merkle tree behind the commitment. `path_for(key)` produces the
    /// inclusion proof and `key_index(key)` reconstructs a key's leaf index in
    /// `O(log n)` — so no separate `sorted_keys` Vec is kept (it duplicated the
    /// keys already in `tree.leaves`, §14).
    tree: MerkleTree,
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
        Self::build_from_tree(tree, sender_peer_id, secret_key, sender_public_key)
    }

    /// Sign and wrap an ALREADY-BUILT Merkle tree. Lets callers that already
    /// built the tree (e.g. the rotation no-op-root check, §11) avoid rebuilding
    /// it inside [`Self::build`].
    ///
    /// # Errors
    ///
    /// Propagates signing / serialization failures, identical to [`Self::build`].
    pub fn build_from_tree(
        tree: MerkleTree,
        sender_peer_id: &[u8; 32],
        secret_key: &MlDsaSecretKey,
        sender_public_key: &[u8],
    ) -> Result<Self, CommitmentError> {
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
        Ok(Self {
            commitment,
            cached_hash,
            tree,
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

    /// The Merkle tree behind this commitment.
    ///
    /// Used by the subtree-audit responder to plan a proof (select the
    /// nonce-determined branch and read its sibling cut-hashes).
    #[must_use]
    pub fn tree(&self) -> &MerkleTree {
        &self.tree
    }

    /// Inclusion path + leaf index for `key`, if it is in this
    /// commitment. Returns `None` if `key` is not committed.
    #[must_use]
    pub fn proof_for(&self, key: &XorName) -> Option<(Vec<[u8; 32]>, u32)> {
        let idx = self.tree.key_index(key)?;
        let path = self.tree.path_for(key)?;
        // u32 cast safe because MerkleTree::build rejects > MAX_COMMITMENT_KEY_COUNT.
        let leaf_index = u32::try_from(idx).unwrap_or(u32::MAX);
        Some((path, leaf_index))
    }

    /// Whether `key` is committed in this tree. Allocation-free membership
    /// check (binary search over the sorted leaf keys) — equivalent to
    /// `proof_for(key).is_some()` but without building the inclusion path, for
    /// hot callers (e.g. the pruner's `is_held` veto) that only need the
    /// boolean.
    #[must_use]
    pub fn contains_key(&self, key: &XorName) -> bool {
        self.tree.contains_key(key)
    }
}

/// Number of recently-gossiped commitments a responder stays answerable for
/// (ADR-0002 "you stay answerable for what you publish").
///
/// The auditor only ever pins a commitment it received via gossip, so retaining
/// the last two **actually-gossiped** commitments (plus the current one)
/// guarantees an honest node can always answer a pin the auditor could have
/// formed. Two — not one — absorbs the race where the auditor pins the
/// commitment a node published just before its newest one. Retention is keyed on
/// gossip emission, NOT on the rotation timer: a node that rebuilds its tree
/// faster than it gossips never drops a commitment it actually put on the wire,
/// so it is never wrongly failed for "unknown commitment hash".
const RETAINED_GOSSIPED_COMMITMENTS: usize = 2;

/// How long a gossiped commitment stays answerable after it was last put on the
/// wire. Retention (and therefore the pruner's `is_held` deletion veto) is
/// anchored to gossip emission, not to the rotation timer or to distinct-hash
/// churn: a commitment record expires this long after its last `mark_gossiped`,
/// even if the node keeps re-gossiping nothing new (the steady-state no-op
/// rotation case) or stops being responsible for all its keys.
///
/// Sized so it strictly dominates the longest realistic auditor pin lifetime —
/// well above the neighbor-sync gossip cadence and per-peer cooldown (≤1 h) —
/// while staying far below the prune hysteresis (days), so once a stale key
/// stops being gossiped the pruner reclaims it promptly. At
/// `RETAINED_GOSSIPED_COMMITMENTS = 2` this is `(2 + 1) ×` the 1 h rotation
/// interval = 3 h.
pub(crate) const GOSSIP_ANSWERABILITY_TTL: Duration = Duration::from_secs(3 * 3600);

/// Responder retention state (ADR-0002).
///
/// Keeps the current (latest-rotated) commitment plus every commitment whose
/// hash is among the last `RETAINED_GOSSIPED_COMMITMENTS` *gossiped* hashes.
/// A built-but-never-gossiped commitment is dropped on the next rotation unless
/// it gets gossiped. Rotation and gossip are the only paths that mutate this.
pub struct ResponderCommitmentState {
    inner: RwLock<Inner>,
}

/// A commitment hash that was emitted on the wire, with the wall-clock time it
/// was last gossiped. The `last_gossiped_at` is the answerability anchor: the
/// record (and any slot it retains) expires `GOSSIP_ANSWERABILITY_TTL` after
/// this instant, independent of rotation ticks or distinct-hash churn.
#[derive(Clone, Copy)]
struct GossipedAt {
    hash: [u8; 32],
    last_gossiped_at: Instant,
}

struct Inner {
    /// Newest-first. When `has_current` is true, `slots[0]` is the current
    /// (advertised) commitment; the rest — and, once retired, `slots[0]` too —
    /// are retained only because their hash is still in `recently_gossiped` and
    /// not yet expired.
    slots: Vec<Arc<BuiltCommitment>>,
    /// Whether `slots[0]` is the live, advertised current commitment. Set by
    /// `rotate`; cleared by `retire_current` (and when the slot set empties).
    /// When false, `current()` returns `None` — the node stops advertising and
    /// re-gossiping the stale root, so it ages out by its gossip TTL — while
    /// `lookup_by_hash` still answers any in-flight pin until then. This
    /// decouples ADVERTISE (gossiped as current, refreshes the TTL) from ANSWER
    /// (still resolvable during the TTL window).
    has_current: bool,
    /// The last `RETAINED_GOSSIPED_COMMITMENTS` commitments actually emitted on
    /// the wire, newest-first, each stamped with when it was last gossiped. A
    /// commitment is retained iff it is the live current one or its hash appears
    /// here with an unexpired stamp.
    recently_gossiped: Vec<GossipedAt>,
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
                slots: Vec::with_capacity(RETAINED_GOSSIPED_COMMITMENTS + 1),
                has_current: false,
                recently_gossiped: Vec::with_capacity(RETAINED_GOSSIPED_COMMITMENTS),
            }),
        }
    }

    /// Rotate: the freshly-rebuilt commitment becomes `current`. Slots that are
    /// neither the new current nor among the last gossiped hashes are dropped
    /// (a built-but-never-gossiped commitment does not linger).
    pub fn rotate(&self, new_current: BuiltCommitment) {
        let new_current = Arc::new(new_current);
        let mut guard = self.inner.write();
        guard.slots.insert(0, new_current);
        guard.has_current = true;
        prune_slots(&mut guard, Instant::now());
    }

    /// Retire the current commitment WITHOUT clearing retention: stop
    /// advertising it (so `current()` returns `None`, the gossip-emit sites stop
    /// re-emitting and re-stamping it, and it can age out by its gossip TTL),
    /// while keeping it answerable via `lookup_by_hash` for any in-flight pin a
    /// peer already formed — until that pin's gossip stamp expires.
    ///
    /// Called when the node has no key it is still responsible for: it must no
    /// longer claim to hold that data going forward, but must not strand a peer
    /// mid-audit on a root it gossiped moments ago. A never-gossiped current is
    /// simply dropped (nothing to stay answerable for).
    pub fn retire_current(&self) {
        let mut guard = self.inner.write();
        guard.has_current = false;
        prune_slots(&mut guard, Instant::now());
    }

    /// Record that `hash` was emitted on the wire (gossiped). Keeps the last
    /// `RETAINED_GOSSIPED_COMMITMENTS` gossiped hashes so the matching
    /// commitments stay answerable (ADR-0002). Call at every gossip-emit site.
    ///
    /// Re-gossiping a hash already present **refreshes** its answerability
    /// deadline to now and moves it to the front: every time the node actually
    /// puts a root on the wire — including re-emitting the current root in the
    /// steady-state no-op-rotation case — its retention legitimately extends.
    /// Conversely a root that stops being gossiped expires
    /// `GOSSIP_ANSWERABILITY_TTL` after its last emission, which is what lets
    /// an out-of-range key age out even when the no-op guard freezes the
    /// committed key set.
    pub fn mark_gossiped(&self, hash: [u8; 32]) {
        let now = Instant::now();
        let mut guard = self.inner.write();
        mark_gossiped_locked(&mut guard, hash, now);
    }

    /// Atomically snapshot the current commitment to advertise AND mark it
    /// gossiped, under a single lock. Returns the commitment to put on the wire,
    /// or `None` if there is no live current (never rotated, or retired).
    ///
    /// This is the ONLY correct way to gossip the current commitment: doing
    /// `current()` then a separate `mark_gossiped()` is a TOCTOU — a concurrent
    /// `retire_current`/`rotate` between the two could drop the slot, so the node
    /// would emit a root the responder no longer retains (a peer pinning it would
    /// get "unknown commitment hash" → false failure). Taking the snapshot and
    /// the stamp in one critical section guarantees anything emitted is
    /// simultaneously retained for its answerability TTL.
    #[must_use]
    pub fn current_for_gossip(&self) -> Option<Arc<BuiltCommitment>> {
        let now = Instant::now();
        let mut guard = self.inner.write();
        if !guard.has_current {
            return None;
        }
        let current = guard.slots.first().map(Arc::clone)?;
        mark_gossiped_locked(&mut guard, current.cached_hash, now);
        Some(current)
    }

    /// Atomically snapshot the current commitment to PIN IN A QUOTE and refresh
    /// its answerability, under a single lock. Returns the live current
    /// commitment, or `None` if there is no live current (never rotated, or
    /// retired) — in which case the caller must quote the baseline with no pin.
    ///
    /// ADR-0003 ("quoting is advertising"): issuing a quote that prices against
    /// the current commitment must extend that commitment's answerability
    /// exactly as gossiping it does, so a recently-quoted pin stays resolvable
    /// for its TTL and a peer auditing it cannot false-fail an honest node.
    /// This deliberately mirrors [`Self::current_for_gossip`]: same atomic
    /// snapshot-and-stamp, same TOCTOU-free guarantee that anything a quote can
    /// pin is simultaneously retained. It refreshes the CURRENT commitment only
    /// — a retired or merely-retained-but-not-current commitment is never
    /// returned here, so quote traffic can never keep a stale fat commitment
    /// alive (it can only be answered, via `lookup_by_hash`, until its own
    /// gossip/quote stamp lapses).
    #[must_use]
    pub fn current_for_quote(&self) -> Option<Arc<BuiltCommitment>> {
        let now = Instant::now();
        let mut guard = self.inner.write();
        if !guard.has_current {
            return None;
        }
        let current = guard.slots.first().map(Arc::clone)?;
        mark_gossiped_locked(&mut guard, current.cached_hash, now);
        Some(current)
    }

    /// Expire retention purely by the wall clock, without building, signing, or
    /// rotating anything. Call once per rotation tick so a gossiped commitment's
    /// answerability deadline advances even when the rotation no-op guard
    /// returns early (unchanged committed set) or when the node has no
    /// responsible keys to commit to. This is the time-driven half of the
    /// retention contract — without it, a frozen `recently_gossiped` entry would
    /// keep a stale key `is_held` forever.
    pub fn age_out(&self) {
        let mut guard = self.inner.write();
        prune_slots(&mut guard, Instant::now());
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

    /// Whether `key` is committed under any retained slot (the current
    /// commitment plus the last-2-gossiped ones) — i.e. whether a peer could
    /// still pin a recently gossiped root and demand this key's bytes in a
    /// round-2 byte challenge.
    ///
    /// This is the SAME predicate the round-2 responder uses to decide a key is
    /// "committed" (`handle_subtree_byte_challenge` calls `built.proof_for(key)`
    /// on the pinned slot, which is committed iff `contains_key`), folded over
    /// every retained slot. The pruner consults it before deleting an
    /// out-of-range key, so "the pruner will not delete it" and "the responder
    /// still owes an answer for it" are provably the same boolean and cannot
    /// drift. `slots` holds at most `RETAINED_GOSSIPED_COMMITMENTS` + 1
    /// commitments, and `contains_key` is an allocation-free binary search, so
    /// this is a short, allocation-free read.
    #[must_use]
    pub fn is_held(&self, key: &XorName) -> bool {
        self.inner.read().slots.iter().any(|c| c.contains_key(key))
    }

    /// Snapshot the current commitment to ADVERTISE, if any. Used by the gossip
    /// piggyback path: emit `state.current()` on the next outbound
    /// `NeighborSyncRequest`/`Response`. Returns `None` once the current
    /// commitment has been retired (the node has no responsible keys), so the
    /// node stops re-gossiping a stale root even though `lookup_by_hash` may
    /// still answer it during its remaining TTL.
    #[must_use]
    pub fn current(&self) -> Option<Arc<BuiltCommitment>> {
        let guard = self.inner.read();
        if guard.has_current {
            guard.slots.first().map(Arc::clone)
        } else {
            None
        }
    }

    /// Number of commitment slots currently retained (the current commitment
    /// plus any still-answerable recently-gossiped ones). Used only for the
    /// v12 `commitment_rotated` event's `retained_slots` field; carries no
    /// behavioural meaning.
    #[must_use]
    pub fn retained_slot_count(&self) -> usize {
        self.inner.read().slots.len()
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
        let mut guard = self.inner.write();
        guard.slots.clear();
        guard.has_current = false;
        guard.recently_gossiped.clear();
    }
}

/// ADR-0003: the responder commitment state is the quote generator's commitment
/// source. `current_binding_for_quote` snapshots the live current commitment's
/// `(key_count, pin)` and refreshes its answerability in one atomic step (via
/// [`ResponderCommitmentState::current_for_quote`]), so a quote that prices
/// against the current commitment keeps it answerable for its TTL.
impl crate::payment::quote::CommitmentSource for ResponderCommitmentState {
    fn current_binding_for_quote(&self) -> Option<crate::payment::quote::QuoteBinding> {
        self.current_for_quote()
            .map(|built| crate::payment::quote::QuoteBinding {
                key_count: built.commitment().key_count,
                pin: built.hash(),
            })
    }

    fn commitment_blob_for_pin(&self, pin: [u8; 32]) -> Option<Vec<u8>> {
        // rmp-encode the `StorageCommitment` itself — the EXACT form the storer's
        // `index_valid_sidecars` deserializes (`rmp_serde::from_slice::<StorageCommitment>`),
        // so a sidecar shipped here resolves identically to one fetched via
        // `GetCommitmentByPin`. Only retained pins resolve; a rotated-out pin
        // yields `None` and the response simply carries no commitment.
        let built = self.lookup_by_hash(&pin)?;
        rmp_serde::to_vec(built.commitment()).ok()
    }
}

/// Enforce retention as of `now`: first expire any gossip record older than
/// `GOSSIP_ANSWERABILITY_TTL`, then keep the live current slot (only while
/// `has_current`) and any slot whose hash is still among the unexpired
/// recently-gossiped hashes; drop the rest. Idempotent; preserves newest-first
/// order. This is the single place retention is enforced.
///
/// The current-slot exemption is conditional on `has_current`: once the current
/// commitment is retired (no responsible keys), `slots[0]` is no longer exempt
/// and ages out by its own gossip TTL exactly like any other retained slot —
/// the fix that stops a stale, continuously-re-gossiped current from pinning its
/// keys forever.
/// Stamp `hash` as gossiped at `now` (newest-first, de-duplicated, bounded to
/// `RETAINED_GOSSIPED_COMMITMENTS`) and re-run retention. Shared by
/// `mark_gossiped` and `current_for_gossip` so the snapshot-and-stamp can be one
/// critical section.
fn mark_gossiped_locked(inner: &mut Inner, hash: [u8; 32], now: Instant) {
    inner.recently_gossiped.retain(|g| g.hash != hash);
    inner.recently_gossiped.insert(
        0,
        GossipedAt {
            hash,
            last_gossiped_at: now,
        },
    );
    inner
        .recently_gossiped
        .truncate(RETAINED_GOSSIPED_COMMITMENTS);
    prune_slots(inner, now);
}

fn prune_slots(inner: &mut Inner, now: Instant) {
    // 1. TTL-expire gossip records first (the answerability anchor). A record
    //    whose last gossip is older than the window no longer keeps anything
    //    answerable, regardless of distinct-hash churn or rotation ticks.
    inner
        .recently_gossiped
        .retain(|g| now.duration_since(g.last_gossiped_at) < GOSSIP_ANSWERABILITY_TTL);

    // 2. Keep the live current slot (only while has_current) + any slot still
    //    covered by an unexpired record. Snapshot the live hashes first to avoid
    //    borrowing `inner` twice (both collections are at most
    //    RETAINED_GOSSIPED_COMMITMENTS + 1 long).
    let live: Vec<[u8; 32]> = inner.recently_gossiped.iter().map(|g| g.hash).collect();
    let has_current = inner.has_current;
    let mut idx = 0usize;
    inner.slots.retain(|c| {
        let keep = (has_current && idx == 0) || live.contains(&c.cached_hash);
        idx += 1;
        keep
    });
    // If nothing remains, there is no current slot to advertise.
    if inner.slots.is_empty() {
        inner.has_current = false;
    }
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
        state.mark_gossiped(h1); // gossiped → retained across the next rotation
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &peer_id, &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        state.mark_gossiped(h2);

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

        // c1 was never gossiped, so the next rotation (a new current) drops it
        // from the retention buffer.
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        state.rotate(c2);
        assert!(state.lookup_by_hash(&h1).is_none());

        // But the in-flight Arc still works (INV: Arc keeps it alive).
        assert_eq!(in_flight.hash(), h1);
        assert!(in_flight.proof_for(&key(1)).is_some());
    }

    #[test]
    fn gossiped_commitment_stays_answerable_across_rotations() {
        // ADR-0002: a commitment that was actually gossiped stays answerable
        // even after rotation, until it falls out of the last-2-gossiped window.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1); // we put c1 on the wire

        // Rotate to c2 and gossip it. c1 is still within the last-2-gossiped.
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        state.mark_gossiped(h2);
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "c1 must stay answerable"
        );
        assert!(state.lookup_by_hash(&h2).is_some());

        // Rotate to c3 and gossip it. Now the last-2-gossiped are {h3, h2};
        // h1 has fallen out of the window and is dropped.
        let c3 = BuiltCommitment::build(vec![(key(3), bh(3))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h3 = c3.hash();
        state.rotate(c3);
        state.mark_gossiped(h3);
        assert!(
            state.lookup_by_hash(&h1).is_none(),
            "c1 aged out of gossip window"
        );
        assert!(state.lookup_by_hash(&h2).is_some());
        assert!(state.lookup_by_hash(&h3).is_some());
    }

    #[test]
    fn current_plus_last_two_gossiped_are_simultaneously_answerable() {
        // ADR-0002 "Two, not one": the retention depth must keep BOTH of the
        // last two gossiped commitments answerable at the same time, alongside
        // the current one. This is the property that "absorbs the race where an
        // auditor asks about the commitment a node published just before its
        // newest one". The existing across-rotations test only ever checks two
        // hashes at once; this one proves three DISTINCT commitments are live
        // simultaneously and that the third-oldest gossiped root is dropped —
        // i.e. RETAINED_GOSSIPED_COMMITMENTS is exactly 2, not 1 and not 3.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        // Gossip three commitments in order: c1, c2, c3. After this the current
        // slot is c3 and the last-two-gossiped are {h3, h2}. But c2 and c1 also
        // need to be checked relative to the window: once c3 is gossiped, the
        // window is {h3, h2}; c1 (the 3rd-oldest gossiped) must be gone.
        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1);

        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        state.mark_gossiped(h2);

        // At this moment: current = c2, last-2-gossiped = {h2, h1}. Both the
        // current AND the previously-gossiped c1 must be answerable — the "two,
        // not one" race window. c1 is the commitment "published just before the
        // newest one" and an auditor may still pin it.
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "the commitment published just before the newest one must stay answerable"
        );
        assert!(
            state.lookup_by_hash(&h2).is_some(),
            "current must be answerable"
        );
        assert_ne!(h1, h2, "the two retained commitments must be distinct");

        // Now gossip a third distinct commitment c3. Window becomes {h3, h2}.
        // c3 (current) + c2 + c1: c1 must now be dropped (3rd-oldest gossiped),
        // while c2 and c3 remain. This proves depth is exactly 2 beyond... no:
        // depth is 2 gossiped TOTAL including current's hash once gossiped.
        let c3 = BuiltCommitment::build(vec![(key(3), bh(3))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h3 = c3.hash();
        state.rotate(c3);
        state.mark_gossiped(h3);

        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
        assert!(
            state.lookup_by_hash(&h3).is_some(),
            "current (c3) answerable"
        );
        assert!(
            state.lookup_by_hash(&h2).is_some(),
            "c2 (published just before newest) answerable — the race-absorbing slot"
        );
        assert!(
            state.lookup_by_hash(&h1).is_none(),
            "c1 is the 3rd-oldest gossiped root and MUST be dropped — depth is exactly 2"
        );
    }

    #[test]
    fn is_held_tracks_keys_across_the_retention_window_and_ages_them_out() {
        // The pruner's deletion veto relies on `is_held`: a key committed under
        // ANY retained slot (current + last-2-gossiped) must read held, and must
        // stop reading held once its commitment ages out of the window — that is
        // the bounded reprieve, not a permanent pin. This mirrors the
        // round-2 responder's `built.proof_for(key).is_some()` check folded over
        // the slots, so "pruner won't delete" == "responder owes an answer".
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        // c1 commits to key(1). Gossip it -> key(1) is held (current slot).
        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1);
        assert!(
            state.is_held(&key(1)),
            "freshly committed+gossiped key is held"
        );
        assert!(!state.is_held(&key(99)), "never-committed key is not held");

        // c2 commits to key(2) only (key(1) dropped from the new commitment,
        // e.g. it went out of range). key(1) must STILL be held via the retained
        // previous gossiped slot (the race-absorbing window), and key(2) too.
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        state.mark_gossiped(h2);
        assert!(
            state.is_held(&key(1)),
            "key dropped from the newest commitment is still held via the previous gossiped slot"
        );
        assert!(state.is_held(&key(2)), "newly committed key is held");

        // c3 commits to key(3). Window becomes {h3, h2}; h1 ages out, so key(1)
        // is no longer held anywhere -> the pruner may now reclaim it.
        let c3 = BuiltCommitment::build(vec![(key(3), bh(3))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h3 = c3.hash();
        state.rotate(c3);
        state.mark_gossiped(h3);
        assert!(
            !state.is_held(&key(1)),
            "key whose commitments all aged out of the retention window is no longer held"
        );
        assert!(
            state.is_held(&key(2)),
            "key(2) still held via the previous gossiped slot"
        );
        assert!(state.is_held(&key(3)), "current key held");
    }

    /// Build a `BuiltCommitment` over the given keys for use in raw `prune_slots`
    /// tests (each key's `bytes_hash` is `bh(k[0])`).
    fn built(keys: &[u8]) -> BuiltCommitment {
        let (pk, sk) = keypair();
        let entries: Vec<_> = keys.iter().map(|&b| (key(b), bh(b))).collect();
        BuiltCommitment::build(entries, &[0; 32], &sk, &pk.to_bytes()).unwrap()
    }

    #[test]
    fn stale_gossip_record_expires_by_ttl_even_without_new_distinct_gossip() {
        // Frozen-retention-window regression: the no-op-rotation guard can freeze
        // `recently_gossiped` (no new distinct hash is ever gossiped once the
        // responsible key set stabilizes). The retention window must still age a
        // stale gossiped commitment out by the WALL CLOCK, so its key stops
        // being `is_held` and the pruner can reclaim it. Driven directly through
        // `prune_slots(now)` with a synthetic clock so it is deterministic.
        let c_current = Arc::new(built(&[1])); // root over key(1) — current
        let c_stale = Arc::new(built(&[2])); // root over key(2) — out-of-range, only retained via gossip
        let h_current = c_current.hash();
        let h_stale = c_stale.hash();

        // Synthetic clock: stamps anchor at `base` and the prune evaluates at a
        // FUTURE `now` (adding to an `Instant` never underflows, unlike
        // subtracting a TTL from a fresh Windows monotonic clock). The stale
        // record was last gossiped just over the TTL before `now`; the current
        // record was gossiped at `now`. This is exactly the frozen-window state:
        // current keeps being re-gossiped (refreshing its stamp) while the stale
        // root is never gossiped again.
        let base = Instant::now();
        let now = base + GOSSIP_ANSWERABILITY_TTL + Duration::from_secs(1);
        let mut inner = Inner {
            slots: vec![Arc::clone(&c_current), Arc::clone(&c_stale)],
            has_current: true,
            recently_gossiped: vec![
                GossipedAt {
                    hash: h_current,
                    last_gossiped_at: now,
                },
                GossipedAt {
                    hash: h_stale,
                    last_gossiped_at: base,
                },
            ],
        };

        prune_slots(&mut inner, now);

        // The stale record (and its slot) must be gone; the current one stays.
        assert!(
            inner.recently_gossiped.iter().all(|g| g.hash != h_stale),
            "stale gossip record past its TTL must expire"
        );
        assert_eq!(inner.slots.len(), 1, "the stale slot must be dropped");
        assert_eq!(inner.slots[0].hash(), h_current, "current slot retained");
        // key(2) — committed only under the now-expired stale slot — is no
        // longer held, so the pruner may reclaim it. key(1) stays held.
        assert!(
            inner.slots.iter().all(|c| c.proof_for(&key(2)).is_none()),
            "stale key is no longer held once its commitment ages out"
        );
        assert!(
            inner.slots.iter().any(|c| c.proof_for(&key(1)).is_some()),
            "current key still held"
        );
    }

    #[test]
    fn recent_gossip_record_stays_answerable_within_ttl() {
        // Early-drop regression: a commitment gossiped recently (within the TTL)
        // must remain answerable even if it is no longer the current root — a
        // peer may still have pinned it. `prune_slots` must NOT drop it early.
        let c_current = Arc::new(built(&[1]));
        let c_prev = Arc::new(built(&[2]));
        let h_current = c_current.hash();
        let h_prev = c_prev.hash();

        // Synthetic clock (forward-only, see the stale-expiry test above).
        let base = Instant::now();
        let now = base + GOSSIP_ANSWERABILITY_TTL / 2;
        let mut inner = Inner {
            slots: vec![Arc::clone(&c_current), Arc::clone(&c_prev)],
            has_current: true,
            recently_gossiped: vec![
                GossipedAt {
                    hash: h_current,
                    last_gossiped_at: now,
                },
                GossipedAt {
                    // Gossiped a while ago, but still comfortably within the TTL.
                    hash: h_prev,
                    last_gossiped_at: base,
                },
            ],
        };

        prune_slots(&mut inner, now);

        assert_eq!(
            inner.slots.len(),
            2,
            "a commitment gossiped within the TTL must stay answerable (the 'two, not one' race window)"
        );
        assert!(
            inner.slots.iter().any(|c| c.hash() == h_prev),
            "the recently-gossiped previous commitment must not be dropped early"
        );
    }

    #[test]
    fn retire_current_hides_current_but_keeps_recent_pin_answerable() {
        // Retire-current regression: retiring the current commitment (no responsible
        // keys) must STOP advertising it (current() -> None, so the gossip loop
        // stops re-stamping it) while keeping it answerable for an in-flight pin.
        let state = ResponderCommitmentState::new();
        let c1 = built(&[1]);
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1);

        assert!(state.current().is_some(), "fresh current is advertised");

        state.retire_current();

        assert!(
            state.current().is_none(),
            "retired current must not be advertised (stops the gossip loop re-stamping it)"
        );
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "retired current stays answerable for an in-flight pin within its TTL"
        );
        assert!(
            state.is_held(&key(1)),
            "its keys are still held while answerable, so the pruner still vetoes them"
        );
    }

    #[test]
    fn retired_current_ages_out_by_gossip_ttl() {
        // The retired current must age out by its gossip TTL — the exact fix for
        // the stale-current permanent pin: its record is never refreshed (not
        // advertised), so once the TTL lapses prune_slots drops it.
        let c1 = Arc::new(built(&[1]));
        let h1 = c1.hash();
        // Synthetic clock (forward-only, see the stale-expiry test above).
        let base = Instant::now();
        let now = base + GOSSIP_ANSWERABILITY_TTL + Duration::from_secs(1);
        let mut inner = Inner {
            slots: vec![Arc::clone(&c1)],
            has_current: false, // already retired
            recently_gossiped: vec![GossipedAt {
                hash: h1,
                last_gossiped_at: base,
            }],
        };

        prune_slots(&mut inner, now);

        assert!(
            inner.slots.is_empty(),
            "retired current past its TTL is dropped"
        );
        assert!(!inner.has_current);
        assert!(
            inner.slots.iter().all(|c| c.proof_for(&key(1)).is_none()),
            "its key is no longer held -> pruner reclaims it"
        );
    }

    #[test]
    fn retired_current_stays_answerable_within_ttl() {
        // A retired current within its TTL must remain answerable (not dropped).
        let c1 = Arc::new(built(&[1]));
        let h1 = c1.hash();
        // Synthetic clock (forward-only, see the stale-expiry test above).
        let base = Instant::now();
        let now = base + GOSSIP_ANSWERABILITY_TTL / 2;
        let mut inner = Inner {
            slots: vec![Arc::clone(&c1)],
            has_current: false, // retired
            recently_gossiped: vec![GossipedAt {
                hash: h1,
                last_gossiped_at: base,
            }],
        };

        prune_slots(&mut inner, now);

        assert_eq!(
            inner.slots.len(),
            1,
            "retired-but-recent current stays answerable"
        );
        assert_eq!(inner.slots[0].hash(), h1);
    }

    #[test]
    fn re_acquire_after_retire_advertises_fresh_current_without_resurrecting_stale() {
        // Re-acquire path: a node retires its current (went out of range), then
        // becomes responsible again and rotates a fresh commitment. The fresh
        // one must become the advertised current; the retired one must only
        // linger as a retained (answerable) slot if still gossiped+unexpired,
        // never resurrect as current.
        let state = ResponderCommitmentState::new();
        let c1 = built(&[1]);
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1); // gossiped, so it stays answerable after retire
        state.retire_current();
        assert!(state.current().is_none());

        // Become responsible again: rotate a fresh commitment.
        let c2 = built(&[2]);
        let h2 = c2.hash();
        state.rotate(c2);
        state.mark_gossiped(h2);

        let cur = state
            .current()
            .expect("fresh current advertised after re-acquire");
        assert_eq!(
            cur.hash(),
            h2,
            "the FRESH commitment is current, not the retired one"
        );
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "the retired-but-recently-gossiped commitment is still answerable as a retained slot"
        );
        assert!(
            state.is_held(&key(1)),
            "retired key still held within its TTL"
        );
        assert!(state.is_held(&key(2)), "fresh current key held");
    }

    #[test]
    fn retire_current_drops_ungossiped_current() {
        // A current that was never gossiped has nothing to stay answerable for,
        // so retiring it drops it outright (no lookup, no current).
        let state = ResponderCommitmentState::new();
        let c1 = built(&[1]);
        let h1 = c1.hash();
        state.rotate(c1); // built but NOT gossiped

        state.retire_current();

        assert!(state.current().is_none(), "no current after retire");
        assert!(
            state.lookup_by_hash(&h1).is_none(),
            "an ungossiped retired current is not answerable (nothing to retain)"
        );
        assert!(!state.is_held(&key(1)));
    }

    #[test]
    fn ungossiped_rebuild_does_not_evict_gossiped_commitment() {
        // The rebuild-faster-than-gossip case: a node rebuilds (rotates) several
        // times without gossiping. The last *gossiped* commitment must remain
        // answerable so the node is not wrongly failed for "unknown hash".
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1);

        // Several ungossiped rebuilds.
        for i in 2..=6u8 {
            let c =
                BuiltCommitment::build(vec![(key(i), bh(i))], &[0; 32], &sk, &pk_bytes).unwrap();
            state.rotate(c);
        }
        // h1 was gossiped and is still within the last-2-gossiped window
        // (nothing else was gossiped), so it must still be answerable.
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "gossiped commitment must survive ungossiped rebuilds"
        );
    }

    // === ADR-0003: current_for_quote (quote-issuance answerability) ===

    use crate::payment::quote::CommitmentSource;

    #[test]
    fn current_for_quote_returns_current_binding_and_is_current_only() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let state = ResponderCommitmentState::new();

        // No current yet -> baseline (None).
        assert!(state.current_binding_for_quote().is_none());

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &peer_id, &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1);
        let c2 = BuiltCommitment::build(
            vec![(key(2), bh(2)), (key(3), bh(3))],
            &peer_id,
            &sk,
            &pk_bytes,
        )
        .unwrap();
        let h2 = c2.hash();
        state.rotate(c2);

        // current_for_quote returns the CURRENT (c2) binding, never the
        // previous (c1) — a quote may pin only the live current commitment.
        let binding = state
            .current_binding_for_quote()
            .expect("current binding present");
        assert_eq!(
            binding.pin, h2,
            "must bind the current commitment, not previous"
        );
        assert_eq!(binding.key_count, 2, "current commitment's key count");
        assert_ne!(
            binding.pin, h1,
            "must never pin the retired/previous commitment"
        );
    }

    #[test]
    fn current_for_quote_refreshes_answerability() {
        // Issuing a quote must refresh the current commitment's answerability,
        // exactly like gossiping it (ADR-0003 "quoting is advertising").
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &peer_id, &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        // NOT gossiped; instead "quote" it. The quote-issuance refresh must make
        // it answerable just as a gossip emission would.
        let binding = state.current_binding_for_quote().expect("binding");
        assert_eq!(binding.pin, h1);
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "a quoted current pin must be answerable (issuance refreshed retention)"
        );
    }

    #[test]
    fn retired_current_cannot_be_quoted() {
        // After retire_current (node has no responsible keys), there is no live
        // current commitment, so current_for_quote yields baseline — a retired
        // commitment can never be newly quoted.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &peer_id, &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1);
        state.retire_current();

        assert!(
            state.current_binding_for_quote().is_none(),
            "a retired current commitment must not be quotable"
        );
        // ...but it stays answerable for any in-flight pin until its TTL lapses.
        assert!(state.lookup_by_hash(&h1).is_some());
    }
}
