# Storage-Bound Audit via Gossip-Embedded Commitments — v2

**Status:** Draft for adversarial review (round 2).
**Previous:** v1 review found 1 BLOCKER + 4 MAJORs. All addressed below.
**Scope:** Closes Findings 1 and 2 (`notes/security-findings-2026-05-22/`).

## Changes vs v1

| # | v1 issue (codex) | v2 fix |
|---|---|---|
| 1 | BLOCKER: root not epoch-bound; same root replayable forever | Leaf now binds to a **network-wide `global_epoch`** that all nodes derive identically; re-signing an old root produces stale leaves whose paths fail proof verification |
| 2 | MAJOR: peer credited as holder of K without proving K is in commitment | Holder status for K now requires either an inline commitment proof at audit OR a cached successful commitment-bound audit for K |
| 3 | MAJOR: downgrade escape — peer pretends to be old-version | Capability is sticky: once a peer has gossiped any commitment, any later `Digests`-only response to a commitment-required challenge is a hard audit failure |
| 4 | MAJOR: ML-DSA verify DoS on inbound gossip | Sig verify is gated behind sender-in-routing-table admission + cheap structural checks; one outstanding verify per peer |
| 5 | MAJOR: commitment is replayable signed blob | State updates are keyed on the authenticated transport sender; epochs must be strictly monotonic per peer; duplicate roots rejected |
| 6 | MINOR: signature lacks canonical encoding + domain tag | Signature is over a canonical serialized struct with explicit `"autonomi.ant.replication.storage_commitment.v1"` domain separation tag |

## Design constraints (unchanged from v1)

1. Lightweight — minimal new state.
2. Stateless at auditor — no per-peer caches an attacker can fill.
3. Reuse existing infra — extend `NeighborSyncRequest`/`Response` + `AuditChallenge`/`Response`.
4. Acceptable to make freeriding more expensive than storing; not required to make it impossible.

## Threat model recap

Same as v1: today's `BLAKE3(nonce || peer_id || key || bytes)` digest proves knowledge of bytes at challenge time, not durable storage. Defeats audit + enables prune-confirmation forgery. The fix must bind responses to *prior* possession at a moment the responder couldn't predict.

## Core idea (revised)

Each node publishes a **storage commitment** every epoch. A commitment is a Merkle root over leaves of the form

```text
leaf_i = BLAKE3("autonomi.ant.replication.storage_leaf.v1" || global_epoch || K_i || BLAKE3(record_bytes_i))
```

Crucially, `global_epoch` is **not** picked by the responder. It is derived deterministically by all nodes from a shared, network-wide source (see §1 for the source choice). A re-signed old root has stale leaves (different `global_epoch`), so the path verification against any new root fails — closing the v1 replay attack.

Auditors verify path-to-root AND that the commitment's `global_epoch` is current. Lazy node options:

- Don't gossip → silent peer, excluded from reward eligibility (see §5).
- Gossip a real commitment → had to recompute leaves with current `global_epoch` over actual bytes. Required possession at this epoch.
- Gossip a fake/stale commitment → epoch mismatch rejected at gossip-receive, OR path verification fails at audit.

## Protocol

### 1. The `global_epoch`

Every node computes the same `global_epoch` deterministically. Options, simplest first:

**Option A — wall-clock slot.** `global_epoch = floor(now_seconds / EPOCH_DURATION_SECS)` where `EPOCH_DURATION_SECS = 3600` (1 hour). Acceptable clock skew: ±5 min (covered by accepting the previous epoch's root for a `GRACE_SLOTS=1` window).

**Option B — saorsa-core sync-cycle epoch.** If saorsa-core already maintains a per-node sync epoch counter that's gossiped (it does — `cycles_since_sync` in `PeerSyncRecord`), tie to that. Simpler but more coupling.

**Proposed: A.** No new gossip channel, no coupling to internal counters. Clock skew is the only failure mode and we already require loose clock sync via QUIC / NTP.

A node accepts a commitment if `commitment.global_epoch ∈ {current_epoch, current_epoch - 1}` at receive time. This 1-slot grace absorbs reasonable clock skew without opening a multi-hour replay window.

### 2. Commitment

```rust
pub struct StorageCommitment {
    /// Network-wide epoch (see §1). Encoded as u64 little-endian.
    pub global_epoch: u64,
    /// Sender peer ID. Bound to the signature.
    pub sender_peer_id: [u8; 32],
    /// Merkle root over sorted leaves: BLAKE3(DOMAIN_LEAF || global_epoch || K_i || BLAKE3(record_bytes_i)).
    pub root: [u8; 32],
    /// Number of leaves committed over.
    pub key_count: u32,
    /// ML-DSA-65 over canonical encoding of (DOMAIN_COMMITMENT, global_epoch, sender_peer_id, root, key_count).
    pub signature: MlDsaSignature,
}
```

Constants:
- `DOMAIN_COMMITMENT = b"autonomi.ant.replication.storage_commitment.v1"`
- `DOMAIN_LEAF = b"autonomi.ant.replication.storage_leaf.v1"`

Canonical encoding: `postcard` (already used for wire types). All multi-byte fields little-endian; domain tags length-prefixed.

In-memory Merkle tree, rebuilt every `EPOCH_DURATION_SECS / 4` (15 min default) — debounced when the key set changes. Tree is **not persisted**; reconstructable from LMDB at boot.

### 3. Gossip — extended `NeighborSyncRequest`/`Response`

```rust
pub struct NeighborSyncRequest {
    pub replica_hints: Vec<XorName>,
    pub paid_hints: Vec<XorName>,
    pub bootstrapping: bool,
    // NEW:
    pub commitment: Option<StorageCommitment>,
}
// (analogous for NeighborSyncResponse)
```

**Receive-side processing (DoS-hardened — addresses v1 MAJOR #4):**

1. Structural validation only (cheap): is `commitment` present? Is `global_epoch` within `{current_epoch, current_epoch - 1}`? Is `sender_peer_id` the same as the authenticated transport peer? Is `key_count > 0`?
   - Any failure: drop commitment silently, continue processing other fields. **No signature verification.**
2. Sender admission (cheap): is the authenticated transport peer in our routing table?
   - If not: drop commitment, continue. **No signature verification for non-RT peers.**
3. Per-peer rate limit: have we verified a commitment from this peer in the last `MIN_VERIFY_INTERVAL = 60s`?
   - If yes: drop, continue.
4. Monotonicity (addresses v1 MAJOR #5): is `commitment.global_epoch > peer_state.last_seen_epoch`?
   - If not: drop. Stale or replayed commitments from the same peer are rejected.
5. **Only now**: verify the ML-DSA-65 signature.
6. On verify success: update `peer_state.last_commitment_root = Some((received_at, root, global_epoch))`. Update `last_seen_epoch = global_epoch`.

Cost ceiling per peer per minute: 1 ML-DSA-65 verify. Total CPU ceiling: |RT peers| × 1 verify/min ≈ ~20 verifies/min for typical RTs — negligible.

### 4. Commitment-bound audit response

```rust
pub struct AuditChallenge {
    pub challenge_id: u64,
    pub nonce: [u8; 32],
    pub challenged_peer_id: [u8; 32],
    pub keys: Vec<XorName>,
    // NEW:
    pub require_commitment_proof: bool,
}

pub enum AuditResponse {
    Digests { ... },             // existing
    Bootstrapping { ... },       // existing
    Rejected { ... },            // existing
    // NEW:
    CommitmentBound {
        challenge_id: u64,
        commitment: StorageCommitment,
        per_key: Vec<CommitmentBoundResult>,
    },
}

pub struct CommitmentBoundResult {
    pub key: XorName,
    pub digest: [u8; 32],                 // BLAKE3(nonce || peer_id || key || bytes) — unchanged
    pub bytes_hash: [u8; 32],             // BLAKE3(record_bytes) — auditor uses to rebuild leaf
    pub path: Vec<[u8; 32]>,              // Merkle inclusion path from leaf to commitment.root
}
```

### 5. Auditor logic — stateless probabilistic choice

When `audit_tick` selects peer P for audit:

1. Read `peer_state.last_commitment_root` for P from the in-memory `PeerSyncRecord` extension.
2. If `None` OR older than `MAX_COMMITMENT_AGE = 2 * EPOCH_DURATION_SECS`: **the peer claims no keys.** Set `require_commitment_proof = false`; treat their response only as a digest check, AND mark them ineligible for reward credit / quorum holder status (§6).
3. Otherwise, with `p_commitment = 1.0` (always — see "Auditor must commitment-audit if possible" below): set `require_commitment_proof = true` and challenge with sampled keys.

**Why p_commitment = 1.0 (changed from v1's 0.7):** v1 mixed commitment-bound and plain digest audits randomly. Codex MAJOR #3 noted that a peer who has *ever* gossiped commitment must not be allowed to escape commitment-bound auditing. So if we *can* commitment-audit (we have a recent root), we always do. Plain `Digests`-only audits are used only for peers that haven't yet gossiped (still in §6's "no rewards" bucket).

On receiving an `AuditResponse`:

- `CommitmentBound`: verify (a) `commitment.global_epoch` matches the gossiped one we have stored, (b) signature, (c) for each key: rebuild `leaf = BLAKE3(DOMAIN_LEAF || global_epoch || key || bytes_hash)`, verify Merkle path to `commitment.root`, then verify `digest` against the auditor's own copy of `bytes_hash` (auditor only audits keys it holds — same as today). All three must pass.
- `Digests` when `require_commitment_proof = true`: **hard audit failure**, `AUDIT_FAILURE_TRUST_WEIGHT` per key. Addresses v1 MAJOR #3.
- `Bootstrapping`: see §7.

Auditor stores nothing new during the audit. The only persistent (in-memory) state is `last_commitment_root` per peer, which §3 already populates.

### 6. Holder eligibility — addresses v1 MAJOR #2

A peer P is credited as a holder of K (for replication quorum, paid-list verification, reward purposes) only if **both**:

- P has gossiped a recent valid `StorageCommitment` (within `MAX_COMMITMENT_AGE`).
- P has either:
  - successfully responded to a commitment-bound audit for K (within `HOLDER_PROOF_CACHE_AGE = 2 * EPOCH_DURATION_SECS`, tracked as a small per-key set of {peer_id, last_proof_epoch} — bounded by `audit_sample_count(stored_chunks)` per epoch, ~sqrt of stored keys), OR
  - included K in a commitment-bound audit we issued during P's current commitment epoch.

A peer that's gossiped but has not (yet) proven K is *not yet* counted as a holder of K. The audit cycle drives the proof; once a key is proven, the proof is cached for `HOLDER_PROOF_CACHE_AGE`. Lazy nodes that commit only to a subset of claimed keys cannot earn rewards for un-committed keys — closing the overclaim attack.

Memory cost: per-key set of recent provers. `audit_sample_count(N) = sqrt(N)`. For a node holding 10k keys and a network of 10k peers, ≤ 10k * 100 / 10k = 100 entries per peer. Bounded.

### 7. Closing Finding 2 (Bootstrap claim shield)

When responder returns `Bootstrapping`:

- If `peer_state.last_commitment_root.is_some()` AND recent: the peer has previously claimed storage. `Bootstrapping` here is a lie. Treat as `AUDIT_FAILURE_TRUST_WEIGHT` per-key, exactly like a digest mismatch. This costs no new state — uses §3's existing record.
- Otherwise (fresh peer never gossiped commitment): treat as legitimate, no penalty, no reward credit (per §6, they're not earning anyway).

### 8. Backwards compatibility

- `commitment: Option<...>` — old peers send `None`, new peers send `Some`. No wire break.
- `require_commitment_proof` — old responders ignore (their decode of the new wire field defaults to `false`); they keep returning `Digests`. New auditors handle both.
- **Capability is sticky (addresses MAJOR #3):** the *first* `Some` commitment we ever see from a peer flips `peer_state.commitment_capable = true`. From then on, any `Digests` response from that peer to a `require_commitment_proof = true` challenge is a hard audit failure. This makes downgrade infeasible — you can't go back to pretending to be old once you've spoken the new protocol.
- Reward exclusion (§6) applies to peers whose `commitment_capable = true` AND who fail to provide a proof. For peers we've never seen gossip from, they're treated like fresh peers (full audit cycle to learn their capability). To avoid permanent fresh-peer exemption: combine with the existing `cycles_since_sync >= 1` `has_repair_opportunity` check — a peer that's been around for any reasonable time without ever gossiping a commitment is suspicious and gets soft-excluded.

### 9. Backwards compatibility — flag day plan

Rollout in two stages:

**Stage 1 (informational, no enforcement):**
- Nodes start gossiping commitments.
- Auditors record `last_commitment_root` and verify, but `require_commitment_proof` is forced to `false` regardless of capability. No reward exclusion.
- This stage establishes the `commitment_capable` baseline across the fleet.

**Stage 2 (enforcement):**
- When fleet majority is observed `commitment_capable`, flip the flag. Auditors set `require_commitment_proof = true` for capable peers, and apply §6's reward exclusion.
- Backwards-compatible peers (genuinely old version) continue to be tolerated but earn nothing — exactly the silent-peer treatment.

## State summary

| Where | What | Size | Note |
|---|---|---|---|
| Responder (this node) | Merkle tree over claimed keys | ~32 bytes × leaves × 2 | In-memory, rebuilt per epoch, reconstructable from LMDB |
| Responder | Cached signed commitment | ~3.4 KB | One per epoch |
| Per-RT-peer record (auditor side, on `PeerSyncRecord`) | `last_commitment_root: Option<(Instant, [u8;32], u64)>` + `last_seen_epoch: u64` + `commitment_capable: bool` | ~64 bytes × RT peers | Bounded by routing table size |
| Per-key prover cache (§6) | `{peer_id, last_proof_epoch}` set | bounded by sqrt(stored_keys) per peer × #peers | Aged out after `HOLDER_PROOF_CACHE_AGE` |

No persistent disk state. All recoverable from LMDB + a network round.

## Wire format precision (addresses v1 MINOR #6)

Domain separation tags are byte-exact:
- Commitment signature: `b"autonomi.ant.replication.storage_commitment.v1"`
- Merkle leaf hash: `b"autonomi.ant.replication.storage_leaf.v1"`
- Tree internal nodes: `BLAKE3("autonomi.ant.replication.storage_node.v1" || left || right)`

Sign-bytes layout (postcard-encoded):

```text
DOMAIN_COMMITMENT (length-prefixed bytes)
|| global_epoch (u64 LE)
|| sender_peer_id (32 bytes)
|| root (32 bytes)
|| key_count (u32 LE)
```

Postcard handles framing deterministically; no hand-rolled concatenation ambiguity.

## DoS analysis (addresses v1 MAJOR #4)

| Vector | Mitigation |
|---|---|
| Flood unsigned commitments from non-RT peers | Sender-in-RT check happens before sig verify |
| Flood signed commitments from many Sybil RT entries | Per-peer rate limit `MIN_VERIFY_INTERVAL = 60s` |
| Replay old commitment from same peer | Monotonic epoch per peer |
| Replay old commitment from someone else's gossip | `sender_peer_id` in commitment must match authenticated transport peer |
| Audit response with bogus signature | Same cheap structural checks before sig verify |
| Audit response with bogus Merkle paths | Hashing only; bounded by audit sample size (`sqrt(N)`) |

## Open questions for review round 2

(a) Is `global_epoch = floor(now / 1h)` simple enough or should we tie to saorsa-core's sync-cycle counter to remove the wall-clock dependency entirely?

(b) The §6 per-key prover cache is the only new state that scales with both peers and keys. Is the `sqrt(N)` bound tight enough, or do we need an explicit TTL eviction?

(c) Is `EPOCH_DURATION = 1h` the right tradeoff? Shorter = less freeriding tolerance but more sig overhead. Longer = more freeriding but less work.

(d) Stage 1 → Stage 2 transition: who decides "fleet majority is capable"? Manual flip via config rollout, or automatic threshold based on observed `commitment_capable` ratio over time?

## Summary

| Property | v2 design |
|---|---|
| New wire types | 1 struct (`StorageCommitment`) + 1 field on `NeighborSync*` + 1 field on `AuditChallenge` + 1 variant on `AuditResponse` |
| New persistent state | 0 |
| New in-memory state | `last_commitment_root` per RT peer + per-key prover cache (bounded sqrt(N)) |
| New crypto | None (reuse BLAKE3 + ML-DSA-65) |
| Closes Finding 1 | Yes — leaf binding to `global_epoch` makes re-signed roots fail proof verification |
| Closes Finding 2 | Yes — `Bootstrapping` from commitment-capable peers = hard failure |
| Stateless at auditor | Yes — all state is per-RT-peer record + bounded prover cache. No attacker-fillable buffers. |
| Reuses existing infra | Yes — extends NeighborSync + AuditChallenge/Response |
| Backwards compatible | Yes, with sticky-capability for downgrade resistance |
