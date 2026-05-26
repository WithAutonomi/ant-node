# Storage-Bound Audit via Gossip-Embedded Commitments — v1

**Status:** Draft for adversarial review.
**Scope:** Closes Findings 1 (audit not storage-bound) and 2 (bootstrap-claim audit shield) from `notes/security-findings-2026-05-22/`.
**Non-goals:** Findings 3 (paid-list forgery), 4 (price floor), 5 (already_stored). These are independent fixes.

## Design constraints (from user)

1. **Lightweight** — minimal new state, minimal new wire types, minimal new code paths.
2. **Stateless at the auditor** — no per-peer caches that an attacker can fill or evict.
3. **Reuse existing infra** — extend `NeighborSyncRequest`/`Response` and the existing `AuditChallenge`/`AuditResponse` flow rather than introducing a new subprotocol.
4. **Greater context** — prevent freeriding by lazy nodes claiming chunks without storing them. Acceptable to make freeriding *more expensive than storing*; not required to make it impossible.

## Threat model recap

The current audit is `BLAKE3(nonce || challenged_peer_id || key || record_bytes)`. The digest proves the responder can *produce the bytes right now*. It does not prove *durable possession*. A lazy node with a fast neighbour can fetch the bytes during the response window (10s + 20ms/key) and answer correctly. Equivalently, a coalition holding bytes only in RAM long enough to clear an audit defeats prune-confirmation, causing real data loss.

Returning `AuditResponse::Bootstrapping` bypasses the failure path entirely; within the 24h grace it is zero penalty.

## Core idea

Each node periodically publishes a **commitment root** over the keys it claims to hold. The root is a Merkle tree with leaves `H(K_i || H(record_bytes_i))` for each key K_i the node currently stores. Publication is piggybacked on `NeighborSyncRequest`/`Response` — no new message type, no new transport, no new schedule.

When an auditor receives gossip carrying a commitment, it has an option: **probabilistically issue a `commitment-bound audit`** that, in addition to the existing digest check, requires a Merkle inclusion proof showing K is in the just-gossiped root. The responder must produce both the bytes (for the digest) AND the path-to-root (for the commitment). The commitment was signed at gossip time — meaning at gossip time the responder had the leaf hash, which required the bytes.

A lazy node has three options, all losing:
- Don't gossip a commitment → never get audited via the commitment path, BUT also forfeit reward eligibility (see §5). Net: starve.
- Gossip a real commitment → had to compute leaves over actual bytes at commit time, i.e. had to have the bytes recently. Defeats freeriding.
- Gossip a fake commitment (random root) → digest check passes via on-demand fetch, but the path-to-root check fails because the leaf hash doesn't match. Caught on the first commitment-bound audit.

Auditor stores nothing. Each commitment-bound audit response is self-contained: signature, path, digest. Auditor verifies all three from the response bytes.

## Protocol

### 1. Commitment

Each node maintains an in-memory Merkle tree:

```text
leaf_i = BLAKE3("ant-node-leaf-v1" || K_i || BLAKE3(record_bytes_i))
root   = MerkleRoot(sorted_leaves)
```

Leaves are sorted by `K_i` so the root is deterministic given the key set. Tree is rebuilt opportunistically (debounced to ~every neighbour-sync interval, currently 5-15 min). Per-leaf hash work: ~2 BLAKE3 invocations. For 10k keys: ~20k hashes, <100ms on commodity hardware.

The tree is **not persisted to disk** — it's reconstructable from LMDB at boot. Cost: one full re-scan of stored chunks on startup, amortized over the first commitment interval.

### 2. Gossip

Extend `NeighborSyncRequest` and `NeighborSyncResponse`:

```rust
pub struct NeighborSyncRequest {
    pub replica_hints: Vec<XorName>,
    pub paid_hints: Vec<XorName>,
    pub bootstrapping: bool,
    // NEW:
    pub commitment: Option<StorageCommitment>,
}

pub struct StorageCommitment {
    pub root: [u8; 32],
    pub epoch: u64,            // wall-clock seconds, sender-claimed
    pub key_count: u32,        // number of leaves the root commits over
    pub signature: MlDsaSignature,  // sign(root || epoch || key_count || sender_peer_id)
}
```

`bootstrapping` is kept for backwards compatibility but its trust impact is changed (see §4). `commitment` is `Option` so old peers (none) and new peers (Some) coexist during rollout.

Wire size add: ~3 KiB (ML-DSA-65 sig is 3293 bytes + 44 bytes header). NeighborSync runs every 5-15 min per peer; bandwidth overhead is negligible.

### 3. Commitment-bound audit (new)

Today's `AuditChallenge`/`Response` is unchanged. We add a new variant that piggy-backs on the existing flow:

```rust
pub struct AuditChallenge {
    pub challenge_id: u64,
    pub nonce: [u8; 32],
    pub challenged_peer_id: [u8; 32],
    pub keys: Vec<XorName>,
    // NEW:
    pub require_commitment_proof: bool,  // if true, expect commitment-bound response
}

pub enum AuditResponse {
    Digests { ... },         // existing
    Bootstrapping { ... },   // existing
    Rejected { ... },        // existing
    // NEW:
    CommitmentBound {
        challenge_id: u64,
        commitment: StorageCommitment,        // the root the responder is binding to
        per_key: Vec<CommitmentBoundResult>,
    },
}

pub struct CommitmentBoundResult {
    pub key: XorName,
    pub digest: [u8; 32],                     // BLAKE3(nonce || peer_id || key || bytes), as today
    pub leaf: [u8; 32],                       // BLAKE3(record_bytes), so auditor can rebuild leaf hash
    pub path: Vec<[u8; 32]>,                  // Merkle inclusion path for leaf_i to root
}
```

### 4. Auditor logic — stateless probabilistic choice

When `audit_tick` selects a peer to audit, it makes a coin flip:

- With probability `p_commitment` (default **0.7**): set `require_commitment_proof = true`. Responder must reply with `CommitmentBound`. Auditor verifies:
  1. `commitment.signature` valid under responder's pubkey.
  2. For each `CommitmentBoundResult`:
     - `leaf == BLAKE3(record_bytes)` — auditor recomputes from the bytes... wait, auditor doesn't have the bytes. **Correction:** the `leaf` field is `BLAKE3(record_bytes)`; auditor recomputes `merkle_leaf = BLAKE3("ant-node-leaf-v1" || key || leaf)`, then verifies path-to-root.
     - `digest == BLAKE3(nonce || peer_id || key || record_bytes)` — auditor can't verify without bytes. **This needs fixing — see §6 open question (a)**.

- With probability `1 - p_commitment` (0.3): set `require_commitment_proof = false`. Responder replies with `Digests` as today.

The auditor *does not cache anything per peer*. The decision is per-audit, per-peer, independent. State that already exists (sync_history for eligibility) is untouched.

### 5. Eviction coupling for silent peers

A peer that never gossips a commitment cannot be commitment-audited. To prevent "stay silent to skip the new audit type":

- ant-node tracks per-peer `last_commitment_root_received: Option<(Instant, [u8;32])>` in `PeerSyncRecord` (same struct that already tracks `last_sync` and `cycles_since_sync`). Memory: 40 bytes per peer in the routing table — kilobytes total.
- If `last_commitment_root_received` is `None` OR older than `MAX_COMMITMENT_AGE` (proposed: 2× max NeighborSync interval, ≈ 30 min), the peer is treated as having claimed **zero keys**:
  - Their replica hints are admitted (so they can learn about keys to replicate) but the peer is **excluded from audit eligibility** (we don't audit a peer claiming no storage).
  - They are also **excluded from being credited as a "verified holder"** in the paid-list / quorum logic, since they haven't bound themselves to any keys.
- Net effect: a silent peer can route Kad traffic but can't earn rewards. They have to either gossip a commitment (and commit to actual bytes) or accept the role of pure-router.

This is the part that makes the design teeth, and it's the only place we add per-peer state — but it's bounded to the routing table size (a couple thousand peers max in practice).

### 6. Open questions for review

**(a) How does the auditor verify the `digest` field without the bytes?**

Today's audit assumes the auditor has the bytes (they're a holder too — they audit peers about keys *they* hold). In commitment-bound mode, the same assumption holds: the auditor only commitment-audits a peer about keys the auditor *also* holds. This keeps the digest check identical to today.

If we want to audit peers about keys the auditor doesn't hold (e.g. a watcher node), the digest check has to drop and we rely entirely on the path-to-root + signature. That's still strong against the lazy-fetch attack (path can't be forged), but loses the freshness binding.

**Proposed:** commitment-bound audits are only issued for keys the auditor holds. Same as today. No new restriction.

**(b) Bootstrap-claim shield (Finding 2) — closing it with this design.**

Today: returning `Bootstrapping` skips the failure path entirely. Fix: if the responder has *ever* gossiped a commitment in the last hour, they cannot also claim to be Bootstrapping — and if they do, treat it as `AUDIT_FAILURE_TRUST_WEIGHT (5.0)`, same as digest mismatch.

Mechanically: when handling `AuditResponse::Bootstrapping`, check our `PeerSyncRecord` for that peer. If `last_commitment_root_received.is_some()` and recent, the Bootstrapping response is a lie → emit full audit-failure penalty, per-key.

This costs nothing new — uses the same `PeerSyncRecord` state §5 already adds.

**(c) Commitment epoch — is `wall-clock seconds, sender-claimed` enough?**

A lazy node could gossip the same root with an incremented epoch each round, having computed the leaves once a long time ago. The bytes might be gone by now. We need the commitment to be **fresh enough**.

**Proposed:** auditors compare `gossip arrival time` against `commitment.epoch`. If the gossip epoch is too old (e.g. > 1 hour stale), the commitment is rejected at gossip-receive time and that peer's `last_commitment_root_received` is not updated. Forces the responder to re-sign a fresh commitment over the current key set every hour.

But the *bytes* could still be stale — they had bytes 59 minutes ago. **That's the design tradeoff:** freeriding is bounded to the commit interval. Set commit interval = ~1 hour. A lazy node would have to refetch every claimed key every hour to keep the commitment alive — which is the freeriding-vs-storage cost we want.

**(d) What if a peer's claimed key set changes between epochs?**

Normal — keys arrive, keys leave. New commitment covers new set. An auditor that has a stale gossiped root in flight gets a new root in the next gossip; the next audit uses the new root. No reconciliation across roots is needed.

**(e) DoS surfaces.**

- Auditor never stores per-peer state beyond what already exists (`PeerSyncRecord`). An attacker cannot fill auditor state.
- The new `last_commitment_root_received` field on `PeerSyncRecord` is bounded by routing table size (≤ k × bucket_count, typically <2000 entries).
- Commitment verification cost: 1 ML-DSA-65 verify per gossip arrival. ~ms each. Bounded by gossip rate.
- Audit-response verification cost: 1 sig verify + N Merkle path verifies + N digest recomputes. For N=100 keys: ~10ms. Bounded by audit rate (~5min/peer).

**(f) Backwards compatibility.**

- `commitment: Option<StorageCommitment>` — old peers send `None`, new peers send `Some`. New peers handle either.
- `AuditChallenge.require_commitment_proof` — old responders ignore the field and reply with `Digests`. New auditors handle both `Digests` and `CommitmentBound` responses.
- Eviction coupling (§5) only applies to peers from whom we've never seen a commitment AND whose version is new enough to support it. During rollout, treat unsupported-version peers as exempt; gradually flip when fleet majority is on the new version.

## Summary

| Property | This design |
|---|---|
| New wire types | 2 fields on existing structs + 1 enum variant on `AuditResponse` |
| New persistent state | 0 (commitment tree reconstructable from LMDB at boot) |
| New per-peer state at auditor | 1 `Option<(Instant, [u8;32])>` on `PeerSyncRecord` (40 bytes × routing table size) |
| New crypto | None (BLAKE3 + ML-DSA-65 already in use) |
| New background work | Periodic Merkle root recompute (~100ms per epoch per node) |
| Closes Finding 1 (lazy-node fetch) | Yes — commitment-path forces prior possession |
| Closes Finding 2 (bootstrap-claim shield) | Yes — silent-but-claimed peers can't shield via Bootstrapping |
| Stateless at auditor | Almost — only the bounded `PeerSyncRecord` extension |
| Reuses existing infra | Yes — NeighborSync + AuditChallenge/Response extension |
| Backwards compatible | Yes — optional fields, optional response variant |

## Anti-summary (what this does NOT close)

- A node that genuinely stores everything is still vulnerable to digest-forgery attacks IF the auditor doesn't hold the same bytes (see §6 (a)). Mitigation: auditors only commitment-audit keys they themselves hold. Same constraint as today.
- Findings 3, 4, 5 are out of scope.
- A coalition that controls a majority of close groups can still forge anything. No design at this layer fixes that — it's a Sybil resistance question for saorsa-core / EigenTrust++.
