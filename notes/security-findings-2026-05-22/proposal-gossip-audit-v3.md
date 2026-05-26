# Storage-Bound Audit via Gossip-Embedded Commitments — v3

**Status:** Draft for adversarial review (round 3).
**Previous:** v2 closed v1's BLOCKER + 4 MAJORs. v2 review found 1 new BLOCKER + 2 MAJORs. All addressed below.
**Scope:** Closes Findings 1 and 2.

## Changes vs v2

| # | v2 issue (codex round 2) | v3 fix |
|---|---|---|
| 1 | BLOCKER: audit binds to `global_epoch`, not to the *exact* previously gossiped root. Lazy node gossips any root early, then forges a fresh response root during the audit window. | Auditor stores `commitment_hash = H(domain || signed_commitment_blob)` from gossip. Audit response carries `commitment_hash` and `commitment`; auditor requires the carried `commitment_hash == stored_commitment_hash`. Mismatch = audit failure. |
| 2 | MAJOR: §6 per-key prover cache grows `O(keys × peers)`, not `sqrt(N)` | Cache is scoped to RT peers and hard-capped per key: `MAX_PROVERS_PER_KEY = CLOSE_GROUP_SIZE × 2 = 16` (extra slack for churn). LRU eviction within the cap. |
| 3 | MAJOR: 1-slot grace on gossip-receive bleeds into reward eligibility — 2-3h freeriding window. | At audit time, holder credit requires `commitment.global_epoch == current_global_epoch` (strict). The 1-slot grace exists ONLY for accepting late gossip into `last_commitment_root`, not for rewarding the bytes the commitment covers. A peer with last-epoch commitment is *capable* but earns no rewards until they refresh. |

## Design constraints (unchanged)

1. Lightweight, minimal state.
2. Stateless at auditor (bounded per-RT-peer record + bounded per-key cache).
3. Reuse `NeighborSyncRequest`/`Response` + `AuditChallenge`/`Response`.
4. Make freeriding more expensive than storing; not required to make it impossible.

## Protocol (v3)

### 1. The `global_epoch`

Unchanged from v2:

```text
global_epoch = floor(now_seconds / EPOCH_DURATION_SECS)
EPOCH_DURATION_SECS = 3600  (1 hour)
```

A node accepts a gossip-arrival commitment if `commitment.global_epoch ∈ {current_epoch, current_epoch - 1}` (1-slot grace for clock skew). This grace applies **only to gossip acceptance**, not to reward eligibility (see §5).

### 2. Commitment — extended with self-hash

```rust
pub struct StorageCommitment {
    pub global_epoch: u64,
    pub sender_peer_id: [u8; 32],
    pub root: [u8; 32],
    pub key_count: u32,
    pub signature: MlDsaSignature,
}
```

The "commitment hash" used to pin the audit to the gossiped commitment is computed deterministically by both sides:

```text
commitment_hash = BLAKE3(
    DOMAIN_COMMITMENT_HASH
    || global_epoch (u64 LE)
    || sender_peer_id (32 bytes)
    || root (32 bytes)
    || key_count (u32 LE)
    || signature (3293 bytes)
)
```

`DOMAIN_COMMITMENT_HASH = b"autonomi.ant.replication.commitment_hash.v1"`.

Including `signature` in the hash means the hash is identity-pinning — no two valid commitments hash the same way unless they are byte-identical. This is the critical addition for v3: the responder cannot substitute a different commitment during the audit response without changing the hash.

### 3. Gossip — receive-side processing

(Same as v2's hardened sequence; reproduced for completeness.)

1. **Structural validation** (no crypto): `commitment.global_epoch ∈ {current_epoch, current_epoch - 1}`, `commitment.sender_peer_id == authenticated_transport_peer`, `commitment.key_count > 0`.
2. **Sender admission**: peer must be in routing table.
3. **Per-peer rate limit**: at most one signature verification per peer per `MIN_VERIFY_INTERVAL = 60s`.
4. **Monotonicity**: `commitment.global_epoch > peer_state.last_seen_epoch`.
5. **Signature verification.**
6. **Update state**:
   - `peer_state.last_commitment_root = (received_at, commitment_hash, global_epoch)`
   - `peer_state.last_seen_epoch = global_epoch`
   - `peer_state.commitment_capable = true` (sticky from first valid commitment).

Note step 6 stores `commitment_hash`, not just `root` — this is what closes v2's BLOCKER.

### 4. Commitment-bound audit — wire types

```rust
pub struct AuditChallenge {
    pub challenge_id: u64,
    pub nonce: [u8; 32],
    pub challenged_peer_id: [u8; 32],
    pub keys: Vec<XorName>,
    pub require_commitment_proof: bool,
}

pub enum AuditResponse {
    Digests { ... },
    Bootstrapping { ... },
    Rejected { ... },
    CommitmentBound {
        challenge_id: u64,
        commitment: StorageCommitment,        // MUST be the exact one previously gossiped
        per_key: Vec<CommitmentBoundResult>,
    },
}

pub struct CommitmentBoundResult {
    pub key: XorName,
    pub digest: [u8; 32],
    pub bytes_hash: [u8; 32],
    pub path: Vec<[u8; 32]>,
}
```

### 5. Auditor verification — addresses v2 BLOCKER + MAJOR #3

On receiving `CommitmentBound`:

1. **Pin to gossiped commitment**: recompute `commitment_hash` from response's `commitment` (same formula as §2). Look up `peer_state.last_commitment_root` for the challenged peer. **Require `response_commitment_hash == stored_commitment_hash`**. Mismatch → hard audit failure, full per-key penalty.
2. **Strict freshness for reward**: `commitment.global_epoch == current_global_epoch` (at audit time, no grace). If only `current_epoch - 1`: peer is *commitment-capable* but earns no holder credit this epoch — the response is accepted as "capability proven" only, no per-key credit applied. This closes v2 MAJOR #3.
3. **Signature** (cheap re-verify; could be cached at gossip step but re-verifying here is small): `commitment.signature` valid.
4. **For each `CommitmentBoundResult`**:
   - Auditor reads its own copy of `record_bytes` for `key` (auditor only commitment-audits keys it holds — same as today).
   - Recompute `expected_bytes_hash = BLAKE3(record_bytes)`. Require `bytes_hash == expected_bytes_hash`. Stops the responder from hashing wrong bytes into the leaf to make the path "verify" against a bogus leaf.
   - Recompute `leaf = BLAKE3(DOMAIN_LEAF || global_epoch || key || bytes_hash)`.
   - Verify Merkle path from `leaf` to `commitment.root`. Mismatch → key-level audit failure.
   - Recompute `expected_digest = BLAKE3(nonce || challenged_peer_id || key || record_bytes)`. Require `digest == expected_digest`.

All four must pass per key. Any per-key failure: `AUDIT_FAILURE_TRUST_WEIGHT` per failed key.

On receiving `Digests` when `require_commitment_proof = true` and `peer_state.commitment_capable = true`: hard audit failure, full per-key penalty. (Sticky-capability from v2.)

### 6. Holder eligibility — addresses v2 MAJOR #2 (cache bound)

A peer P is credited as holder of key K (for replication quorum, paid-list verification, rewards) only if:

- P's `commitment_capable = true`, AND
- P's `last_commitment_root.global_epoch == current_global_epoch` (no grace for credit), AND
- P has either:
  - included K in a commitment-bound audit *we* issued during the current epoch (proven by our local audit log for the current epoch), OR
  - is in the `recent_provers[K]` cache for the current epoch.

**`recent_provers` cache shape — explicitly bounded:**

```rust
struct ProverEntry { peer_id: PeerId, proof_epoch: u64 }
recent_provers: HashMap<XorName, BoundedSet<ProverEntry>>
```

Caps:
- **Per-key**: `MAX_PROVERS_PER_KEY = 2 * CLOSE_GROUP_SIZE = 16`. The 2× slack is for churn; beyond that the LRU evicts the oldest entry by `proof_epoch`. Provers we audited *this epoch* are immune from eviction by older entries.
- **Per-peer**: only peers in our routing table can contribute entries. Non-RT peers' audit responses are not cached (they aren't audited in the first place).
- **TTL**: `proof_epoch < current_global_epoch` triggers eviction at the start of each new epoch (cheap O(keys) sweep run as a once-per-epoch task).

Total cache size ceiling: `keys_we_hold × MAX_PROVERS_PER_KEY × sizeof(ProverEntry) = 10k × 16 × 40 bytes = 6.4 MB` for a node holding 10k keys. Bounded, deterministic, attacker-floor-able only up to that ceiling.

### 7. Closing Finding 2 (Bootstrap-claim shield)

Unchanged from v2 §7:

- `AuditResponse::Bootstrapping` + `peer_state.commitment_capable = true` + `peer_state.last_commitment_root` is recent → lie, full audit failure per key.
- Otherwise (truly fresh peer): treat as legitimate, no penalty, no reward credit (per §6).

### 8. Backwards compatibility

Same as v2:

- `commitment: Option<StorageCommitment>` — old peers `None`, new peers `Some`.
- `require_commitment_proof` — old responders ignore (decodes to `false`).
- **Sticky capability**: first `Some` from a peer flips `commitment_capable = true` permanently. Downgrade-proof.
- **Stage 1 (informational)** then **Stage 2 (enforcement)** flag-day plan.

### 9. State summary — updated

| Where | What | Size ceiling | Note |
|---|---|---|---|
| Responder (self) | In-memory Merkle tree over keys | `~64 bytes × keys` | Rebuilt per epoch, reconstructable from LMDB |
| Responder | Cached signed commitment | ~3.4 KB | Per epoch |
| Per-RT-peer record (auditor side) | `(received_at, commitment_hash, global_epoch)` + `last_seen_epoch` + `commitment_capable` | ~80 bytes × RT peers (~160 KB) | Bounded by RT size |
| `recent_provers[K]` cache | `BoundedSet<ProverEntry>`, cap 16 per key | `keys × 16 × 40 = 6.4 MB` worst-case for 10k keys | LRU within cap, full sweep at epoch boundary |

All in-memory. No persistent disk state. Recoverable from LMDB + a network round.

### 10. Wire format precision (unchanged from v2)

Domain tags:
- Commitment signature: `b"autonomi.ant.replication.storage_commitment.v1"`
- Commitment hash: `b"autonomi.ant.replication.commitment_hash.v1"`
- Merkle leaf: `b"autonomi.ant.replication.storage_leaf.v1"`
- Merkle node: `b"autonomi.ant.replication.storage_node.v1"`

Postcard canonical encoding everywhere.

### 11. DoS analysis (updated)

| Vector | Mitigation |
|---|---|
| Flood unsigned commitments from non-RT peers | Sender-in-RT before sig verify (§3 step 2) |
| Flood signed commitments from many Sybils | Per-peer rate limit 60s (§3 step 3) |
| Replay old commitment from same peer | Monotonic epoch + sticky `last_seen_epoch` (§3 step 4) |
| Replay someone else's commitment | `sender_peer_id` in commitment must equal authenticated transport peer (§3 step 1) |
| Audit-time root substitution attack (v2 BLOCKER) | Audit-time `commitment_hash` pin (§5 step 1) |
| Per-key cache exhaustion | Hard cap 16/key, LRU, RT-only (§6) |
| Audit response with bogus signature | Same cheap structural checks before sig verify |
| Audit response with bogus Merkle paths | Hashing only; bounded by audit sample size |

## Why v3 closes the attacks

**Finding 1 — lazy node via on-demand fetch:**

A lazy node L tries to claim K rewards.

- Path A: gossip a real commitment. Requires `BLAKE3(record_bytes_K)` at gossip time. L must have K's bytes at gossip. Cost = storage, not fetch.
- Path B: gossip a fake commitment (random root). On audit, response carries this same commitment (forced by the `commitment_hash` pin). The audited keys' Merkle paths to the fake root will never verify against real `bytes_hash` values. Fail.
- Path C: gossip a real commitment over a small subset, then claim a larger set. The §6 holder cache only credits L for keys actually proven through a commitment-bound audit. Unproven keys → no credit. Lazy node earns rewards proportional to what they actually committed (and thus had bytes for).
- Path D: gossip a fresh commitment, then during audit window try to fetch K from honest peers, build a new commitment with K included, and respond with the new commitment. **Fails the §5 step 1 hash pin**: the response commitment_hash won't match the gossiped one.

**Finding 2 — Bootstrap-claim shield:**

Same as v2: a commitment-capable peer returning `Bootstrapping` is treated as a hard audit failure. The 24h grace no longer shields freeloaders.

## Open questions for review round 3

(a) The `commitment_hash` includes the signature, making it identity-pinning. Is the BLAKE3 over the postcard-encoded struct + signature standard enough, or do we need a stronger commitment-to-blob primitive?

(b) The §6 cache ceiling of 6.4 MB is for 10k keys held locally. If we expect nodes to hold 100k+ keys, do we need a tighter per-key cap (e.g. 8) or a different cache scheme (e.g. Bloom filter for "have we proven this peer-key pair this epoch")?

(c) The strict epoch freshness for reward eligibility means a peer with `current - 1` epoch commitment earns nothing until they refresh. If a network has correlated late commitments (e.g. all peers gossip at the start of each hour and audit cycles fire later), is the bookkeeping right? Should holder credit have a small grace window measured in *audit cycles*, not epochs?

(d) Stage 1 → Stage 2 transition: who decides "fleet majority is capable"? Config rollout vs. observed-ratio.
