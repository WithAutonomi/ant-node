# Storage-Bound Audit via Gossip-Embedded Commitments — v4

**Status:** Draft for adversarial review (round 4).
**Previous:** v3 closed v2's BLOCKER but reintroduced two new flaws (pin against mutable state, stale-proof cache contamination). v4 addresses all.
**Scope:** Closes Findings 1 and 2.

## Changes vs v3

| # | v3 issue (codex round 3) | v4 fix |
|---|---|---|
| 1 | BLOCKER: pin is against `peer_state.last_commitment_root` which the responder can rewrite between challenge and response | **Snapshot the expected commitment hash at challenge-issue time**. Embed `expected_commitment_hash` in `AuditChallenge`. Verifier compares response against this challenge-local value, never against mutable peer state. |
| 2 | MAJOR: `recent_provers[K]` stores only `{peer_id, proof_epoch}`; a proof against `epoch - 1` can be cached and then satisfy current-epoch eligibility | Cache entry now carries `commitment_epoch` AND `commitment_hash`. Holder credit checks that the cached entry's commitment_hash matches the peer's *currently credited* commitment. Stale-epoch proofs are never written into the cache to begin with. |
| 3 | MEDIUM: response-shape bounds (per_key length, path length) not enforced before crypto work | Cheap structural checks added at top of audit-response handling: `per_key.len() == challenge.keys.len()`, `keys` are unique and in the requested order, `path.len() <= ceil(log2(key_count + 1))`. Reject before signature work. |

## Design constraints (unchanged)

1. Lightweight, minimal state.
2. Stateless at auditor (bounded per-RT-peer record + bounded per-key cache).
3. Reuse `NeighborSyncRequest`/`Response` + `AuditChallenge`/`Response`.
4. Make freeriding more expensive than storing; not required to make it impossible.

## Protocol (v4)

### 1. The `global_epoch` (unchanged)

```text
global_epoch = floor(now_seconds / EPOCH_DURATION_SECS)
EPOCH_DURATION_SECS = 3600  (1 hour)
```

Gossip acceptance: `commitment.global_epoch ∈ {current_epoch, current_epoch - 1}` (1-slot grace for clock skew). The grace applies ONLY to gossip acceptance.

### 2. Commitment (unchanged from v3)

```rust
pub struct StorageCommitment {
    pub global_epoch: u64,
    pub sender_peer_id: [u8; 32],
    pub root: [u8; 32],
    pub key_count: u32,
    pub signature: MlDsaSignature,
}
```

Commitment hash (deterministic, identity-pinning):

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

### 3. Gossip — receive-side processing (unchanged from v3)

Sequence: structural → admission → rate-limit → monotonicity → sig verify → state update. State update stores `(received_at, commitment_hash, root, global_epoch)`.

### 4. Audit wire types — addresses v3 BLOCKER

```rust
pub struct AuditChallenge {
    pub challenge_id: u64,
    pub nonce: [u8; 32],
    pub challenged_peer_id: [u8; 32],
    pub keys: Vec<XorName>,
    pub require_commitment_proof: bool,
    // NEW (addresses v3 BLOCKER):
    pub expected_commitment_hash: Option<[u8; 32]>,
}
```

When the auditor issues a `require_commitment_proof = true` challenge, it snapshots the peer's current `peer_state.last_commitment_root.commitment_hash` and embeds it as `expected_commitment_hash`. This value is sent on the wire as part of the challenge.

The responder MUST reply with a `CommitmentBound` carrying a commitment whose hash equals `expected_commitment_hash`. If the responder gossiped a newer commitment between receiving the challenge and crafting the response, it cannot use that newer commitment for *this* challenge — the auditor will reject it.

If the responder has rotated their commitment in the meantime, they can either:
- Respond using the old commitment they're being challenged on (still requires having had bytes at that epoch's gossip time). The path/leaf math still works because `expected_commitment_hash` covers the specific signed blob, not just the epoch.
- Decline (timeout). Audit failure via the existing timeout path.

```rust
pub enum AuditResponse {
    Digests { ... },
    Bootstrapping { ... },
    Rejected { ... },
    CommitmentBound {
        challenge_id: u64,
        commitment: StorageCommitment,
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

### 5. Auditor verification (v4)

On receiving an `AuditResponse`:

**5a. Cheap structural checks (before any crypto — addresses v3 MEDIUM):**

For `CommitmentBound { commitment, per_key, .. }`:
- `per_key.len() == challenge.keys.len()` (exact match, not subset)
- `per_key[i].key == challenge.keys[i]` for all i (same order, no substitution)
- `per_key` contains no duplicate keys (HashSet check)
- For each result: `path.len() <= ceil(log2(commitment.key_count + 1))` (Merkle path length bounded by tree depth implied by `key_count`)
- `commitment.key_count > 0` (sanity)

Any failure → audit failure (`AUDIT_FAILURE_TRUST_WEIGHT × challenge.keys.len()`), no further work.

**5b. Commitment-hash pin (addresses v3 BLOCKER):**

- Compute `response_commitment_hash` from `response.commitment` (§2 formula).
- Require `response_commitment_hash == challenge.expected_commitment_hash`. The auditor knows `expected_commitment_hash` because it embedded it in the challenge — no read of mutable state at verification time.
- Mismatch → audit failure.

**5c. Epoch freshness for reward credit:**

- `commitment.global_epoch == current_global_epoch` (no grace). If only `current - 1`: still counts as capability proof, but no holder credit applied this epoch.
- An auditor that previously embedded an `expected_commitment_hash` from a `current - 1` epoch commitment will accept a response that matches that hash, but the resulting `recent_provers` cache entry is tagged with `commitment_epoch = current - 1` and §6 will refuse to grant credit using it (see below).

**5d. Signature verification:**

`commitment.signature` valid over the canonical commitment bytes. (Cheap re-verify; could be elided if we cached the verify outcome at gossip time and trust it didn't expire, but cheaper to re-verify than maintain a verify-cache.)

**5e. Per-key verification:**

For each `CommitmentBoundResult`:
- Auditor reads its own `record_bytes` for `key` (auditor only commitment-audits keys it holds — same as today's `audit.rs`).
- Recompute `expected_bytes_hash = BLAKE3(record_bytes)`. Require `bytes_hash == expected_bytes_hash`.
- Recompute `leaf = BLAKE3(DOMAIN_LEAF || commitment.global_epoch || key || bytes_hash)`.
- Verify Merkle path from `leaf` to `commitment.root`. Mismatch → key-level audit failure.
- Recompute `expected_digest = BLAKE3(nonce || challenged_peer_id || key || record_bytes)`. Require `digest == expected_digest`.

All four must pass per key. Any failure → `AUDIT_FAILURE_TRUST_WEIGHT` for that key.

On `Digests` response when `require_commitment_proof = true` AND `peer_state.commitment_capable = true`: hard audit failure, full per-key penalty (sticky-capability from v2).

### 6. Holder eligibility cache — addresses v3 MAJOR #2

**Cache shape (v4 — explicit epoch + hash binding):**

```rust
struct ProverEntry {
    peer_id: PeerId,
    proof_epoch: u64,
    commitment_hash: [u8; 32],   // which commitment proved K
}

recent_provers: HashMap<XorName, BoundedSet<ProverEntry>>
```

**Insertion rule:** an entry is added to `recent_provers[K]` only when the auditor successfully verifies a commitment-bound audit response in which `commitment.global_epoch == current_global_epoch`. Stale-epoch proofs (epoch − 1) are NOT cached — they only count as capability proof (§5c).

**Holder credit rule:** peer P is credited as holder of K when ALL of:
- P's `commitment_capable = true`, AND
- P's `last_commitment_root.global_epoch == current_global_epoch`, AND
- `recent_provers[K]` contains an entry with `peer_id == P` AND `commitment_hash == P's currently credited commitment_hash` AND `proof_epoch == current_global_epoch`.

The hash check stops the v3 MAJOR exploit: a cached entry from a previous epoch (or an older root from this same peer) won't match the *current* commitment hash even if `proof_epoch` were current.

**Cache caps (v3 unchanged):**
- `MAX_PROVERS_PER_KEY = 2 × CLOSE_GROUP_SIZE = 16`
- Per-peer: only routing-table peers populate entries
- TTL: entries with `proof_epoch < current_global_epoch` are evicted at epoch boundary
- LRU within per-key cap

Total ceiling: `keys_held × 16 × sizeof(ProverEntry) = 10k × 16 × 72 bytes = 11.5 MB` for 10k keys.

### 7. Bootstrap-claim shield (unchanged from v3)

- `Bootstrapping` response + `commitment_capable = true` + recent commitment → hard audit failure, full per-key penalty.
- Otherwise → legitimate, no penalty, no reward credit.

### 8. Backwards compatibility (unchanged from v3)

- `commitment: Option<StorageCommitment>` and `expected_commitment_hash: Option<[u8; 32]>` are `Option`-typed for old-peer compatibility.
- Sticky capability: first `Some` commitment from a peer flips `commitment_capable = true` permanently.
- Stage 1 (informational) → Stage 2 (enforcement) rollout.

### 9. State summary (v4)

| Where | What | Size ceiling | Note |
|---|---|---|---|
| Responder (self) | In-memory Merkle tree | `~64 bytes × keys` | Rebuilt per epoch from LMDB |
| Responder | Cached signed commitment | ~3.4 KB | Per epoch |
| Per-RT-peer record (auditor) | `(received_at, commitment_hash, root, global_epoch, last_seen_epoch, commitment_capable)` | ~96 bytes × RT peers (~200 KB) | Bounded by RT size |
| `recent_provers[K]` cache | `BoundedSet<ProverEntry>` cap 16/key | `keys × 16 × 72 = 11.5 MB` for 10k keys | LRU within cap, full sweep at epoch boundary |

All in-memory. Recoverable from LMDB + a network round.

### 10. Wire format precision (unchanged from v3)

Domain separation tags:
- Commitment signature: `b"autonomi.ant.replication.storage_commitment.v1"`
- Commitment hash: `b"autonomi.ant.replication.commitment_hash.v1"`
- Merkle leaf: `b"autonomi.ant.replication.storage_leaf.v1"`
- Merkle internal node: `b"autonomi.ant.replication.storage_node.v1"`

Postcard canonical encoding.

### 11. DoS analysis (updated — addresses v3 MEDIUM)

| Vector | Mitigation |
|---|---|
| Flood unsigned commitments from non-RT peers | Sender-in-RT before sig verify (§3 step 2) |
| Flood signed commitments from many Sybils | Per-peer rate limit 60s |
| Replay old commitment from same peer | Monotonic epoch (§3 step 4) |
| Replay someone else's commitment | `sender_peer_id` in commitment must equal authenticated transport peer |
| Audit-time commitment substitution (v2 BLOCKER) | `expected_commitment_hash` in challenge (§5b) |
| Per-key cache exhaustion | Hard cap 16/key, RT-peer-only, epoch sweep (§6) |
| **Audit response with oversized per_key / path vectors** (v3 MEDIUM) | **Pre-crypto structural bounds (§5a)** |
| Audit response with bogus signature | Same cheap structural checks before sig verify |
| Audit response with bogus Merkle paths | Hashing only; bounded by depth = log2(key_count) |
| Auditor reboot loses peer history | In-memory tracking re-populates within one gossip round (5-15 min). Conservative: treat all peers as `fresh` (no audits / no credit) for the first epoch after restart. |

### 12. Why v4 closes the attacks

**Finding 1 — lazy node via on-demand fetch:**

A lazy node L:
- **Path A**: gossip a real commitment. Required to compute `BLAKE3(record_bytes_K)` per leaf at gossip time. Has bytes at gossip → cost = storage.
- **Path B**: gossip a fake commitment. On audit, response must hash to `expected_commitment_hash` (§5b). Either matches the fake gossiped commitment → path verification fails (§5e) because real `bytes_hash` doesn't combine to the fake root. Or doesn't match → §5b fails. Audit failure either way.
- **Path C**: gossip a real commitment over a small subset, claim larger set via hints. §6 holder credit requires per-key proof tied to *current* commitment. Unproven keys earn nothing.
- **Path D**: gossip a fresh commitment between receiving challenge and responding. `expected_commitment_hash` was snapshot at challenge-issue time, so the freshly-rotated commitment can't be substituted (v3 BLOCKER closed).
- **Path E**: prove K with `epoch - 1` commitment, then rely on the cache for current-epoch credit. Cache entry's `commitment_hash` won't match the peer's current commitment_hash → §6 refuses credit.

**Finding 2 — Bootstrap-claim shield:** unchanged; commitment-capable peer returning `Bootstrapping` is a hard failure.

### 13. Open questions

(a) The `expected_commitment_hash: Option<[u8; 32]>` in `AuditChallenge` exposes the auditor's view of the peer's latest commitment on every challenge. Could a passive observer use this to infer routing-table membership? Probably not material — the auditor is already revealing a routing-table relationship by issuing an audit at all.

(b) An honest peer that genuinely rotates their commitment between epochs may face an awkward window where the auditor is challenging on the previous epoch's hash. Acceptable: the responder can still answer (they have the old commitment cached, see §2; this is the §5c capability-but-no-credit case). The next audit will use the fresh hash.

(c) Stage 1 → Stage 2 transition: still unsettled (config rollout vs observed-ratio).

(d) The `recent_provers` cache assumes the auditor sees a representative slice of the network. If audit selection is biased (e.g. only auditing peers who recently synced), some peers might never get cached → never earn rewards. Worth verifying audit-selection fairness once implementation lands.
