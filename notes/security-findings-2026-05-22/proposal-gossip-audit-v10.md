# Storage-Bound Audit via Piggybacked Commitments — v10

**Status:** Draft for adversarial review. Stripped-down version.
**Replaces:** v1-v9. The earlier iterations bolted on a network-wide `global_epoch` that turned out to solve a problem the commitment-hash pin already solved. Removing the epoch collapses several MAJORs.
**Scope:** Closes Findings 1 (audit not storage-bound) and 2 (bootstrap-claim shield).

## Design principles

1. **Lightweight.** New state is bounded and local; no shared clock, no retention contract.
2. **Stateless at auditor.** Only `last_commitment` per RT peer + per-key recent-provers cache, both bounded by RT and key set.
3. **Reuse existing infra.** Extend `NeighborSyncRequest`/`Response` + `AuditChallenge`/`Response`. No new transport, no new background task.
4. **Make freeriding more expensive than storing.** Not impossible.

## The protocol

### 1. Responder gossips a storage commitment, piggybacked

Each node maintains a Merkle tree over its claimed keys:

```text
leaf_i = BLAKE3(DOMAIN_LEAF || K_i || BLAKE3(bytes_i))
root   = MerkleRoot(sorted_leaves)
```

When the key set changes meaningfully (new keys added, keys deleted, threshold-debounced), the responder rebuilds the tree and signs:

```rust
pub struct StorageCommitment {
    pub root: [u8; 32],
    pub key_count: u32,
    pub sender_peer_id: [u8; 32],
    pub signature: MlDsaSignature,  // over (DOMAIN_COMMITMENT, root, key_count, sender_peer_id)
}
```

The commitment is piggybacked on the next outbound `NeighborSyncRequest` (and `Response`):

```rust
pub struct NeighborSyncRequest {
    pub replica_hints: Vec<XorName>,
    pub paid_hints: Vec<XorName>,
    pub bootstrapping: bool,
    pub commitment: Option<StorageCommitment>,  // NEW
}
```

No new gossip schedule, no new message type. Free transport ride.

### 2. Auditor stores the latest received commitment per RT peer

On receiving a `NeighborSyncRequest`/`Response` with a `Some(commitment)`:

```text
1. structural: commitment.sender_peer_id == authenticated_transport_peer
                AND commitment.key_count > 0
2. admission:  sender is in our routing table
3. rate limit: at most one signature verify per peer per 60s
4. verify:     ML-DSA signature
5. store:      peer_state.last_commitment = (received_at, commitment_hash, commitment)
               peer_state.commitment_capable = true  (sticky)
```

Where `commitment_hash = BLAKE3(DOMAIN_COMMITMENT_HASH || serialized_commitment)`.

This is the only new gossip-side state: one Option<(Instant, [u8;32], StorageCommitment)> per RT peer. ~3.5 KB × |RT| ≈ kilobytes total.

### 3. Auditor decides when to challenge

The auditor reuses the existing audit cadence (`audit_tick_interval_min..max`). When auditing peer P:

- If `peer_state.last_commitment` is None: P has not gossiped a commitment, ignore for audits and reward credit. (Closes Finding 2 implicitly — see §6.)
- If Some: snapshot `expected_commitment_hash` and issue:

```rust
pub struct AuditChallenge {
    pub challenge_id: u64,
    pub nonce: [u8; 32],
    pub challenged_peer_id: [u8; 32],
    pub keys: Vec<XorName>,
    pub expected_commitment_hash: [u8; 32],  // NEW: pin to the gossiped commitment
}
```

`keys` is sampled from keys the auditor *also* holds (only audit your own keys, same as today).

### 4. Responder answers

Responder keeps the **latest committed tree** in memory plus the in-flight `StorageCommitment`. On receiving an `AuditChallenge`:

- If `expected_commitment_hash == hash(my current commitment)`: build response from current tree.
- Else: respond `Rejected { UnknownCommitmentHash }`. No epoch logic — the responder doesn't owe history.

```rust
pub enum AuditResponse {
    // ...existing variants
    CommitmentBound {
        challenge_id: u64,
        commitment: StorageCommitment,
        per_key: Vec<CommitmentBoundResult>,
    },
}

pub struct CommitmentBoundResult {
    pub key: XorName,
    pub digest: [u8; 32],     // BLAKE3(nonce || peer_id || key || bytes)
    pub bytes_hash: [u8; 32], // BLAKE3(bytes), used to rebuild the leaf
    pub path: Vec<[u8; 32]>,  // Merkle inclusion path
}
```

### 5. Auditor verifies

Cheap structural checks first (before any crypto):

- `per_key.len() == challenge.keys.len()`, same order, no duplicates.
- For each result: `path.len() <= ceil(log2(commitment.key_count))`.

Then crypto:

- `BLAKE3(response.commitment) == challenge.expected_commitment_hash`. Mismatch → audit failure.
- `commitment.signature` valid.
- For each `(key_i, digest_i, bytes_hash_i, path_i)`:
  - Auditor reads its own local copy of `bytes_i` for key_i.
  - `bytes_hash_i == BLAKE3(bytes_i)`. Mismatch → key-level failure.
  - `leaf_i = BLAKE3(DOMAIN_LEAF || key_i || bytes_hash_i)`.
  - Merkle path leaf_i → `response.commitment.root` verifies.
  - `digest_i == BLAKE3(nonce || challenged_peer_id || key_i || bytes_i)`. **The nonce defeats replay** — each challenge picks a fresh random nonce, so the digest is challenge-specific. Lazy node cannot precompute or cache.

On `UnknownCommitmentHash`: treat as no-op. Auditor drops the stale snapshotted hash, waits for the next gossip, retries on the next audit cycle. No penalty either way. The responder didn't lie about anything — they're just on a newer commitment than our snapshot.

(A lazy node that rotates *fast* to invalidate audits gains nothing: the next gossip will refresh our pin, and we'll challenge again. They can stall forever, but stalling = no successful audits = no holder credit = no rewards. See §6.)

On any other rejection or malformed response: today's audit-failure path, full penalty per key.

### 6. Holder eligibility — rewards only flow to peers we've audited

The auditor maintains a bounded per-key cache:

```rust
struct ProverEntry {
    peer_id: PeerId,
    proved_at: Instant,
    commitment_hash: [u8; 32],
}

recent_provers: HashMap<XorName, BoundedSet<ProverEntry>>
```

Insert on every successful commitment-bound audit. Caps:

- `MAX_PROVERS_PER_KEY = 2 × CLOSE_GROUP_SIZE = 16` (LRU within cap).
- Per-peer scope: only RT peers populate entries.
- TTL: entry expires after `RECENT_PROOF_TTL = 2 × max audit interval` (≈ 40 min default). Past TTL the peer must be re-audited.

Peer P is credited as holder of key K iff:

- `peer_state.last_commitment[P].commitment_capable == true`, AND
- `recent_provers[K]` contains an entry with `peer_id == P AND commitment_hash == peer_state.last_commitment[P].commitment_hash AND not expired`.

The `commitment_hash` check on the cache entry binds the proof to a specific gossiped commitment. A peer who proves K against commitment C1, then rotates to C2 (a different key set), loses the cached credit because the cache entry's hash no longer matches their current commitment. They must re-prove K against C2.

**Bootstrap-claim shield (Finding 2) is closed by §3 and §6 together:** a peer that returns `Bootstrapping` to audits is `commitment_capable == false` (they haven't gossiped) so they earn nothing anyway. There's no longer any free-grace path. Today's `AuditResponse::Bootstrapping` becomes equivalent to "I'm not participating in audits," which is fine — they just don't earn.

### 7. Why this stops the lazy-node attack

**Path A — Lazy node gossips a real commitment, drops bytes, fetches on demand at audit:**

The audit response must include the real `bytes_hash` for each challenged key (the auditor recomputes and checks). The bytes_hash is `BLAKE3(bytes)`, content-derived. The lazy node can fetch the bytes from a honest neighbour and produce a valid `bytes_hash` + `digest` + `path` — same as the v1 attack survives this far.

But the cache binding in §6 requires the proof to match the peer's *currently credited* commitment_hash. As long as the lazy node continues to claim the same key set, the cache says "you proved K against commitment C." For each newly-audited K, the lazy node fetches K and proves it. Net cost = bandwidth per audited key.

How does this prevent freeriding? It doesn't *prevent* it in absolute terms — it just makes the bandwidth cost scale with audit frequency. Set audit frequency such that re-fetching every audited key costs more than storing.

**This is the design's actual claim, restated:** freeriding requires fetching on-demand per audit. If audits are frequent enough relative to chunk size, fetching exceeds storage cost. That's the lever — not a cryptographic impossibility, just an economic one.

For 4 MB chunks, sqrt(N)-sized samples, an audit every ~15 min, a 10k-key node sees ~100 keys/audit × 4 MB = 400 MB of fetch per audit, or ~38 GB/day. Vs the cost of holding 40 GB on disk. Disk wins.

**Path B — Lazy node gossips a fake commitment (random root):**

The path verification in §5 fails: real `bytes_hash` (which auditor recomputes from its local bytes) won't combine via any path to a random root. Audit fails.

**Path C — Lazy node gossips no commitment:**

Per §3 + §6, never gets audited, never earns rewards. Silent peer = no income.

### 8. Replay-attack defence

Repeating the nonce point explicitly: every `AuditChallenge` carries a fresh random `nonce`. The digest binds the nonce, so two challenges over the same `(K, bytes)` produce different digests. A lazy node cannot:

- Cache an old response and replay it (nonce mismatch).
- Precompute digests in advance (nonce is unknown until challenge).
- Replay another peer's response (digest binds `challenged_peer_id`).

This is the standard freshness mechanism. No epoch needed.

### 9. State summary

| Where | What | Size ceiling | Note |
|---|---|---|---|
| Responder | In-memory Merkle tree | ~64 bytes × keys | Rebuilt when key set changes, reconstructable from LMDB at boot |
| Responder | Cached current commitment | ~3.4 KB | Sent on next gossip |
| Per-RT-peer record (auditor) | `last_commitment` (Option<(Instant, hash, commitment)>) + `commitment_capable` | ~3.6 KB × \|RT\| ≈ ~50-200 KB | Bounded by RT size |
| `recent_provers[K]` cache | `BoundedSet<ProverEntry>`, cap 16 | `keys × 16 × 80 bytes` ≈ 13 MB for 10k keys | LRU within cap; TTL-evicted |

All in-memory, recoverable from LMDB + gossip rounds.

### 10. Wire format

Domain separation:

- Commitment signature: `b"autonomi.ant.replication.storage_commitment.v1"`
- Commitment hash: `b"autonomi.ant.replication.commitment_hash.v1"`
- Merkle leaf: `b"autonomi.ant.replication.storage_leaf.v1"`
- Merkle internal node: `b"autonomi.ant.replication.storage_node.v1"`

Postcard canonical encoding.

### 11. DoS analysis

| Vector | Mitigation |
|---|---|
| Flood unsigned commitments from non-RT peers | Sender-in-RT check before sig verify (§2 step 2) |
| Flood signed commitments from many Sybils | Per-peer rate limit 60s (§2 step 3) |
| Replay someone else's commitment as our own | `sender_peer_id` in commitment must equal authenticated transport peer (§2 step 1) |
| Audit-time response substitution | `expected_commitment_hash` pin (§5) |
| Per-key cache exhaustion | Hard cap 16/key, RT-only, TTL eviction (§6) |
| Oversized response vectors | Pre-crypto structural bounds (§5) |
| Replay old audit response | Per-challenge random nonce (§8) |

### 12. Backwards compatibility

- `commitment: Option<StorageCommitment>` — old peers send `None`. No wire break.
- `expected_commitment_hash` is a new required field in `AuditChallenge` — only sent by new auditors. Old auditors don't send it; old responders ignore it. New responders see it present and behave per §4. New auditors challenging old responders won't have a `last_commitment` so won't issue commitment-bound audits anyway — they fall back to today's plain audit.
- Sticky `commitment_capable`: a peer's first gossiped commitment flips the flag, never reverts. Downgrade infeasible.

### 13. Implementation checklist

- [ ] Wire types: `StorageCommitment`, `CommitmentBoundResult`, `AuditResponse::CommitmentBound`, `Option<commitment>` on `NeighborSync*`, `expected_commitment_hash` on `AuditChallenge`.
- [ ] Domain-separation constants (§10).
- [ ] Responder: Merkle tree builder, signed commitment, gossip piggyback.
- [ ] Gossip receive: 5-step pipeline (§2).
- [ ] Auditor: snapshot `expected_commitment_hash` at challenge issue, response verification (§5), `recent_provers` cache with hash binding.
- [ ] Holder-eligibility check threaded through replication quorum + paid-list verification paths.
- [ ] Tests:
  - [ ] Lazy-fetch attack: forged commitment fails path verification.
  - [ ] Forged commitment without backing bytes: fails path.
  - [ ] Bootstrap-claim shield: silent peer earns nothing.
  - [ ] Replay: old digest with fresh nonce challenge fails.
  - [ ] All v1 PoC tests (`tests/poc_lazy_audit_*.rs`) must FAIL after this lands.
  - [ ] Rotation: peer gossips a new commitment between audits, `UnknownCommitmentHash` returned, refresh-and-retry works without penalty.

## What's NOT in this design

- No `global_epoch`, no shared wall clock.
- No retention contract on `previous` commitments — responder just keeps the latest. Auditor pin mismatch = no-op refresh.
- No epoch-classifier rules for `UnknownCommitmentHash`. The simplest possible thing: drop pin, refresh, retry. No penalty for honest rotation, no abuse path (lazy nodes that rotate-to-dodge gain nothing because they still need to be successfully audited to earn rewards).
- No two-stage rollout. The protocol is purely additive — old peers continue working unchanged, new peers gradually gain audit/credit relative to each other.

## Open question

(a) The §6 cache TTL (`2 × max audit interval`) is the only freshness parameter. Set too low → peers fall out of credit between audits. Set too high → lazy node has more leeway before re-audit is required. Worth validating in implementation under realistic audit cadence.
