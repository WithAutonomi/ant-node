# Storage-Bound Audit via Gossip-Embedded Commitments — v5

**Status:** Draft for adversarial review (round 5).
**Previous:** v4 closed v3's BLOCKER (mutable-state pin) and two MAJORs (cache binding, structural bounds). v4 review accepted those fixes; only one operational MAJOR remained — honest peers can't answer audits pinned to `epoch − 1` because they don't keep the previous Merkle tree around.
**Scope:** Closes Findings 1 and 2.

## Changes vs v4

| # | v4 issue (codex round 4) | v5 fix |
|---|---|---|
| 1 | MAJOR (operational): responder keeps only the current tree; an audit pinned to `expected_commitment_hash` from `epoch − 1` cannot be answered after rotation → false-positive failures at epoch boundaries | Responder retains the **previous epoch's commitment + Merkle tree** for `WITNESS_RETENTION_DURATION = EPOCH_DURATION × 2` (= 2 hours). Audit responder picks the tree matching `expected_commitment_hash`. After retention expires the old tree is dropped. |
| — | NIT: §5a path-length bound `ceil(log2(key_count + 1))` over-accepts by 1 on powers of 2 | Tightened: `ceil(log2(key_count))` for `key_count >= 2`, `0` for `key_count == 1`. Not a security break, just a cleaner DoS bound. |

Everything else from v4 carries forward unchanged. Concisely below; full text is in v4 for any section not touched.

## Protocol (v5 deltas only)

### 2. Commitment — responder-side retention

The responder maintains an in-memory structure that holds **two** trees:

```rust
struct ResponderCommitments {
    current: BuiltCommitment,        // for the current `global_epoch`
    previous: Option<BuiltCommitment>,  // for `global_epoch - 1`, retained for ~1 epoch after rotation
}

struct BuiltCommitment {
    commitment: StorageCommitment,      // the signed wire-form blob (~3.4 KB)
    commitment_hash: [u8; 32],          // cached, computed once at build
    tree: MerkleTree,                   // keys + leaf hashes + internal nodes (~64 bytes × keys)
    built_at: Instant,
}
```

At epoch rollover (`now / EPOCH_DURATION_SECS` ticks over):
1. Build new tree over the current LMDB key set.
2. Move `current` → `previous` (drop the old `previous` if any).
3. Set new tree as `current`.

`previous` is dropped when `built_at + WITNESS_RETENTION_DURATION < now` (constant `WITNESS_RETENTION_DURATION = EPOCH_DURATION_SECS × 2`). This gives any in-flight audit pinned to the previous commitment a full hour after rollover to land before witnesses disappear.

Memory cost: 2× the v4 single-tree cost. For 10k keys: ~1.3 MB of tree state (still small).

### Audit-responder handling

When the responder receives an `AuditChallenge { expected_commitment_hash, .. }`:

1. Look up `expected_commitment_hash` in `ResponderCommitments`. Three cases:
   - Matches `current` → use `current.tree` to build the `CommitmentBound` response.
   - Matches `previous` (if retained) → use `previous.tree`.
   - No match (the auditor's pin doesn't correspond to any commitment we recognize) → respond `Rejected { reason: "unknown expected_commitment_hash" }`. Treated as audit failure by the auditor (existing behaviour from today's `Rejected` handling, see `audit.rs:297-322`).

2. The response carries the corresponding `commitment` from the matched tree. Auditor's §5b hash check passes by construction.

### Auditor logic (unchanged)

The auditor's §5c rule still says: if `commitment.global_epoch == current - 1`, no holder credit for that key this epoch. So the previous-epoch retention exists *purely to keep honest audits from false-failing*, not to extend reward eligibility. The freeriding-bound semantics from v4 hold.

### 5a (tightened path-length bound)

```text
expected_path_max = if key_count <= 1 { 0 } else { ceil_log2(key_count) }
require path.len() <= expected_path_max
```

Where `ceil_log2` uses the standard `(key_count - 1).next_power_of_two().trailing_zeros()` or equivalent. For `key_count == 1`: tree is a single leaf, path is empty.

### 11. DoS analysis — responder-side cost note

Holding 2 trees instead of 1 doubles responder memory cost. Worst case at 10k keys: ~1.3 MB tree state vs ~650 KB. Still bounded by `2 × 64 bytes × keys`, no attacker amplification. Building two trees vs one: at epoch boundary the new tree is built once; the old tree is reused as `previous` without recomputation. Net build cost per epoch is one tree, same as v4.

## Why v5 closes the operational gap

**Honest-rotate corner case (v4 MAJOR):**

Auditor A snapshots peer P's commitment at epoch `E−1`. P rolls into epoch `E` and rebuilds its tree. The challenge arrives carrying `expected_commitment_hash = H(E−1)`. P looks it up:
- `current` is `H(E)` → no match.
- `previous` is `H(E−1)` → match. P uses `previous.tree` to build the response.

Honest audit passes. False-positive avoided.

**Attack-rotate case (lazy node tries to abuse retention):**

A lazy node L was challenged on `H(E−1)`. By v5's §5c rule, even if L answers correctly using `previous.tree`, L earns no holder credit for the current epoch — the commitment-bound audit only counts as capability confirmation, not reward. So the retention window does not extend freeriding. L's only path to current-epoch rewards is to gossip a fresh commitment at epoch `E`, which requires having had the bytes at epoch `E`'s start.

## State summary (v5)

| Where | What | Size ceiling | Note |
|---|---|---|---|
| Responder | `current` + `previous` `BuiltCommitment` (each: tree + signed blob + cached hash) | ~`2 × (64 bytes × keys + 3.4 KB)` | ~1.3 MB for 10k keys |
| Per-RT-peer record (auditor) | same as v4 | ~96 bytes × RT peers | bounded by RT |
| `recent_provers[K]` cache | same as v4 | ~11.5 MB worst-case for 10k keys | bounded |

Everything else unchanged from v4.

## Open questions

(a) Should we retain *more than one* previous tree (e.g. 2-3 epochs) to handle slow / delayed audits? Conservative answer: no — v4's §5c rule means stale audits don't earn rewards anyway, so retaining more epochs just costs memory without buying anything. One-back is enough for the honest-rotate case.

(b) The `current → previous` transition happens at wall-clock epoch boundary on each node. Nodes with skewed clocks may have brief windows where both ends disagree about which commitment is current. The `current_epoch ∈ {current, current − 1}` gossip grace from §1 absorbs this, and the responder's two-tree lookup (`current` or `previous`) covers both cases on the audit-response side.

(c) The next-power-of-two path-length bound is exactly correct for balanced binary Merkle trees. If we ever switch to a different tree shape (e.g. domain-separated odd-leaf duplication), the bound formula must update — flag for implementation.
