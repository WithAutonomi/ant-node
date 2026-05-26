# Storage-Bound Audit via Piggybacked Commitments — v12

**Status:** Draft for adversarial review.
**Replaces:** v11. v11's unconditional `last_commitment = None` on `UnknownCommitmentHash` raced with honest rotation (peer gossips C2, then stale C1 audit returns Unknown, auditor wrongly clears the fresh C2). v12 makes the invalidation conditional: only clear if the currently stored hash is still the rejected one.
**Scope:** Closes Findings 1 (audit not storage-bound) and 2 (bootstrap-claim shield).

## Change vs v11

One condition added.

### §5 (revised) — auditor handling of `UnknownCommitmentHash`

When the auditor receives `Rejected { UnknownCommitmentHash }` for a challenge it issued with `expected_commitment_hash = H`:

```rust
if peer_state.last_commitment.map(|c| c.hash) == Some(H) {
    peer_state.last_commitment = None;   // only invalidate if still the rejected one
}
// else: a fresh commitment arrived during the in-flight audit; don't clobber it.
```

That's the only change.

### Why this works

Three cases:

1. **Lazy rotation (the v10 attack):** P proves K under C1, then locally drops bytes. No fresh gossip. Auditor still has `last_commitment = C1`. Audit on C1 → `UnknownCommitmentHash` → stored hash matches H → `last_commitment = None` → cached entries lose their match basis → credit dropped. ✓

2. **Honest rotation (the v11 race):** P gossips C2 between audit issue (pinned to C1) and audit response. Auditor's `last_commitment = C2` (gossip step updated it). Audit on C1 → `UnknownCommitmentHash` → stored hash is C2, not H=C1 → no invalidation. C2 remains valid; honest peer not punished. ✓

3. **Stale auditor:** Auditor was offline; never received gossip update from P. Auditor's `last_commitment = C1` still. P long since rotated. Audit on C1 → `UnknownCommitmentHash` → stored hash matches H → `last_commitment = None`. Next gossip from P refreshes to C_current. Re-audit. Honest behaviour, minor delay. ✓

No new state, no new wire types, one extra `if` in the response handler.

## Everything else from v10/v11 (unchanged)

§§1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13 carry from v10. The only line that differs across v10 → v11 → v12 is the auditor's UnknownCommitmentHash handler.

## What this design is

**The simplest possible storage-bound audit:**

| Mechanism | Purpose |
|---|---|
| Commitment piggybacked on existing gossip | Free transport, no new schedule |
| `expected_commitment_hash` in audit challenge | Pin to gossiped commitment, defeat fresh substitution |
| Per-challenge random nonce | Defeat replay |
| Per-key Merkle path + `bytes_hash` recompute | Force real possession at gossip time |
| `recent_provers[K]` bound by current commitment hash | Credit only flows through audits against a still-current commitment |
| Conditional invalidation on UnknownCommitmentHash | Lazy rotation drops credit; honest rotation doesn't |
| Silent peer = no `commitment_capable` = no credit | Closes Bootstrap-claim shield |

No epochs. No shared clocks. No retention contracts. No two-tree storage. No classifier rules.

## Why v12 is final

The decision tree is exhaustive:

- **Honest rotation gossip-before-audit-response**: tested by case 2 above → no false invalidation.
- **Lazy rotation no-gossip**: tested by case 1 → credit dropped, attack closed.
- **Stale auditor**: case 3 → resolves via next gossip cycle.
- **Replay**: nonce defeats.
- **Fresh-commitment substitution at audit response**: hash pin defeats.
- **Fake commitment (random root)**: Merkle path verification defeats.
- **Overclaim (claim more keys than committed)**: §6's per-key cache requires proof per key.
- **Silent peer**: no commitment, no credit.

No remaining attack vector that doesn't reduce to "lazy node has to fetch bytes per audit at bandwidth cost ≥ storage cost," which is the design's accepted economic disincentive (per user constraint #4: make freeriding more expensive than storing, not impossible).
