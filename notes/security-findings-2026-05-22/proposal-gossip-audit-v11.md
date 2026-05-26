# Storage-Bound Audit via Piggybacked Commitments — v11

**Status:** Draft for adversarial review.
**Replaces:** v10. v10 review found one MAJOR: `UnknownCommitmentHash` left the auditor's stored `last_commitment` in place, so cached `recent_provers` entries still matched the stale credited hash → peer keeps holder credit until TTL or fresh gossip. v11 adds one line: invalidate `last_commitment` when the responder denies it.
**Scope:** Closes Findings 1 (audit not storage-bound) and 2 (bootstrap-claim shield).

## Change vs v10

Only one section changes. Everything else identical to v10.

### §5 (revised) — auditor handling of `UnknownCommitmentHash`

When the auditor receives `Rejected { UnknownCommitmentHash }` for a challenge it issued with `expected_commitment_hash = H`:

```text
peer_state.last_commitment = None   // invalidate; the credited commitment is gone
peer_state.commitment_capable stays true (sticky)
```

Effect: §6's holder-credit rule requires `peer_state.last_commitment[P].commitment_hash` to equal the cache entry's `commitment_hash`. With `last_commitment = None`, the first condition (`last_commitment.commitment_capable == true`) trivially passes via the sticky flag, but the second (cached entry hash matches `last_commitment`'s hash) fails — there's nothing to match against. P loses holder credit for all keys until they gossip a fresh commitment AND get re-audited against it.

This costs the lazy node what v10 mistakenly promised: rotating the commitment to dodge audits also drops the credit they were silently keeping. Re-earning credit requires gossiping the new commitment AND being successfully audited against it — same cost as starting from scratch.

No new state, no new wire types, no new logic. Just `last_commitment = None` on UnknownCommitmentHash receipt.

## Why this closes the v10 MAJOR

The v10 attack:
1. P proves K under C1 → cached `{peer_id: P, commitment_hash: C1}` in `recent_provers[K]`.
2. P locally drops bytes and switches to C2 (does not gossip yet).
3. Auditor A challenges on C1 → P replies `UnknownCommitmentHash`.
4. v10: A's `last_commitment[P] = C1`. Cache entry C1 matches. P keeps credit until TTL.
5. v11: A's `last_commitment[P] = None`. Cache entry C1 has nothing to match against. P loses credit immediately.

P's only path back is to gossip C2 (or any new commitment), which A then verifies and stores. Then A re-audits. P must prove every key against C2 to regain credit. Same path as a fresh peer — no shortcut.

A lazy node rotating to dodge gains *nothing*: each rotation flushes their credit. They have to refill it through real audits, which require actually answering with valid bytes_hash + path + digest. Bandwidth cost scales with the number of keys claimed, exactly the economic disincentive the design wants.

## Everything else from v10 (unchanged)

Sections 1, 2, 3, 4 (responder-side), 6 (cache caps), 7 (lazy-node attack analysis), 8 (replay-nonce), 9 (state summary), 10 (wire format domain separation), 11 (DoS table), 12 (backwards compatibility), 13 (implementation checklist) are unchanged. Only §5 gains the one-line invalidation.

## Updated DoS table addition

| Vector | Mitigation |
|---|---|
| Force responder to deny pin to retain stale credit (v10 MAJOR) | `UnknownCommitmentHash` invalidates `last_commitment` → cache entries lose their match basis (v11 §5) |

## State summary

Unchanged. `last_commitment: Option<...>` was already `Option` in v10. The change is purely in the auditor's update rule.

## Why v11 is final

- v1-v9 bolted on `global_epoch`, which solved problems the hash pin already solved.
- v10 removed the epoch, simplified massively, but had a credit-preservation bug at audit-vs-gossip race.
- v11 fixes the bug with one line. No epoch, no shared clock, no two-tree retention, no epoch classifier. Just: pin invalidation on responder denial.

The design is now:

- Commitment piggybacked on existing gossip — free transport.
- Hash pin on audit challenge — defeats fresh-commitment substitution.
- Nonce in digest — defeats replay.
- Per-key Merkle path + bytes_hash check — forces real possession at gossip time.
- Cache binds to commitment_hash — credit follows the gossiped commitment.
- Denial invalidates the pin → invalidates the credit. No dodge.
- Silent peer = no credit. No bootstrap-claim shield.
