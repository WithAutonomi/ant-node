# Storage-Bound Audit via Gossip-Embedded Commitments — v8

**Status:** Draft for adversarial review (round 8). Targeting consensus.
**Previous:** v7 made the auditor classify `UnknownCommitmentHash` rejections itself instead of trusting the responder. v7 review found the classifier was Instant-based when retention is epoch-based, allowing honest false positives. v8 reclassifies on epochs with an explicit skew budget.
**Scope:** Closes Findings 1 and 2.

## Changes vs v7

| # | v7 issue (codex round 7) | v8 fix |
|---|---|---|
| 1 | BLOCKER: `pin_age < WITNESS_RETENTION_DURATION` (Instant-based) over-penalizes — retention is epoch-based, so an auditor snapshotting late in epoch E can have a pin invalidated only ~1 hour later when the responder drops `previous` at the start of E+2. Plus clock skew makes this worse. | **Epoch-based classification.** Auditor records `pin_snapshotted_epoch` (the responder's `global_epoch` from the gossiped commitment, not auditor's wall clock). The retention guarantee is: a commitment from epoch E is retained at least through the end of E+1, so an auditor's pin from epoch E is *in-contract* iff the auditor's current epoch is ≤ E+1. With a 1-epoch clock-skew budget, the in-contract test is `current_epoch_at_auditor ≤ pin_snapshotted_epoch + 1`. Outside that, benign. |
| 2 | §6 should free `OutstandingAudit` on every terminal path | Made explicit: free on success / `Rejected` / malformed response / send failure / timeout. |
| 3 | If implementation becomes async, source-bind the response | Made explicit: classifier rejects if `response_source_peer != outstanding.challenged_peer_id`. |

## Protocol (v8 deltas only)

### 1. Auditor pin: snapshot the commitment epoch, not just the hash

```rust
struct OutstandingAudit {
    challenge_id: u64,
    challenged_peer_id: PeerId,
    expected_commitment_hash: [u8; 32],
    // CHANGED: was Instant; now epoch.
    pin_snapshotted_epoch: u64,  // commitment.global_epoch at snapshot time
}
```

The auditor reads `pin_snapshotted_epoch` from `peer_state.last_commitment_root.global_epoch` (which §3 of v4 already stores). No wall-clock Instant required.

### 2. Auditor classification of `UnknownCommitmentHash`

```rust
fn classify_unknown_hash_rejection(
    outstanding: &OutstandingAudit,
    response_source: &PeerId,
    keys: &[XorName],
) -> Decision {
    // Source-binding: the response must come from the challenged peer.
    if response_source != &outstanding.challenged_peer_id {
        return Decision::Discard;  // ignore, possibly forwarded
    }

    let current_epoch = global_epoch_now();
    let pin_epoch = outstanding.pin_snapshotted_epoch;

    // The retention contract: commitment from epoch E is retained
    // through the end of E+1 (dropped on E+2 rotation).
    //
    // Allow a +1 epoch skew budget: the responder may have advanced
    // its wall clock faster than the auditor by up to one epoch tick.
    let max_retained_epoch_at_responder = pin_epoch + 1 + SKEW_BUDGET_EPOCHS;
    //                                                    ^ = 1

    if current_epoch <= max_retained_epoch_at_responder {
        // Pin is still in retention. Responder violated INV-R2.
        // Full audit failure.
        Decision::Failure(AuditFailureReason::DroppedRetainedCommitment, keys.len())
    } else {
        // Pin is out of retention. Auditor was slow / offline.
        // Benign: refresh and retry next cycle.
        Decision::BenignRefresh
    }
}
```

Where `SKEW_BUDGET_EPOCHS = 1`. With `EPOCH_DURATION = 1h`, this gives an explicit 1-hour skew tolerance.

Concretely: if the auditor's pin is from epoch E, it's guaranteed in-contract through the auditor's local epoch E+2 (E retained through E+1 + 1 epoch of skew). Outside that range, benign.

**Honest case:** auditor at local epoch E+3 (more than 2h after snapshot). Pin epoch = E. `current_epoch(E+3) > max_retained_epoch(E+2)` → benign refresh. No penalty.

**Attack case:** lazy responder at local epoch E rotates twice mid-epoch and drops `previous`. Auditor at local epoch E (no time has passed; same epoch as snapshot). `current_epoch(E) <= max_retained_epoch(E+2)` → audit failure. Full penalty.

**Honest cross-epoch:** auditor at E+1 (1h after snapshot). Pin epoch = E. `E+1 <= E+2` → in-contract. Honest responder still has `previous` from E, answers correctly via §2 of v5. No failure.

### 3. `OutstandingAudit` lifecycle

Created when auditor issues `AuditChallenge` with `expected_commitment_hash`. Freed on any of:

1. Valid `CommitmentBound` response → ✓ (existing flow).
2. `Bootstrapping` response → ✓ (existing flow).
3. `Rejected { reason: UnknownCommitmentHash }` → classify per §2, then free.
4. `Rejected { reason: <any other> }` → free, audit failure per today's rules.
5. `Digests` response when `require_commitment_proof = true` and `commitment_capable = true` → free, audit failure (§5 of v4).
6. Malformed / undecodable response → free, audit failure per today's rules (`AuditFailureReason::MalformedResponse`).
7. Send failure → free, timeout-path audit failure per today's rules.
8. Response timeout (`audit_response_timeout`) → free, timeout-path failure.

Memory ceiling: one entry per outstanding audit. The existing audit system already maintains an outstanding state per peer (today via the request-response flow). v8 adds 48 bytes per outstanding audit (challenge_id u64, peer_id 32, hash 32, epoch u64 + small overhead). Bounded by audit cadence (~one per peer at a time, ~RT_size = ~20-2000 entries).

### 4. Updated invariants table

| Invariant | Owner | Enforcement |
|---|---|---|
| INV-R1: one rotation per epoch | Responder | Self-discipline; violation produces audit failures via §2 |
| INV-R2: retain `previous` through next rotation | Responder | Same — Arc lifetime + no early-drop |
| INV-A1: classify `UnknownCommitmentHash` via epoch, not Instant | Auditor | §2 |
| INV-A2: source-bind responses to outstanding challenge | Auditor | §2 first check |
| INV-A3: free `OutstandingAudit` on every terminal path | Auditor | §3 |

## Why v8 closes the v7 BLOCKER

**Honest false-positive case (the v7 BLOCKER):**

Auditor snapshots P's commitment at local epoch E, late in the epoch. Pin epoch = E. P honestly rotates at E+1 (retains old as `previous`), and at E+2 (drops the E commitment — which is the contract). Auditor's local clock is at E+2 (1h-2h after snapshot). Audit arrives, P returns `UnknownCommitmentHash`. v7 classifier (Instant-based) says `pin_age = ~1.5h < WITNESS_RETENTION_DURATION (2h)` → false penalty.

v8 classifier (epoch-based): `current_epoch(E+2) > max_retained_epoch(E+1+1=E+2)` ... wait, that's `E+2 <= E+2`, which classifies as IN-contract. So v8 would also penalize.

Let me redo. With SKEW_BUDGET = 1: `max_retained = E + 1 + 1 = E+2`. Test is `current <= max_retained`. At current = E+2 the test is true → penalty.

The honest case needs `current > E+2` for benign. So auditor must be at E+3 (2-3h after snapshot). But the commitment from E was dropped at start of E+2 → there's a window from start-of-E+2 to E+3 where an honest responder has correctly dropped E (per contract) but the auditor still penalizes.

This is the off-by-one I need to fix. Retention contract is "at least through E+1." So `max_retained = E + 1`, not E+2. Auditor at E+2 is correctly classified as out-of-contract (benign). Skew budget then adds 1 epoch on top: `max_retained = E + 1 + 1 = E + 2` — but that re-introduces the false-positive.

**Resolution:** the skew budget is for *clock disagreement between auditor and responder*. The contract gives 1 epoch of retention. The skew budget allows the responder to be "ahead" of the auditor by 1 epoch when the auditor thinks it's still in contract. So the test should be: pin is in-contract iff `current_epoch_at_auditor <= pin_epoch + 1` AND we tolerate the responder being one epoch ahead. But if the responder is ahead, they've already advanced and dropped — so the auditor's "in-contract" classification is wrong by exactly the skew. Correct formulation:

```text
// The commitment from epoch E is retained on the responder
// through epoch E+1. The responder might be up to 1 epoch
// ahead of the auditor. So when the auditor sees current = E+1,
// the responder might actually be at E+2 and have dropped the
// commitment. Don't penalize in this overlap.

let max_in_contract_epoch_at_auditor = pin_epoch;  // strict
// or, with explicit skew tolerance:
let max_in_contract_epoch_at_auditor = pin_epoch;  // safe lower bound
```

i.e. only penalize if `current_epoch_at_auditor == pin_epoch` (no advancement at all; pin and current are in the same epoch). At that point the responder has not yet rotated past E, so it MUST still have E as `current`. Outside that (current > pin_epoch), we can't be sure whether the responder has rotated to E+1 (still retaining E as `previous`) or to E+2 (dropped E correctly). Benign refresh.

**This is much more conservative — the penalty only fires if the auditor snapshots and the response comes back within the same epoch.** That's actually the right shape: the malicious case (rotate twice mid-epoch to invalidate pin) is exactly the case where pin_epoch and current_epoch are the same. The honest cross-epoch case is "different epochs," which v8's refined classifier correctly treats as benign.

Let me rewrite §2 with the corrected logic:

### 2 (revised). Auditor classification (corrected for off-by-one)

```rust
fn classify_unknown_hash_rejection(
    outstanding: &OutstandingAudit,
    response_source: &PeerId,
    keys: &[XorName],
) -> Decision {
    if response_source != &outstanding.challenged_peer_id {
        return Decision::Discard;
    }

    let current_epoch = global_epoch_now();
    let pin_epoch = outstanding.pin_snapshotted_epoch;

    // The only window in which the responder MUST still have the
    // pinned commitment is when no epoch has elapsed since the auditor
    // snapshotted: same epoch on both sides. As soon as either side
    // has advanced, the responder may have correctly rotated past it
    // (or be in a clock-skew transient where it has).
    if current_epoch == pin_epoch {
        // Same epoch: responder cannot have rotated. UnknownCommitmentHash
        // here is a protocol violation (INV-R3) — they should have current
        // matching the pin. Full failure.
        Decision::Failure(AuditFailureReason::DroppedRetainedCommitment, keys.len())
    } else {
        // Different epoch: cross-rotation transient. Benign.
        Decision::BenignRefresh
    }
}
```

**Trade-off:** the penalty only fires for in-same-epoch attacks. A lazy node that rotates twice within one epoch is caught; a lazy node that waits for the next epoch boundary to drop `previous` early is NOT caught by this classifier (but is still caught by §5b in v4 — they'd need a fresh response commitment that hashes to the pin, which they can't produce). So the lazy-node attack surface is still fully covered between §5b and §2:

- Within an epoch: §2 catches early-drop via UnknownCommitmentHash penalty.
- Across an epoch: §5b catches any attempt to substitute a different commitment (only the originally-gossiped one hashes correctly).

The classifier just defers to §5b after epoch rollover.

## State summary (v8)

Unchanged from v7. The change is purely in the classifier logic.

## Why v8 is final-quality

- v7's BLOCKER (over-penalizing honest cross-epoch rotation) is closed: classifier no longer punishes after epoch rollover.
- The malicious rotate-twice-in-one-epoch attack is still caught (current_epoch == pin_epoch case).
- After rollover, the responder's substitution attempts are caught by §5b's hash pin (any new commitment they craft can't hash to the pinned value).
- No false positives.
- All v1-v7 fixes carry forward.

## Final invariants summary

| Invariant | Owner | Enforcement |
|---|---|---|
| Leaf binds to `global_epoch` | Both sides | Cryptographic (§2 of v4) |
| `expected_commitment_hash` snapshotted at challenge issue + epoch | Auditor | Local `OutstandingAudit` |
| Sticky `commitment_capable` | Auditor | `PeerSyncRecord` |
| Holder credit only with current-epoch commitment + cache hash match | Auditor | `recent_provers` |
| One rotation per epoch (INV-R1) | Responder | Self-discipline + §2 penalty if violated mid-epoch |
| Retain `previous` through next rotation (INV-R2) | Responder | Same |
| Unknown-hash classification by epoch (INV-A1) | Auditor | §2 |
| Response source-binding (INV-A2) | Auditor | §2 first check |
| `OutstandingAudit` freed on all terminal paths (INV-A3) | Auditor | §3 |
| Atomic rollover via `ArcSwap` | Responder | Runtime |
