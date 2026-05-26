# Storage-Bound Audit via Gossip-Embedded Commitments — v9

**Status:** Draft for adversarial review (round 9). Targeting consensus.
**Previous:** v7 (Instant-based) penalized honest cross-epoch. v8 (auditor's-epoch-only) was too lax — lazy responders could drop `previous` at E+1 and get benign-refresh. Plus clock skew between auditor and responder broke v8's same-epoch reasoning. v9 solves both with **responder-attested current_epoch** in the rejection, which the auditor cross-checks against the responder's contractual retention obligation.
**Scope:** Closes Findings 1 and 2.

## The core insight

Whether a `UnknownCommitmentHash` rejection is in-contract or out-of-contract depends on the **responder's own current epoch at the time it generated the rejection**, not on the auditor's clock. So v9 has the responder include its own `current_epoch` in the rejection. The auditor then has all the data it needs to apply the retention contract:

> A commitment from `pin_epoch` MUST be retained on the responder while the responder's own `current_epoch ∈ {pin_epoch, pin_epoch + 1}`. After `current_epoch >= pin_epoch + 2` the responder is permitted to drop it.

This is exactly the protocol's retention contract from §2 of v5. The auditor can verify it using the responder's own attested epoch.

The responder cannot lie about being at a later epoch without consequences: if they claim `current_epoch_responder = E+3` to escape penalty, but later gossip a commitment with `global_epoch = E+1`, the gossip's monotonicity check (§3 step 4 of v4) will fail at the auditor — `last_seen_epoch` for that peer is `E+3` (recorded from the rejection), and the gossip's `global_epoch = E+1 < E+3` is non-monotonic → drop. They've just locked themselves out of future audits, which §6 then converts into "no rewards."

## Changes vs v8

| # | v8 issue (codex round 8) | v9 fix |
|---|---|---|
| 1 | BLOCKER: cross-epoch UnknownCommitmentHash benign-refreshed even when responder dropped `previous` at E+1 (should be penalty) | Responder includes its `current_epoch_responder` in the rejection. Auditor applies the retention contract: penalize iff `pin_epoch ∈ {current_epoch_responder, current_epoch_responder - 1}`. |
| 2 | MAJOR: sub-epoch clock skew could shift auditor's epoch ahead of responder's, breaking v8's `current_epoch == pin_epoch` check | Auditor uses the *responder's* attested epoch in the classifier, not its own. Skew is no longer auditor-vs-responder; it's between the responder's truth and its own claims, which monotonicity bookkeeping (§3 step 4) handles. |

## Protocol (v9 deltas only)

### 1. `Rejected` carries responder's epoch

Wire type addition: when the responder rejects with `UnknownCommitmentHash`, it includes its own current epoch:

```rust
pub enum AuditResponse {
    // ...
    Rejected {
        challenge_id: u64,
        reason: AuditRejectReason,
        responder_current_epoch: Option<u64>,  // Some(epoch) for UnknownCommitmentHash, None for others
    },
}
```

The responder fills `responder_current_epoch = Some(self.current_epoch())` only for `UnknownCommitmentHash` rejects. For other reject reasons (key count exceeded, wrong peer ID, etc.) it's `None` — those aren't subject to the retention contract.

### 2. Auditor classification (final form)

```rust
fn classify_unknown_hash_rejection(
    outstanding: &OutstandingAudit,
    response_source: &PeerId,
    responder_epoch: u64,
) -> Decision {
    if response_source != &outstanding.challenged_peer_id {
        return Decision::Discard;  // not from the challenged peer
    }

    let pin_epoch = outstanding.pin_snapshotted_epoch;

    // Retention contract: commitment from epoch E MUST be retained
    // while the responder's current epoch is E or E+1. After E+2 they
    // may drop it.
    let must_retain = pin_epoch == responder_epoch
                   || pin_epoch + 1 == responder_epoch;

    if must_retain {
        // Responder claims they don't have the pinned commitment, but
        // the contract says they must. Full audit failure.
        Decision::Failure(AuditFailureReason::DroppedRetainedCommitment, outstanding.keys.len())
    } else if pin_epoch + 2 <= responder_epoch {
        // Responder is past the retention window. Benign.
        Decision::BenignRefresh
    } else {
        // pin_epoch > responder_epoch. Responder claims to be IN THE PAST
        // relative to our pin. Either we have a bogus pin (shouldn't happen
        // because we snapshotted from gossip the responder sent us) OR
        // the responder is lying about being earlier than us. Latter is
        // not exploitable on its own — but treat as malformed.
        Decision::Failure(AuditFailureReason::MalformedResponse, outstanding.keys.len())
    }
}
```

### 3. Auditor records `responder_epoch` for monotonicity

After processing the rejection, the auditor MUST update `peer_state.last_seen_epoch = max(last_seen_epoch, responder_epoch)`. This binds the responder's claim — any subsequent gossip from this peer with `global_epoch < responder_epoch` is non-monotonic and dropped (§3 step 4 of v4).

A lazy responder claiming `responder_epoch = E+10` to escape penalty thus loses the ability to ever gossip a commitment for epochs E through E+10. They've boxed themselves out of audits for ten epochs and earn no rewards during that time. The lie has a self-imposed cost: silence == no rewards (§6 of v4). Net: lying is at best a wash, more likely a loss.

### 4. Defense against the responder lying about its epoch

Can a lazy responder set `responder_epoch = pin_epoch + 2` (just enough to claim benign) to escape penalty on a still-in-contract pin?

Yes, **at the cost of locked-out gossip until they actually reach that epoch in real time**. If pin_epoch = E and they claim responder_epoch = E+2, the auditor's `last_seen_epoch` for them is now E+2. They cannot send any gossip until wall-clock advances to E+2. During that ~2-hour window they have no recent commitment from this auditor's view → no holder credit → no rewards.

Compare to today's lazy node who gets 24h of free grace via Bootstrapping. v9 reduces that to "lie costs you a 2-hour gossip silence per audit cycle, at most one audit per peer per 5-15 minutes." Still cheap? Run the math:
- Each lie buys ~5-15 minutes of dodge.
- Each lie costs ≥2 hours of gossip silence.
- Net: ≤7.5/120 = 6% of time productive, vs ~100% for an honest node. **Lying is strictly dominated by storing.**

If the attacker tries to amortize by lying once and then living through the 2h silence: they earn nothing for 2h, which is the cost of one full lazy-audit dodge plus all subsequent audit credit they would have earned. Strictly worse than honest behavior. v9's retention contract is enforced economically.

### 5. State summary

Same as v7 + the `responder_current_epoch` field on the wire. No new auditor state beyond what v7 already had.

## Final invariants summary

| Invariant | Owner | Enforcement |
|---|---|---|
| Leaf binds to `global_epoch` (closes root-replay) | Both sides | Cryptographic (v4 §2) |
| `expected_commitment_hash` snapshotted at challenge issue | Auditor | Local `OutstandingAudit` |
| `pin_snapshotted_epoch` recorded with the pin | Auditor | Same |
| Sticky `commitment_capable` | Auditor | `PeerSyncRecord` |
| Holder credit only with current-epoch commitment + cache hash match | Auditor | `recent_provers` |
| One rotation per epoch (INV-R1) | Responder | Self-discipline; violation caught by §2 (same-epoch) |
| Retain previous through next rotation (INV-R2) | Responder | Same; caught by §2 (E or E+1 case) |
| Responder attests its current_epoch on `UnknownCommitmentHash` | Responder | Wire-level (v9 §1) |
| Auditor classifies using responder's epoch + retention contract (INV-A1) | Auditor | v9 §2 |
| Auditor records responder_epoch into last_seen_epoch (INV-A4) | Auditor | v9 §3 — binds the responder's claim via monotonicity |
| Response source-binding (INV-A2) | Auditor | v8 §2 |
| `OutstandingAudit` freed on all terminal paths (INV-A3) | Auditor | v8 §3 |
| Atomic rollover via `ArcSwap` | Responder | Runtime (v6 §2) |
| Leaf domain separation | Both sides | Wire format (v4 §10) |

## Why v9 closes everything

| Attack | Caught by |
|---|---|
| Lazy node gossips real commitment, drops bytes, fetches on demand at audit | Fails §5b (commitment hash pin) and §5e (Merkle path verification with real bytes_hash) |
| Lazy node gossips fake commitment | Fails §5e (path doesn't verify against fake root) |
| Lazy node claims more keys than committed | Fails §6 (no per-key proof, no holder credit) |
| Lazy node rotates twice mid-epoch, drops `previous` | Caught by v9 §2 (same-epoch case) |
| Lazy node drops `previous` early (still pre-E+2) | Caught by v9 §2 (E+1 case) |
| Lazy node lies about its current_epoch to escape | Self-imposed gossip silence via INV-A4, dominates honest behavior |
| Bootstrap-claim shield (Finding 2) | Capable peer + Bootstrapping = full failure (v4 §7) |

## Open questions (unchanged)

(a) Stage 1 → Stage 2 transition.
(b) Audit-selection fairness validation.

## Implementation checklist (final)

(Inherits all items from v6-v8.) Additions:

- [ ] Wire: `Rejected.responder_current_epoch: Option<u64>`.
- [ ] Auditor: classify per v9 §2 logic.
- [ ] Auditor: update `last_seen_epoch = max(last_seen_epoch, responder_epoch)` on UnknownCommitmentHash receipt.
- [ ] Tests:
  - [ ] Same-epoch UnknownCommitmentHash → audit failure.
  - [ ] pin_epoch + 1 == responder_epoch UnknownCommitmentHash → audit failure.
  - [ ] pin_epoch + 2 <= responder_epoch UnknownCommitmentHash → benign refresh, no penalty.
  - [ ] Responder lies about future epoch → subsequent gossip is non-monotonic and dropped.
  - [ ] All v6-v8 tests still pass.
