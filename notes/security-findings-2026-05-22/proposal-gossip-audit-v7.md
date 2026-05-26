# Storage-Bound Audit via Gossip-Embedded Commitments — v7

**Status:** Draft for adversarial review (round 7). Targeting consensus.
**Previous:** v6 added `ArcSwap` rollover + `UnknownCommitmentHash` reject. v6 review found the `UnknownCommitmentHash` lane could be abused via selective forgetting or rapid rotation. v7 closes that.
**Scope:** Closes Findings 1 and 2.

## Changes vs v6

| # | v6 issue (codex round 6) | v7 fix |
|---|---|---|
| 1 | `UnknownCommitmentHash` as written trusts the responder's claim. A responder that drops `previous` early or rotates more than once per epoch can produce free audit skips. | **Auditor classifies the rejection based on its own pin age, independently of the responder's claim.** If the auditor's snapshotted `expected_commitment_hash` is younger than `WITNESS_RETENTION_DURATION`, the responder is contractually obliged to know it. Auditor responds: `UnknownCommitmentHash` for an in-retention pin = **audit failure** (responder dropped contractually retained state). Out-of-retention pin = benign, auditor refreshes. |
| 2 | "Exactly one rotation per `global_epoch`, retain previous through next swap" not stated as a hard invariant | Added as **protocol invariant** in §2. Responder MUST rotate at most once per `global_epoch`, and the demoted tree MUST remain reachable until the next rotation. Violation = self-induced audit failure (since pins land on dropped state) — no enforcement infrastructure needed, the auditor's pin-age classification provides the penalty. |
| 3 | Tests not enumerated for these invariants | §6 implementation checklist adds: test that auditor penalizes `UnknownCommitmentHash` from an in-retention pin; test that rapid rotation produces self-induced audit failures; test that honest rotation across one epoch boundary does not. |

Everything else unchanged.

## Protocol (v7 deltas only)

### 1. Auditor-side classification of `UnknownCommitmentHash`

When the auditor issues an audit, it embeds:

```rust
pub struct AuditChallenge {
    pub challenge_id: u64,
    pub nonce: [u8; 32],
    pub challenged_peer_id: [u8; 32],
    pub keys: Vec<XorName>,
    pub require_commitment_proof: bool,
    pub expected_commitment_hash: Option<[u8; 32]>,
}
```

The auditor records locally (not on the wire):

```rust
struct OutstandingAudit {
    challenge_id: u64,
    challenged_peer_id: PeerId,
    expected_commitment_hash: [u8; 32],
    pin_snapshotted_at: Instant,    // when the auditor snapshotted from peer_state
}
```

This is a single in-memory entry per outstanding audit. It's freed when the response arrives or the audit times out. Memory: ~80 bytes × concurrent audits. Bounded by audit cadence (~one outstanding audit per peer at a time).

**On receiving `AuditResponse::Rejected { reason: UnknownCommitmentHash, .. }`:**

```rust
let pin_age = Instant::now() - outstanding.pin_snapshotted_at;
if pin_age < WITNESS_RETENTION_DURATION {
    // Auditor's pin is YOUNGER than the responder's contractual retention.
    // Responder is required to still have this commitment. They don't.
    // This is a self-induced audit failure: full per-key penalty.
    emit_audit_failure(challenged_peer_id, keys.len(), AuditFailureReason::DroppedRetainedCommitment);
} else {
    // Auditor's pin is OLDER than retention window. Benign.
    // Auditor missed a gossip cycle or was offline. Drop snapshot, refresh on next gossip, retry next cycle.
    log_skipped_audit(challenged_peer_id, "stale auditor pin");
}
```

The auditor never trusts the responder's word about whether they *should* have the commitment. The decision is made independently from the auditor's local `pin_snapshotted_at` timestamp.

This closes v6's abuse vector: a lazy responder cannot escape by claiming `UnknownCommitmentHash` because the auditor checks its own clock, not the responder's claim. If the pin is in-retention, the responder violated the protocol → full penalty.

### 2. Responder protocol invariants (mandatory)

The responder MUST:

**INV-R1 (one rotation per epoch):** Activate exactly one new `current` commitment per `global_epoch`. Rotation occurs when wall-clock `global_epoch` ticks over (see §1 of v4).

**INV-R2 (retention through next rotation):** After rotation, the previously-current tree becomes `previous` and MUST remain reachable until the NEXT rotation (one full epoch later). Implementation: the `previous` slot is only overwritten by the next rotation, never explicitly dropped earlier. The Arc-based lifetime from v6 §2 already guarantees in-flight readers see consistent state; INV-R2 just says the responder must not deliberately publish a `ResponderCommitments { previous: None, .. }` between rotations.

**INV-R3 (commitment hash binding):** A responder must answer audits against `expected_commitment_hash` matching either `current` or `previous`. Any other hash → `Rejected { reason: UnknownCommitmentHash }`.

Enforcement: implicit. A responder that violates INV-R1 or INV-R2 will receive `UnknownCommitmentHash`-classification audit failures the next time an auditor pins to a dropped commitment. The auditor-side classification in §1 punishes the violation without requiring extra protocol machinery.

### 3. Updated rejection-reason wire type

```rust
pub enum AuditRejectReason {
    /// Auditor's expected_commitment_hash is not in this responder's
    /// `current` or `previous` slot. Auditor classifies as failure or benign
    /// based on its own pin_snapshotted_at age.
    UnknownCommitmentHash,
    /// Existing today: challenge size > max_incoming_audit_keys.
    ChallengedKeyCountExceedsLimit,
    /// Existing today: challenge.challenged_peer_id != self.
    WrongChallengedPeerId,
}
```

Old non-typed `Rejected { reason: String }` is preserved for backwards compat; new code uses the enum. (Existing `audit.rs:554, 567` already uses string reasons; this can be a typed-then-stringified migration.)

### 4. State summary update

| Where | What | Size | Note |
|---|---|---|---|
| Auditor | `OutstandingAudit` per in-flight challenge (challenge_id, peer, hash, pin_snapshotted_at) | ~80 bytes × concurrent audits | Freed on response or timeout |

All other state from v4/v5/v6 unchanged.

### 5. Why v7 closes the v6 abuse

**Attack: lazy responder rotates twice per epoch to invalidate auditor pins.**

Lazy node L performs:
- T=0: gossip commitment C₁.
- Auditor A snapshots `pin = H(C₁)` at T=2 min, issues audit.
- T=3 min: L "rotates" to C₂ (despite being mid-epoch), drops C₁.
- Audit arrives at T=4 min. L returns `Rejected { UnknownCommitmentHash }`.

Auditor checks: `pin_age = 2 minutes < WITNESS_RETENTION_DURATION (2h)`. **Audit failure** for L. Full per-key penalty. L cannot escape by rotating.

**Attack: lazy responder drops `previous` early to invalidate pins from the previous epoch.**

Same mechanism: if the auditor's pin is < 2h old, it's in-retention from the responder's perspective. Dropping `previous` doesn't help — the auditor classifies on its own clock.

**Honest case: auditor offline for >1 hour, returns with stale pin.**

Auditor's `pin_snapshotted_at` is now >2h old. Auditor's check classifies the rejection as benign, refreshes, retries on next cycle. No penalty.

### 6. Implementation checklist additions

- [ ] Auditor: maintain `outstanding_audits: HashMap<challenge_id, OutstandingAudit>`. Free on response or timeout.
- [ ] Auditor: on `Rejected { reason: UnknownCommitmentHash }`, compute `pin_age`; full penalty if < `WITNESS_RETENTION_DURATION`, benign refresh otherwise.
- [ ] Responder: enforce one rotation per epoch (idempotent tick handler).
- [ ] Responder: `previous` slot is mutated only by rotation, never explicitly dropped.
- [ ] **Tests:**
  - [ ] Responder that rotates twice in one epoch and then receives an audit pinned to the dropped tree → full audit failure penalty.
  - [ ] Honest responder that rotates at the epoch boundary, receives an audit pinned to `previous` (epoch-1) → no false failure.
  - [ ] Auditor offline 3h, gossip arrived, pin became stale → benign refresh, no penalty.
  - [ ] All PoC tests from Friday's `tests/poc_lazy_audit_*.rs` (Findings 1 + 2) must FAIL after this lands.

## Open questions (unchanged from v6)

(a) Stage 1 → Stage 2 transition (config rollout vs observed-ratio).
(b) Audit-selection fairness check.

## Final invariants summary

| Invariant | Owner | Enforcement |
|---|---|---|
| Leaf binds to `global_epoch` (closes root-replay) | Both sides | Cryptographic |
| `expected_commitment_hash` is snapshotted at challenge issue | Auditor | Local memory |
| Sticky `commitment_capable` | Auditor | `PeerSyncRecord` field |
| Holder credit only with current-epoch commitment + cache `commitment_hash` match | Auditor | `recent_provers` cache |
| One rotation per epoch + retention through next rotation | Responder | INV-R1/R2, penalized via UnknownCommitmentHash classification |
| `UnknownCommitmentHash` benign iff auditor's pin is older than retention window | Auditor | Local clock check |
| Atomic rollover via `ArcSwap` | Responder | Runtime |

No persistent disk state. All recoverable from LMDB + a network round.
