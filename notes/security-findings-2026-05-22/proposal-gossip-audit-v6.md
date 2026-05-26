# Storage-Bound Audit via Gossip-Embedded Commitments — v6

**Status:** Draft for adversarial review (round 6). Targeting consensus.
**Previous:** v5 closed v4's operational MAJOR. v5 review accepted all security properties; one MEDIUM remained (rollover atomicity + retention lifetime) plus a documentation request (audit-delay assumption).
**Scope:** Closes Findings 1 and 2.

## Changes vs v5

| # | v5 issue (codex round 5) | v6 fix |
|---|---|---|
| 1 | MEDIUM: rollover steps 1-3 described sequentially; without atomic swap a concurrent audit handler can observe neither `current` nor `previous` as valid, or have `previous` freed mid-response | Rollover is specified as one atomic swap over `Arc<ResponderCommitments>`. Audit handlers acquire a reference to the matched `BuiltCommitment` for the full response build, so the swap can drop the prior `Arc` without disturbing in-flight responses. |
| 2 | DOCUMENTATION: assumption "audit-delay > 1 epoch is out of contract" not stated | §1 makes the assumption explicit: `expected_commitment_hash` older than the responder's retained `previous` is treated as `Rejected { reason: "unknown expected_commitment_hash" }`. Auditor knows this rejection is benign (their own pin was stale) and skips the penalty for this specific reason code, retrying with a fresh pin on the next cycle. |

Nothing else changed. All v4 + v5 security properties carry forward.

## Protocol (v6 deltas only)

### 1. Audit-delay contract (made explicit)

A challenge's `expected_commitment_hash` is valid against a responder iff the hash matches either the responder's `current` or `previous` commitment. The retention window is `WITNESS_RETENTION_DURATION = 2 × EPOCH_DURATION = 2 hours`. Any audit issued more than ~1 hour after the auditor's snapshotted gossip will:

- Find the responder has already rotated `previous` out.
- Receive `AuditResponse::Rejected { challenge_id, reason: "unknown expected_commitment_hash" }`.

To distinguish this benign rejection (stale auditor pin, not a bad responder) from a malicious rejection (responder lying), v6 adds a typed reason:

```rust
pub enum AuditRejectReason {
    UnknownCommitmentHash,
    ChallengedKeyCountExceedsLimit,
    WrongChallengedPeerId,
    // ... existing reasons
}
```

The auditor's handling of `Rejected { reason: UnknownCommitmentHash }`:

- **Do not** apply audit-failure trust penalty.
- Refresh the auditor's view: drop the snapshotted `expected_commitment_hash`, wait for the next gossip from this peer, and re-issue the audit on the fresh hash next cycle.
- The audit slot is effectively wasted but the peer is not falsely penalized. Same outcome as today's `Bootstrapping` path: no penalty, no credit, move on.

All *other* `Rejected` reasons continue to be treated as audit failures (today's behaviour, see `audit.rs:297-322`). Lazy nodes cannot abuse `UnknownCommitmentHash` because they cannot make their *own* commitment unknown — they always have at least their `current` tree, and that's what they gossiped. The reason fires only when the auditor's pin is genuinely stale.

### 2. Responder state — atomic rollover (made explicit)

Responder maintains:

```rust
pub struct ResponderCommitments {
    current: Arc<BuiltCommitment>,
    previous: Option<Arc<BuiltCommitment>>,
}

// Wrapped for atomic swap:
pub struct CommitmentState {
    inner: ArcSwap<ResponderCommitments>,    // or `RwLock<Arc<ResponderCommitments>>`
}
```

**Read path (audit responder):**

```rust
fn lookup(&self, expected_hash: &[u8; 32]) -> Option<Arc<BuiltCommitment>> {
    let snapshot = self.inner.load_full();   // single atomic Arc clone
    if snapshot.current.commitment_hash == *expected_hash {
        Some(Arc::clone(&snapshot.current))
    } else if let Some(prev) = &snapshot.previous {
        if prev.commitment_hash == *expected_hash {
            Some(Arc::clone(prev))
        } else { None }
    } else { None }
}
```

The audit responder builds its response from the returned `Arc<BuiltCommitment>`. Even if rollover replaces the inner `ResponderCommitments` mid-response, the responder's `Arc` holds the tree alive until the response is sent.

**Write path (epoch rollover):**

```rust
fn rotate(&self, new_current: BuiltCommitment) {
    let old = self.inner.load_full();
    let new = ResponderCommitments {
        current: Arc::new(new_current),
        previous: Some(Arc::clone(&old.current)),  // demote old current to previous
    };
    self.inner.store(Arc::new(new));  // single atomic swap
    // The old `previous` (if any) and the old `ResponderCommitments` are dropped
    // once any in-flight readers release their Arcs.
}
```

This guarantees:
1. Readers always see *exactly one* `ResponderCommitments` snapshot for the duration of their `load_full()` call.
2. The previous tree is reachable for at least one full epoch after rotation (it becomes `previous` after one rotation, then dropped on the next rotation when `WITNESS_RETENTION_DURATION` has elapsed naturally).
3. An in-flight audit response that grabbed the old `previous` is unaffected by rotation — the `Arc` keeps it alive until the response is built and sent.

**Recommended implementation:** `arc_swap::ArcSwap` (already a transitive dep via tokio-util / saorsa-core ecosystem in many places). Alternative: `tokio::sync::RwLock<Arc<ResponderCommitments>>` is also fine; write contention is rare (once per epoch).

### State summary update

| Where | What | Note |
|---|---|---|
| Responder | `ArcSwap<ResponderCommitments>` holding `current` + optional `previous` `Arc<BuiltCommitment>` | Atomic rollover; in-flight reads safe |

Everything else unchanged.

## Why v6 is final-quality

- All five security findings codex raised across rounds 1-4 are closed (root replay, key-overclaim, downgrade escape, gossip-verify DoS, replay/poison, structural bounds).
- v5's operational MAJOR closed by previous-tree retention.
- v5's only remaining MEDIUM (atomicity + lifetime) made explicit via `ArcSwap` + `Arc<BuiltCommitment>` semantics.
- Audit-delay assumption (>1 epoch) handled with a typed `UnknownCommitmentHash` rejection that doesn't penalize the responder.

## Open questions (unchanged from v5)

(a) Stage 1 → Stage 2 transition: still unsettled (config rollout vs observed-ratio).

(b) `recent_provers` cache assumes audit selection is reasonably fair across the network. Worth validating in implementation that no peer is permanently never-audited.

## Implementation checklist (for when this lands)

- [ ] Wire types: `StorageCommitment`, `CommitmentBoundResult`, `AuditResponse::CommitmentBound`, `AuditRejectReason`, optional fields on `NeighborSyncRequest`/`Response` and `AuditChallenge`.
- [ ] Domain separation constants (4 byte-strings, listed in §10 of v4).
- [ ] Responder: epoch tick, `BuiltCommitment` builder, `ArcSwap<ResponderCommitments>`.
- [ ] Receiver/gossip: 6-step processing pipeline (structural → admission → rate → monotonicity → sig → state update).
- [ ] Auditor: `expected_commitment_hash` snapshot at challenge issue, response verification (5a-e), `recent_provers` cache with `commitment_hash` binding.
- [ ] Holder-eligibility check threaded through replication quorum + paid-list verification paths.
- [ ] Bootstrap-shield closure: `Bootstrapping + commitment_capable` = hard failure.
- [ ] Stage-1 informational mode + Stage-2 flag-day toggle.
- [ ] Tests: PoC tests from `tests/poc_lazy_audit_*.rs` (Findings 1 + 2) must FAIL after this lands. New tests for: honest-rotate cross-epoch audit, lazy-fetch attempt rejected, stale-cache replay rejected, `UnknownCommitmentHash` doesn't penalize, atomic rollover concurrent access.
