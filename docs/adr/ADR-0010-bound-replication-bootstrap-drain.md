# ADR-0010: Bound replication bootstrap drain with an overall deadline

- **Status:** Proposed
- **Date:** 2026-08-06
- **Decision owners:** @dirvine
- **Reviewers:** @jacderida, @grumbach
- **Supersedes:** none
- **Superseded by:** none
- **Related:** Linear V2-882 (implementation), V2-864 (production pruning impact), ADR-0005 (replication repair hardening)

## Context

A joining node remains in replication bootstrap until all peer requests,
bootstrap-discovered keys, and capacity-rejection debt have drained. While
`is_bootstrapping` is true, audits are paused (Invariant 19), remote prune
confirmation is gated, and the node continues advertising itself as
bootstrapping.

ADR-0005 and the changes already on `main` bound one known wedge: each
capacity-rejected source is first-seen timestamped and eventually expires if it
never returns for a clean admission cycle. That does not bound every bootstrap
state. Multiple sources can enter at different times, or a `pending_keys` /
`pending_peer_requests` path can fail to reach its terminal cleanup after
storage failure or restart. There is no overall deadline, so a new or
unanticipated cleanup defect can still keep audits and pruning disabled for the
lifetime of the process.

Production evidence in V2-864 includes peers claiming bootstrap beyond the
24-hour grace period and pruning candidates remaining entirely
`bootstrap_deferred`. The safe fail-closed behaviour prevents unsafe deletion,
but an unbounded bootstrap stall fills disks and removes the node from effective
audit participation.

## Decision Drivers

- No peer or stale internal state may disable audits and pruning indefinitely.
- Honest bootstrap work must retain a meaningful period to complete normally.
- Missed bootstrap work must remain recoverable through steady-state neighbour
  sync and the audit/repair pipeline.
- The change must not alter wire messages, storage format, payments, or trust
  attribution.
- Operators need explicit evidence when the safety ceiling fires.

## Considered Options

1. **Rely only on per-source capacity-rejection expiry.** Rejected: it closes the
   known source-debt wedge but does not cover stalled pending requests, pending
   keys, or future cleanup defects.
2. **Restart any node that exceeds the bootstrap grace period.** Rejected: this
   is an operational workaround, loses causal evidence, and can replay the same
   stale state or bootstrap path.
3. **Force replication bootstrap drain after an overall deadline (chosen).**
   Preserve normal drain checks before the deadline, then transition to steady
   state with an explicit warning once the ceiling is reached.
4. **Delete or ignore all bootstrap work immediately under pressure.** Rejected:
   it weakens normal completeness and makes transient load indistinguishable
   from a real terminal wedge.

## Decision

We will add a configurable `bootstrap_drain_deadline`, defaulting to 30 minutes,
and record `bootstrap_started_at` when replication drain tracking begins.

`check_bootstrap_drained` will check this deadline before pending-request,
capacity-rejection and pending-key gates. Once elapsed, it will mark bootstrap
drained and emit a WARN containing the configured deadline and the remaining
source/request/key counts. Before the deadline, existing drain and per-source
expiry semantics remain unchanged.

The default is aligned with `PENDING_VERIFY_MAX_AGE` (30 minutes). By the time
the ceiling fires, stale pending-verification entries have already reached their
normal eviction bound. Any forfeited or late work remains discoverable through
post-bootstrap periodic neighbour sync and the audit/repair pipeline.

## Consequences

### Positive

- Total replication bootstrap stall is bounded independently of attacker pattern
  or the exact cleanup defect.
- Audits and prune confirmation resume instead of remaining disabled for the
  process lifetime.
- The forced transition is visible and carries the outstanding-state counts
  needed for follow-up investigation.
- No protocol, data-format, payment, or client compatibility change.

### Negative / Trade-offs

- A node can enter steady state with genuine bootstrap work still outstanding.
  This trades bootstrap completeness for bounded liveness.
- The 30-minute default is a policy value and may require tuning from fleet
  evidence.
- Forced drain does not repair the underlying failed work item; steady-state
  reconciliation must recover it.

### Neutral / Operational

- The deadline is configurable through `ReplicationConfig` but is not a new CLI
  surface in this change.
- A force-drain WARN is an investigation signal, not proof of data loss.
- Per-source capacity-rejection expiry remains the first-line targeted defence;
  this deadline is the unconditional backstop.

## Validation

- Unit test: force drain after the deadline despite outstanding requests,
  rejected sources and pending keys.
- Unit test: before the deadline, outstanding work still blocks drain.
- Existing bootstrap capacity-rejection, peer-removal and TTL tests remain
  green.
- Run the focused replication/config suites plus `cargo check`, formatting and
  clippy.
- Fleet review trigger: monitor force-drain frequency and outstanding counts. If
  normal healthy nodes hit the ceiling, investigate before increasing it; do not
  silently normalise repeated forced drains.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
