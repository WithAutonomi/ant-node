# Finding 2: Bootstrap-claim audit shield

**Severity:** HIGH
**Category:** Lazy-node defeats audit
**PoC:** `tests/poc_lazy_audit_evasion.rs` (4 tests, all pass)

## Root cause

A responder under audit can return `AuditResponse::Bootstrapping` (claiming
"I'm still bootstrapping, can't answer yet"). The challenger's `audit_tick`
treats this as `AuditTickResult::BootstrapClaim` and **never invokes**
`handle_audit_failure` — so neither the digest binding nor the responsibility
check ever runs.

The decision tree:
- During `BOOTSTRAP_CLAIM_GRACE_PERIOD` (24h, `config.rs:113-116`): the
  observation returns `WithinGrace` → **no trust event emitted at all**.
  Zero penalty.
- Past 24h: `PastGrace` → emits a trust event with
  `REPLICATION_TRUST_WEIGHT (1.0)` — **not** `AUDIT_FAILURE_TRUST_WEIGHT (5.0)`.
  Per-claim weight, not per-failed-key.

## Quantified impact

PoC simulates a 5-minute audit cadence:
- 24h × (60/5) = **288 audits** during grace window. Total trust penalty: **0.0**.
  Honest baseline if all 288 had failed normally: 1440.0.
- Past grace: 5× discount per audit + loss of per-key amplification.

Sybil-friendly: a fresh peer ID gets a fresh 24h window. Lazy nodes rotate
identities every ~24h and accumulate effectively zero penalty.

The lazy node retains routing-table presence (returning Bootstrapping doesn't
disable inbound neighbour-sync), so it stays selected for audits — every audit
returns Bootstrapping harmlessly.

## Why this matters

This is a **trivial** lazy-node strategy. Unlike Finding 1 (which requires the
attacker to actually fetch bytes during the window), this requires literally
zero work: return the same `Bootstrapping` response forever.

The grace period was added so that a genuinely-bootstrapping node isn't
penalised before it has had time to sync. But the grace is open-ended — the
node tells the auditor it's bootstrapping, and the auditor believes it. No
external evidence required.

## Fix space

Three independent fixes; any one closes the bypass.

1. **Tie grace to actual bootstrap drain.** A node receives one grace window
   measured from when its own bootstrap state transitioned to drained. Once
   drained, future `Bootstrapping` responses are treated as failures. Requires
   per-peer tracking of "have we observed this peer in the network long enough
   that it should be drained?".
2. **Invalidate hint claims while bootstrap is claimed.** A node that claims to
   be bootstrapping cannot also claim responsibility for keys (i.e. cannot send
   replication hints during its claim). Today there's no coupling between
   "bootstrap claim" and "hint admission" — a node can keep advertising
   responsibility while also dodging audits via the claim.
3. **Penalty parity for repeated claims.** First Bootstrapping → grace OK.
   Second from same peer ID within N hours → `AUDIT_FAILURE_TRUST_WEIGHT (5.0)`,
   per-key, same as a digest mismatch. Counters identity rotation only if the
   penalty fires fast enough that a rotation cycle is more expensive than the
   reward stream.

Fix 2 is the architecturally cleanest: it says "if you're bootstrapping, you're
not yet a responsible peer; we won't audit you, but we also won't accept your
hints." Today these are independent, which is the bug.

## Post-fix test

`poc_lazy_node_escapes_all_audits_within_grace_window` must FAIL: total trust
penalty over 288 audits must be non-zero (specifically `>= AUDIT_FAILURE_TRUST_WEIGHT`
per real failure).
