# ADR-0012: Back off and report once when a verification round finds no holder

- **Status:** Proposed
- **Date:** 2026-08-24
- **Decision owners:** chrisoneil
- **Reviewers:** TBD
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0005 (replication repair hardening — owns the verification/fetch pipeline this changes); ADR-0011 (capacity-gated source discovery — adds the flat write-blocked deferral this change deliberately keeps flat). V2-1049 is the issue, V2-1062 tracks the cause, and [saorsa-core #152](https://github.com/WithAutonomi/saorsa-core/pull/152) characterises it.

## Context

A pending key whose presence probe finds no holder is put back with
`defer_pending(key, verification_request_timeout)` — a flat 15 seconds — and a
`warn!` is emitted every time. Neither the retry nor the log has any notion of
how many times this key has already failed.

On the beta cohort this produced **1,153,502 log lines from 2,072 distinct keys
on a single node in ten hours — 557 lines per key**, 98.8% of every WARN the
whole cohort emitted in 24 hours. `PENDING_VERIFY_MAX_AGE` does not bound it:
`evict_stale` drops the entry at 30 minutes, a neighbour re-hints the key
minutes later, it is re-admitted with a fresh `created_at`, and the cycle
restarts. One sampled key ran through fifteen such 30-minute residencies.

The keys were not a backlog being worked through. They were the same keys,
re-asked of the same peers, receiving the same answer. The node was a first
start, and per saorsa-core #152 a node whose routing table has not converged
"cannot name anyone closer to a distant key than itself, so every consumer
asking *am I among the `w` closest to this key* gets yes for most of the
keyspace". Replaying `is_responsible` against that node's reconstructed routing
table shows it claimed ~1,451 of those keys at bootstrap and only **98** once
the table converged: roughly 95% of the storm was work it should never have
taken on.

This ADR does not address that cause — see V2-883, whose cold-start half is
still open. It addresses the fact that the symptom is unbounded: the retry and
the log both cost the same on the five-hundredth failure as on the first, and
the log volume masked every other signal in the beta soak.

## Decision Drivers

- A retry whose question has not changed will not get a new answer; paying a
  verification round trip per key every 15 seconds buys nothing.
- At 2,071 stuck keys the node pushed ~14,500 key references per round to 7
  peers every ~16 seconds. This is responder load on the close group, not only
  local noise.
- The first failure for a key is genuine operational information and must not be
  suppressed. The five-hundredth is not.
- Whatever the underlying cause, the observable cost of it should be
  proportionate to the number of *affected keys*, not to how long the condition
  persists.

## Considered Options

1. **Leave the cadence, rate-limit the log only.** Fixes the log volume, leaves
   the redundant probe traffic.
2. **Raise `VERIFICATION_REQUEST_TIMEOUT`.** One constant, but it is the
   per-batch request timeout for every verification round, including rounds that
   succeed. It would slow first-attempt discovery for every key to fix a
   repeated-failure case.
3. **Drop the key after N failures.** Cheapest, but a key legitimately awaiting a
   holder that has not yet come online would be abandoned; the condition is
   frequently transient during a node's first hours.
4. **Exponential backoff per entry, plus warn once per entry.** Keeps retrying
   indefinitely, but at a cost that decays.

## Decision

We will take option 4.

`VerificationEntry` gains `unresolved_retries`, and deferral splits into two
methods that mean different things:

- `defer_pending(key, retry_after)` keeps today's flat behaviour, for deferrals
  that are **not** a failed round — the write-blocked capacity gate of ADR-0011
  defers without asking anyone, so nothing was learned about the key and neither
  the backoff nor the first-failure warning should be consumed. That ADR states
  the gate is "applied flat, through the ordinary `defer_pending`"; keeping the
  two methods distinct is what preserves that.
- `defer_unresolved(key, base_retry_after)` is the failed-round path. It
  increments the counter and returns `DeferralOutcome { attempt, retry_after }`,
  where `retry_after` doubles from the base and saturates at a new
  `VERIFICATION_RETRY_BACKOFF_MAX` of **5 minutes**, never falling below the
  base.

Both no-holder sites and the inconclusive-quorum deferral use
`defer_unresolved`.

Reporting is tracked **separately** from the count, by a `no_holder_reported`
flag claimed through `claim_no_holder_report` at the two no-holder sites. The
two answer different questions. The counter asks "how many consecutive rounds
failed", which an inconclusive quorum legitimately advances. The flag asks "have
we told anyone", which only a no-holder result may consume. Deriving the second
from `attempt == 1` would lose the first — and only — warning for any key whose
opening round is inconclusive, which is the common case: a key entering
`PaidForList` after its first quorum round takes the local-paid fast path on the
next cycle.

A round that *does* find a holder clears both, via `clear_unresolved`. The
round succeeded even where a full fetch queue leaves the key pending, so it must
not inherit the earlier backoff, and a later relapse deserves a fresh warning.
Eviction and re-admission likewise start a fresh episode, so "once per episode"
is literal rather than approximate.

The per-cycle count is added to the verification cycle summary as `no_holders=`,
so the scale of a backlog stays visible without a line per key per retry.

## Consequences

### Positive

- Inside one 30-minute residency a stuck key is probed roughly **10 times
  instead of roughly 110**, cutting both redundant verification traffic and the
  responder load it imposes on the close group.
- Per-key WARN volume for a storm of this shape drops from ~557 lines per key to
  **1 per episode**.
- The retry is still unbounded, so a holder that appears late is still found.

### Negative / Trade-offs

- Worst-case delay in noticing that a holder *has* appeared rises from 15
  seconds to the 5-minute cap. Acceptable: this path is background replica
  repair, not a read path, and the key is re-hinted by neighbour sync every
  10–20 minutes regardless.
- The two no-holder messages are unified on the wording
  `has no responding holders yet`; the network-verification site previously read
  `has no holders yet`. Any saved query matching the old string needs updating.
- A key that oscillates between resolvable and unresolvable warns once per
  oscillation rather than once ever. This is deliberate — silence after the
  first-ever report would hide a recurrence — but it means the log is not
  strictly one line per key.

### Neutral / Operational

- `no_holders=` appears in both verification cycle summaries: at `info` when the
  cycle exceeds `VERIFICATION_CYCLE_SLOW_LOG_MS`, and at `debug` otherwise. Beta
  ships at `info`, so in practice the operational signal is the slow-cycle one —
  which is when a backlog is most likely present, but is therefore not a
  continuous gauge. If a continuous signal is wanted it belongs in the periodic
  replication summary.
- `VerificationEntry` is `pub` with `pub` fields and no `#[non_exhaustive]`, so
  the two new fields break downstream struct literals. Nothing outside this
  repository is known to construct one, but the PR is marked breaking on that
  basis. Adding `#[non_exhaustive]` would stop this recurring; it is itself a
  breaking change and so belongs with a deliberate bump, not this one.
- Beta ships at `info`, so the `debug!` follow-ups are dropped at ingest and do
  not reach Elasticsearch.

## Validation

- Unit tests cover the doubling sequence, saturation at the cap across 64
  further attempts, the `None` result for an unknown key, backoff restart after
  eviction and re-admission, and that a base above the cap is never shortened.
- Three tests pin the separations this decision rests on: a non-reporting round
  (inconclusive quorum) advances the count without consuming the warning; a flat
  `defer_pending` does neither; and a duplicate hint merges into the live entry
  rather than replacing it, so it restarts neither the backoff nor the retry
  time. The last of these guards a silent revert — a refactor that replaced
  instead of merging would undo the fix with every other test still green.
- `VERIFICATION_RETRY_BACKOFF_MAX` is pinned in `config.rs` beside
  `CAPACITY_BLOCKED_RETRY`: above the request timeout, and far enough below
  `PENDING_VERIFY_MAX_AGE` that a capped retry still gets several looks per
  episode.
- The beta cohort is the live check: the next first-start node should produce on
  the order of one WARN per affected key per episode instead of hundreds, and
  `no_holders=` in the cycle summary should show the affected-key count directly.
- This decision should be revisited if V2-883's cold-start half lands, since a
  node that stops over-claiming should rarely reach these sites at all. The
  backoff remains correct either way; the log-once rule may then be more
  conservative than necessary.

## Notes for AI-assisted work

Drafted with AI assistance from the V2-1049 investigation. Not to be marked
Accepted without human review.
