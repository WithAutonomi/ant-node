# ADR-0011: Capacity-gated source discovery in the replication verification cycle

- **Status:** Proposed
- **Date:** 2026-08-18
- **Decision owners:** Anselme
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0003 (full-node detection and eviction — decides how *other* nodes treat a full peer; this decides what the full peer itself stops doing); ADR-0005 (replication repair hardening — owns the verification/fetch pipeline this changes). V2-1009 is the issue, V2-963 / PR #202 added the pre-check this builds on, V2-987 is the testnet run that measured the cost.

## Context

PR #202 stopped a node that cannot write from *pulling* chunks: `execute_single_fetch`
runs `check_capacity()` before it dials, and a local write failure is classified as
`LocalWriteFailed` so no alternate holder is conscripted. That removed 93.9% of
replication egress on a local testnet with a quarter of the nodes capacity-blocked.

It did not remove the round that *precedes* the dial. A node that cannot write still
holds none of the keys it owes, so none of them terminate. Each one is selected by the
verification cycle, probed against its close group for a holder, promoted, refused by
the capacity pre-check, and requeued at `VERIFICATION_REQUEST_TIMEOUT`. At 15 seconds
that is up to 120 close-group probes per entry lifetime, for every key the node owes —
nominally, since the 15 seconds is a requested delay and cycle polling, round duration
and bounded per-cycle selection all stretch it. The owed set grows with the network
rather than with anything the node can do about it.

The testnet run on V2-987 measured it at scale: 195 services with 50 (25.6%) held
storage-full produced **99.6% of every `verification_request_tx_bytes` on the network**
from that quarter of the fleet. Freeing half the full VMs collapsed their
verification-request traffic 87% within 28 minutes while the untouched half moved
+9.5%, which is what attributes the traffic to the storage-full condition rather than
to the fetch guard.

The absolute volume in that run was small. The reason to act is the scaling: the
per-node cost is `owed_keys x close_group x 32 B` per round, `MAX_PENDING_VERIFY` is
131,072 keys, and every probe costs a close-group neighbour an LMDB presence lookup on
its serial replication message path.

## Decision Drivers

- A node that cannot write should stop *repeating* work that cannot succeed. Re-probing
  for a key it has already authorized and still cannot store buys nothing, and its
  neighbours pay a presence lookup for each attempt.
- Suppressing work must not suppress duties that do not need a local write. A full node
  must keep learning which keys it owes were paid for, and must keep retiring keys it
  already holds or is no longer admitted for, or it stalls its own bootstrap drain and
  keeps its audits disabled.
- Recovery should stay prompt. Capacity comes back — an operator resizes a volume, a
  prune pass frees space — and the node should notice while the duty is still live. That
  is the objective, not a guarantee: see the trade-offs below for when it is missed.
- No wire or storage change, and no public API change in a default build. This rides the
  release train into a mixed fleet, and an upgraded node must stay wire-compatible with
  old peers — which it does, since no peer-side behaviour depends on receiving the
  requests it stops sending.

## Considered Options

1. **Gate on hint provenance at the top of the cycle.** Drop every key whose hint
   carried a possession claim before the cycle does anything else.
2. **Gate the two steps that exist to enable a fetch**, after authorization and after
   the terminal checks: the presence probe that discovers holders, and the promotion
   that queues the download.
3. **Leave the cycle alone and only lengthen the requeue delay** after a refused fetch.
4. **Do nothing.** The measured volume was ~6 KB/s per full node.

## Decision

We will take option 2: gate source discovery, not the cycle.

`run_verification_cycle` reads the storage capacity verdict once and uses it in exactly
two places — before the local paid-list presence probe, and before promotion on the
network-verified path. Everything else runs unchanged on a full node: the local
paid-list fast path, `PaidForList` convergence through the quorum round, and the
terminal checks that retire a key the node already holds or is no longer admitted for.

Held keys are deferred by `CAPACITY_BLOCKED_RETRY` (5 minutes) through the existing
`defer_pending`, and deliberately nothing more: an earlier revision also clamped the deferral to
half the entry's remaining life, gave the deferred key fairness-eviction protection, and
carried a capacity verdict through `FetchResult` so a refused fetch took the same long
backoff. All three were cut on review.

The clamp existed so an aged entry could not be retired without one last look. It cost a
logarithmic burst of looks near expiry, and — where the paid-list insert had failed —
those looks become *ungated* quorum rounds, working against the thing this ADR is for.
Without it, a key deferred inside the last five minutes of its life expires without a
final look and is re-acquired from the next neighbour-sync hint, which is what the
30-minute TTL already implies.

The eviction protection preserved a duty the node cannot discharge, letting a full node
hoard pending entries against the 131,072-entry ceiling. Losing one to fairness
reclamation is the better outcome, and it returns on the next hint.

The `FetchResult` propagation duplicated the gate. After a refused fetch the key returns
to pending and the gate at the head of the next cycle defers it for minutes anyway, so
the machinery bought one 15-second round on a race the gate already makes rare.

Only a **full** disk drives the gate. `check_capacity()` answers `Err` both for
insufficient space and for a space query that itself failed, and neither the second nor a
failed resize, write transaction or commit is a standing condition. A three-way
`CapacityVerdict` separates `Full` from `Unknown`, and the gate reads only `Full`. The
fetch path is left alone entirely: a refused fetch returns `LocalWriteFailed` and requeues
on the ordinary schedule, because the gate at the head of the next cycle re-decides.

Option 1 was implemented first and rejected in review: `HintPipeline` records only
whether an advertiser claimed possession, so gating on it skips `PaidForList`
convergence for keys that arrive as replica hints, strands keys that should have
retired, and can be flipped by any routing-table peer adding a false possession claim to
a paid-only key. Option 3 leaves the dominant cost in place, because the probe is paid
before the fetch is ever attempted. Option 4 ignores that the cost scales with the owed
set.

## Consequences

### Positive

- The loop this targets goes away: a key the node has **already authorized** and cannot
  store is no longer re-probed on every cycle it comes back on, for the rest of its
  entry's life. That is the loop that scales with the owed set. (The 15 s request timeout
  is the requested eligibility, not the achieved cadence — poll latency, round duration
  and bounded per-cycle selection all stretch it.)

  **How much of V2-987's 99.6% that removes is a hypothesis, not a measurement.**
  `verification_request_tx_bytes` aggregates both branches — the gated local-paid
  presence round and the ungated network-authorization round — so the run never
  established which dominated. The mechanism favours the gated branch: `PaidForList` is
  persistent LMDB, `PaidNotify` inserts into it across the 20-wide paid group with no
  storage requirement, a successful quorum inserts before the second gate, and definitive
  quorum failure removes the key rather than retrying. So an owed key should reach the
  gated branch and stay there. Against that, real ENOSPC can fail the paid-list insert
  itself, and `QuorumInconclusive` keeps the old cadence entirely. A reasoned estimate is
  80–90% of the cohort's verification bytes; treat it as a prediction the testnet run is
  there to test.
- What remains is purposeful but not free. A key the node has **not** yet authorized
  still runs its quorum round, because that is how `PaidForList` converges, and its close
  group still pays a presence lookup for it. If that round comes back
  `QuorumInconclusive` — partial reachability, too few replies to succeed or fail fast —
  it is deferred by the request timeout and tried again, so an unauthorized key under a
  degraded close group can still re-probe on the old cadence until it authorizes, fails
  definitively, or ages out. Traffic from a full node therefore falls to a convergence
  floor whose height depends on reachability, not to zero.
- For an authorized key that stays blocked, the probe count drops from roughly 120 to
  **zero**: the gate stops the round before it is sent. What the five-minute cadence
  schedules are *looks* — cheap local capacity checks — not probes. A probe happens only
  if capacity has returned by the time a look runs, which is the point.
- A transient LMDB error keeps the ordinary retry schedule rather than inheriting the
  capacity backoff. That is a property this change has to *preserve* rather than one it
  introduces — the pre-change path already requeued on the request timeout — and it is
  why the fetch path keeps the ordinary schedule rather than inheriting the gate's.

### Negative / Trade-offs

- The deferral is flat, so an aged entry is looked at no more often than a young one, and
  a key deferred inside the last five minutes of its entry's life expires without a
  further look. It returns on the next neighbour-sync hint; this is the trade for not
  carrying a clamp whose tail looks can themselves become ungated quorum rounds.
- Recovery after capacity frees is slower, and five minutes is the *requested* deferral
  rather than a bound. The actual delay adds worker poll latency, cycle runtime, bounded
  per-cycle selection under backlog, and a capacity verdict read once per cycle. Under a
  deep backlog those can push a given key's next look well past five minutes, so the
  figure belongs in a design discussion and not in a fleet acceptance threshold. What is
  bounded is the entry lifetime: past stale eviction at 30 minutes, re-acquisition
  depends on a fresh neighbour-sync hint.
- `CAPACITY_BLOCKED_RETRY` is a constant, not a `ReplicationConfig` field. The struct is
  publicly re-exported and is not `#[non_exhaustive]`, so a new field would be a
  semver-visible break for a knob nothing needs to tune at runtime. The cost is that
  operators cannot retune it without a release.
- Each gate is pinned independently. Disabling the promotion gate alone leaves the first
  gate passing and fails only the promotion phase, with the key requeued on the 15 s
  schedule instead of the capacity backoff; disabling both fails the probe count first.
  Neither can be removed without a test catching it.
- `CapacityVerdict::Full` means "available space is below the configured reserve", not
  "storage cannot write". A persistent LMDB transaction, commit, resize or permission
  error with filesystem headroom still reads `Writable`, so an equivalent loop caused by
  one of those is not suppressed. The default 500 MiB reserve normally makes the node
  refuse chunks well before literal ENOSPC, which is why this predicate covers the
  observed condition — but it is narrower than the name suggests.
- The verdict restates the pre-check's predicate rather than sharing its code, so the two
  can drift apart. That is not hypothetical. ant-node #210 makes the pre-check two-part —
  below the reserve *and* out of reusable pages inside the store, since LMDB returns a
  deleted record's pages to its own free list and never to the filesystem. Left
  unreconciled, a heavily pruned node would read as `Full` here while its own dial
  pre-check admits the write, standing its keys down for five minutes at a time instead
  of looking for chunks it could store. That is under-replication, which is worse than
  the probe traffic this gate exists to remove, so the coupling is held by a test rather
  than by a comment: `capacity_verdict_refuses_exactly_when_check_capacity_does` fails in
  exactly that state.
- The second gate is now covered by a test rather than by inspection. Hosting the chunk
  on every other node clears the four-of-seven quorum threshold, and leaving it out of
  the target's paid list forces the network branch. Cutting the capacity-specific
  `FetchResult` backoff is what made this observable: a refused fetch now requeues on the
  ordinary 15 s schedule, so the deferral delay separates "held before promotion" from
  "promoted, then refused".

### Neutral / Operational

- `capacity_deferred_probe` and `capacity_deferred_promote` are reported on the existing
  per-cycle verification summary, so each gate is visible in fleet logs without a new
  instrumentation path.
- No wire or storage change, and no public API change in a default build; under
  `test-utils` four additive test-only items appear. An upgraded node is quieter where an
  old one probed, and no peer-side heuristic consumes the absence of unsolicited
  verification requests.

## Validation

- Unit: the existing `apply_fetch_result` cases still hold with `LocalWriteFailed` back
  to its upstream shape — no alternate source is conscripted, and the no-metadata path
  stays terminal.
- Unit: `capacity_verdict_refuses_exactly_when_check_capacity_does` holds the gate's
  verdict and the dial's pre-check to one predicate. It is built on a store that has
  deleted more than one chunk's worth of pages rather than on a bare full disk, because
  that is the state the two predicates are about to part company over; on a bare full
  disk they still agree, so a test built on one would pass straight through the
  divergence. Applying #210's predicate to the pre-check fails this test and nothing
  else in the 934-test suite.
- E2E: `write_blocked_node_neither_probes_nor_dials` runs all three phases on one
  network — no dial, then no probe — seeding two nodes identically through the local
  paid-list path so they differ only in whether storage accepts writes. Probes are
  counted per key at the *sending* side, on the wire call itself, so the assertion is a
  measurement rather than an inference and a responder shedding a request cannot turn a
  probe that happened into a zero: `blocked_probes=0` against `control_probes=7`, and
  neutralising the gates turns the blocked count into 7 and fails the test. The control
  also completes its acquisition, so a cycle that never reached the probe cannot read as
  a pass.
- **The measurement that settles the branch question, and its limit.** The per-cycle
  verification summary counts each gate separately, `capacity_deferred_probe=` against
  `capacity_deferred_promote=`, so sampling those on a storage-full node for an hour
  establishes which branch its gated keys are taking. They have to be separate counts:
  `local_paid_probe=` counts probes actually sent, so it reads zero on a full node once
  the first gate fires, and a single combined deferral count could not be split back
  apart. The line is `debug!` unless the cycle is slow, so it wants debug logging on a
  canary. What it does **not** give is the byte share: the two
  branches fan out differently (the presence probe to the close group, the quorum round to
  the union of quorum and paid targets, which is up to 20 wide) and the network round also
  carries `paid_list_check_indices`, so equal key counts do not mean equal bytes. Settling
  the byte fraction needs per-branch encoded-byte accounting or a straight A/B, which is
  what the testnet run is for.
- Fleet: this is the T2 evidence that is *not* in the PR and has to be run. On a repeat
  of the V2-987 topology, the full cohort's **per-hour delta** of
  `verification_request_tx_bytes` should settle instead of climbing with the owed set —
  the counter itself is cumulative and will keep rising, so the criterion is its growth
  rate, not its value. On V2-987 that delta went 1.06 → 1.77 → 2.53 GB across three
  hours; settling is the result to look for. `key_absent` audit rates and download
  success should be unchanged, and freed nodes should still resume acquisition inside
  the plan's 60-minute allowance. Flat *near zero* is the wrong expectation either way:
  unauthorized keys still run their quorum round by design.
- Review trigger: if `PENDING_VERIFY_MAX_AGE`, the neighbour-sync cadence, or
  `MAX_PENDING_VERIFY` change, revisit the 5-minute constant. If what
  `LmdbStorage::check_capacity` refuses on changes, carry the change into
  `capacity_verdict` in the same commit.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**.
Accepted ADRs are immutable: create a new superseding ADR rather than editing an
Accepted ADR.
