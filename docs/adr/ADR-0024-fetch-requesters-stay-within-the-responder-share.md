# ADR-0024: Fetch requesters stay within the responder's per-peer share

- **Status:** Proposed
- **Date:** 2026-10-13
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR-0005](ADR-0005-replication-repair-hardening.md) (the repair fetch pipeline),
  [ADR-0017](ADR-0017-bounded-fresh-offers-and-copy-free-sends.md) (send-path bounds)

## Context

A replication fetch is a request/response exchange between two nodes. The responder bounds what
one requester can occupy:

- `FETCH_RESPONDER_MAX_OUTSTANDING_PER_PEER = 2` admitted requests per source, checked before the
  12-slot admission pool, in front of a 3-worker serving pool;
- a request past that share is not answered. The responder logs
  `Fetch response dropped at admission: reason=per_peer_cap_full` and returns nothing.

The requesting side never matched that share:

- the fetch worker ran one fetch per hardware thread;
- it sent each one to the first verified holder of its key, in source-preference order (the
  closest holder that answered Present);
- the fetch queue is nearest-first, so the keys at its head usually share the same few holders.

When more than two fetch slots were available and several queued keys shared a holder, the worker
could send more than that holder's two-request share. A request arriving while two from the same
requester were still admitted was dropped. Each such drop cost the requester:

- the full fetch timeout (30 s) before moving on;
- a `ConnectionTimeout` trust event, recorded by the transport against the holder that dropped it,
  although that holder had done nothing wrong;
- a retry that went to the next holder without regard to how busy that holder was.

On the production fleet this was common, according to the per-service cumulative counters:

| period | inbound fetch requests dropped at admission |
|---|---|
| on 0.21.0 | 36.6% |
| on 0.22.0 | 44.3% |
| 25-hour window containing a wave of 177 freshly installed nodes filling their ranges | 65.8% overall by cumulative counters; 3.22M WARN-line drops came from the new nodes, about 2.8 per chunk attributed to them |

In that window, 68.5% of drops happened with only 2 of the responder's 12 admission slots in use,
both held by the refused peer.

## Decision Drivers

- No wire, storage or production public API change, so the fix ships as a behavioural change on
  the release train.
- Do not weaken the responder's protection against one peer occupying the whole serving pool.
- A key must never be lost, tracked twice, or released from bootstrap accounting early because of
  scheduling.
- Keep the queue's nearest-first priority and each key's source preference whenever they do not
  conflict with the share.
- No scenario may drain more slowly than before the change by more than one fetch timeout, in
  particular the keys of a holder that has stopped answering.

## Considered Options

1. **Raise the responder's per-peer share.** Rejected. It hides the symptom, lets one requester take
   all three serving workers, which is what the share exists to prevent, and still drops requesters
   with more threads than the new share.
2. **Answer an over-share request with an explicit "busy" reply.** Deferred. It needs a new
   response variant, which peers that cannot decode it treat as malformed and charge an application
   failure, so it is a wire change with its own rollout. It removes the cost of a drop, not the
   cause.
3. **Limit fetch concurrency to 2.** Rejected. It serialises a node's whole repair and bootstrap fill
   through one share even when other holders are idle.
4. **Ship the scheduler switched off, behind a per-node switch, for a later canary.** Rejected. It
   merges code that no node runs, so its risks are deferred rather than measured. The risks were
   simulated instead (below), and the one regression found was fixed before merge.
5. **Keep at most the share in flight per answering holder on the requesting side, and give each
   free slot to the nearest queued key that can start now.** Chosen.

## Decision

The fetch worker keeps at most `FETCH_MAX_IN_FLIGHT_PER_SOURCE` fetches in flight to any one source
peer that is answering. The constant is defined equal to `FETCH_RESPONDER_MAX_OUTSTANDING_PER_PEER`,
the share every deployed responder grants. It is the worker's only scheduling path.

**Dispatch.** Each free fetch slot goes to the nearest queued key that can start now. In the key's
source-preference order, over its untried sources, it starts on:

1. the first source that is answering and below the limit;
2. otherwise the first silent source (below), past the limit.

**Parking.**

- A key whose untried sources are all answering and at the limit is parked: it leaves the fetch
  heap and is indexed under each of those sources.
- It becomes a candidate again as soon as any of them has a free share or falls silent, and it
  competes with the heap on distance.
- Each key leaves the heap once, so a startable key further down is reached in the same pass, and
  no source ordering can hide a startable key.

**Retries.**

- A failed fetch moves to its next untried source by the same rule. If every untried source is
  answering and at the limit, it is parked rather than sent to a full holder.
- It keeps the sources it already tried, so none is asked twice in one verification cycle, and it
  keeps its verification retry reservation.
- When no untried source is left, or the fetch queue is full, it returns to verification as before,
  so the fetch queue's hard bound holds.

**Silent sources.** The limit protects a holder's admission share, and only a holder that answers
has one. Without an exception, the keys held only by a holder that stopped answering would be tried
two per fetch timeout instead of one per free slot: four times more slowly than before on a node
with eight slots.

- Each attempt records whether its source answered. Requests and answers take places in one
  process-wide sequence, as a request is sent and as an answer returns, so they can be ordered
  exactly, whatever order their outcomes are applied in and whatever the clock reads.
- An answer reaches the scheduler as soon as it arrives, before its chunk is checked and stored,
  and again with the attempt's outcome, to no further effect. A timeout that an answer already
  outdates therefore never marks the source while that answer's chunk is still being written.
- A source is **silent** while a request sent to it after its latest answer has gone without any
  response (a timeout or connection failure). Any answer received after that request was sent ends
  it.
- A silent source is fetched from past the limit, as before the change, until it answers again,
  or until this node has learned of no newer unanswered request to it for two fetch timeouts (at
  least one second). A holder that stays dead while this node keeps fetching from it therefore
  stays silent, and one this node stopped fetching from is probed under the limit when it is next
  used, marked again only if a request sent then also goes unanswered.
- The table of observations is bounded at 8,192 sources. It drops only entries that hold no mark and
  whose source has no fetch in flight. If that frees nothing, a source not in the table counts as
  silent for one mark lifetime, which is again the behaviour before the change, never a slower one.

**Source limit.**

- The sources a queued or in-flight key is associated with, tried ones included, are bounded by
  `close_group_size + paid_list_close_group_size + MAX_HINT_SOURCES_PER_KEY` from the running
  configuration.
- That never truncates a verification round's own sources, and it bounds the parked index.
- A re-advertisement of a queued or in-flight key merges into the verification entry kept for its
  retry under `MAX_HINT_SOURCES_PER_KEY`, the bound a pending entry has, in the same order: replica
  claimants first, displacing paid-only advertisers other than the key's capacity owner, then
  paid-only advertisers while there is room. Before the change that merge had no bound.

**Dispatch summary.** The fetch worker logs `replication fetch dispatch summary` every 5 minutes and
at shutdown, with:

- the parked count, the index size and the oldest parked age;
- queued and in-flight fetches, and sources at the limit;
- parks and retry parks;
- attempts by outcome, bytes stored, and attempt latency;
- the longest fill-pass lock wait and hold, and the longest parked-index maintenance after a
  departure;
- silent sources now and at peak, marks, clears, expiries, ignored stale timeouts, starts on silent
  sources, unreachable attempts, tracked sources and table overflows.

Responder admission, the fetch timeout, fetch concurrency and the wire protocol are unchanged.

## Risk simulation

A local 12-node network, eight fetch slots per node and a 5 s fetch timeout, timed each scenario on
this change and on a build with the limit removed and no silent-source handling, which schedules
exactly as before the change: each key to its first untried source.

| scenario | this change | before the change |
|---|---|---|
| fill: 48 keys held by 3 answering holders | 0.36 s | 10.08 s |
| a non-answering holder first among 3 sources, 2 answering: 24 keys | 5.1 s | 20.1 s |
| a non-answering sole holder: 16 keys | 15.0 s | 10.15 s |

The third row is the accepted penalty: the first two requests to a holder that just went silent take
one fetch timeout to show it, and the rest then go out past the limit. It is paid once each time
this node starts fetching from a silent holder again after two fetch timeouts without trying it.
For `N` keys held only by that holder, `C ≥ 2` fetch slots and fetch timeout `T`, draining takes
`T × (1 + ceil((N − 2) / C))` against `T × ceil(N / C)` before the change. With one fetch slot the
first wave is one request, and the bound is the same with 1 in place of 2. Without the
silent-source exception the same scenario took 40.1 s.

The scale benchmark at the fetch queue's hard bound (`scale_benchmark_at_the_fetch_queue_bound`,
release build, 131,072 parked keys) stayed within the thresholds declared before it ran, apart from
dropping the queues (below):

| sources per key | one park pass, over repeated runs | peak process RSS |
|---|---|---|
| 1 | 89 to 99 ms | 197 MiB |
| 8 | 207 to 216 ms | 342 MiB |
| 35 (the limit) | 754 to 960 ms | 1.13 GiB |

- Waking and the stats read took under 1 ms; a departure took at most 107 ms.
- Dropping the queues at the limit took 274 to 315 ms over repeated runs. The scheduler before the
  silent-source handling took 226 to 295 ms, and the same time as this code in alternating runs on
  one machine. It was first held to 250 ms, which a loaded machine did not meet. It happens once,
  when the engine shuts down, outside any lock, so it is now held to 1 s.
- The silent-source check makes the park pass about 5% slower than before.

## Consequences

### Positive

- A requester on this release keeps its own in-flight fetches to one answering holder within that
  holder's share. That removes the ordinary over-share bursts and their timeout and trust cost; it
  does not cover stale work the responder still holds, described below.
- A fill or repair can finish sooner, because fetch slots no longer spend 30 s on over-share
  requests that will not be answered.
- Responders should log fewer `per_peer_cap_full` drops as requesters upgrade.
- The dispatch summary shows the scheduler's queue state, lock times and silent sources in
  production.

### Negative / Trade-offs

- It is not a guarantee of zero refusals. A request this node has already timed out on can still
  hold its share at the responder until a worker sheds it, and a new request sent in that window
  is refused. Closing that window needs option 2. During the 25-hour wave, responders shed 31,172
  admitted requests after waiting 30 s for a worker; the production data do not show how often
  that window caused a later refusal.
- The requester counts a fetch as in flight for its whole attempt, local checks and the local write
  included, which is longer than the responder holds its share. A holder can therefore sit below
  its share while this node waits, and a fetch whose local work stalls holds its holder's share for
  as long as it holds its fetch slot.
- A key whose answering holders are all busy waits in the queue, or goes to a lower-ranked holder
  with room, instead of being sent to its first holder.
- Keys held only by a holder that just stopped answering take one fetch timeout longer to drain
  than before the change, as in the simulation. A holder that is alive but so overloaded that it
  times out is fetched from as before the change while its mark lasts.
- Recovering the slots dropped requests used to waste raises a filling node's instantaneous
  bandwidth, disk and CPU use. Each responder still serves at most its share per requester with
  three workers; the data a joining node needs to move is unchanged.
- At the source limit, the parked index can reach 4.6 million entries and about 1.1 GiB of process
  memory; at 8 sources per key, about 340 MiB.
- Requesters on older releases still overshoot until they upgrade, so the network-wide drop rate
  falls only as the release spreads, and the traffic pattern changes during that time.
- There is no runtime switch. Undoing the change means a release without it.

### Neutral / Operational

- The effect shows in the responders' cumulative counters (`replication responder admission
  summary`): `fetch_admission_dropped_per_peer_share` relative to `fetch_request_rx_count` should
  fall as the fleet and the community upgrade.
- Before release, a dev testnet run with a join wave of fresh nodes should compare drain time,
  stored bytes, admission drops, trust events and host load against the previous release.

## Validation

**Unit tests on the queue:**

- no answering source exceeds the share;
- preference order is kept;
- a startable key behind hundreds of blocked keys starts in the same pass;
- a freed share starts the nearest parked key, whatever its source;
- parked and retried keys keep their payload, tried sources and retry reservation;
- departures and merges keep the parked index exact;
- the source limit holds across park, retry and merge;
- a silent source is fetched from past the share, an answering source with room is preferred, and
  parked keys start when a full source falls silent;
- whether a source is silent does not depend on the order its outcomes are applied in; marks are
  set, cleared and expired as described, and the table bound keeps every guard and mark;
- an answer reported when it arrives keeps a source within its share when an earlier request to it
  times out while the answered fetch is still storing its chunk; known only from the outcome, the
  same answer comes too late and the source is sent every waiting key;
- re-advertisements keep a queued or in-flight key's retry entry within the hint bound, with its
  capacity owner;
- sixteen keys held only by a silent holder, with eight slots, start in exactly three waves of 2, 8
  and 6;
- a randomised run of queue operations, re-advertisements and source contacts keeps every
  invariant, the retry entries' bound included.

**End-to-end tests:**

- with eight fetch slots and twelve keys directed to one holder that holds what it admits, the
  requester's own pipeline records at most two in-flight fetches to that holder; with the limit
  removed it records eight and the test fails;
- with a 5 s fetch timeout and sixteen keys directed to a holder that answers nothing, the requester
  sends past the share once the first requests time out and the keys leave its pipeline within four
  timeouts (15.1 s measured); with the silent-source exception removed the test fails.

**Revisit if:**

- the responder's per-peer share changes;
- a busy reply is introduced;
- the fleet counters keep showing a high dropped share once most requesters run this release;
- the dispatch summary shows sustained table overflows or a large count of silent sources.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
