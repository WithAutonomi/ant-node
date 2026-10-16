# ADR-0025: Tell a fetch requester "busy" instead of refusing silently

- **Status:** Proposed
- **Date:** 2026-10-15
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR-0005](ADR-0005-replication-repair-hardening.md) (the repair fetch pipeline),
  [ADR-0017](ADR-0017-bounded-fresh-offers-and-copy-free-sends.md) (responder admission bounds),
  ant-node #252 / ADR-0024 (requesters stay within the responder's per-peer share)

## Context

A replication fetch is a request/response exchange. The responder admits at most two
outstanding fetches per requesting peer (`FETCH_RESPONDER_MAX_OUTSTANDING_PER_PEER`) and twelve
overall (`FETCH_RESPONDER_MAX_OUTSTANDING`). A request past either limit is refused at admission:
the responder logs `Fetch response dropped at admission` and sends nothing back.

Silence is expensive for both sides:

- the requester waits its whole fetch timeout (30 s) before moving on to the next holder;
- saorsa-core records a `ConnectionTimeout` trust event against the responder, which did nothing
  wrong;
- the requester learns nothing about why, so it keeps choosing that holder for new keys.

On the production fleet this was the common case, not an edge. As measured for #252 from the
responders' own cumulative admission counters, 36.6% of inbound fetch requests on 0.21.0 and 44.3%
on 0.22.0 were refused at admission. In the 25 hours around a wave of 177 newly installed nodes
filling their ranges (2026-10-11 20:00 to 2026-10-12 21:00 UTC), the WARN line counted 3.38M
refusals, 95.2% of them to the new nodes.

ant-node #252 removes most of the per-peer over-share by keeping a requester's own fetches within
each answering holder's share. It cannot remove every refusal: a request the requester has
already timed out on still holds its share at the responder until the responder sheds it, the
twelve-slot pool can be full of other peers' requests, a holder #252 currently counts as silent
may be sent requests past its share until an answer clears the mark or the mark expires and the
holder is probed under the share again, and older requesters keep over-sharing until they
upgrade. #252's description leaves the first case to a busy reply, and its ADR defers that reply
as a wire change with its own rollout.

## Decision Drivers

- Most peers run older versions for weeks after any release. An old node must decode the same
  messages it always did and never be sent a `Busy` it cannot decode.
- A delivered `Busy` must not cost an honest responder trust; a refusal that cannot be answered
  stays the old silence.
- The added reply traffic must be bounded: no request storm from requesters retrying on every busy
  answer, and no echo amplification at responders.
- No new requester scheduling state that would collide with #252's per-source scheduler.

## Considered Options

1. **Keep silence; rely on #252 alone.** Leaves every remaining refusal at 30 s and a false
   trust charge.
2. **Reply with the existing `FetchResponse::Error`.** Decodable by old requesters, but they
   charge the responder an `ApplicationFailure` for it and fail over at once, so it trades a
   timeout for an immediate hop storm.
3. **Add a field to `FetchRequest`.** Old responders would ignore a trailing field, but a current
   responder would have to read old requests without it, which postcard reports as an error, not a
   missing field. A hand-written tolerant deserializer can paper over that, but it cannot tell a
   missing flag from a malformed one and only stays correct while `FetchRequest` is the last value
   in every message that carries it.
4. **A capability trailer after the whole message, and an appended `FetchResponse::Busy`
   variant (chosen).**
5. **Busy with requester-side retry rotation and budgets.** Reviewed and rejected: hopping on every
   busy answer turns each refusal into an immediate new request, so a requester whose holders all
   refuse asks once per round trip instead of once per fetch timeout; it competes with `tried`
   state; and charging at budget expiry punishes honest overloaded holders once per key per cycle.

## Decision

We will let a requester say it understands a busy reply, and have a responder that refuses such a
request at admission say `Busy` at once, within bounds, instead of staying silent.

**Wire.** `FetchRequest` keeps its serialized layout (`key`). A requester that understands busy
replies appends the 5-byte fetch capability trailer, `antf` and a flags byte with bit 0 set,
immediately after the postcard message. `ReplicationMessage::decode` uses `take_from_bytes` and
sets `FetchRequest::busy_reply` (not serialized) only when that trailer follows a fetch request;
bytes after the flags byte are reserved and ignored. Older nodes decode with `from_bytes`, which
ignores everything after the message, so they read the key and refuse silently as before.
`FetchResponse::Busy { key }` is appended after `Success`, `NotFound` and `Error`, whose
discriminants are unchanged, and is only ever sent in answer to a request carrying the trailer.

**Responder.** Every saorsa-core message is signed with ML-DSA-65, so a busy reply costs a
signature and about 5 KiB on the wire, not a few bytes. On an admission refusal of a request that
asked, the responder takes a busy-reply send permit (48 at once), then a grant from
`FetchBusyReplyLimiter`: per peer, two back to back and then one a second, with at most two in
flight; overall, 32 back to back and then 16 a second (at most 48 replies, about 250 KiB, in any
one second; about 85 KiB/s sustained). Both rate allowances are tested and spent together under
one lock, a denial spends neither, and the per-peer table is capped at 4096 entries, forgetting
only peers whose allowance has refilled and that have nothing in flight. Within all bounds it
sends `Busy` on the detached task tracker, abandons the send after 2 s and races shutdown;
otherwise it refuses silently, exactly as before. The `Fetch response dropped at admission`
WARN line and its counters are unchanged, with `capability=asked|not_asked` and
`reply=scheduled|none` fields added.

**Requester.** Every fetch request this node's fetch worker sends asks for busy replies. A `Busy` for the requested key carries
no trust event. The attempt then waits 5-10 s (uniform jitter), never past its own fetch timeout,
still holding its fetch slot, and ends as `SourceFailed`, so the queue moves on to the next untried
holder exactly as after a timeout. `SourceBusyTracker` remembers the busy holder: a new key starts,
and a failed key retries, on the first holder in preference order that is not cooling down,
falling back to the first when all are. It reorders and never withholds, so it lowers how often a
busy holder is asked but is not a hard per-holder bound; the hard bound is the busy wait per fetch
slot. The cooldown is 1, 2, 4, then 8 times the full jittered wait drawn for that busy answer,
the multiplier rising with each further busy answer before the holder next serves this
requester, capped at 60 s, and a later busy answer never shortens a running cooldown; once it
runs out the holder is no longer put last. Serving once clears the holder's record, so its next
busy answer starts the multiplier again; a record with no busy answer for 10 minutes does the
same. When the 4096-entry table is full, a holder that is no longer cooling is forgotten first,
or, if every holder in it is cooling, the one whose cooldown ends soonest. A `Busy` for any
other key is treated as malformed, like every other key mismatch.

**Order.** This is merged after #252. #252's per-source share is what removes most per-peer
over-share and bounds how many fetches one requester has open at one answering holder; without
it, a requester with many fetch slots still over-shares, and most of those refusals exceed the
per-peer busy allowance and stay silent. On rebase, #252's source choice also puts cooling holders
last. The two changes conflict in `src/replication/mod.rs` and have not yet been built or measured
together; the gates and the real-node measurements below will be rerun on the rebased change.

## Consequences

### Positive

- When a refused requester receives `Busy`, it moves on after 5-10 s, or sooner if its own fetch
  timeout runs out first, instead of 30 s, without charging the responder.
- A holder that just refused is not handed this requester's next keys while another holder that is
  not cooling exists.
- Old nodes decode exactly the messages they always did: a request carries 5 bytes after the
  message that they never read, and they are never sent `Busy`. Rollback is a release without the
  change.
- With #252, each busy wait keeps one attempt counted against that holder's two-request share for
  its duration, reducing new requests and stopping them when both share slots are occupied; the
  busy answer also counts as an answer for #252's silent-source logic.

### Negative / Trade-offs

- New outbound traffic at responders: at most 16 signed busy replies a second sustained, about
  85 KiB/s, and 48 (about 250 KiB) in any one second, plus that many signatures. Today a refusal
  sends nothing. Each refused request already cost its sender the same signed message.
- A requester asks a refusing holder up to once per busy wait per fetch slot instead of once per
  fetch timeout `T`: at most `C / min(5 s, T)` small requests with `C` hardware-thread fetch
  slots, against `C / T` today, in the case where every holder refuses everything; with the
  default 30 s timeout, `C / 5 s` against `C / 30 s`. Capping `C` is a separate decision.
- Refusals beyond the per-peer busy allowance stay silent and are still charged by saorsa-core.
  Without #252, a requester that over-shares by more than two requests at once still meets some
  silence.
- Busy is trust-neutral. A holder that tries to answer busy to everything can still be charged when
  a request did not ask, a reply was suppressed, or a scheduled send did not complete; otherwise,
  when this requester starts or retries a key, it is put behind every holder that is not cooling
  (when all are cooling, the first is still tried), for up to 60 s at a time, and remains subject
  to storage audits.
  Penalising "never serves" would need a service audit with reserved capacity, which is not part
  of this decision.
- Sixteen identities each spending their per-peer second can use up the global allowance and
  deny busy replies to everyone else, and stalled peers can hold the 48 send permits for up to
  2 s each. What they win is the old silence for those peers, not a new failure. The global
  allowance is kept small on purpose, because it is what bounds the signed bytes a full node
  spends on refusals.

### Neutral / Operational

- New fields on the `replication responder admission summary (cumulative)` line: the cumulative
  counters
  `fetch_busy_reply_{not_asked,send_pool_full,rate_limited,peer_in_flight,sent,send_failed,timed_out,cancelled}`,
  `fetch_busy_received` and `fetch_busy_cooling_skips`, and the gauge `fetch_busy_sources_tracked`,
  the current size of the requester's busy-holder table.
  `not_asked` against the rest is the share of refused requests that did not ask for a busy reply:
  a proxy, and an upper bound, for how much refused traffic still comes from older versions (a
  request from a current node can also not ask, through the API or a malformed trailer).

## Validation

- Unit tests:
  - mirrors of the previous types decode current requests, and the unchanged answers 0-2;
  - a current node reads an older request as not asking;
  - trailer parsing: exact, wrong magic, truncated, unknown bits, reserved bytes, padding;
  - an older requester cannot decode `Busy`;
  - limiter: burst, refill, global cap, no spend on a denial, in-flight limit, bounded table;
  - the busy wait's range and its cap at the fetch timeout;
  - tracker: cooldown, escalation, cap, not shortened by a later busy answer, reset, expiry,
    bounded table;
  - a retry passes over a cooling holder but still takes it last;
  - a busy reply is not counted as served bytes.
- End to end on a local network, made deterministic with a test-only fetch serve gate (the same
  one #252 adds):
  - a refused request that asks is told `Busy` at once;
  - one that does not ask is refused silently;
  - the held requests are served once the gate opens;
  - the requester's own fetch worker, refused because its two-request share at the holder is
    full, records the holder as cooling, keeps the attempt for at least the minimum busy wait,
    then gives the key up, and the holder's trust at the requester never drops.
- Measured on real nodes against upstream main a6e3388e with the same test-only gate, in
  `tests/e2e/fetch_busy_ab.rs` (opt-in):
  - 20 requesters each within their two-request share, the first of five holders with its
    12-slot pool full for 2 s (26 refusals with this change, 28 on main), one of the refusal
    cases left after #252: all 40 chunks in 10.5 s, no holder charged, against 90.3 s with 14,
    9, 9, 4 and 3 requesters charging the five holders (one run each; on the previous main
    8d25f0c3 it was 60.4 s with 14 and 4 requesters charging the first two);
  - one requester with 8 fetch slots over-asking three holders, which #252 removes: 38.1 s, 39.2 s
    and 37.2 s with only the first holder charged (4 charges), against 90.2 s, 90.2 s and 90.3 s
    with all three charged (6 charges on the first, 1 to 4 on the others).
- A local, unpublished discrete-event model of the 177-node join wave and 24 more scenarios
  informed the design, including the 5-10 s wait. Its source and raw output are not part of this
  change, so its results are not offered as validation.
- In production:
  - `fetch_busy_reply_sent` against `fetch_admission_dropped_*`;
  - the fall in `connection_timeout` trust events between fleet nodes;
  - `fetch_busy_reply_rate_limited` and `fetch_busy_reply_send_pool_full` staying small.

  Revisit the 5-10 s wait and the allowances against measured admission hold times.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
