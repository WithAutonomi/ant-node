# ADR-0023: Spread hot-record reads across the close group, and refuse full browser sessions explicitly

- **Status:** Proposed
- **Date:** 2026-10-12
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR-0015](./ADR-0015-direct-browser-clients-over-webrtc-direct.md)
  (amends its capacity-rejection rule and three listener defaults),
  ADR-0020 (get-or-closer chunk reads, open in #249),
  ant-client ADR-0004 (direct browser read client),
  [RFC 8489 §6.3.4](https://www.rfc-editor.org/rfc/rfc8489#section-6.3.4) (STUN error responses),
  [RFC 8445 §7.2.5.2.4](https://www.rfc-editor.org/rfc/rfc8445#section-7.2.5.2.4) (connectivity-check failure)

## Context

The question that prompted this ADR: can the network serve thousands of
browser clients who all want the same chunks at once, for example because they
are watching the same film?

A node admits a bounded number of browser sessions (ADR-0015, "Public-listener
resource isolation"). Before this ADR the defaults were:

| Setting | Default |
|---|---:|
| `max_connections` | 32 |
| `max_connections_per_ip` | 4 |
| `max_channels` | 32 |
| `max_concurrent_requests` | 16 |
| `max_requests_per_second` | 256 |

saorsa-transport refuses to bind a listener with `max_connections` above 256
(`MAX_PENDING_ASSOCIATIONS`). Configuration can raise the limits below that,
but only through a `--config` file. No CLI flag sets them.

Three findings matter more than the limits themselves.

**1. Every client reads a record from the same holder.** Each record is stored
on its close group of `CLOSE_GROUP_SIZE` = 7 nodes. Both read paths in the
shared client engine (`ant-core/src/client_engine/read.rs`, used by native and
browser clients) order candidates by XOR distance. Early reads during
discovery always take the nearest unattempted hint. The final ordinary path
sorts the close group nearest-first. A second holder is asked only after the
1-second hedge delay or a failure. So every client sends its first GET for a
record to the same node, and a popular record is served by one node while
the other six idle.

**2. Upload bandwidth runs out before session slots do.** Take a 5 Mbit/s
stream and 4 MiB chunks, so each chunk is about 7 seconds of playback. If
1,000 viewers are at the same point, one chunk window asks for 4 GiB in about
7 seconds, roughly 5 Gbit/s. One node cannot supply that. Spread evenly over
all seven holders it is about 700 Mbit/s each. Viewers who started at
different times spread across the file's chunks, but every viewer reads the
data map and the first chunks, so those are hot whether or not viewers are in
sync. Raising session limits alone admits more viewers to the same uplink.

**3. A full node looks unreachable.**
- When a proven association finds no free slot, the transport ignores the
  browser's ICE check without replying (`DirectUdpMux::run`).
- Application-level capacity and rate rejections close the channel or
  association, also without a reply. ADR-0015 chose this to avoid amplifying
  attacker traffic.
- The browser therefore waits out its 10-second channel-open timeout. It then
  records a dial failure, and `ENDPOINT_FAILURE_COOLDOWN` keeps that node out
  of every lookup and read for **30 minutes**.

Under load, busy nodes vanish from each client's view one by one, so the
network looks smaller exactly when demand peaks. ant-client's lookup notes say
a third to a half of the WebRTC Direct endpoints discovered on mainnet time
out when dialled. Some of those may be full rather than down. That is
unverified, but each node's `rejected_connections` diagnostic can show it.

## Decision Drivers

- Use the capacity of the whole close group before anything costlier.
- A busy node should cost a client about one round trip, not ten seconds,
  and should come back into rotation in seconds, not half an hour.
- No new wire message, no protocol version, and no flag day. Every mix of old
  and new nodes and clients must behave at least as well as today.
- Keep ADR-0015's resource bounds and its refusal to amplify traffic.
- Leave the larger fixes for hot content (more holders, delegated lookups)
  open for their own decisions.

## Considered Options

1. **Raise the per-node limits only.** Rejected as the sole measure. It is
   capped at 256 by the transport, and it fixes neither single-holder
   concentration nor full nodes looking dead. Raising the session-shaped
   limits alongside the other changes is cheap, so we do that too (Decision,
   section 4).
2. **Spread reads across the close group.** A client-only change to read order.
3. **An explicit "busy" signal.** Three ways to send one:
   1. *A new browser-protocol status.* This needs a wire change across
      saorsa-transport, ant-node and ant-client. Worse, sending it needs a
      full ICE, DTLS and SCTP association for every refused attempt, which is
      exactly the cost the session limit exists to bound.
   2. *A STUN error response at transport admission.* A browser fails a
      candidate pair as soon as its connectivity check gets an error response
      (RFC 8445 §7.2.5.2.4). A refusal costs the node one STUN parse, one HMAC
      and one send, after the reachability-cookie round trip it already
      requires. No wire change.
   3. *Client heuristics alone,* such as a shorter cooldown for every dial
      failure. Rejected: clients would redial genuinely unreachable endpoints
      every few seconds, at ten seconds per attempt.
4. **More holders for hot records** (caching along lookup paths), browser
   peer-to-peer sharing, or a CDN-backed HTTP gateway. These are the real
   answer to finding 2, but each needs its own ADR. Deferred.

## Decision

We adopt options 2 and 3.2, and the client classification that makes 3.2
useful. We also raise the listener's session-shaped defaults (option 1, not
as the sole measure).

### 1. Spread first reads across the close group (ant-client)

For every chunk read, the read order is:
1. the close group, meaning the `CLOSE_GROUP_SIZE` nearest candidates that
   discovery has found so far, in uniformly random order;
2. then the remaining candidates, nearest first.

Known-peer fallbacks, used when discovery comes up short, keep nearest-first
order. Pointer reads are unaffected: they already ask the whole close group
at once.

How each read path applies this:
- **Early reads during discovery** choose uniformly among the unattempted
  members of the currently known close group. When all of them have been
  tried, the nearest remaining hint is next.
- **The ordinary path** shuffles the close group at the front of its final
  candidate list.

The hedge delay, the early-read allowance, the at-most-two-GETs rule and the
absence rule are unchanged. The engine takes the choice as a parameter.
Production passes a uniform random choice, and tests pass nearest-first to pin
order. Native clients use the same engine, so they spread too.

### 2. Refuse proven associations explicitly when full (saorsa-transport)

**When it applies.** An association becomes proven when it has returned the
source-bound reachability cookie (ADR-0015). If a proven association then
finds no slot, because the listener is at `max_connections`, the pending queue
is full or the accept queue is full, or because its IPv4 address or IPv6 /64
holds its full share, the mux no longer ignores the request that would have
admitted it.

**What the mux sends.** It answers with a STUN Binding error response that:
- carries the same transaction ID as the request;
- has `ERROR-CODE` 486 (*Allocation Quota Reached*), with the reason phrase
  "Insufficient Capacity" or "Source Quota Reached". A 4xx code ends the STUN
  transaction (RFC 8489 §6.3.4), so any compliant ICE agent fails the pair at
  once. A 5xx code such as 508 *Insufficient Capacity* may be retried, so it
  is not used. Browsers do not expose STUN errors to applications; the phrase
  only makes packet captures readable.
- carries `MESSAGE-INTEGRITY` keyed by the listener credential that
  authenticated the request, so the browser accepts it as the answer to its
  own check;
- carries `FINGERPRINT`;
- is never larger than the request it answers. If it would be, it is not
  sent.

**What stays silent.**
- Duplicates of an association already being built. Answering one would fail
  that browser's live candidate pair.
- Attempts that arrive while the listener is shutting down (its accept queue
  is closed). That is not capacity.

**Counters.** Refusals are counted in `rejected_connections`, as silent
rejections were.

**Application-level rejections.** In ant-node, admission, channel, request,
rate and byte rejections after ICE and DTLS keep their current behaviour: the
node closes the association or channel. The client reads that close as the
refusal (section 3).

This amends ADR-0015's rule that "capacity or rate rejection closes the
channel or association without sending an error response". At the transport,
capacity rejection of a proven association now sends one, under the existing
amplification bound.

### 3. Tell a declining node from an unreachable one (ant-client, browser)

**What counts as `Refused`.** A failed fresh dial is `Refused` when the node
answered it and turned it away:
- **Transport refusal:** the browser declared the association failed within
  `REFUSAL_DETECTION_WINDOW` (3 s) of its ICE checks starting, without it ever
  reaching connected, and with ICE not connected at that moment. The test is
  "ICE not connected" rather than "ICE reads failed", because Chromium declares
  the association failed while its legacy `iceConnectionState` still reads
  "checking". Or:
- **Application refusal:** ICE and DTLS completed, and the node then closed
  the channel, or the association died, before the post-quantum session was
  established.

**Cooldowns.** A refused endpoint is suppressed for `ENDPOINT_REFUSAL_COOLDOWN`
(15 s). Every other dial failure keeps the 30-minute cooldown. That includes:
- DTLS failing after ICE connected, which means a different node answered at
  the endpoint;
- an authentication failure with the channel still open;
- a lane the client closed itself because the node sent malformed data.

A full failure cache evicts the stored record that expires soonest, so a
stored refusal is dropped before any longer-lived failure.

**Waiting less.** The channel-open wait now ends as soon as the browser
declares the association dead, instead of running out its 10-second timeout.

**Why the window separates the two cases.** A refusal arrives within a few
round trips, one cookie round trip plus one retransmitted check: 67 ms in
Chromium and 54 ms in WebKit on loopback. Against a node that never answered
(the baseline below), both browsers were still checking when the client's
10-second channel-open timeout fired. Playwright Firefox reported its failed
dials after 5.0 s, which is also outside the window.

**Why 15 s.** It is long enough not to redial a full node for every chunk of
a stream, since a 4 MiB chunk plays for several seconds at video bit rates. It
is short enough that the node rejoins lookups and reads soon after viewers
leave.

### 4. Raise the session-shaped listener defaults (ant-node)

| Setting | Before | Now |
|---|---:|---:|
| `max_connections` | 32 | 256 |
| `max_channels` | 32 | 256 |
| `max_concurrent_requests` | 16 | 128 |

- **256 sessions is the transport's ceiling** (`MAX_PENDING_ASSOCIATIONS`).
  Going higher needs a saorsa-transport change and the load test below.
- **Sessions alone would not help.** A session that opens a channel needs a
  channel slot. The post-quantum handshake and every request take a request
  slot, and when none is free the node closes the channel. With 16 request
  slots, a node already turns away new channels once 16 GETs are queued. The
  channel and request limits therefore keep their ratio to sessions: one
  channel and half a request slot per session.
- **What does not change:** the per-IP session quota (4), channels per session
  (2), every rate bucket, and both in-flight byte budgets.
  - Frame and response memory is bounded by the byte budgets, not by slot
    counts. A GET builds its response only while it holds one of the four
    bulk-response slots that the 64 MiB budget allows. While it waits for one
    it holds only its small request frame.
  - The rate buckets bound handshake and request CPU.
- **What grows** is per-association state outside those budgets: ICE, DTLS and
  SCTP state and tasks for each session, and one handler task per channel.
  The network A/B measures node memory and CPU at the new limits.
- A node whose `--config` file sets these limits keeps its values.

## Consequences

### Positive

- **Up to seven times the serving capacity for a hot record,** with no
  protocol change. First reads land evenly on its holders instead of on one.
- **A full node costs a browser a round trip, not ten seconds.** Local
  Chromium and WebKit measurements (Validation) show 54–67 ms instead of
  10.0 s.
- **A full node rejoins rotation after 15 s instead of 30 minutes,** so
  overload no longer shrinks the network a client can see.
- **Eight times the browser sessions per node by default,** with the request
  slots to serve them, under the same memory and rate budgets.
- **Refusing costs the node almost nothing.** A STUN refusal allocates no RTC
  state, and it is sent only to a source that has proved reachability, at most
  once per returned cookie.
- **Mixed deployments behave at least as well as today:**
  - New client, old node: at transport capacity the old node stays silent, and
    the client times out and applies the 30-minute cooldown exactly as before.
    Application-level closes behave the same on old and new nodes, so they get
    the 15 s cooldown either way.
  - Old client, new node: the browser fails the association at once, but the
    old client still waits for its channel-open timeout and records a 30-minute
    failure, as before.

### Negative / Trade-offs

- **A random holder may not have the record yet,** for example a node that
  just joined the close group and has not finished replicating. That costs one
  `NotFound` round trip, and possibly a dial, before the next holder. The
  network A/B in Validation measures it.
- **Spreading changes which node a client reads each record from.** It does
  not change how many it reads from: one per record, plus the hedge.
  Connection reuse may change slightly, because the nearest holder is no
  longer favoured.
- **Transport refusals are recognised by timing.** Browser JavaScript cannot
  read the STUN error code. A fast ICE failure for another reason, such as no
  usable local candidate for the endpoint's address family or a client that
  just went offline, is also classed `Refused` and gets 15 s instead of 30
  minutes. Those dials fail at once, so the extra retries are cheap.
- **A browser replacing its own association can hit its source quota.** Its
  stale association still holds a slot until ICE closes it or the 10 s pending
  expiry runs. Before, a silent listener could admit the retry once that slot
  freed, if that happened before the client's 10 s timeout. Now the retry is
  refused at once and the client tries again after 15 s.
- **Only the request that completes admission is refused.** A retransmission
  of it that arrives later meets a fresh reachability challenge rather than
  the same error. Chromium and WebKit failed the dial on the first refusal,
  and the client closes the peer connection as soon as it is reported dead,
  so later challenges reach a closed connection.
- **A node or network that drops mid-handshake** after DTLS is also classed
  `Refused`. That is acceptable: the node was demonstrably up seconds earlier.
- **Application refusals still cost the node a DTLS handshake** per attempt,
  as today. Only transport refusals are cheaper.
- **A saturated node holds more per-session state.** At 256 sessions each
  association's ICE, DTLS and SCTP state and tasks sit outside the byte
  budgets. Until the network A/B measures it, that cost is an estimate.
- **None of these changes adds capacity for finding 2.** Synchronised demand
  for one chunk still outruns seven uplinks; more sessions only queue more
  viewers on the same uplink. Spreading and fast refusal make the best use of
  the holders that exist. More holders need the deferred options.

### Neutral / Operational

- The new defaults reach nodes on upgrade. Raising the transport's 256
  ceiling is a separate decision, based on the per-session cost the network
  A/B measures.
- `rejected_connections` now counts answered refusals. An operator who sees
  it rise knows browsers are being turned away, and no longer silently dropped.
- Once ADR-0020 (get-or-closer) lands, its holder choice should follow the
  same rule: spread across the known close group, then nearest first.

## Validation

**Unit and regression tests.**
- saorsa-transport, `webrtc::direct::admission`:
  - A refusal echoes the request's transaction, passes the listener
    credential's integrity check and fingerprint, and is no larger than the
    request.
  - An unparseable request is never answered.
- saorsa-transport, `webrtc::direct`:
  - A listener at capacity and one at its source quota both answer a proven
    check with 486 and their own reason phrase. In both cases
    `rejected_connections` increments and no association is admitted.
- ant-client, `client_engine::read`:
  - Over 7,000 trials, each close-group holder serves about 1/7 of first reads
    (within ±300), and peers beyond the close group keep nearest-first order.
  - Early reads choose within the known close group, then fall back to
    nearest-first.
  - An out-of-range choice stays inside the close group.
- ant-client, `EndpointFailureCache`: a refusal expires after its shorter
  cooldown while a failure does not.
- ant-client, `wasm-tests/capacity-refusal.test.mjs`:
  - A mock node that refuses at its transport, and one that closes during the
    handshake, both fail the dial in under 2 s.
  - Both are suppressed inside the cooldown, both are dialled again after it,
    and the client connects.
  - A third mock node that fails DTLS after ICE connected is not dialled again.
  - With refusal detection disabled, or with the earlier "dead and fast" test
    that ignored ICE state, this test fails.

**Real browsers (2026-10-12).**
- **Setup:** a local 7-node devnet with `max_connections` = 2 and
  `max_connections_per_ip` = 1. One `BrowserNetworkClient` holds node 0's
  per-source slot, a second client connects to the same seed, and the first
  client leaves after the second is refused. This exercises the source-quota
  refusal. A capacity refusal sends the same error code, so it is handled the
  same way.

  | Browser | Refused after (baseline → this ADR) | Error shown | After 16 s, holder gone |
  |---|---|---|---|
  | Chromium | 10,011 ms → **67 ms** | "DataChannel opening timed out" → "peer connection failed" | still suppressed → **connects in 132 ms** |
  | WebKit | 10,005 ms → **54 ms** | same | still suppressed → **connects in 115 ms** |

- **Firefox:** Playwright Firefox does not establish WebRTC Direct sessions
  with local nodes at all, even with loopback ICE enabled. This is independent
  of this ADR, so the refusal path is unverified there. Its failed dials were
  reported after 5.0 s, outside the 3 s window, and were correctly kept at the
  30-minute cooldown.

**On a network, before Accepted.**
- Run an A/B with the WASM benchmark harness: one hot file read by N clients.
  Compare the per-holder GET distribution, chunk read latency p50/p95, GETs per
  chunk (the `NotFound` cost), and nodes' `rejected_connections`.
- In the same run, measure node memory and CPU with sessions near the new
  limits.
- Check mainnet nodes' `rejected_connections` to learn how many of the
  endpoints that "time out when dialled" were full. The node binary does not
  log or serve its listener diagnostics today, so this needs them exported
  first.

**Review triggers.**
- A browser changes how it handles STUN error responses to connectivity
  checks.
- ADR-0020 changes the read path.
- A hot-record caching ADR lands.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
