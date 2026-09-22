# ADR-0016: Bounded fresh-replication offers and copy-free message sends

- **Status:** Proposed
- **Date:** 2026-09-22
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR-0003](ADR-0003-full-node-detection-and-eviction.md)
  (best-effort fresh delivery and possession checks),
  [ADR-0005](ADR-0005-replication-repair-hardening.md),
  ant-node `perf/replication-send-path`, saorsa-core `perf/replication-send-path`,
  saorsa-transport `perf/replication-send-path`,
  `ant-testnet/state/comparisons/web-support-memory-diag-0921/` (heap profiles
  and per-minute live/RSS reports from the diagnosis)

## Context

Under sustained client uploads on a 60-node DigitalOcean testnet, individual
nodes grew from ~100 MiB to 1–2 GiB of resident memory within an hour and
kept growing for as long as writes continued. Heap profiles taken on the
running nodes attributed roughly 80% of live memory to one site: encoded
`FreshReplicationOffer` messages queued by the fresh-write drainer.

The mechanism was structural rather than a leak:

- Every accepted PUT was pushed to the drainer with the full chunk, and
  `replicate_fresh` encoded the offer (chunk plus proof, up to ~4–5 MiB)
  immediately, before any send permit was held.
- One send task per close-group peer then waited for one of
  `MAX_CONCURRENT_REPLICATION_SENDS` (3) permits while pinning that encoded
  buffer. Nothing bounded how many chunks could be waiting in that state.
- On a real network each send holds its permit for seconds (QUIC delivery
  acknowledgement, retries, unreachable NAT peers), so a write rate above
  the send rate grew the queue without limit. Loopback devnets never showed
  it because sends complete instantly.

Once the backlog was bounded, the profile showed the remaining cost per
in-flight send: the same frame existed as the caller's serialized message
*and* as the QUIC stream's copy for the whole transfer, plus transient
copies made while framing (payload clone per channel attempt, owned wire
message for signing, and a doubling `Vec` that left chunk-sized frames with
up to twice their length in capacity).

## Decision Drivers

- Node memory must stay bounded under any client write rate; replication
  may be delayed by backpressure but must not be dropped.
- The change must not alter the wire format, storage format or payment
  logic, so it can ship as a behavioural fix.
- Existing callers of the send APIs in saorsa-core and saorsa-transport must
  keep compiling and behaving the same.

## Considered Options

1. Bound the fresh-write channel and drop or block PUT handling when full.
   Rejected: either silently loses replication or blocks client responses
   on network conditions.
2. Raise `MAX_CONCURRENT_REPLICATION_SENDS`. Rejected: only moves the
   knee of the curve and increases bandwidth pressure on home links; the
   queue behind the permits would still be unbounded.
3. Keep events small and take a bounded permit before materialising an
   offer; separately remove the avoidable copies on the send path. Chosen.

## Decision

We will bound the number of encoded fresh offers that can exist at once and
make the send path hand a single owned buffer down to the QUIC stream:

- `FreshWriteEvent` carries only the key and the payment proof. The drainer
  acquires a `MAX_PENDING_FRESH_OFFERS` (8) permit before it reads the chunk
  back from storage and encodes it; the permit lives with the encoded offer
  until the last per-peer send drops it. A backlog therefore waits as small
  queued events, and at most ~40 MiB of encoded offers exist per node.
- The chunk moves into the offer rather than being copied, and
  `ReplicationMessage::encode` serializes into an exactly-sized buffer.
- The encoded offer is shared as `Bytes`; saorsa-core's `send_message`
  accepts `impl Into<Bytes>`, frames the payload through a borrowing
  `WireMessageRef` (byte-identical to `WireMessage` on the wire) into an
  exactly-sized frame, and passes that frame as `Bytes` to
  saorsa-transport's new `send_bytes`, where the QUIC stream takes ownership
  via `write_chunks` instead of copying it.

## Consequences

### Positive

- Memory under write load is bounded by configuration: pending offers plus
  the three in-flight sends, each held once, instead of growing with the
  backlog. On the diagnostic fleets peak live memory fell from 1068 MiB to
  298 MiB (mimalloc build) and from 674 MiB to 262 MiB (jemalloc build)
  after the backpressure change alone.
- Every large send node-wide (chunk GET responses included) stops paying
  for a second copy of its frame during the transfer.
- No wire, storage or API break: `send(&[u8])` remains and copies once as
  before; `Vec<u8>` callers of `send_message` convert without copying.

### Negative / Trade-offs

- Replication of a burst of writes is spread out in time rather than
  encoded eagerly; the delayed possession check is scheduled after each
  offer's sends are dispatched, so it shifts by the same amount.
- The drainer re-reads each chunk from disk when its permit arrives, one
  extra read per accepted write.

### Neutral / Operational

- `MAX_PENDING_FRESH_OFFERS` and `MAX_CONCURRENT_REPLICATION_SENDS` are
  the two knobs; raising the first trades memory for burst absorption.
- The signing step still serializes the payload once to produce the signed
  bytes; changing that would alter the signature input and is out of scope.

## Validation

- Unit tests: exact-capacity encoding of chunk-sized offers (ant-node) and
  byte-for-byte equivalence of `WireMessageRef` with `WireMessage`
  (saorsa-core); replication unit and e2e fresh-replication scenarios pass.
- Testnet evidence (2026-09-21): with the backpressure change, the node
  that had reached 1051 MiB live memory stayed flat at 0.0 MiB/min with a
  150 MiB peak, and the worst bootstrap's queued offers dropped from 101
  (463 MiB) to 6 (17.7 MiB) in heap profiles.
- Review trigger: any change to fresh replication fan-out, send permits, or
  the wire-message framing must re-run the memory diagnostics under
  sustained uploads and confirm live memory stays bounded.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
