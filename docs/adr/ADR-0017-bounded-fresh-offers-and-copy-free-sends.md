# ADR-0017: Bounded fresh-replication offers and copy-free message sends

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

- The chunk-sized buffers held for replication must stay bounded under any
  client write rate, and what queues ahead of them must be small;
  replication may be delayed by backpressure but must not be dropped by it.
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

- `FreshWriteEvent` carries only the key and the payment proof, and fresh
  replication runs as two stages. The fresh-write drainer never waits for
  chunk back-pressure: for every event, at arrival rate, it records the key
  in `PaidForList(self)` and sends `PaidNotify` to the paid close group —
  the evidence later repair depends on — then forwards the event to the
  offer dispatcher. The dispatcher is the only permit-gated stage: it
  acquires a `MAX_PENDING_FRESH_OFFERS` (8) permit before it reads the
  chunk back from storage and encodes it; the permit lives with the encoded
  offer until the last per-peer send drops it. A backlog therefore waits as
  small queued events, and at most ~40 MiB of encoded offers exist per node.
  Nothing is dropped by back-pressure: both queues are unbounded and FIFO,
  and every offer is dispatched with the same fan-out, retries and delayed
  possession check.
- The read-back is the same verified read the fetch path serves from
  (`ChunkStore::get`), not a raw one. The bytes were content-checked when
  they were stored, but they now come off disk, possibly long after, and
  every receiver rejects an offer that does not hash to its key and charges
  the sender for it. A chunk that fails verification is quarantined by that
  read, as on any serve, so the node stops advertising it and ordinary
  repair replaces it; it is never offered. Like every serve, verification
  follows the store's `verify_on_read` setting (on by default).
- A failed read-back is retried up to `MAX_FRESH_READ_ATTEMPTS` (7) times
  with the permit released in between, the pause doubling from
  `FRESH_READ_RETRY_DELAY` (1, 2, 4, 8, 16 and 32 s). The delay runs on a
  task of its own, never on the dispatcher, so a chunk that alone cannot be
  read does not hold the healthy writes queued behind it. Read faults tend
  to be store-wide (exhausted descriptors), though, and then every queued
  write fails together: each failure frees its permit for the next write at
  once, so a fixed short retry window would spend the whole backlog's
  attempts within seconds. The backoff spreads them over about a minute, and
  a store-wide fault shorter than that costs no offers. Only a chunk that is
  no longer stored is skipped without retry.
- The chunk moves into the offer rather than being copied, and
  `ReplicationMessage::encode` serializes into an exactly-sized buffer. The
  chunk-carrying fields — the offer's data and proof, `PaidNotify`'s proof,
  `FetchResponse::Success::data` and a subtree slice's `bao_slice` — are
  byte strings (`serde_bytes`), which postcard lays out exactly like a `u8`
  sequence: one copy each way instead of a per-byte loop, and an
  exactly-sized buffer on decode.
- The encoded offer is shared as `Bytes`; saorsa-core's `send_message`
  accepts `impl Into<Bytes>`, frames the payload through a borrowing
  `WireMessageRef` (byte-identical to `WireMessage` on the wire) into an
  exactly-sized frame, and passes that frame as `Bytes` to
  saorsa-transport's new `send_bytes`, where the QUIC stream takes ownership
  via `write_chunks` instead of copying it.

## Consequences

### Positive

- Chunk memory under write load is bounded by configuration: pending offers
  plus the three in-flight sends, each held once, instead of growing with
  the backlog. On the diagnostic fleets peak live memory fell from 1068 MiB to
  298 MiB (mimalloc build) and from 674 MiB to 262 MiB (jemalloc build)
  after the backpressure change alone.
- Every large send node-wide (chunk GET responses included) stops paying
  for a second copy of its frame during the transfer, and a fetched chunk is
  encoded and decoded in one copy each.
- No wire, storage or API break: `send(&[u8])` remains and copies once as
  before; `Vec<u8>` callers of `send_message` convert without copying.

### Negative / Trade-offs

- Replication of a burst of writes is spread out in time rather than
  encoded eagerly; the delayed possession check is scheduled after each
  offer's sends are dispatched, so it shifts by the same amount. A chunk
  fetched seconds after its upload can therefore have fewer replicas than
  before (the 2026-09-22 comparison measured downloads of just-uploaded
  files 8% slower). Paid-list evidence is not affected, and the previous
  unbounded fan-out lost that evidence outright under load (2,795
  "paid notify dropped at admission" in one hour on the baseline fleet).
- It is not a hard memory bound. The queues ahead of the permit hold a key
  and a stripped payment proof per write (about 40 KB for a single-node
  proof, about 130 KB for a merkle proof, at most 512 KiB), so a sustained
  write rate above the send rate still grows memory, roughly a hundred times
  more slowly than one encoded chunk per write did. Capping those queues
  would mean dropping offers, which is left to a later decision if testnets
  show a sustained backlog.
- The dispatcher re-reads and re-verifies each chunk when its permit
  arrives: one extra read and one BLAKE3 pass per accepted write, the same
  as serving it once.
- The pending-offer budget bounds the sender's memory, not what receivers
  admit. Offers are one-way and the sender does not read the answer, so a
  burst of small chunks from one sender can exceed a receiver's per-source
  fresh-offer admission cap, and that receiver refuses the excess. Chunk-
  sized sends are slow enough that this is rare in practice, and neighbor
  sync fills the gap, as it does for any refused offer.

### Neutral / Operational

- `MAX_PENDING_FRESH_OFFERS` and `MAX_CONCURRENT_REPLICATION_SENDS` are
  the two knobs; raising the first trades memory for burst absorption.
- A write whose read-back fails `MAX_FRESH_READ_ATTEMPTS` times is not
  offered, and neither is its possession check scheduled. A store-wide
  fault lasting longer than the retry window does this to every write
  queued at the time. Each failed read also leaves the key marked suspect,
  so the node stops advertising it. That is self-correcting: the store
  clears the mark on the next read that succeeds — another holder's
  possession probe, a late duplicate offer or client PUT checking what it
  holds, a client GET, or this node's own neighbor sync re-fetching a key it
  no longer claims — and on a repair or re-put. The paid-list evidence went
  out before the read was attempted, and the client stored the chunk
  directly on a majority of the close group, each of which fans it out, so
  one node's lost offers cost a replica for a while, not the data.
- The signing step still serializes the payload once to produce the signed
  bytes; changing that would alter the signature input and is out of scope.

## Validation

- Unit tests: exact-capacity encoding of chunk-sized offers and
  exact-capacity decoding of fetched chunks; wire equivalence of every
  byte-string field with its `u8`-sequence layout, both directions, across
  the varint length boundaries (ant-node); byte-for-byte equivalence of
  `WireMessageRef` with `WireMessage` (saorsa-core).
- E2E tests over the real harness, whose nodes wire the PUT handler to the
  fresh-write pipeline as a node does: a PUT through the handler replicates
  and a missing chunk queued ahead of it is skipped; with the send stage
  held, a burst three times the budget encodes exactly
  `MAX_PENDING_FRESH_OFFERS` offers, then all of them once sends resume,
  and returns every permit; a failed read-back releases its permit, does
  not delay a healthy write behind it, and is offered once the fault
  clears; a chunk corrupted on disk is quarantined and never offered.
- Testnet evidence (2026-09-21): with the backpressure change, the node
  that had reached 1051 MiB live memory stayed flat at 0.0 MiB/min with a
  150 MiB peak, and the worst bootstrap's queued offers dropped from 101
  (463 MiB) to 6 (17.7 MiB) in heap profiles.
- Review trigger: any change to fresh replication fan-out, send permits, or
  the wire-message framing must re-run the memory diagnostics under
  sustained uploads and confirm live memory stays bounded.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
