# ADR-0020: Kademlia-style chunk GET: return the chunk or closer peers

- **Status:** Proposed
- **Date:** 2026-10-07
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** Linear V2-1358; ant-client investigation
  `docs/investigations/2026-10-06-kademlia-chunk-get/`;
  [ADR-0015](ADR-0015-direct-browser-clients-over-webrtc-direct.md) (browser
  capabilities); saorsa-core, ant-protocol and ant-client branches
  `mickvandijke/v2-1358-kad-chunk-get`

## Context

A native chunk read runs two separate steps today:

1. saorsa-core's iterative closest-peers lookup runs until it converges on the
   target's close group.
2. GETs are then sent one at a time, in XOR order.

While the lookup runs, early GETs go to peers that were already connected.
A `ChunkGetResponse::NotFound` carries no peers, so a GET never helps
discovery.

Measured on the production network, reading 150 chunks of one 612 MB file:

- **Native reads spend most of their time finding a holder.** Discovery takes
  5.1 s at p50 and transfer 0.8 s, so 82% of read time is discovery.
- **The lookup runs past the point where it could stop.** It needs about 6 s to
  converge, but the round that first reaches the close group is usually round
  2, about 0.3 s in.
- **Sending a GET beside every FIND_NODE removes almost all of that wait.** The
  read stops at the first verified chunk. In the measurements:

  | | p50 | p90 |
  | --- | ---: | ---: |
  | Today | 5.95 s | 13.0 s |
  | GET beside every FIND_NODE | 0.97 s | 1.9 s |

  The whole file then reads in 49–55 s instead of 199–205 s.
- **That speed costs bytes.** The round that reaches the close group queries
  up to alpha holders at once, so the read downloads 2.5–3.3 copies of a chunk
  on average.

Kademlia's FIND_VALUE folds the value into the lookup: a node that holds the
key returns it; one that doesn't returns closer peers. This network cannot
just switch to that, for three reasons:

- **Old peers.** Nodes on 0.20 and 0.21 drop an unknown `ChunkMessageBody`
  variant. Natively they send no reply, so the client waits out its timeout.
  Over WebRTC Direct, an undecodable request closes the browser's data channel.
- **No native capability exchange.** A connected node's user agent
  (`node/0.21.0 migration/files`) is the only signal of what it supports.
- **Peer validation lives in saorsa-core.** FIND_NODE answers are checked
  there: owner-signed address records, publish sequences, LAN filtering and
  dial plans. A chunk-protocol message that carries peers must not bypass
  those checks.

## Decision Drivers

- Cut native read latency to about one round trip per lookup step, and stop
  the lookup as soon as a verified chunk arrives.
- Stay compatible in both directions:
  - Old clients work unchanged with new nodes.
  - New clients work with old nodes at full speed, not after timeouts.
  - Rollout can happen in any order.
- Keep peer encoding and validation in saorsa-core, so a peer learned from a
  chunk response is trusted exactly as far as one learned from FIND_NODE.
- Leave the chunk-absence rule unchanged: a completed lookup and a majority of
  `NotFound`s.
- Give the client one place to evolve read policy without further wire
  changes.

## Considered Options

1. **Status quo.** Native discovery stays at about 5 s per chunk.
2. **Lookup progress feeds the early GETs (client only).** Measured native p50
   1.8 s, p90 4.9 s, one copy. No wire change, but more than 0.8 s slower at
   p50 than options 3 and 5.
3. **GET beside each FIND_NODE (client only).** The same latency as option 5,
   working with today's nodes. It sends two requests per peer, and the GET
   carries nothing useful when the peer doesn't hold the chunk. It remains the
   per-peer fallback under option 5.
4. **"Do you hold it?" request, then one fetch.** Measured native p50 1.16 s
   with 1.07 copies. Keeps bytes down at the cost of an extra round trip
   before the transfer. Deferred: it can be added later as another appended
   variant.
5. **Chunk-or-closer-peers request in ant-protocol, with the closer peers in
   saorsa-core's FIND_NODE answer format (chosen).** One request per lookup
   step to upgraded nodes, with per-peer fallback to option 3 for older ones.
6. **FIND_VALUE inside saorsa-core's DHT.** Rejected:
   - DHT messages are capped at 64 KiB, too small for a 4 MiB chunk.
   - The DHT layer would have to know about chunk storage.

## Decision

We will add a chunk-or-closer-peers request to the chunk protocol. Native
clients will run their own iterative lookup with it, and fall back per peer to
FIND_NODE plus GET.

### Wire (ant-protocol, additive)

`ChunkMessageBody` gains two variants, appended after every existing one, so
existing discriminants keep their wire values:

```rust
GetOrCloserRequest(ChunkGetOrCloserRequest { address: XorName })
GetOrCloserResponse(ChunkGetOrCloserResponse)

enum ChunkGetOrCloserResponse {
    /// The responder holds the chunk.
    Found { address: XorName, content: Bytes },
    /// The responder does not hold the chunk; `peers` are its closest known
    /// peers to `address`, encoded by saorsa-core.
    Closer { address: XorName, peers: Bytes },
    Error(ProtocolError),
}
```

`peers` is opaque to ant-protocol. saorsa-core produces and reads it with two
public calls:

- **`DhtNetworkManager::encode_closer_peers(key, requester)`** builds exactly
  what a FIND_NODE answer to that requester would hold:
  - the K closest routing-table peers, without the requester
  - QUIC addresses with publish sequences
  - owner-signed address records, within the FIND_NODE size limit
- **`DhtNetworkManager::decode_closer_peers(responder, key, payload,
  transport_source)`** validates the payload as a FIND_NODE answer from that
  responder. It goes through the same signed-record verification, owner-view
  protection, LAN filtering and dial-plan checks.

The peer format is therefore versioned in one place, saorsa-core, as it is for
FIND_NODE today.

### Node (ant-node)

- **If the node holds the chunk,** it answers `Found`, read from storage like a
  GET.
- **Otherwise it answers `Closer`,** using `encode_closer_peers` with the
  authenticated sender as the requester.
- **It advertises support** with the user-agent token `get-or-closer/1`
  (`ant_protocol::GET_OR_CLOSER_AGENT_TOKEN`), after the existing migration
  token. The `node/` prefix that saorsa-core gates DHT membership on is kept.
- **It does not advertise support to browsers yet.** Browsers cannot decode the
  native peer format. The WebRTC Direct listener keeps refusing the request,
  and HELLO does not list it.

### Native client (ant-client)

A chunk read runs a client-driven iterative lookup on saorsa-core's public
lookup engine (`IterativeLookup`). The parameters match today's native lookup:
alpha 3, K, a 5 s grace period per round, and a 120 s deadline.

For each peer the lookup queries, the client:

1. **Connects to it.** It uses `DhtNetworkManager::connect_lookup_peer`, which
   the lookup's own request would need anyway. It then reads the peer's user
   agent.
2. **If the peer advertises `get-or-closer/1`,** sends `GetOrCloserRequest`:
   - `Found`: verify the content hash, then stop the read.
   - `Closer`: `decode_closer_peers` supplies the lookup candidates.
3. **Otherwise,** sends FIND_NODE (`DhtNetworkManager::find_node_on_peer`) and
   a GET at the same time. FIND_NODE supplies the candidates, and a `Success`
   from the GET stops the read.
4. **If the connection fails,** marks the peer failed in the lookup, as a
   failed FIND_NODE is marked today.

The read driver owns every request, not the lookup round that triggered it.
The round's grace window therefore never cancels a chunk transfer that is
still arriving. Conflicting reports about a peer are resolved with
`client_routing::compute_winner`, as in both existing lookups.

- **When the lookup ends without a chunk,** or fails, the client runs today's
  read path (`retrieve_progressive`) unchanged. Its absence rule and retry
  round are unchanged.
- **Browser clients keep today's read path.** Supporting this request there
  needs a portable decoder for the peer format and a HELLO capability.

## Consequences

### Positive

- **Native read latency drops to about one round trip per lookup step.**
  Measured with the per-peer fallback that this decision keeps for old nodes:
  p50 5.95 s to about 1 s, p90 13 s to about 2 s, and the whole file 3.7 times
  faster.
- **Today's nodes, through the per-peer fallback.** A client built from
  this design downloaded the 612 MB production file in 56 s, against 242 s
  for the current client, with identical bytes. Production nodes do not
  announce the token yet, so every lookup step took the FIND_NODE-plus-GET
  route, and all 150 chunks were found without falling back to the old
  read path.
- **Upgraded nodes answer each lookup step with one request** instead of
  FIND_NODE plus GET. The chunk travels in that same reply.
- **Compatible in both directions.** Old clients never send the new variant.
  New clients send it only to nodes that advertise it, and treat every other
  peer as before.
- **Peer trust is unchanged.** Peers learned from `Closer` pass the same
  saorsa-core validation as FIND_NODE answers.
- **The absence rule, the retry policy and the browser path are untouched.**

### Negative / Trade-offs

- **Duplicate downloads.** Up to alpha holders can return the chunk in the
  same round: measured at 2.5–3.3 copies per chunk natively. That costs bytes
  for the client and egress for the nodes. A "have it" or inline-flag variant
  can bound this later without changing the request defined here.
- **The native client runs its own lookup**, beside the one in saorsa-core.
  Lookup parameters and peer policy must be kept in step.
- **Capability is a user-agent token**, and is known only once a peer is
  connected. Every queried peer has to be connected before the client can
  choose what to send it. The lookup's own request would have needed that
  connection anyway.
- **A second chunk response shape** to maintain, with its own traffic
  accounting.

### Neutral / Operational

- **Version bumps.** ant-protocol takes a minor version bump for the appended
  variants. saorsa-core gains public API with no wire change.
- **Node user agents gain a token.** Any tooling that parses them must split
  on whitespace.
- **Rollout order is free.** Nodes are a no-op until clients use the request,
  and clients fall back per peer.

## Validation

- **ant-protocol**
  - Round-trip tests for the new messages.
  - Every existing discriminant keeps its wire value.
- **saorsa-core**
  - `encode_closer_peers` / `decode_closer_peers` return the same trusted
    candidates as a FIND_NODE answer for the same key.
  - `find_node_on_peer` and `connect_lookup_peer` behave against a live peer.
- **ant-node**
  - The handler answers `Found` for a held chunk and `Closer`, with decodable
    peers, otherwise.
  - The user agent carries the token and keeps the `node/` prefix.
- **ant-client**
  - The read driver is tested on a scripted network. It must:
    - stop at the first verified chunk
    - fall back per peer for legacy peers
    - handle a mixed network
    - treat a hash mismatch as an error
    - keep a transfer alive past its lookup round's grace window
    - fall back to today's path when the lookup finds nothing
  - In-process test networks:
    - A network whose nodes all announce the token is read with
      get-or-closer requests only, and no plain GET.
    - The full end-to-end suite reads through the new path.
  - Live: a new client against today's nodes takes the legacy route for every
    peer and stays within the measured latency of option 3.
- **Review triggers**
  - Node egress for reads rises enough to matter: add the "have it" variant.
  - Browser reads need this request: add the portable decoder and a HELLO
    capability.
  - saorsa-core changes its native lookup parameters: mirror them in the
    client lookup.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
