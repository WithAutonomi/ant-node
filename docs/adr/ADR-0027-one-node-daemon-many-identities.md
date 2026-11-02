# ADR-0027: One node daemon per machine, hosting many node identities

- **Status:** Proposed
- **Date:** 2026-11-02
- **Decision owners:** Mick van Dijke
- **Reviewers:** TBD
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0003 (full-node detection), ADR-0014 and ADR-0022 (file-per-chunk store),
  ADR-0015 (WebRTC Direct), ADR-0016 (pointers). Prototype branches
  `feat/multi-identity-daemon` in `ant-node` (`098da0b0`) and `saorsa-core` (`351be1b9`),
  whose unmerged draft ADR this record replaces.

## Context

Operators scale a storage machine by starting one `ant-node` process per identity, each on
its own port in 10000–10999 and each with its own root directory. Every process owns a
complete stack:

- a QUIC endpoint, connection pool, NAT/relay state machine, bootstrap cache and routing
  table (`saorsa-core::P2PNode`);
- a WebRTC Direct listener and DTLS certificate (ADR-0015);
- a chunk store, pointer store and paid list under its root;
- payment-verifier caches, including on-chain merkle pool lookups;
- an upgrade monitor, signal handling and logging.

Running N copies of that stack on one machine costs in four places.

1. **Connections scale with identities, not machines.** Two machines running 20 identities
   each can hold up to 400 QUIC connections between them where one would do, each with its
   own handshake, keep-alives, relay allocation and NAT mapping.
2. **Capacity is overcommitted.** Each store's `CapacityGuard` measures its partition's free
   space and charges only its own writes against that measurement. N stores on one partition
   each treat the whole partition's free space as their own, so concurrent writes from
   several identities can overrun the reserve between measurements.
3. **Identical work is repeated.** Every process polls for upgrades, bootstraps on its own,
   and queries the chain for the same merkle pool when co-hosted identities are candidates
   in one payment batch.
4. **Operators manage N services.** Adding a drive or growing a disk means deciding by hand
   how many more processes to start. Nothing on the machine knows how many identities it can
   carry.

Two facts constrain the fix.

**Identity and transport are coupled in `saorsa-core`.** A `P2PNode` creates its transport
endpoint and authenticates TLS with the node's own ML-DSA key. The signed `WireMessage`
names a sender (`from`) but no destination. Several `P2PNode`s in one process would still
mean several endpoints and pools, and sharing one endpoint without a destination field would
deliver messages to the wrong identity. Separately, `NodeBuilder::resolve_identity` refuses
to start when `nodes/` holds more than one identity.

Three details of today's transport shape the design below.

- A connection's peer identity is registered from whichever key signed a valid message on
  it. Nothing compares that key with the connection's TLS key, and `saorsa-core` has removed
  its wire-level message-age check. A valid signature on its own therefore says nothing
  about which connection a message should have arrived on.
- Every new connection is announced automatically, signed by the transport's own key and
  carrying its user agent. The DHT admits any peer whose user agent starts with `node/`
  (`is_dht_participant`).
- The transport already maps several peers to one connection. Disconnecting a peer closes a
  connection only once no other peer still uses it.

`ant-devnet` already runs several `P2PNode`s in one process.

**The network already treats an IP address as one failure domain.** `saorsa-core` admits at
most `IP_EXACT_LIMIT` (2) peers per exact IP, and `K / 4` per /24 (IPv4) or /48 (IPv6), into
each routing-table bucket and close group. Identities co-hosted behind one address are
already limited this way, with or without a daemon. The daemon does not create that
exposure, and disclosing co-hosting must not leave an operator worse off than one who runs
separate processes on the same IP.

### What the prototype taught

A prototype was built in August 2026: three commits in each of `ant-node` and `saorsa-core`.
It is 401 commits behind `main` and predates the file-per-chunk store, pointers and WebRTC
Direct, so it will be reimplemented rather than rebased. Its networking design (the
destination-addressed envelope, the per-identity legacy endpoints and the signed capability
upgrade) is kept below. Four of its other choices are not.

- **A shared content-addressed blob store with a SQLite lease catalogue.** The deduplication
  it bought is modest. Two identities with independent random IDs are both responsible for a
  key with probability about (W−1)/(N−1). Here W is the storage admission width
  (`CLOSE_GROUP_SIZE + STORAGE_ADMISSION_MARGIN` = 9) and N is the network size, so the
  probability is under 1% per pair at a thousand nodes and falls as the network grows. The
  price was a second authority for what an identity holds, which ADR-0014 rejected for the
  single store ("a persistent index cannot remove reconciliation"). It also introduced a
  machine-wide database whose corruption reaches every identity at once.
- **Lease handoff on scale-down.** Draining moved all of a retiring identity's leases to one
  arbitrary live identity. That identity is generally not responsible for those keys, so its
  own pruning would drop them, and until then it was credited with data it had no reason to
  hold. When an identity departs, its close group repairs its keys, as it does after any
  other departure.
- **An anchor identity.** The first logical node owned the physical reachability driver and
  the only upgrade monitor, so it could never be retired. Machine-level duties belong to the
  daemon, not to one of its identities.
- **Rosters written from three places.** Startup, auto-scale preparation and runtime
  reconciliation each persisted the roster and allocated legacy ports with their own code.
  One roster type with one writer replaces them.

## Decision Drivers

- Connections, NAT/relay state and bootstrap work scale with machines, not identities.
- Every logical identity keeps its own key, peer ID, DHT position, routing view, storage
  responsibility, paid list, commitments, trust outcomes and rewards entitlement. Identities
  share machinery, never entitlement.
- Capacity is accounted once per filesystem, across every identity on it.
- Existing identity directories are adopted in place: no key rewrite, no data migration.
  Rolling back means starting standalone nodes on the same directories.
- Single-identity startup is unchanged and remains the default.
- Each stage ships on its own. A stage that changes the wire protocol interoperates with
  peers that do not have it.
- One identity's load cannot starve another's.

## Considered Options

1. **Keep one process per identity.** No change, and all four costs remain.
2. **Supervise unchanged nodes in one process.** Fixes lifecycle, upgrades and capacity, but
   every identity keeps its own endpoint, so connections still scale with identities.
3. **Make identities aliases of one DHT participant.** Shares everything, but aliases have
   no independent DHT position or responsibility, so they are not node identities in the
   current protocol.
4. **A daemon that owns the machine's services and hosts logical identities over a
   destination-addressed transport.** One process owns the endpoint, capacity, upgrades and
   lifecycle. Each identity is a full protocol participant inside it. Signed messages name
   both the sending and the receiving identity.

## Decision

We adopt option 4. Option 2 is its first stage, not a rival: the daemon runtime ships before
the shared transport and is useful on its own.

### What the daemon owns, and what an identity keeps

| Daemon (one per machine) | Logical identity (many per daemon) |
|---|---|
| Process lifecycle, signal handling, shutdown | ML-DSA key and peer ID |
| Daemon transport identity (`daemon_identity.key`) | DHT position and routing view |
| Shared QUIC endpoint, connection pool and NAT/relay driver (stage 3) | Chunk store, pointer store and paid list under its own root (ADR-0014 layout unchanged) |
| Upgrade monitor and the single upgrade exit | Commitments, audits and trust outcomes |
| One capacity budget per filesystem | Quotes, payment admission and rewards address |
| Identity roster and placement on storage roots | WebRTC Direct listener and certificate (see *Out of scope*) |
| Cache of identity-independent chain facts | Verified-payment and closeness caches |
| Scheduling of work by remote machine (stage 4) | |

An identity is a set of services that the daemon constructs, not a separately supervised
`RunningNode`. Its tasks run under a cancellation token derived from the daemon's.

### Storage: per-identity stores, machine-wide capacity

Each identity keeps its own `ChunkStore`, `PointerStore` and `PaidList` in its own root,
exactly as a standalone node does. Nothing about what an identity holds is recorded outside
that root, so an identity directory remains a complete standalone node.

The daemon adds three things:

- **One capacity budget per filesystem.** Every store on a filesystem charges its writes to
  one shared guard. That guard measures the partition and applies the disk reserve once for
  all of them.
- **Placement.** Operators list storage roots, one per drive. Each identity lives on exactly
  one root, and the daemon places new identities on the root with the most usable capacity.
  Rebalancing chunks across drives is out of scope; moving an identity to another drive
  means moving its directory.
- **Local fetch.** Before fetching a key over the network, an identity checks whether a
  co-hosted identity holds it, and if so copies the record into its own store. Local fetch
  changes only where the bytes come from. The identity has already decided to fetch through
  its normal admission, and the copy is verified and admitted exactly as a network fetch
  would be. For a chunk that means checking its content address. For a pointer it means the
  merge rule and the payment check against its `state_id` (ADR-0016). This is an
  optimisation; correctness never depends on it. Hard-linking chunk files instead of copying
  them is a possible later refinement. It needs its own review against the store's repair
  paths, because off Unix a repair truncates and rewrites the existing file, and a sibling
  reading through a shared link could see that truncation.

Identity-independent payment-chain facts, such as settled merkle pool information keyed by
pool hash, are cached once per daemon. Every result that depends on identity stays per
identity, because sharing it would let one identity's payment or closeness check authorise
another. That covers the verified-address cache, closeness passes, price floor, rewards and
paid-list membership.

### Destination-addressed transport

The daemon has a persistent **daemon transport identity**, separate from every logical
identity, that authenticates its shared QUIC/TLS endpoint. The daemon transport identity is
never a DHT participant:

- It never presents a `node/` user agent, so `is_dht_participant` cannot admit it.
- On a new shared connection, the transport's automatic announce carries the bindings of the
  hosted identities instead of announcing the daemon key as a peer.

Daemons exchange traffic in a **multiplexed envelope**. This is a new format with its own
magic prefix, not an extra field on the positional postcard `WireMessage`, so a peer that
does not understand it fails deterministically instead of mis-decoding it. The envelope
carries `from` and `to` logical peer IDs, and the sender's ML-DSA signature covers both;
`WireMessage` already carries a per-message signature, so this adds no signing work. The
receiver, whether a daemon or a standalone node:

- accepts a multiplexed message only if its `from` is either the connection's
  TLS-authenticated identity (a standalone peer) or an identity holding a verified binding to
  the daemon that TLS authenticated on that connection (a hosted identity). The same rule
  decides which identities a connection is registered as carrying. A valid signature alone
  is not enough, because a signed message can be replayed onto another connection;
- delivers an inbound message only to the registered local identity named by `to`, and drops
  a message whose `to` is unknown, never broadcasting it or guessing the destination from the
  payload;
- keys request/response correlation by local identity, remote identity and request ID, so a
  co-hosted identity cannot consume or evict another's response slot;
- rejects a legacy envelope, which has no destination, arriving on the shared endpoint.

**Hosted-identity binding.** A daemon announces each identity it hosts with a binding. A
binding names the identity and the daemon's transport peer ID, carries an epoch and an
expiry, and is signed by both the identity and the daemon.

- The identity's signature stops a daemon from claiming identities it does not host.
- The daemon's signature stops an identity from claiming a daemon it is not on.
- A binding counts only when it carries both signatures.
- A binding is used for routing only when the daemon presents it on a connection that TLS
  authenticated as that daemon.

A peer sends a logical identity's traffic over a physical connection only after verifying a
live binding for it there, and accepts traffic from it there only under the receive rule
above. When two bindings for one identity conflict, the higher epoch wins.

The expiry keeps a move to another daemon from leaving a permanent stale association. It is
coarse (hours, not seconds) and checked with a generous clock tolerance. `saorsa-core`
deliberately removed its wire-level message-age check, and the network should not start
depending on tight clocks again. A verified binding is never downgraded by a later unsigned
or destinationless message.

**Connection limits.** One physical connection now carries a whole roster's traffic,
including chunk transfers, through one flow-control window and one concurrent-stream limit.
The shared endpoint's windows and stream limits are sized for the roster rather than
inherited from single-node defaults. Requests from different identities on one connection
are served fairly.

**Compatibility.** Until legacy endpoints are removed, each hosted identity also keeps its
own legacy endpoint on its own port, pinned to that identity. That is the same endpoint a
standalone node exposes today. Its signed identity announcement carries a capability naming
the daemon transport peer ID and the shared endpoint's addresses. An upgraded peer:

1. verifies the capability;
2. connects to the shared endpoint;
3. confirms that the identity is hosted there;
4. only then moves its traffic over;
5. closes its connection to the legacy endpoint, so the connection count actually drops.

If any of these steps fails, the peer stays on the legacy endpoint and backs off before
trying again. A peer that has not advertised the capability is never sent a multiplexed
envelope. Once a peer holds a shared connection to a daemon, it reaches every other identity
whose binding the daemon presents there directly over that connection, without first
contacting that identity's legacy endpoint.

Eventually a logical identity's routing record will resolve to the daemon endpoint plus its
binding. Until then, routing records advertise the legacy endpoint, and peers discover the
shared endpoint through the capability.

**Failure domains.** Co-hosted identities share a failure domain. Where independence matters
(close-group diversity, quorum, replica counting), a peer that has verified a binding,
carrying both signatures, counts identities by daemon as well as by IP. Because a binding
needs the daemon's signature, no one can inflate another operator's per-daemon count by
claiming to be hosted on their daemon. The per-IP limit already caps co-hosted identities on
one address, so counting by daemon only tightens anything for a daemon that spans several
addresses. It costs a disclosing operator nothing compared with running separate processes.

**Traffic between co-hosted identities.** Identities on one daemon do end up in each other's
routing tables, since the per-IP limit admits two per bucket. In stage 1 each has its own
endpoint, and they reach each other as separate nodes do today. Once they share an endpoint,
a message between them would mean the daemon connecting to itself, so the daemon delivers it
in process instead. In-process delivery uses the same envelope, signature check, destination
dispatch and request/response correlation as network traffic, so no handler can tell the
difference and no check is skipped.

### Scheduling by remote machine

Once connections are physical, the daemon groups and rate-limits neighbour-sync,
audit-challenge and fetch work per remote physical connection, across all of its local
identities, so twenty local identities do not independently burst one remote daemon. Grouping
never merges identity-specific signatures, timeouts, evidence or penalties. A failed
sub-request is attributed to the identity that sent it and charged against the identity that
failed it.

### Capacity-driven identity count (opt-in)

An opt-in controller sets the number of active identities on each storage root:

```text
capacity      = free space + bytes held by the root's identities − reserve
per_identity  = max(configured budget, observed average holding × headroom)
target        = clamp(floor(capacity / per_identity), min, max)
```

"Bytes held by the root's identities" includes retired identities whose data has not yet
been deleted, so the controller never retires another identity because of space that is
about to be freed.

Counting held bytes back in means ordinary filling does not change the target, because every
byte an identity writes leaves free space and joins its holding. The target moves only when
the root itself gains or loses room, or when identities' holdings grow. The observed holding
matters because an identity does not choose how much it is responsible for. As the network's
data grows, each identity's share grows, and a fixed budget would let the root fill without
the controller noticing.

- **Scale-up** is immediate. It first reactivates a retired identity on that root whose data
  is still on disk, so the identity resumes at its old DHT position and keeps whatever is
  still valid; normal pruning removes the rest. Otherwise it generates a new identity,
  persisting the key and its roster entry before the identity starts.
- **Scale-down** waits until the lower target has held for a grace period, then retires one
  identity at a time by stopping it. Its close group repairs its keys as after any departure.
- **Reclaiming space.** A retired identity's chunk and pointer data is deleted once a
  retention period has passed that comfortably exceeds the close group's repair time. The
  key, roster entry and paid list are kept, so the identity can be reactivated later.

Identity count is an allocation of capacity. It is not a claim of independent durability.

### Roster

The daemon reads its roster from its own root. Each entry records an identity's peer ID,
root directory, state, legacy port and an optional rewards-address override. The state is
either `active`, or `retired` together with the retirement time and whether the identity's
data has been deleted. One type owns the roster, and one writer updates it atomically (write a temporary
file, then rename it).

Startup checks that every directory resolves and contains `node_identity.key`, and that no
directory or peer ID appears twice. It refuses ambiguous or unreadable configuration rather
than generating replacement keys. Each identity's legacy port stays the same across restarts
and roster reorderings, and never collides with another identity's port or the shared port.

Existing node directories are adopted in place. A configuration without a roster runs
today's standalone node unchanged.

### Out of scope

Each of these needs its own ADR:

- Browser multiplexing. Browser sessions authenticate a specific node identity (ADR-0015),
  so sharing one WebRTC Direct listener requires the browser handshake to name its target
  identity. Until then each identity keeps its own listener.
- Batching several logical requests into one wire message.
- A local client API that lets lightweight clients use the daemon's network services. Such an
  API must never expose identity keys or privileged node operations.
- Rebalancing chunks across drives, and byte-level deduplication beyond local fetch.

## Consequences

### Positive

- Once both ends run the daemon and peers have upgraded, physical connections approach one
  per pair of machines.
- Capacity is correct in aggregate on shared disks.
- A machine runs one process, one service unit and one upgrade monitor. Adding a drive or an
  identity is a configuration or roster change.
- An identity directory remains a complete standalone node, so rollback, moving an identity
  and debugging all use existing tools.
- There is no machine-wide record of holdings, so each identity keeps ADR-0014's
  single-authority property.

### Negative / Trade-offs

- **One crash takes every identity down.** Release builds set `panic = "abort"`, so no task
  isolation can contain a panic. Today a panic costs one identity. This is the largest new
  risk. Panics are already forbidden in production code, and the daemon makes that rule
  load-bearing. It also makes restart behaviour and health reporting essential.
- **Every upgrade restarts the whole roster at once.** Staged rollout today staggers each
  identity by its own node ID. With one daemon, a machine's identities leave and return
  together on every upgrade. The restart also takes longer, because every store is reopened
  and its key set rebuilt (ADR-0014). The per-IP limit keeps such a departure to a couple of
  members of any close group, but it is still a correlated departure.
- **One connection carries the roster.** Shared flow control and stream limits can hold one
  identity's transfers behind another's unless the shared endpoint's limits are sized for
  the roster.
- The shared endpoint needs coordinated `saorsa-core` support. Until most peers have it,
  legacy endpoints keep the per-identity port, NAT mapping and connection cost.
- Shared queues, connection limits and request registries need explicit per-identity
  fairness.
- Legacy peers learn nothing about co-hosting beyond what the per-IP limit already tells
  them.
- WebRTC Direct still costs one listener and one port per identity.

### Neutral / Operational

- Metrics and logs carry both the daemon and the logical peer ID. Dashboards must distinguish
  physical connections from logical peers.
- Several `ant-node` traffic counters are process-wide statics today (`storage/traffic.rs`,
  `replication/protocol.rs`, `payment/traffic.rs`, `upgrade/traffic.rs`). In a daemon they
  would silently sum every identity, so they move to per-identity state before any
  per-identity metric is relied on.
- Legacy ports need a reserved range inside 10000–10999, sized for the largest roster, and
  each port needs its own reachability mapping.
- Rewards go to the daemon's configured address unless the roster overrides it per identity.
- Staged-rollout upgrade timing is seeded from the daemon identity instead of a node
  identity, with the correlated restart described above.

## Migration and Rollout

1. **Daemon runtime (`ant-node` only, no wire change).** The roster, one-process lifecycle,
   signal handling, a single upgrade monitor and exit, the per-filesystem capacity guard,
   the shared chain-fact cache, local fetch and per-identity traffic counters. Each identity
   keeps its own endpoint. `ant-devnet` already runs several `P2PNode`s in one process, so
   this step needs no transport change. Ships opt-in.
2. **The peer side of the multiplexed protocol (`saorsa-core`).** Every node gains
   everything it needs to talk to a daemon:
   - parsing, verifying and dispatching multiplexed envelopes;
   - verifying bindings and capabilities, and applying the receive rule;
   - dialling a shared endpoint and sending envelopes;
   - moving traffic over, closing the legacy connection, and falling back with backoff.

   All of it stays inactive until a daemon advertises a shared endpoint, which no node does
   yet. This ships in regular releases, so that when step 3 starts, peers already have it
   and no further network-wide release is needed.
3. **Shared endpoint.** Daemons bind the shared endpoint, present bindings on it, deliver
   traffic between their own identities in process, and advertise the capability on each
   legacy endpoint. Upgraded peers move over. Mixed-version testnets cover
   old-to-new, new-to-old and new-to-new traffic, and verify that logical pairs between two
   daemons converge on one physical connection. `ant-client`, the node launcher and the
   dashboards gain the capability and the logical/physical connection counts in this step.
4. **Scheduling by remote machine.**
5. **Capacity-driven identity count**, once per-filesystem accounting and retirement have
   passed soak and failure testing.
6. **Legacy endpoint removal.** This is a declared protocol cutover. It is gated on measured
   adoption and bootstrap reachability (the share of peers and traffic still on legacy
   endpoints), not on a number of elapsed releases. Legacy endpoints first become off by
   default with a time-bounded opt-in, and are then removed.

## Validation

- **Roster:** a duplicate directory, a duplicate peer ID, a missing key and an unreadable key
  each refuse startup. Peer IDs and legacy ports survive restarts and reorderings.
- **Capacity:** under a concurrent write burst, N identities on one filesystem cannot
  together admit more than the partition's free space minus one reserve.
- **Isolation:** saturating one identity's inbound queue still leaves another identity's
  requests served within bounds.
- **Envelope:** each of these is rejected:
  - an unknown `to`;
  - an unsigned or mis-signed `to`;
  - a destinationless envelope on the shared endpoint;
  - a co-hosted identity answering another identity's request;
  - a validly signed message whose `from` is neither the connection's TLS identity nor bound
    to its daemon, such as a message replayed onto another connection.
- **Binding:** stale, expired, replayed and unsigned bindings and capabilities are rejected,
  as are a binding missing either signature and a binding naming a daemon other than the one
  TLS authenticated. A verified binding is never downgraded, and a moderate clock skew does
  not invalidate a live binding.
- **Daemon key:** a peer connected to a shared endpoint never adds the daemon transport
  identity to its routing table.
- **Connection sharing:** two daemons with at least two identities each use one physical
  connection between them, and once peers have moved over, no legacy connection between the
  daemons remains. Through each legacy endpoint of the same daemons, a legacy node can
  bootstrap, send requests, answer them and receive unsolicited traffic.
- **Co-hosted traffic:** with the shared endpoint enabled, two identities on one daemon
  exchange requests and responses in process under the same checks as network traffic, and
  the daemon never dials itself.
- **Shared limits:** with every identity on one connection transferring chunks, one
  identity's transfers do not starve another's.
- **Scheduling:** grouped audits and syncs keep the correct signer, response, timeout and
  penalty for each identity.
- **Capacity controller:** filling a root whose capacity is steady leaves the target
  unchanged, and growing average holdings lower it. No sequence of samples makes the
  controller retire identities in a loop.
- **Retirement:** retiring an identity deletes nothing before the retention period, and its
  close group re-replicates its keys as after any departure. After the retention period its
  space is freed. Scale-up reactivates a retired identity at its old peer ID before
  generating a new one.
- **Local fetch:** a pointer copied from a co-hosted identity that loses the merge rule or
  fails its payment check is not admitted.
- **Metrics:** in a daemon, per-identity counters sum to the daemon's total, and no counter
  is shared between identities.
- **Rollback:** after the daemon stops, standalone nodes start on the same directories
  without any conversion.
- **Soak:** memory, CPU, file descriptors, physical connections and bootstrap traffic are
  compared with the same identities run as separate processes.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**.
Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted
ADR.
