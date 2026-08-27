# ADR-0011: Run multiple node identities behind one node daemon

- **Status:** Proposed
- **Date:** 2026-08-25
- **Last updated:** 2026-08-27
- **Decision owners:** Autonomi node maintainers
- **Reviewers:** TBD
- **Supersedes:** none
- **Superseded by:** none
- **Related:** `src/node.rs`, `src/config.rs`, `saorsa-core::P2PNode`

## Context

An Autonomi storage machine currently runs one operating-system process per node identity. Each
process owns its own QUIC endpoints, connection pool, NAT/relay state, bootstrap work and cache,
routing state, logging and lifecycle. Operators scale a machine by starting more copies of the node
binary with different data directories and ports.

That model gives strong process isolation, but it duplicates both machine-level infrastructure and
node business logic. In particular, co-hosted identities establish independent connections to the
same remote machine and repeat bootstrap, reachability, routing-table maintenance, peer liveness and
trust observations, neighbour sync, audits, chunk-catalogue scans, replication planning, payment
lookups and paid-list maintenance. Separate chunk stores also duplicate overlapping content and make
machine-wide capacity, multi-drive placement and fair resource allocation difficult to enforce.

The intended destination is one full node daemon per machine, not a networking sidecar in front of
otherwise independent nodes. The daemon hosts multiple cryptographic node identities and owns the
network, storage, routing-maintenance, replication, audit and payment services used by them. A
logical identity remains an independent protocol participant, but becomes a daemon-managed identity
context rather than an independent node runtime. The daemon adds or drains identities in response
to usable storage capacity. Shared networking is a stage-one requirement; automatic
capacity-based scaling is not.

Identity and transport identity are currently coupled in `saorsa-core`: a `P2PNode` creates and owns
a transport endpoint whose TLS and application messages use the same `NodeIdentity`. The existing
application wire envelope identifies the sender but not the intended local identity. Consequently,
putting several independent `P2PNode` values in one process would still create several connection
pools, while merely sharing an event stream would deliver messages to the wrong logical node.

This is a protocol and failure-domain change, not just process supervision. Peers must be able to
discover that several logical identities are hosted by one physical daemon, reuse one authenticated
connection to it, and address a message to a specific hosted identity.

## Decision Drivers

- Stage one must reuse listeners, QUIC sessions, NAT/relay state and connection pools across local
  node identities.
- The long-term design must consolidate node business logic in the daemon rather than stopping at a
  transport proxy.
- A logical identity must retain its own key, peer ID, DHT position, routing-table projection,
  storage responsibility, trust decisions, paid entitlement and rewards accounting even when the
  daemon shares their physical state and work.
- Shared work must preserve identity-specific signatures, authorization, responsibility and audit
  evidence; a machine-wide cache hit must never silently turn one identity's payment or trust result
  into another identity's entitlement.
- The default one-identity configuration must remain supported during rollout.
- Existing identity directories and keys must be adopted without changing their peer IDs.
- A remote daemon must never count several co-hosted identities as independent machine-level
  replicas or independent failure domains.
- Overload in one identity must not starve other identities sharing the daemon.
- Automatic identity creation and retirement must be separable from the shared-networking change.
- Client and operator tooling must participate in capability negotiation and expose the daemon
  model without gaining access to privileged node operations or identity keys.

## Considered Options

1. **Keep one process and transport per identity.** This preserves isolation but does not share
   connections, bootstrap or machine-wide resource control.
2. **Supervise several unchanged nodes inside one process.** This reduces process-management
   overhead but still creates one endpoint and connection pool per identity, so it misses the main
   goal.
3. **Make identities aliases of one DHT participant.** This shares everything, but the aliases no
   longer have independent DHT positions or storage/reward responsibility and therefore are not
   node identities in the current protocol.
4. **Run a full node daemon with logical identity contexts.** The daemon owns connections,
   reachability and the shared node services. Signed application messages carry both logical sender
   and logical destination. Per-identity DHT positions and protocol state are projections or
   namespaces inside those daemon services.

## Decision

We will adopt option 4 in stages. The staging order limits migration risk; it does not redefine the
destination as a networking-only daemon.

### Daemon ownership boundary

The daemon is the unit of process lifecycle, network reachability, resource control and physical
storage. It constructs and owns every node service. Logical identities supply identity-specific
keys, DHT positions, routing projections, responsibility sets, signatures, rewards addresses and
accounting namespaces to those services. They are not separately supervised copies of the complete
node stack.

The target daemon contains the following shared services:

- A physical networking service with one listener set, QUIC endpoint, NAT/relay state machine,
  connection pool, bootstrap discovery cache and peer-machine registry.
- A parent peer-observation and routing-maintenance service. Each identity still has its own routing
  table or routing projection for its DHT position, while address observations, daemon bindings,
  liveness probes and reusable trust evidence are collected once and fanned out under explicit
  per-identity trust rules.
- A content-addressed physical chunk store with durable per-identity ownership/responsibility
  leases. The store owns placement across one or more configured drives, sharding, rebalancing and
  repair of physical blobs. Identity catalogues refer to blobs rather than storing duplicate bytes.
- A daemon-wide replication planner. It scans the physical chunk catalogue once, computes
  responsibility across all local identities in one pass, groups work by remote physical daemon,
  deduplicates downloads, satisfies a newly-added local identity from an existing local blob, and
  coordinates fetch, prune and repair so one identity cannot delete data another identity needs.
- A neighbour-sync and audit scheduler that groups compatible requests going to the same remote
  daemon. Logical subrequests, signatures, timeouts, evidence and penalties remain attributable to
  the correct identities even when their transport work is batched.
- Shared payment-verification and chain-query caches for identity-independent facts, plus a shared
  paid-chunk catalogue whose records retain the identity/rewards entitlement that authorized them.
  Identity-dependent closeness, price, rewards and paid-list decisions are never represented by an
  unscoped global boolean.

These services expose reusable internal APIs so future client software can reuse the non-node-
specific protocol logic or call a local daemon API and remain lightweight. A client does not gain
access to node identity keys, storage leases or privileged node operations. Client-facing API
details may be specified separately, but this daemon boundary must support a lightweight client.

### Identity and networking model

The daemon owns one persistent **daemon transport identity**, one set of listeners, one QUIC/TLS
endpoint per supported IP family, one NAT/relay state machine and one connection pool. It also owns a
registry of **logical node identities**. Each logical identity has its own persistent ML-DSA key and
peer ID and continues to be an independent DHT participant.

The shared transport multiplexes application traffic by logical identity. A multiplexed wire
envelope contains an authenticated `from` peer ID and an explicit `to` peer ID; both fields are
covered by the sender's signature. Incoming traffic is dispatched only to the registered local
identity named by `to`. Request/response correlation is scoped to the destination identity so one
identity cannot consume another identity's response. Connection, byte and queue limits are enforced
at daemon level with per-identity fairness and observability.

During the compatibility window the daemon is dual-stack. In addition to its multiplexed endpoint,
it exposes one legacy-protocol endpoint and port per logical identity. A legacy connection is pinned
to the identity whose endpoint was dialled, making destinationless legacy envelopes unambiguous.
The identity's signed legacy identity announcement advertises support for multiplexing, the daemon
transport identity and the shared endpoint addresses. An upgraded peer verifies that announcement,
connects to the shared endpoint, verifies that the intended logical identity is hosted there, and
uses destination-addressed envelopes for subsequent traffic. A peer that does not advertise this
capability remains on its identity-pinned legacy connection. Capability absence must never be
guessed from malformed data, and an authenticated capability learned during a session must not be
downgraded by a later unsigned or destinationless message.

After a physical connection is authenticated, daemons exchange the logical identities hosted on
that connection. Routing records for a logical identity must ultimately include, or resolve to, the
physical daemon endpoint and a signed binding between the logical identity and daemon identity. The
binding needs an expiry/epoch so moving an identity to another daemon cannot leave a permanent stale
association. A remote daemon may then map many logical peer IDs to one connection while retaining
logical peer IDs in routing and protocol APIs.

Co-hosted identities share a failure domain. Diversity, quorum and replication selection must
deduplicate by daemon identity (and continue applying network-location diversity) when independence
matters. Co-hosted identities must not be counted as independent votes or replicas merely because
their peer IDs differ.

### Stage one: daemon-owned fixed roster and shared connections

Stage one introduces the daemon runtime, shared transport and a fixed, operator-configured identity
roster. Startup loads the roster, validates that every identity directory and peer ID is unique,
starts the shared networking layer once, and constructs daemon-owned identity contexts for DHT,
storage responsibility, verification, replication and payment handling. The daemon owns OS signal
handling, upgrade/restart coordination and shutdown for the full roster. It refuses partial or
ambiguous identity configuration rather than silently generating replacements for unreadable keys.

The existing single-identity configuration remains the default and uses the existing wire protocol.
Multi-identity daemons use the dual-stack policy above during rollout: upgraded peers share the
daemon connection, while old clients and nodes use a dedicated legacy port for each identity.
Silently sending multiplexed envelopes to legacy software is not safe. Legacy endpoints must never
broadcast a destinationless request to all local identities or guess its destination from payload
contents. Each legacy listener needs its own reachability/NAT mapping and externally advertised
address; stable deployments should reserve a predictable port range large enough for the maximum
identity roster.

To reduce migration risk, stage one may reuse existing per-identity storage and replication
components behind the daemon-owned identity-context boundary. Later stages move their shared work
into daemon services. At every stage, each identity performs the DHT participation needed for its
own position and retains identity-specific trust, responsibility, rewards and evidence.

### Stage two: shared maintenance, request planning and batching

The shared transport is the parent physical-peer observation view: listeners, authenticated
channels, logical identities per channel, relay/address observations and connection liveness are
machine-wide, while per-identity DHT and trust projections remain separate. Node replication uses
the physical channel key to group and rate-coordinate neighbour-sync, audit and fetch work across
all local identities. Compatible logical subrequests are batched when the remote daemon advertises
support for it. A batch preserves independently signed subrequests, destinations, responses,
timeouts, evidence and penalties; it must never collapse identity-specific authorization or
attribution. When batching is not negotiated, the daemon still groups and rate-coordinates separate
requests by physical peer.

Payment-chain lookup results are cached once per daemon only where their keys contain every input
that affects the result. Paid-list state uses one physical LMDB catalogue with a peer-ID namespace,
so the same address never turns one identity's payment into another identity's entitlement.
Identity-specific rewards, closeness and price-floor outcomes are not globally cached.

### Stage three: shared chunk storage and replication planning

The daemon uses a content-addressed machine store plus durable `(peer ID, chunk address)` leases.
Lease metadata lives in one daemon-owned embedded SQLite catalogue, separate from chunk bytes. The
catalogue indexes both identity-to-chunk and chunk-to-identity queries, applies lease handoffs in
bounded transactions, and durably records last-owner garbage collection that remains unfinished
after a crash. It uses full commit durability and a bounded write-ahead log; no external database
service is required.
Blob creation precedes lease creation and final lease removal precedes blob deletion: a crash can
leave a reclaimable orphan but cannot leave an acknowledged obligation with no blob. A daemon-wide
mutation lock coordinates store, handoff, prune, drain and rebalance operations. The maintenance
pass scans the physical catalogue once and evaluates every active local identity; existing blobs are
adopted by lease without download. Concurrent network fetches for one address collapse behind one
single-flight lock, and work is grouped by authenticated remote physical channel.

Physical placement belongs to this store. Operators configure one or more storage roots/drives once;
the daemon chooses shard placement, rebalances data and accounts capacity across them without
requiring per-identity drive configuration.

### Stage four: capacity-driven identity scaling

The opt-in controller adds and drains identities according to free capacity across distinct
configured filesystems. Its policy defines per-filesystem reserve, GiB per identity, minimum and
maximum counts, sampling interval and scale-down grace. Adding an identity persists its key and
manifest entry before its node context starts. Scale-down preserves the anchor identity, waits for a
stable lower target, transfers every source lease to a live identity before cancellation, marks the
identity retired, and never deletes its key or directory.

Scaling policy uses machine-wide usable capacity rather than raw filesystem free bytes and must
account for storage already committed by every hosted identity. Identity count is a resource
allocation choice, not a claim that one machine provides additional independent durability.

## Consequences

### Positive

- Connections to a remote machine, QUIC handshakes, listeners, NAT traversal and relay allocations
  are shared across local identities.
- Bootstrap discoveries and machine-level resource limits are shared and coordinated.
- Routing maintenance, liveness work, neighbour sync, audits and replication are deduplicated,
  grouped or batched where identity semantics permit it.
- Overlapping chunks consume one physical blob, and existing local data can satisfy a new identity
  without a network download.
- One daemon can place and rebalance chunks across several drives for every hosted identity.
- Identity-independent payment and chain-query results can be reused without collapsing
  identity-specific entitlements.
- Operators manage one daemon and one upgrade lifecycle per machine.
- The daemon can scale identity count without redesigning networking again.
- Logical keys, DHT positions and existing identity data can be preserved through migration.

### Negative / Trade-offs

- The multiplexed envelope and logical-to-daemon binding require coordinated protocol support in
  nodes and clients. During the transition, legacy peers retain interoperability through the
  per-identity endpoints but do not benefit from connection sharing.
- The compatibility window requires one listener port, NAT/relay mapping and potentially one remote
  connection per identity for legacy peers. It deliberately reintroduces that networking overhead
  only on legacy paths.
- Legacy peers cannot recognize that identities on different compatibility ports share one machine.
  They may count them as independent failure domains; protocols requiring machine-level diversity
  cannot be fully corrected until those peers upgrade.
- One process or transport failure now interrupts every identity on the machine. The daemon needs
  strong task isolation, health reporting and restart behavior; the release profile's
  `panic = "abort"` makes this failure-domain expansion especially important.
- Connection limits, inbound queues, rate limits and request registries become shared resources and
  require explicit per-identity fairness to prevent noisy-neighbour starvation.
- Routing, replication and quorum logic must understand daemon failure domains or the network may
  overestimate durability and independence.
- Moving an identity between daemons introduces binding freshness, replay and split-brain risks.
- DHT membership and identity-specific trust still require per-identity projections. Physical
  liveness and request scheduling are shared, but the daemon must not globally reuse an application
  trust verdict whose meaning may differ by local identity.
- A parent routing view can share observations, but DHT membership and some trust outcomes remain
  identity-specific and still require per-identity projections.
- Shared storage adds a critical ownership/reference database. Corruption in that database can
  affect every local identity, and garbage collection becomes a machine-wide safety boundary.
- Request batching and shared scheduling create fairness and attribution risks: one busy identity
  must not delay another, and a failed logical subrequest must not penalize the wrong identity.

### Neutral / Operational

- Existing node identity directories are placed under a daemon manifest/roster; their keys are not
  rewritten.
- Metrics and logs gain both daemon and logical peer identifiers. Alerts and dashboards must
  distinguish physical connection count from logical peer count.
- Rewards addresses and paid entitlements remain explicit per identity. Physical storage limits and
  drive placement are daemon-wide.
- Migration copies and verifies old chunk and paid-list state, writes a per-identity completion
  marker, and retains the source databases. Rolling back means stopping the daemon and starting the
  same preserved identity directories; writes accepted only after cutover need an explicit export
  before those legacy processes can become authoritative again.

## Migration and Rollout

1. Add destination-addressed, signed multiplexing, hosted-identity registration and signed
   capability negotiation in `saorsa-core`. Add an identity-pinned legacy endpoint for every hosted
   identity and reject ambiguous legacy traffic arriving on the shared endpoint.
2. Add an opt-in, daemon-owned fixed roster to `ant-node`. Keep single-identity startup and on-disk
   layout as the default. Multi-identity daemon records advertise legacy per-identity endpoints to
   all peers; upgraded peers discover and switch to the shared endpoint through the signed
   capability exchange.
3. Run mixed-version testnets covering old-to-new, new-to-old and new-to-new communication. Verify
   that old peers see ordinary independent node endpoints, upgraded logical pairs converge onto one
   physical daemon connection, and neither response correlation nor destination routing crosses
   identities.
4. Update `ant-client`, `ant-gui`, the node manager/launcher and operational dashboards for the new
   capability, separate logical/physical connection counts and legacy-port range requirements.
5. Canary the dual-stack release on the public network. Track the percentage of peers and traffic
   using legacy endpoints, failed upgrades to the shared endpoint, old bootstrap infrastructure and
   the number of operators without sufficient port/NAT configuration.
6. Once bootstrap nodes and the required network majority support multiplexing, release a transition
   version that disables legacy endpoints by default while retaining an explicit, time-bounded
   operator opt-in. Re-enabling compatibility must not change identity keys or shared stored state.
7. Remove the legacy listeners, negotiation downgrade path and operator opt-in in a later protocol
   release. This is a declared compatibility cutover: nodes below the minimum supported protocol
   version will no longer communicate with the upgraded network. The removal gate is based on
   measured adoption and bootstrap reachability, not merely on one release interval having elapsed.
8. Canary the parent physical observation view and daemon-wide neighbour-sync, audit and replication
   scheduling. Introduce capability-negotiated multi-subrequest wire batching under a separate wire-
   protocol ADR before changing request formats or trust semantics.
9. Canary the shared content-addressed store and paid catalogue using reversible copy-and-verify
   migration. Do not remove old per-identity stores until operational reconciliation proves every
   obligation is represented.
10. Enable capacity-driven scaling only after shared capacity accounting, local lease handoff and
   identity draining pass soak and failure testing.

## Validation

- Unit tests reject duplicate identities, duplicate directories, unknown destinations, unsigned or
  incorrectly signed destination fields, and cross-identity response correlation.
- An integration test runs two daemons with at least two logical identities each and demonstrates
  that all logical pairs use one physical QUIC connection between the machines.
- Mixed-version tests prove a legacy node can bootstrap, request, respond and receive unsolicited
  traffic through each identity-pinned endpoint, while the same daemon uses one shared connection
  with an upgraded peer. Malformed, unsigned and stale capability advertisements are rejected.
- Failure tests saturate one identity's work queue and show bounded service for another identity.
- Parent-routing tests prove liveness work is deduplicated while identity-specific routing and trust
  outcomes remain isolated.
- Batch tests prove neighbour-sync/audit subrequests retain the correct logical signer, response,
  timeout and penalty attribution.
- Shared-store tests prove duplicate writes occupy one blob, multiple identity leases survive
  restart, concurrent fetches collapse, and pruning one lease cannot delete another identity's data.
- Multi-drive tests cover deterministic placement, full/offline volumes, rebalance and recovery.
- Replication-planner tests scan one catalogue snapshot, compute all local responsibility sets, group
  by remote daemon, reuse local blobs and prevent fetch/prune races.
- Payment tests distinguish shareable chain facts from per-identity paid entitlements and rewards.
- Restart tests preserve every peer ID and per-identity storage directory.
- Migration tests adopt existing identity directories and can roll back to individual-node startup
  without key or record conversion.
- Soak tests compare memory, CPU, file descriptors, physical connection count and bootstrap traffic
  against the current multi-process deployment.

## Notes for AI-assisted work

AI tools may help implement and test this proposal, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted
ADR.
