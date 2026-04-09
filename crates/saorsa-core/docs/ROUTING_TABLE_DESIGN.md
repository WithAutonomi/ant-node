# Routing Table Logic Specification (Codebase-Agnostic)

> Status: Design-level specification for pre-implementation validation.

## 1. Purpose

This document specifies routing table behavior as a pure system design, independent of any language, framework, transport, or existing codebase.
It is designed for a Kademlia-style decentralized network with trust-weighted peer management, and assumes Kademlia nearest-peer routing semantics.

Primary goal: validate correctness, safety, and liveness of routing table logic before implementation.

The routing table is a **peer phonebook** — it tracks who is on the network and how to reach them. Higher-level concerns such as data storage responsibility, replication, close group semantics, and quorum math are the API consumer's responsibility (e.g., saorsa-node). The routing table exposes `find_closest_nodes_local(K, count)` and `find_closest_nodes_network(K, count)` as generic primitives; the consumer passes whatever `count` it needs.

## 2. Scope

### In scope

- Kademlia routing table structure, peer admission, eviction, and maintenance.
- Trust-aware peer management and Sybil resistance via IP diversity.
- Iterative and local peer lookup algorithms.
- Close neighborhood maintenance for routing correctness.

### Out of scope

- Concrete wire formats and RPC APIs.
- Data storage, replication, close group semantics, and quorum logic (consumer-side).
- EMA scoring model internals (Section 4 defines the interface; tuning rationale is implementation guidance, not specification).
- Transport-layer connection management and NAT traversal.
- Disk layout, serialization details, and database choices.

## 3. System Model

- `Node`: participant with a persistent 256-bit identity (`PeerId`), one or more reachable network addresses, and a local routing table.
- `PeerId`: 256-bit cryptographic identity. Used directly as the DHT key for the node's position in the keyspace. No secondary hashing — `DhtKey ≡ PeerId`.
- `Address`: typed multiaddress (e.g., `/ip4/1.2.3.4/udp/9000/quic`). A node may have up to `MAX_ADDRESSES_PER_NODE` addresses (multi-homed, NAT traversal).
- `NodeInfo(N)`: record containing `PeerId`, address list, and `last_seen` timestamp for node `N`.
- `Distance(A, B)`: XOR of the 256-bit representations of `A` and `B`, compared as big-endian unsigned integers.
- `BucketIndex(A, B)`: index of the first bit position (0-indexed from MSB) where `A ⊕ B` differs. Equal IDs have no bucket index (self-insertion is forbidden).
- `KBucket(i)`: the `i`-th k-bucket (0 ≤ `i` < 256), holding up to `K_BUCKET_SIZE` `NodeInfo` entries for peers whose `BucketIndex` relative to the local node is `i`.
- `LocalRT(N)`: node `N`'s authenticated local routing-table peer set. Union of all k-bucket contents, excluding `N` itself.
- `TrustScore(N, P)`: node `N`'s current trust assessment of peer `P`, queried from the trust subsystem. Computed by EMA over the weighted history of all trust events — both internal (DHT-layer) and consumer-reported (application-layer) — with time decay toward neutral (0.5).

## 4. Tunable Parameters

All parameters are configurable. Values below are a reference profile used for logic validation.

| Parameter | Meaning | Reference |
|---|---|---|
| `K_BUCKET_SIZE` | Maximum number of peers per k-bucket | `20` |
| `MAX_ADDRESSES_PER_NODE` | Maximum addresses stored per node | `8` |
| `BUCKET_COUNT` | Number of k-buckets (one per bit in keyspace) | `256` |
| `ALPHA` | Parallel queries per iteration in network lookups | `3` |
| `MAX_LOOKUP_ITERATIONS` | Maximum iterations for iterative network lookups | `20` |
| `IP_EXACT_LIMIT` | Maximum nodes sharing an exact IP per enforcement scope | `2` |
| `IP_SUBNET_LIMIT` | Maximum nodes sharing a subnet per enforcement scope | `K_BUCKET_SIZE / 4` (at least `1`) |
| `IPV4_SUBNET_MASK` | Prefix length for IPv4 subnet grouping | `/24` |
| `IPV6_SUBNET_MASK` | Prefix length for IPv6 subnet grouping | `/48` |
| `TRUST_PROTECTION_THRESHOLD` | Trust score above which a peer resists swap-closer eviction | `0.7` |
| `BLOCK_THRESHOLD` | Trust score below which a peer is evicted and blocked | `0.15` |
| `EMA_ALPHA` | EMA smoothing factor — weight of each new observation (higher = faster response) | `0.3` |
| `DECAY_LAMBDA` | Per-second exponential decay rate toward neutral (0.5) | `4.198e-6` |
| `SELF_LOOKUP_INTERVAL` | Periodic self-lookup cadence (maintenance phase only; bootstrap self-lookups run back-to-back with no interval) | random in `[5 min, 10 min]` |
| `BUCKET_REFRESH_INTERVAL` | Periodic refresh cadence for stale k-buckets | `10 min` |
| `STALE_BUCKET_THRESHOLD` | Duration after which a bucket without activity is considered stale | `1 hour` |
| `LIVE_THRESHOLD` | Duration of no contact after which a peer is considered stale for revalidation and loses trust protection | `15 min` |
| `STALE_REVALIDATION_TIMEOUT` | Maximum time to wait for a stale peer's ping response during admission contention | `1s` |
| `AUTO_REBOOTSTRAP_THRESHOLD` | Routing table size below which automatic re-bootstrap is triggered | `ALPHA` (3) |
| `MAX_CONSUMER_WEIGHT` | Maximum weight multiplier per single consumer-reported event | `5.0` |
| `MAX_PEERS_PER_RESPONSE` | Maximum peers accepted from a single `FIND_NODE` response (prevents memory exhaustion from malicious responses) | `K_BUCKET_SIZE` |
| `LOOKUP_STAGNATION_LIMIT` | Consecutive non-improving iterations before a network lookup terminates | `3` |
| `REBOOTSTRAP_COOLDOWN` | Minimum time between consecutive auto re-bootstrap attempts | `5 min` |
| `MAX_CONCURRENT_REVALIDATIONS` | Maximum number of stale revalidation passes running simultaneously across all buckets | `8` |

#### EMA Scoring Model

The trust score for a peer is an exponential moving average (EMA) of success/failure observations that decays toward neutral (0.5) when idle.

**Update rule**: On each event, time decay is applied first, then the new observation is blended in:

```
score = neutral + (score - neutral) * e^(-DECAY_LAMBDA * elapsed_secs)    // decay
score = (1 - EMA_ALPHA) * score + EMA_ALPHA * observation                 // blend
```

Where `observation` is `1.0` for a positive event and `0.0` for a negative event. For a consumer event with weight `W`, the blend uses the continuous generalization:

```
score = (1 - EMA_ALPHA)^W * score + (1 - (1 - EMA_ALPHA)^W) * observation
```

This is equivalent to applying the unit-weight blend step `W` times when `W` is a positive integer, and extends naturally to fractional weights without ambiguity.

**Decay tuning**: `DECAY_LAMBDA = 4.198e-6` is tuned so that a peer experiencing ~3 evenly-spaced failures per day converges to the block threshold (0.15). The worst possible score (0.0) decays back above `BLOCK_THRESHOLD` in ~1 day. Derivation: at steady state with T = 28800 s between events, `0.15 = 0.5·(1 − d) / (1 − 0.7·d)` → `d = 0.8861` → `λ = −ln(0.8861) / 28800 ≈ 4.198e-6`.

**Failures to block** (consecutive negative events from neutral 0.5 to below `BLOCK_THRESHOLD` 0.15, ignoring decay):

| Event weight | Events to block | Effective failures |
|---|---|---|
| `1.0` (internal event) | 4 | 4 |
| `2.0` | 2 | 4 |
| `3.0` | 2 | 6 |
| `5.0` (`MAX_CONSUMER_WEIGHT`) | 1 | 5 |

Note: time decay between events works in the peer's favor — in practice, more events may be needed if failures are spread over time. Core only records penalties (no internal success events), so the only counterforce is time decay. Higher weights are slightly less efficient per unit weight due to EMA non-linearity: at lower scores, each successive failure has diminishing marginal impact. The "Effective failures" column shows total weight applied (events × weight), not a count of equivalent unit-weight events.

Parameter safety constraints (MUST hold):

1. `IP_EXACT_LIMIT >= 1`.
2. `IP_SUBNET_LIMIT >= 1`.
3. `TRUST_PROTECTION_THRESHOLD > BLOCK_THRESHOLD`.
4. `ALPHA >= 1`.
5. `LIVE_THRESHOLD > max(SELF_LOOKUP_INTERVAL)` (peers touched by self-lookup must not oscillate between live and stale between consecutive cycles; at reference values: 15 min > 10 min). The 5-minute margin at reference values is sufficient for typical network latencies (sub-second RTTs). Operators in high-latency environments (satellite, Tor overlay) SHOULD increase `LIVE_THRESHOLD` proportionally.
6. `STALE_REVALIDATION_TIMEOUT > 0`.
7. `MAX_CONSUMER_WEIGHT >= 1.0`.
8. `EMA_ALPHA` in (0.0, 1.0). Values near 0 make the score nearly unresponsive to events; values near 1 make it hypersensitive.
9. `DECAY_LAMBDA > 0`.
10. If constraints are violated at runtime reconfiguration, node MUST reject the config and keep the previous valid config.
11. `AUTO_REBOOTSTRAP_THRESHOLD >= 1`.
12. `REBOOTSTRAP_COOLDOWN > 0`.
13. `MAX_CONCURRENT_REVALIDATIONS >= 1`.

Note: `K_BUCKET_SIZE` values below 4 produce degenerate behavior (single-peer routing neighborhoods, constant swap-closer churn) and are not recommended for production use.

## 5. Core Invariants (Must Hold)

1. **Self-exclusion**: A node MUST NOT appear in its own routing table (`LocalRT(N)` never contains `N`).
2. **Bucket correctness**: A peer `P` exists in exactly one k-bucket of node `N`, at index `BucketIndex(N, P)`.
3. **Capacity bound**: Each k-bucket holds at most `K_BUCKET_SIZE` entries.
4. **Address requirement**: A `NodeInfo` with an empty address list MUST NOT be admitted to the routing table.
5. **Authenticated membership**: Only peers that have completed transport-level authentication are eligible for routing table insertion. Unauthenticated peers MUST NOT enter `LocalRT`.
6. **IP diversity**: No enforcement scope (per-bucket or routing-neighborhood) may exceed `IP_EXACT_LIMIT` nodes per exact IP or `IP_SUBNET_LIMIT` nodes per subnet, except via explicit loopback or testnet overrides.
7. **Trust blocking**: Peers with `TrustScore(self, P) < BLOCK_THRESHOLD` MUST be evicted from the routing table and MUST NOT be re-admitted until their trust score recovers above `BLOCK_THRESHOLD`.
8. **Trust protection (staleness-gated)**: A peer with `TrustScore(self, P) >= TRUST_PROTECTION_THRESHOLD` **AND** `last_seen` within `LIVE_THRESHOLD` MUST NOT be evicted by swap-closer admission. A peer whose `last_seen` exceeds `LIVE_THRESHOLD` receives no trust protection regardless of score — stale peers MUST NOT hold slots against live candidates.
9. **Deterministic distance**: `Distance(A, B)` is symmetric, deterministic, and consistent across all nodes. Two nodes compute the same distance between the same pair of keys.
10. **Atomic admission**: IP diversity checks, capacity checks, swap-closer evictions, trust score reads, and insertion MUST execute within a single write-locked critical section to prevent TOCTOU races. All `TrustScore` queries during admission (steps 4, 8) MUST occur while the routing table write lock is held.
11. **Monotonic liveness**: `touch_node` updates `last_seen` to the current time and moves the peer to the tail (most recently seen) of its k-bucket. This preserves Kademlia's eviction preference for long-lived peers.
12. **Lookup determinism**: Two nodes with identical `LocalRT` contents compute identical `find_closest_nodes_local(K, count)` results for any key `K` and count. Disagreements between nodes are caused only by routing table divergence, never by algorithm divergence.

## 6. Routing Table Structure

### 6.1 K-Bucket Array

The routing table is an array of `BUCKET_COUNT` (256) k-buckets, indexed 0 through 255.

Each k-bucket `KBucket(i)` stores up to `K_BUCKET_SIZE` `NodeInfo` entries for peers whose XOR distance from the local node has a leading bit position of `i`. Bucket 0 holds the most distant half of the keyspace (peers differing in the MSB), bucket 255 holds the closest peers (differing only in the LSB).

Within each k-bucket, entries are ordered by recency: the most recently seen peer is at the tail. This ordering governs eviction preference — head-of-bucket peers are evicted first when swap-closer admits a new peer.

### 6.2 Bucket Index Computation

For local node `N` and candidate peer `P`:

1. Compute `D = N.id ⊕ P.id` (256-bit XOR).
2. Find the position of the first set bit in `D`, scanning from MSB (bit 0) to LSB (bit 255).
3. That position is `BucketIndex(N, P)`.
4. If `D = 0` (identities are equal), insertion is rejected (Invariant 1).

Property: lower bucket indices correspond to more distant peers.

### 6.3 NodeInfo Lifecycle

A `NodeInfo` entry tracks:

- `PeerId`: immutable after creation.
- `addresses`: mutable list of up to `MAX_ADDRESSES_PER_NODE` multiaddresses, ordered by recency (most recent first).
- `last_seen`: timestamp of last successful interaction.

  Implementations SHOULD use a monotonic clock source (e.g., `Instant` in Rust) for `last_seen` comparisons against `LIVE_THRESHOLD`. `SystemTime` is vulnerable to backward clock jumps (NTP corrections, VM migration) that could make peers appear permanently live or instantly stale. Monotonic time does not persist across restarts, but this is acceptable — restarted nodes re-enter via bootstrap with fresh liveness state.

Address management rules:

1. When a known peer is contacted on a new address, that address is prepended to the list. If the address already exists, it is moved to the front.
2. The list is truncated to `MAX_ADDRESSES_PER_NODE` after each update.
3. The first address in the list is the preferred dial address.
4. A peer's address list MUST NOT be updated to include a loopback address (e.g., `127.0.0.0/8`, `::1`) unless the node was originally admitted with loopback allowed. This prevents a peer admitted on a routable IP from later claiming a loopback address via `touch_node` or address merge, which would bypass IP diversity enforcement.
5. A peer's accumulated address list is not re-checked against IP diversity limits after initial admission. Diversity is enforced at admission time. Address accumulation does not grant additional routing table slots — the peer already holds exactly one slot in its correct bucket.

## 7. Peer Admission

### 7.1 Admission Flow

When a candidate peer `P` with `NodeInfo` and IP address `candidate_ip` is presented for insertion:

1. **Self-check**: If `P.id == self.id`, reject.
2. **Address check**: If `P.addresses` is empty, reject.
3. **Authentication check**: If `P` has not completed transport-level authentication, reject.
4. **Trust block check**: If `TrustScore(self, P) < BLOCK_THRESHOLD`, reject.
5. **Update short-circuit**: If `P` already exists in `KBucket(BucketIndex(self, P))`, merge addresses (Section 6.3), refresh `last_seen`, move `P` to tail, and return. The peer already holds its slot — IP diversity and capacity checks are skipped.
6. **Loopback check**: If `candidate_ip` is loopback and loopback is disallowed, reject. If loopback is allowed, skip all IP diversity checks (step 7–8) and proceed directly to step 9.
7. **Non-IP transport bypass**: If `P` has no IP-based address (e.g., Bluetooth, LoRa), skip IP diversity checks and proceed directly to step 9.
8. **IP diversity enforcement** (under write lock — Invariant 10):
   a. Compute `bucket_idx = BucketIndex(self, P)`.
   b. Run per-bucket IP diversity check (Section 7.2) against nodes in `KBucket(bucket_idx)`.
   c. Run routing-neighborhood IP diversity check (Section 7.2) against the routing neighborhood (the `K_BUCKET_SIZE` closest peers to self, including `P` and excluding any bucket-swap candidates).
   d. Deduplicate swap candidates from steps (b) and (c). For routing-neighborhood swap candidates whose evictee is NOT in `KBucket(bucket_idx)`, apply the following decision tree:
      1. Does `KBucket(bucket_idx)` have capacity (fewer than `K_BUCKET_SIZE` entries)?
         - **Yes**: execute the routing-neighborhood swap (it resolves the diversity violation) and proceed — the candidate enters via existing capacity.
         - **No**: continue to step 2.
      2. Does another swap candidate (from step 8b or 8c) free a slot in `KBucket(bucket_idx)`?
         - **Yes**: execute both swaps and proceed.
         - **No**: defer the routing-neighborhood swap until after the capacity pre-check (step 9).
      3. After step 9, does `KBucket(bucket_idx)` now have capacity (e.g., stale revalidation freed a slot)?
         - **Yes**: execute the deferred routing-neighborhood swap and proceed.
         - **No**: reject the deferred swap. The candidate is rejected — the routing-neighborhood diversity violation cannot be resolved without displacing a peer from the wrong bucket.
9. **Stale collection and capacity pre-check**: Verify that one of these holds for `KBucket(bucket_idx)`:
   - The bucket has fewer than `K_BUCKET_SIZE` entries.
   - A per-bucket swap candidate from step 8b frees a slot in this bucket, OR a routing-neighborhood swap candidate from step 8c evicts a peer that happens to reside in this bucket.
   If none holds, attempt **merged stale peer revalidation** (Section 7.5). Collect ALL stale peers from both scopes into a single revalidation set:
   - Stale peers in `KBucket(bucket_idx)` (bucket-level contention).
   - Stale routing-neighborhood violators identified in step 8c (if any).
   Release the write lock **once**, ping all collected stale peers in parallel (bounded by `STALE_REVALIDATION_TIMEOUT`), then re-acquire the write lock **once** and **re-evaluate the following checks** against the current routing table state:
   - Trust block check (step 4): `TrustScore` may have changed during the unlocked window.
   - Per-bucket IP diversity (step 8b): bucket composition may have changed.
   - Routing-neighborhood IP diversity (step 8c): K-closest set may have changed.
   - Capacity pre-check (this step): slots may have been filled by concurrent admissions.
   Steps 1–3, 5–7 are not re-evaluated (candidate identity, addresses, authentication, and loopback status are immutable within a single admission attempt). Re-evaluation MUST NOT trigger a second round of stale revalidation — if any check fails during re-evaluation, reject the candidate. This bounds admission latency to a single `STALE_REVALIDATION_TIMEOUT` per admission attempt with a single lock-release window. This prevents TOCTOU races caused by concurrent mutations during the unlocked ping window. If revalidation frees at least one slot and re-evaluation passes, proceed. If no slots freed or re-evaluation fails, reject.
10. **Execute swaps**: Remove all deduplicated swap candidates. Disconnect evicted peers at the transport layer.
11. **Insert**: Add `P` to `KBucket(bucket_idx)`.

### 7.2 IP Diversity Enforcement

IP diversity is checked per scope (a set of `NodeInfo` entries: either a single k-bucket or the routing neighborhood — the `K_BUCKET_SIZE` closest peers to self). For a candidate with `candidate_ip`:

When a candidate has multiple IP-based addresses, IP diversity checks apply to ALL of them independently. Each IP in the candidate's address list is checked against both exact-IP and subnet limits. If any IP violates a diversity limit and swap-closer cannot resolve it, the candidate is rejected. This prevents a peer from gaming diversity checks by placing a diverse address first while concentrating other addresses on a single subnet.

Example: a candidate has IPs [1.2.3.4, 5.6.7.8]. Both are checked independently. If 1.2.3.4's `/24` exceeds `IP_SUBNET_LIMIT` and swap-closer fails for that subnet, the candidate is rejected — even though 5.6.7.8 would pass.

**Exact IP check:**

1. Count nodes in scope whose IP matches `candidate_ip` exactly.
2. If count `>= IP_EXACT_LIMIT`, attempt swap-closer (Section 7.3).

**Subnet check:**

1. Mask `candidate_ip` to the configured prefix length (`/24` for IPv4, `/48` for IPv6).
2. Count nodes in scope whose masked IP matches the candidate's masked IP.
3. If count `>= IP_SUBNET_LIMIT`, attempt swap-closer (Section 7.3).

Both checks apply independently. If either fails, the candidate is rejected (unless swap-closer succeeds).

### 7.3 Swap-Closer Eviction

The reference point for both per-bucket and routing-neighborhood scopes is the local node's ID. All distance comparisons in swap-closer use XOR distance to self.

When an IP diversity limit is exceeded and a candidate `P` contends for a slot:

1. Among the nodes in scope that share the candidate's IP or subnet (the "violating set"), find the one farthest from the local node by XOR distance.
2. Let `V` be that farthest violating peer.
3. If `Distance(self, P) < Distance(self, V)` **AND** (`TrustScore(self, V) < TRUST_PROTECTION_THRESHOLD` **OR** `now - V.last_seen > LIVE_THRESHOLD`):
   - Swap: evict `V`, disconnect `V` at the transport layer, admit `P`.
4. Otherwise: reject `P`. Live, well-trusted peers hold their slot.

Rationale: swap-closer prefers geographically closer peers (lower XOR distance) while protecting long-lived, recently-seen, well-trusted peers from displacement by unproven newcomers from the same subnet. A peer that has not been seen within `LIVE_THRESHOLD` loses trust protection regardless of its score — it may have silently departed, and holding its slot against a live candidate degrades routing table quality.

### 7.4 Blocked Peer Handling

When any interaction records a trust failure and `TrustScore(self, P)` drops below `BLOCK_THRESHOLD`:

1. Remove `P` from `LocalRT(self)`.
2. Disconnect `P` at the transport layer.
   2a. Cancel all in-flight RPCs to or from `P`. Cancelled operations do not record trust events — the eviction/blocking decision has already been made, and partial responses from a blocked peer should not influence trust state. The mechanism for distinguishing cancellation from genuine failure is an implementation choice, but MUST prevent cancelled RPCs from recording trust events.
3. Silently drop any incoming DHT messages from `P`.
4. Do not re-admit `P` until `TrustScore(self, P) >= BLOCK_THRESHOLD`.

Blocking is enforced at both the transport and routing table layers. API consumers can rely on `LocalRT` membership as the trust gate.

Transport-level enforcement: the transport layer MUST query `TrustScore(self, P)` at authentication time and reject the connection if the score is below `BLOCK_THRESHOLD`. The transport MUST NOT rely solely on a cached block list, as peers may recover above `BLOCK_THRESHOLD` via time decay (see re-admission path below). The check occurs after the peer's identity is established but before allocating application-layer resources (buffers, session state, routing table interaction). The transport layer MUST also refuse outbound dials to blocked peers.

Re-admission path: a blocked peer can only re-enter when its trust score recovers above `BLOCK_THRESHOLD` through time-decay toward neutral AND the peer is rediscovered through normal network activity:

1. Peer `P` is returned in a `FIND_NODE` response from another peer during a lookup.
2. Local node checks `TrustScore(self, P)`. If still below `BLOCK_THRESHOLD`, `P` is silently skipped (not dialed).
3. If trust has recovered above `BLOCK_THRESHOLD`, local node dials `P`, authentication completes, and the standard admission flow (Section 7.1) applies.

A blocked peer cannot trigger its own re-admission — it requires third-party discovery after trust recovery.

Implementations SHOULD bound trust record storage for peers not in the routing table. The specific mechanism (LRU eviction, TTL-based expiry, score-at-neutral garbage collection) is an implementation choice. Unbounded accumulation of trust records for blocked or departed peers is a memory leak.

### 7.5 Stale Peer Revalidation on Admission Contention

When a candidate `P` is presented for admission but `KBucket(bucket_idx)` is at capacity and neither the update path, IP diversity swap, nor available capacity can accommodate `P`, stale peer revalidation merges all stale peers from both scopes into a single revalidation pass:

1. Collect the **merged stale set**:
   a. All peers `S` in `KBucket(bucket_idx)` where `now - S.last_seen > LIVE_THRESHOLD` (bucket-level stale peers).
   b. All peers in the K-closest-to-self set that share IP or subnet with candidate `P` (routing-neighborhood violators from step 8c) where `now - last_seen > LIVE_THRESHOLD`.
   c. Deduplicate (a peer may appear in both sets).
2. If the merged stale set is empty: no slots can be freed. Reject `P`.
3. **Ping all stale peers in parallel** (bounded by `STALE_REVALIDATION_TIMEOUT`). This is a single unlock window — the write lock is released once for all pings.

Only one stale revalidation may be in progress per bucket at a time. At most one additional admission attempt may queue behind the active revalidation. Further concurrent candidates targeting the same bucket are immediately rejected with "revalidation in progress." This bounds per-bucket blocking to at most 2 × `STALE_REVALIDATION_TIMEOUT` per admission attempt.

A **global revalidation semaphore** with capacity `MAX_CONCURRENT_REVALIDATIONS` (reference: 8) limits the total number of stale revalidation passes running simultaneously across all buckets. When the semaphore is full, admission attempts that reach stale revalidation are immediately rejected with "global revalidation limit reached" — they do not queue behind the semaphore. This prevents a Sybil flood targeting many buckets simultaneously from creating O(`BUCKET_COUNT`) parallel ping storms, bounding total revalidation network load to at most `MAX_CONCURRENT_REVALIDATIONS × K_BUCKET_SIZE` concurrent pings (160 at reference values).

4. For each peer that responds: `touch_node(S)`. `S` retains its slot and regains live status. (No trust reward — successful responses are the expected baseline.)
5. For each peer that fails to respond: record `ConnectionFailed` trust event, evict `S` from its respective k-bucket, disconnect `S` at the transport layer. Emit `PeerRemoved(S)` event.
6. Re-acquire the write lock and re-evaluate (see Section 7.1 step 9 for the full re-evaluation list).
7. If routing-neighborhood violators were in the stale set: recompute the K-closest-to-self set (composition may have changed due to evictions) and re-run the routing-neighborhood IP diversity check. If the violation is now resolved, skip swap-closer for the routing-neighborhood scope. If it persists, proceed to swap-closer (Section 7.3) against the remaining live violators.
8. If any slots were freed in `KBucket(bucket_idx)` and re-evaluation passes: proceed with admission of `P` (step 10 of Section 7.1).
9. If no slots were freed or re-evaluation fails: reject `P` with "bucket at capacity."

Note: evicting a routing-neighborhood violator from its bucket frees a slot in that bucket, not necessarily in the candidate's target bucket. Routing-neighborhood revalidation resolves IP diversity violations; the capacity pre-check (Section 7.1 step 9) is a separate gate that must still pass independently.

**Design rationale**: this is a reactive liveness mechanism inspired by original Kademlia's ping-on-insert design, adapted with a staleness threshold (BEP 5's "questionable" concept). Unlike proactive background pinging (Ethereum discv5's revalidation loop) or connection-state tracking (libp2p), it incurs zero network overhead when there is no admission contention. The cost is paid only when a real candidate needs a slot and an incumbent has not been seen recently — exactly the moment when liveness information has the most value.

Pinging all stale peers in the bucket (not just one) revalidates the entire bucket's stale set in a single contention event, freeing multiple slots if several peers have departed. This avoids repeated single-peer probes across successive admission attempts.

**Latency impact**: stale revalidation adds up to `STALE_REVALIDATION_TIMEOUT` to the admission path, but only when the bucket is full AND contains stale peers AND no other admission path (update, capacity, swap) succeeds. In a healthy network where peers interact regularly, most peers remain within `LIVE_THRESHOLD` and this path is never triggered.

**Trust event durability**: trust events recorded during stale revalidation (steps 4–5) are committed regardless of whether the candidate is ultimately admitted. If the write lock is re-acquired and re-evaluation fails (due to concurrent mutations), the candidate is rejected, but the trust events stand — the liveness information they encode is accurate and valuable independent of the admission outcome.

**Eviction and disconnection**: all evictions during stale revalidation result in transport-layer disconnection. This prevents ghost connections — open transport connections to peers no longer in the routing table that would consume resources without routing benefit.

## 8. Peer Lookup

### 8.1 Local Lookup: `find_closest_nodes_local`

Returns the `count` nearest nodes to a key `K` from `LocalRT(self)` without network requests.

Algorithm:

1. Collect all entries from all k-buckets, computing `Distance(K, entry)` for each.
2. Sort all collected candidates by `Distance(K, candidate)`.
3. Return the top `count`.

Note: bucket index correlates with distance from self, not distance from key `K`. Peers in buckets far from `BucketIndex(self, K)` in the spiral can still be closer to `K` than peers in nearby buckets. The routing table holds at most `BUCKET_COUNT * K_BUCKET_SIZE` (5,120) entries, so a full scan and sort is trivially fast.

Properties:
- Read-only: no write lock required, safe to call from request handlers. Concurrent mutations may cause a lookup to observe intermediate state (e.g., a peer evicted but its replacement not yet inserted). This is acceptable — lookups are advisory and callers verify results. Note: the K-closest snapshot used for `KClosestPeersChanged` event computation (Section 9.4) is taken within the write-locked admission critical section, not via `find_closest_nodes_local`. Consumer-facing local lookups remain lock-free.
- Excludes self (Invariant 1).
- Deterministic: same routing table state produces same result.

### 8.2 Network Lookup: `find_closest_nodes_network`

Iterative Kademlia lookup that queries remote peers to refine the closest set.

Algorithm:

1. Seed `best_nodes` with results from `find_closest_nodes_local(K, count)`.
2. Include self in `best_nodes` (self competes on distance but is never queried).
3. Mark self as "queried" to prevent self-RPC.
4. Loop (up to `MAX_LOOKUP_ITERATIONS`):
   a. Select up to `ALPHA` unqueried peers from `best_nodes`, nearest first. Skip any peer with `TrustScore(self, peer) < BLOCK_THRESHOLD` (the peer may have been blocked since it entered `best_nodes`).
   b. Query each in parallel with `FIND_NODE(K)`.
   c. For each failed query, record trust penalty (`ConnectionFailed`/`ConnectionTimeout`). Successful responses are the expected baseline and do not generate trust events.
   d. For each response, accept at most `MAX_PEERS_PER_RESPONSE` peers (closest to `K` first; additional entries are silently dropped). Merge accepted peers into `best_nodes`, deduplicating by `PeerId`.
   e. Sort `best_nodes` by `Distance(K, node)`, truncate to `count`.
   f. Convergence check: compare the entire top-K set of peer IDs against the previous iteration. If the set is unchanged AND no unqueried candidate in the queue is closer than the farthest member of top-K, the lookup has converged — stop. If top-K hasn't filled `count` slots yet, continue regardless.
5. Return `best_nodes` (may include self).

Properties:
- **Per-lookup isolation**: Each invocation of `find_closest_nodes_network` maintains its own `best_nodes` set, queried set, and top-K convergence state. Concurrent lookups (e.g., a self-lookup and a consumer-triggered lookup running simultaneously) do not share or interfere with each other's state. They may independently query the same remote peers and independently record trust outcomes.
- Makes network requests: MUST NOT be called from within DHT request handlers (deadlock risk).
- Trust recording: each RPC outcome is fed to the trust subsystem.
- Blocked peers: silently excluded from query candidates (they are not in `LocalRT`).

## 9. Routing Table Maintenance

### 9.1 Touch on Interaction

Any successful RPC (inbound or outbound) with a peer `P` triggers `touch_node(P)`:

1. If `P` is in the routing table: update `last_seen` to now, optionally merge the address used, move `P` to the tail of its k-bucket.
2. If `P` is not in the routing table: no action (touch is not an admission path). Re-admission of evicted peers happens only through the normal admission flow — either via a new inbound connection (Section 10.2) or via discovery during a network lookup.

This ensures Kademlia's preference for long-lived peers: recently-active peers move to the tail, and head-of-bucket peers become eviction candidates. It also prevents evicted peers from silently re-entering the routing table by sending RPCs, which would bypass IP diversity and trust checks.

`touch_node` is the sole mechanism that keeps a peer in "live" state (i.e., `last_seen` within `LIVE_THRESHOLD`). A peer that is not touched for longer than `LIVE_THRESHOLD` becomes stale, loses trust protection (Invariant 8), and becomes eligible for revalidation-based eviction on admission contention (Section 7.5).

### 9.2 Self-Lookup for Close Neighborhood Freshness

Nodes MUST periodically perform a network lookup for their own `PeerId` to discover new close peers.

1. On a randomized timer (`SELF_LOOKUP_INTERVAL`), run `find_closest_nodes_network(self.id, K_BUCKET_SIZE)`.
2. For each discovered peer not already in `LocalRT(self)`, attempt admission via the full admission flow (Section 7.1).
3. This keeps the close neighborhood current under churn, which is critical for routing correctness and for API consumers that depend on accurate nearest-peer queries.

### 9.3 Bucket Refresh

Buckets that have not been touched (no node in the bucket updated via `touch_node`) for longer than `STALE_BUCKET_THRESHOLD` are considered stale.

On a periodic timer (`BUCKET_REFRESH_INTERVAL`):

1. For each stale bucket `i`:
   a. Generate a random key `K` that would land in bucket `i` (a key whose XOR with `self.id` has its leading set bit at position `i`).
   b. Perform `find_closest_nodes_network(K, K_BUCKET_SIZE)`.
   c. Attempt to admit discovered peers.
2. Mark the bucket as refreshed.

Purpose: Kademlia requires periodic refresh to maintain routing table completeness. Stale buckets in distant parts of the keyspace would otherwise lose all entries to churn without replacement.

### 9.4 Routing Table Event Notifications

The routing table MUST emit events on membership changes to allow consumers to react without polling:

| Event | Trigger |
|---|---|
| `PeerAdded(PeerId)` | New peer inserted into routing table |
| `PeerRemoved(PeerId)` | Peer evicted, blocked, or departed |
| `KClosestPeersChanged { old, new }` | Composition of the `K_BUCKET_SIZE`-closest peers to self changed |
| `BootstrapComplete { num_peers }` | Bootstrap process finished (routing table stabilized or timeout reached) |

`KClosestPeersChanged` is emitted when a routing table admission attempt causes the set of `K_BUCKET_SIZE` nearest peers to self to differ from the pre-admission set. The routing table snapshots the K-closest set before each admission attempt and compares after; the event carries both the old and new sets. This fires at most once per admission attempt — the entire admission (including sub-mutations like swaps and stale evictions) is treated as one logical operation.

`BootstrapComplete` is emitted once per bootstrap cycle — both at initial startup and on each auto re-bootstrap (Section 10.3). It fires when the bootstrap lookups for that cycle complete — specifically, after the self-lookup and bucket refresh operations (Section 11) have all terminated. The event carries the total number of peers in the routing table at the time of emission. Consumers (e.g., replication, application-layer services) SHOULD wait for this event before initiating operations that depend on a populated routing table.

Events MUST be emitted reliably for every routing table mutation. Consumers MAY additionally perform periodic recomputation as a defense-in-depth measure, but MUST NOT depend on polling as the primary mechanism.

## 10. Churn Handling

### 10.1 Peer Departure Detection

Peers are detected as departed through:

1. **RPC failure**: Failed outbound RPC records trust failure. If trust drops below `BLOCK_THRESHOLD`, peer is evicted (Section 7.4).
2. **Iterative lookup feedback**: Network lookups record success/failure per queried peer.
3. **Self-lookup refresh**: Periodic self-lookups discover that a previously-close peer is no longer returned by the network.
4. **Stale peer revalidation**: When a new candidate contends for a full bucket, all stale peers (not seen within `LIVE_THRESHOLD`) in that bucket are pinged. Non-responders are evicted immediately (Section 7.5).

The routing table does not run a background ping loop. Liveness is assessed reactively: through actual RPC interactions, trust score changes, and on-demand revalidation during admission contention. This avoids the overhead of proactive health checks (e.g., Ethereum discv5's revalidation loop) while ensuring stale peers are detected at the moment a live replacement is available.

Idle peers that are never contacted and never contended for will decay toward neutral trust (0.5) and lose trust protection after `LIVE_THRESHOLD`, making them displaceable by swap-closer (Invariant 8). Close peers are naturally contacted frequently by lookups and consumer-layer interactions, so silent departures in the close neighborhood are detected quickly through RPC failures and admission contention from self-lookups.

### 10.2 Peer Arrival Handling

New peers enter the routing table through:

1. **Inbound connections**: A new peer connects and completes authentication. After successful handshake, attempt admission.
2. **Iterative lookup discovery**: Network lookups return peers not yet in `LocalRT`. Attempt admission.
3. **Self-lookup discovery**: Periodic self-lookups discover new close peers.
4. **Bootstrap peer seeding**: At startup, bootstrap peers are dialed and their `FIND_NODE(self)` responses seed the routing table.

All paths converge on the same admission flow (Section 7.1), ensuring consistent IP diversity and trust enforcement.

### 10.3 Automatic Re-Bootstrap

When `routing_table_size()` drops below `AUTO_REBOOTSTRAP_THRESHOLD` (e.g., due to mass blocking or network partition), the node MUST automatically trigger the bootstrap process (Section 11.1 steps 2–7). This prevents permanent isolation when the routing table is depleted.

Re-bootstrap follows the same flow as cold start: dial bootstrap peers, perform self-lookup, refresh buckets, emit `BootstrapComplete`. The close group cache is not reloaded (it reflects the state that led to depletion). A minimum cooldown of `REBOOTSTRAP_COOLDOWN` (reference: 5 minutes) MUST elapse between consecutive re-bootstrap attempts to prevent bootstrap node overload during persistent partitions. Re-bootstrap MAY fire multiple times if the routing table repeatedly drops below the threshold, subject to the cooldown.

## 11. Bootstrap

### 11.1 Cold Start

A node starting with an empty routing table:

1. Load close group cache from disk (if available). Import trust scores into the trust subsystem and place cached peers into the dial queue (not the routing table — Invariant 5 requires authentication before insertion).
2. Dial bootstrap peers (well-known, hardcoded or configured).
3. Send `FIND_NODE(self.id)` to each bootstrap peer.
4. Admit returned peers via the standard admission flow.
5. Perform iterative self-lookup to expand close neighborhood.
6. Refresh all k-buckets farther than the bucket containing the nearest bootstrap peer by looking up a random key in each bucket's range. Close buckets are already populated by the self-lookup in step 5; only distant buckets need explicit refresh.
7. Emit `BootstrapComplete { num_peers }` with the current routing table size.

### 11.2 Warm Restart

A node restarting with a close group cache:

1. Load cached trust scores into the trust subsystem. Place cached peers into a dial queue (not the routing table — Invariant 5 requires authentication before insertion).
2. Dial cached peers first (they are likely still alive and nearby).
3. For each successful dial + authentication, admit the peer via the standard admission flow (Section 7.1).
4. Fall back to bootstrap peers if cached peers are unreachable.
5. Perform two consecutive self-lookups to ensure the close neighborhood is fully refreshed. The second lookup may discover peers that joined or became reachable during the first lookup.
6. Refresh stale k-buckets by looking up random keys in their ranges.
7. Emit `BootstrapComplete { num_peers }` with the current routing table size.

The close group cache (`CloseGroupCache`) stores:

- `K_BUCKET_SIZE` closest peers to self with their addresses and trust records.
- Saved at shutdown, loaded at startup.
- Trust scores are imported without decay for offline time (cannot observe behavior while offline).

## 12. Security Properties

### 12.1 Sybil Resistance via IP Diversity

IP diversity enforcement (Section 7.2) limits the influence of a single operator:

- **Per-bucket**: An attacker controlling one IP can place at most `IP_EXACT_LIMIT` (2) nodes in any single bucket. An attacker controlling a `/24` subnet can place at most `IP_SUBNET_LIMIT` (5) nodes per bucket.
- **Routing-neighborhood**: The same limits apply to the `K_BUCKET_SIZE` closest peers to self, preventing a single operator from dominating the routing neighborhood.
- **Two-scope enforcement**: Both per-bucket and routing-neighborhood checks must pass. An attacker could fill distant buckets without threatening the routing neighborhood, but cannot concentrate nodes near any target.

Limitations:
- An attacker with access to many subnets across diverse providers can still accumulate routing table presence. IP diversity is one layer of defense, complemented by trust scoring and proof-of-work/stake at higher layers.
- VPN and cloud provider ASNs are identifiable (BGP geo provider) but not currently enforced at the routing table level. Future work may add ASN-level diversity.

### 12.2 Eclipse Attack Resistance

An eclipse attack attempts to surround a target node with attacker-controlled peers, isolating it from the honest network.

Defenses:

1. **IP diversity**: Limits attacker concentration per scope (Section 12.1).
2. **Trust protection**: Live, well-trusted peers (score ≥ 0.7, seen within `LIVE_THRESHOLD`) cannot be evicted by swap-closer, even if the attacker generates IDs closer to the target. Stale peers lose this protection — an attacker could displace them, but stale peers are already degrading routing quality and their replacement by any live peer (even an attacker's) is a net improvement for that slot.
3. **Authenticated insertion**: Only transport-authenticated peers enter the routing table. An attacker must complete cryptographic handshakes for each fake identity.
4. **Self-lookup refresh**: Periodic self-lookups discover honest peers that the attacker may be trying to hide.
5. **Close group cache**: On restart, the node reconnects to previously-trusted close peers before the attacker can fill the empty routing table.

### 12.3 Routing Table Poisoning Resistance

An attacker attempts to insert malicious entries via `FIND_NODE` responses:

1. **No blind insertion**: Peers returned by `FIND_NODE` are not automatically added. They must be dialed, authenticated, and pass the admission flow.
2. **Trust baseline**: New peers start at neutral trust (0.5), well above `BLOCK_THRESHOLD` (0.15) but below `TRUST_PROTECTION_THRESHOLD` (0.7). They must demonstrate good behavior to earn protection.
3. **IP diversity gates**: Even if an attacker can authenticate many identities, IP diversity limits prevent flooding.

## 13. Consumer API

The routing table exposes the following operations to consumers (e.g., saorsa-node):

| Operation | Input | Output | Description |
|---|---|---|---|
| `find_closest_nodes_local(K, count)` | Key, count | `Vec<NodeInfo>` sorted by distance | Nearest peers from local routing table |
| `find_closest_nodes_local_with_self(K, count)` | Key, count | `Vec<NodeInfo>` sorted by distance | Same as `find_closest_nodes_local` but includes self in the candidate set. Used by consumers to determine storage responsibility. |
| `find_closest_nodes_network(K, count)` | Key, count | `Vec<NodeInfo>` sorted by distance | Iterative network lookup |
| `is_in_routing_table(P)` | PeerId | bool | Membership check |
| `routing_table_size()` | — | usize | Total peer count |
| `touch_node(P, addr)` | PeerId, optional address | bool | Liveness update on successful interaction |
| `report_trust_event(P, event)` | PeerId, TrustEvent | — | Report a trust-relevant outcome for a peer (Section 13.1). Consumer events carry a weight multiplier expressing severity. |
| `peer_trust(P)` | PeerId | float (0.0–1.0) | Query current trust score; returns neutral (0.5) for unknown peers |
| `all_peers()` | — | `Vec<NodeInfo>` | All peers currently in the routing table. Used for replication and diagnostics. |
| `trigger_self_lookup()` | — | — | Trigger an immediate self-lookup to refresh the close neighborhood. Returns after the lookup completes. |
| `routing_table_stats()` | — | `RoutingTableStats` | Diagnostic statistics: total peers, per-bucket counts, trust distribution, staleness counts. |

The routing table MUST provide a mechanism for consumers to observe routing table events (Section 9.4). The specific mechanism (channel, callback, trait) is an implementation choice, but it MUST support all four event types (`PeerAdded`, `PeerRemoved`, `KClosestPeersChanged`, `BootstrapComplete`) and deliver them reliably and in order.

Consumers MUST NOT:

- Directly read or write k-bucket contents.
- Bypass IP diversity or trust checks when admitting peers.
- Remove peers from the routing table (that is owned by the trust/blocking subsystem).
- Manipulate trust scores directly — all trust mutations flow through `report_trust_event`.

Consumers MAY:

- Report trust events via `report_trust_event` to reward or penalize peers based on application-level outcomes, which may indirectly cause routing table changes (eviction on block, trust protection gain/loss).
- Query `peer_trust` to make trust-informed decisions (e.g., preferring higher-trust peers for data retrieval).
- Request network lookups to discover new peers (which may be admitted to the routing table as a side effect).

### 13.1 Consumer Trust Reporting

The trust subsystem accepts trust events from two sources: **internal events** recorded automatically by DHT operations, and **consumer-reported events** submitted by the API consumer via `report_trust_event`. All events flow through the same EMA scoring model. Consumer events carry a weight multiplier that controls how heavily a single event influences the score, allowing the consumer to express severity without needing a separate scoring mechanism.

#### Trust Event Taxonomy

All events are classified as positive (successful interaction) or negative (failed interaction) and processed by the same EMA scoring model. Consumer events additionally carry a `weight` parameter that scales their impact.

**Internal events** (recorded automatically — consumers do not report these):

Core only records penalties. Successful responses are the expected baseline and do not generate trust events.

| Event | Category | Weight | Trigger |
|---|---|---|---|
| `ConnectionFailed` | Negative | `1.0` (implicit) | Outbound connection could not be established |
| `ConnectionTimeout` | Negative | `1.0` (implicit) | Outbound connection attempt timed out |

**Consumer-reported events** (submitted via `report_trust_event`):

| Event | Parameter | Category | Trigger (example) |
|---|---|---|---|
| `ApplicationSuccess(weight)` | `weight`: severity multiplier in (0.0, `MAX_CONSUMER_WEIGHT`] | Positive | Peer served a valid chunk, fulfilled a storage request, passed an audit |
| `ApplicationFailure(weight)` | `weight`: severity multiplier in (0.0, `MAX_CONSUMER_WEIGHT`] | Negative | Peer returned corrupted data, failed to serve expected chunk, failed a storage audit |

A weight of `1.0` has the same EMA impact as a single internal event. A weight of `3.0` has the same impact as three consecutive events of the same category. This lets the consumer express that serving corrupted data (e.g., `ApplicationFailure(3.0)`) is more significant than a slow response (e.g., `ApplicationFailure(1.0)`) without needing to call `report_trust_event` multiple times.

#### `MAX_CONSUMER_WEIGHT` Parameter

| Parameter | Meaning | Reference |
|---|---|---|
| `MAX_CONSUMER_WEIGHT` | Maximum weight multiplier per single consumer event | `5.0` |

Capping the weight prevents a single consumer event from having disproportionate impact on the EMA. At weight `5.0`, one event is equivalent to 5 internal events — significant, but the EMA's smoothing still prevents an instant score collapse from a single report.

Parameter safety constraint: `MAX_CONSUMER_WEIGHT >= 1.0`. If violated at runtime reconfiguration, the node MUST reject the config and keep the previous valid value.

#### Weight Validation

When `report_trust_event` receives a consumer event:

1. If `weight <= 0.0`: reject the event (no-op). Zero and negative weights are meaningless.
2. If `weight > MAX_CONSUMER_WEIGHT`: clamp `weight` to `MAX_CONSUMER_WEIGHT`.
3. Proceed with the validated weight.

#### Scoring Pipeline

All events — internal and consumer-reported — follow the same path through the scoring pipeline:

1. **Event received**: `report_trust_event(P, event)` is called (by DHT internals or by the consumer).
2. **Category mapping**: Event mapped to positive (successful interaction) or negative (failed interaction).
3. **Weight resolution**: Internal events have implicit weight `1.0`. Consumer events use their caller-specified weight (after validation/clamping).
4. **EMA update**: The trust engine applies time decay, then blends the observation using the EMA model (Section 4). Positive events use observation `1.0`, negative events use `0.0`. The weight scales influence via the continuous formula `score = (1 - EMA_ALPHA)^W * score + (1 - (1 - EMA_ALPHA)^W) * observation`, which generalizes naturally to fractional weights. At reference values (`EMA_ALPHA = 0.3`), a single weight-1.0 failure moves a neutral peer's score from 0.5 to 0.35; a single weight-5.0 failure moves it from 0.5 to ~0.08.
5. **Threshold checks**:
   a. **Block check**: If `TrustScore(self, P)` dropped below `BLOCK_THRESHOLD`, trigger the blocked peer handling flow (Section 7.4) — peer is evicted from the routing table, disconnected, and blocked.
   b. **Protection evaluation**: If `TrustScore(self, P)` crossed `TRUST_PROTECTION_THRESHOLD` in either direction, the peer's swap-closer protection status changes accordingly (Section 7.3).

#### Consumer Reporting Invariants

1. **Unified model**: All events (internal and consumer-reported) are processed by the same EMA scoring model. There is no separate scoring path for consumer events. The trust score is a single value derived from the weighted history of all events, with time decay toward neutral.
2. **Weight as severity**: A consumer event with weight `W` has the same EMA impact as `W` consecutive internal events of the same category (exact for integer `W`, continuously interpolated for fractional `W` via the generalized blend formula in Section 4). Weight `1.0` is equivalent to a single internal event; weight `5.0` is equivalent to five.
3. **Bounded weight**: A single consumer event's weight is capped at `MAX_CONSUMER_WEIGHT`. At reference values (`EMA_ALPHA = 0.3`, `MAX_CONSUMER_WEIGHT = 5.0`), a single maximum-weight failure moves a neutral peer from 0.5 to ~0.08 — enough to cross `BLOCK_THRESHOLD` (0.15) in one event. This is intentional: with the penalty-only model, a severe application-level failure should be able to immediately block a neutral peer.
4. **Natural decay**: Because consumer events flow through the EMA, their influence decays over time just like internal events. A penalty reported last week has less influence on the current score than a penalty reported today. A peer that was penalized but then goes idle will drift back toward neutral (0.5).
5. **Idempotent path**: Reporting a trust event for a peer not in the routing table is valid. The trust engine maintains scores independently of routing table membership (a peer can have a trust record without being in `LocalRT`).
6. **No direct score manipulation**: Consumers cannot set a trust score to an arbitrary value. Scores are derived exclusively from the weighted EMA of all events plus time decay.

#### Consumer Guidance: Choosing Weights

The routing table design does not prescribe specific weights for application-level events — that is the consumer's domain. However, the following guidelines help consumers calibrate:

- **Weight `1.0`**: Routine outcomes equivalent in significance to a single connection failure. Use for ordinary request completions (rewards) and minor timeouts (penalties).
- **Weight `2.0–3.0`**: Significant outcomes. A peer failing to serve a chunk it was expected to hold, or serving data that fails integrity verification.
- **Weight `4.0–5.0`**: Severe outcomes. Provably malicious behavior such as serving corrupted data with a valid-looking wrapper, or consistently failing storage audits.
- **Asymmetric weighting**: Consumers may reasonably weight penalties higher than rewards. Core already embodies this principle by only recording penalties — rewards are opt-in via `ApplicationSuccess`.

#### Design Rationale

The consumer trust reporting API exists because the DHT layer operates as a peer phonebook and cannot observe application-level behavior. Core only records penalties (connection failures) — successful responses are the expected baseline and do not generate rewards. Without consumer-reported `ApplicationSuccess` events, a peer's trust can only decrease from neutral. This penalty-only model means consumers must actively reward peers they trust, preventing free-riding on implicit connection successes.

All events (internal and consumer) use the same EMA model because:

1. **One model, one score**: A single scoring mechanism is simpler to reason about than two interacting models (e.g., EMA for internal events plus direct adjustments for consumer events) modifying the same trust score. With one model, the consumer does not need to understand how its adjustments interact with EMA smoothing — its events *are* EMA events.
2. **Natural time decay for all signals**: Consumer-reported penalties and rewards decay over time, just like internal events. A peer that was penalized for serving bad data a week ago but has since behaved well naturally recovers. With direct adjustments, old penalties would persist until explicitly counteracted.
3. **Severity via weight**: The consumer expresses severity through the weight multiplier. A `weight: 3.0` failure is three times as influential as a `weight: 1.0` failure within the EMA, which is the same as reporting three separate failures. This is intuitive and requires no knowledge of EMA internals — the consumer just asks "how many unit-failures is this worth?"

By funneling all trust signals through a single `report_trust_event` interface and a single EMA model:
- The trust engine remains a single source of truth for peer reputation.
- The routing table's trust-based admission, eviction, and protection mechanisms work identically regardless of event source.
- The consumer has proportional, bounded control over trust impact without needing to reason about absolute score positions or competing scoring mechanisms.

## 14. Logic-Risk Checklist (Pre-Implementation)

Use this list to find design flaws before coding:

1. **IP diversity deadlock**:
   - In networks where many honest peers share subnets (e.g., all on AWS), can IP diversity limits prevent a node from populating its routing table? `IP_SUBNET_LIMIT = K_BUCKET_SIZE / 4` (5 per subnet per scope) allows 5 AWS peers per bucket, which is substantial. Operators with extreme concentration may need testnet/permissive overrides.

2. **Trust cold-start asymmetry**:
   - New peers start at neutral trust (0.5) and are not protected from swap-closer. A well-established network may be slow to admit new peers if existing peers are all well-trusted (≥ 0.7) and buckets are full. New peers can enter when:
     a. A bucket has capacity, or
     b. An existing peer is below 0.7 trust, or
     c. An existing peer has not been seen within `LIVE_THRESHOLD` (loses trust protection per Invariant 8), or
     d. A stale peer fails revalidation during admission contention (Section 7.5).
   In a stable, healthy network where all incumbents are live and well-trusted, new peers can only enter via (a). This is by design — stable networks resist unnecessary churn.

3. **Self-lookup failure under eclipse**:
   - If an attacker eclipses the self-lookup, the node may not discover honest close peers. Mitigation: cache-based warm restart and multiple independent bootstrap endpoints.

4. **Bucket refresh overhead**:
   - With 256 buckets and high churn, bucket refresh could generate significant network traffic. Mitigation: only stale buckets are refreshed, and the refresh interval is configurable.

5. **Stale `last_seen` and false liveness**:
   - A peer could be in the routing table with a recent `last_seen` (from a `touch_node` on an inbound message) but actually be unreachable for outbound connections. Trust scoring handles this: failed outbound RPCs reduce trust, eventually triggering eviction.

6. **Stale revalidation admission latency**:
   - Stale peer revalidation (Section 7.5) adds up to `STALE_REVALIDATION_TIMEOUT` (1s) to the admission path when triggered. In a healthy network this path is rarely hit (most peers are within `LIVE_THRESHOLD`). Under mass churn (many stale peers per bucket), parallel pinging bounds the latency to a single timeout regardless of stale-set size.

7. **Distant stale peers without contention**:
   - A stale peer in a distant, partially-filled bucket may never face admission contention and thus never be revalidated. It will sit at neutral trust (~0.5) indefinitely. This is acceptable: distant peers don't affect routing-neighborhood accuracy, don't get selected for routing-neighborhood-based operations, and the slot cost is negligible. Bucket refresh (Section 9.3) may eventually trigger contention if new peers are discovered for that bucket.

8. **Close group cache staleness**:
   - After a long offline period, the close group cache may contain departed peers. Mitigation: warm restart dials cached peers and falls back to bootstrap if they are unreachable. Self-lookup then refreshes the neighborhood.

9. **Consumer trust event flooding**:
   - A misbehaving or buggy consumer could flood `report_trust_event` with `ApplicationFailure(MAX_CONSUMER_WEIGHT)` events, rapidly blocking many peers and depleting the routing table. Mitigation: `MAX_CONSUMER_WEIGHT` caps per-event influence, and the EMA's smoothing factor limits how far a single event can move the score — even at maximum weight, the score change is bounded by EMA dynamics, not by the weight alone. The consumer is a trusted local process. If rate limiting is needed in the future, it can be added at the `report_trust_event` interface without changing the scoring model. For v1, the consumer is assumed to report events honestly and at a reasonable rate.

10. **Internal vs consumer event divergence**:
    - Core only records penalties (connection failures), so a peer that is DHT-reachable but never receives consumer rewards will gradually drift below neutral as occasional connection hiccups accumulate. Consumer `ApplicationSuccess` events are the only way to push trust above neutral, preventing free-riding on bare connectivity. A peer that is reachable but serves bad data will be blocked even faster since there are no internal success events to counteract consumer-reported failures.

11. **Consumer reward inflation**:
    - A consumer could report `ApplicationSuccess(MAX_CONSUMER_WEIGHT)` for every interaction, inflating a peer's trust toward 1.0. Because all events flow through EMA, the score asymptotically approaches 1.0 but the smoothing factor limits the rate. This is acceptable: the consumer is a trusted local process, and inflating trust simply means the peer gains stronger protection. If the peer later misbehaves, subsequent failures (internal or consumer-reported) will pull the score back down, and time decay ensures idle peers drift toward neutral.

12. **Routing-neighborhood subnet concentration**:
    - The routing neighborhood (K-closest-to-self) enforces `IP_SUBNET_LIMIT` per `/24` (IPv4) or `/48` (IPv6) subnet, requiring at least `ceil(K_BUCKET_SIZE / IP_SUBNET_LIMIT)` distinct subnets to fill the neighborhood (4 subnets at reference values). In networks where most honest peers are concentrated on fewer subnets (e.g., a small deployment on 2-3 AWS subnets), the routing neighborhood may be permanently underpopulated. Operators in such environments should increase `IP_SUBNET_LIMIT` or deploy across more subnets. This is a known trade-off between Sybil resistance and liveness in low-diversity networks.

13. **Composite eclipse attack** (routing-neighborhood level):
    - This describes a routing-neighborhood eclipse (the K-closest-to-self set), not a full routing table eclipse. A full eclipse would require filling many buckets across the keyspace, each subject to its own independent IP diversity limits. An attacker with `ceil(K_BUCKET_SIZE / IP_SUBNET_LIMIT)` distinct subnets (4 at reference values) and free keypair generation can theoretically fill the routing neighborhood by generating IDs close to the target, one subnet at a time. Combined with frequent interactions to earn trust protection (≥ 0.7) within approximately 1 hour, the attacker’s peers become entrenched. Mitigation at the routing table level is bounded by IP diversity limits; higher-layer defenses (quorum verification, data integrity checks, multi-path lookups in the consumer application) are the primary protection against a fully-resourced eclipse attack. Future work may add ASN-level diversity or broader subnet grouping.

14. **Swap-closer Sybil amplification**:
    - The swap-closer mechanism, designed to improve routing quality by preferring closer peers, can be exploited by an attacker generating keypairs with IDs closer to a target. Swap-closer will displace honest peers whose trust is below `TRUST_PROTECTION_THRESHOLD` (0.7) or who are stale. This is an inherent trade-off: preferring closer peers improves routing efficiency but creates a displacement vector. IP diversity limits bound the attack surface (at most `IP_SUBNET_LIMIT` attacker peers per subnet per scope), and trust protection makes displacement permanent once honest peers earn protection. The alternative — never displacing based on distance — would prevent the routing table from improving its topology.

15. **Close-peer staleness bound**:
    - The worst-case time to detect a departed close peer is `max(SELF_LOOKUP_INTERVAL) + LIVE_THRESHOLD` (25 minutes at reference values). A peer that departs immediately after being touched can hold its slot until the next self-lookup discovers a replacement candidate and triggers admission contention. For distant peers not subject to admission contention, staleness is unbounded but harmless (see item 7). Close peers are naturally contacted frequently, so this worst case requires the peer to depart during a quiet period with no consumer-layer interactions.

16. **Sparse network lookup termination**:
    - The iterative lookup terminates when the entire top-K set stabilises across consecutive iterations and no unqueried candidate is closer than the farthest member of top-K. In sparse networks with intermittent connectivity, this may still terminate before finding the true K-closest peers if all reachable candidates have been queried. Consumers that need higher confidence in sparse networks can issue multiple lookups. The convergence check is distance-aware: as long as any queued candidate is closer than the current worst member, the lookup continues.

## 15. Pre-Implementation Test Matrix

Each scenario should assert exact expected outcomes and state transitions.

### Admission Tests

1. **Happy path admission**:
   - Authenticated peer with unique IP, bucket has capacity. Peer is added to correct bucket. `find_closest_nodes_local` returns it at correct distance rank.

2. **Self-insertion rejection**:
   - Attempt to add `self.id` to routing table. Rejected. Routing table unchanged.

3. **Empty address rejection**:
   - Candidate with zero addresses. Rejected with error. Routing table unchanged.

4. **Blocked peer rejection**:
   - Peer with `TrustScore < BLOCK_THRESHOLD`. Rejected. Not in routing table.

5. **Bucket-full rejection (no stale peers)**:
   - Bucket at `K_BUCKET_SIZE` capacity, candidate cannot swap-closer, all incumbent peers have `last_seen` within `LIVE_THRESHOLD`. Stale revalidation finds no candidates. Rejected with "bucket at capacity." Routing table unchanged.

6. **Swap-closer success**:
   - Bucket at capacity, candidate is closer than farthest same-subnet peer (trust < 0.7). Farthest peer evicted, candidate admitted.

7. **Trust-protected swap-closer failure (live peer)**:
   - Same as test 6, but farthest peer has trust ≥ 0.7 AND `last_seen` within `LIVE_THRESHOLD`. Swap rejected. Candidate not admitted.

8. **Exact IP limit enforcement**:
   - Insert `IP_EXACT_LIMIT` peers with same IP. Next peer with same IP rejected unless swap-closer applies.

9. **Subnet limit enforcement**:
   - Insert `IP_SUBNET_LIMIT` peers within same `/24`. Next peer in subnet rejected unless swap-closer applies.

10. **Routing-neighborhood IP diversity enforcement**:
    - Bucket admits a peer, but it would violate subnet limit in the K-closest-to-self set. Peer triggers routing-neighborhood swap-closer. If successful, farthest violating peer in the routing neighborhood is evicted.

11. **Loopback bypass**:
    - With loopback allowed, peers on 127.0.0.1 skip all IP diversity checks. Multiple loopback peers admitted up to bucket capacity.

12. **Non-IP transport bypass**:
    - Peer with Bluetooth-only address. IP diversity skipped. Admitted up to bucket capacity.

13. **Duplicate admission (update short-circuit)**:
    - Peer already in routing table is re-admitted with new address. Update short-circuit (step 5) fires: address is merged, `last_seen` updated, peer moved to tail. IP diversity and capacity checks are skipped. No duplicate entry created.

14. **Loopback address injection prevention**:
    - Peer admitted on routable IP (e.g., `1.2.3.4`). Later, `touch_node` is called with a loopback address (`127.0.0.1`). The loopback address is NOT merged into the peer's address list (Section 6.3 rule 4). Address list unchanged.

15. **Atomic admission under concurrent access**:
    - Two concurrent admissions targeting the same bucket. Write lock ensures both see consistent state. No TOCTOU: diversity check and insertion are atomic.

### Stale Revalidation Tests

16. **Stale revalidation evicts departed peer**:
    - Bucket at capacity. One peer has `last_seen` older than `LIVE_THRESHOLD`. New candidate arrives. Stale peer is pinged, fails to respond. `ConnectionFailed` trust event recorded. Stale peer evicted. Candidate admitted.

17. **Stale revalidation retains live peer**:
    - Bucket at capacity. One peer has `last_seen` older than `LIVE_THRESHOLD`. New candidate arrives. Stale peer is pinged, responds successfully. `touch_node` called. Stale peer stays (moved to tail). Candidate rejected. (No trust reward — successful responses are the expected baseline.)

18. **Bulk stale revalidation (multiple stale peers)**:
    - Bucket at capacity with 3 stale peers. New candidate arrives. All 3 pinged in parallel. 2 fail, 1 responds. 2 evicted, 1 stays (moved to tail). Candidate admitted. Bucket now has `K_BUCKET_SIZE - 1` entries (2 freed, 1 filled by candidate).

19. **Stale revalidation not triggered when bucket has capacity**:
    - Bucket has room. Candidate admitted directly. No pings sent, even if existing peers are stale.

20. **Stale revalidation not triggered when swap-closer succeeds**:
    - Bucket at capacity but IP diversity swap-closer frees a slot. Candidate admitted via swap. No stale revalidation pings sent.

21. **Staleness-gated trust protection: swap-closer displaces stale well-trusted peer**:
    - Bucket at capacity. Farthest same-subnet peer has trust ≥ 0.7 but `last_seen` older than `LIVE_THRESHOLD`. Candidate is closer. Swap-closer succeeds — stale peer evicted despite high trust. Candidate admitted.

22. **Staleness-gated trust protection: live well-trusted peer holds slot**:
    - Same as test 20, but farthest peer has `last_seen` within `LIVE_THRESHOLD`. Swap-closer fails — live well-trusted peer holds its slot. Candidate rejected (or proceeds to stale revalidation if other paths exist).

23. **Routing-neighborhood stale revalidation resolves violation without swap-closer**:
    - Routing-neighborhood IP diversity check finds subnet violation. Two violating peers are stale (in different buckets). Both pinged in parallel. One responds (touch, retains slot), one fails (evicted from its bucket, disconnected, `PeerRemoved` emitted). K-closest-to-self recomputed. Violation now resolved (only one peer from that subnet remains). Swap-closer skipped. Candidate proceeds to capacity pre-check.

24. **Routing-neighborhood stale revalidation with persisting violation**:
    - Routing-neighborhood IP diversity check finds subnet violation. Two violating peers are stale. Both pinged. Both respond (touch, retain slots). Violation persists. Swap-closer runs against the remaining live violators. Farthest violator has trust < 0.7 — swap succeeds.

### Lookup Tests

25. **Local lookup correctness**:
    - Insert peers at known distances. `find_closest_nodes_local` returns them in correct XOR distance order.

26. **Local lookup with self-exclusion**:
    - Self is never returned by `find_closest_nodes_local`.

27. **Network lookup convergence**:
    - Mock network with known topology. Iterative lookup converges to the true K-closest peers within `MAX_LOOKUP_ITERATIONS`.

28. **Network lookup records trust penalties**:
    - Failed query records `ConnectionFailed` or `ConnectionTimeout`. Successful queries do not generate trust events (expected baseline).

29. **Network lookup includes self in result**:
    - Self competes on distance in network lookup results but is never queried.

30. **FIND_NODE response truncation at MAX_PEERS_PER_RESPONSE**:
    - Remote peer returns 50 peers in a `FIND_NODE` response. `MAX_PEERS_PER_RESPONSE = 20`. Only the 20 closest to the lookup key are accepted. Remaining 30 are silently dropped.

### Maintenance Tests

31. **Touch moves to tail**:
    - Peer at head of bucket. `touch_node` moves it to tail. Other peers shift forward.

32. **Touch merges address**:
    - Peer touched with new address. New address prepended. Old address retained. List capped at `MAX_ADDRESSES_PER_NODE`.

33. **Self-lookup discovers new close peers**:
    - Peers join network closer to self. Self-lookup discovers them. They pass admission and enter routing table.

34. **Bucket refresh populates stale bucket**:
    - Distant bucket has been idle for > `STALE_BUCKET_THRESHOLD`. Refresh finds peers for that region and populates the bucket.

35. **KClosestPeersChanged event emission**:
    - Insert a peer into a bucket that affects the K-closest-to-self set. `KClosestPeersChanged` emitted with correct old and new sets. Insert a peer into a distant bucket that does NOT affect the K-closest set. `KClosestPeersChanged` is NOT emitted. Verify at-most-once semantics: a single admission with multiple swaps emits the event at most once.

36. **Blocked peer eviction**:
    - Peer trust drops below 0.15 after failed interaction. Peer is immediately removed from routing table and disconnected.

37. **Blocked peer inbound connection rejected**:
    - Blocked peer initiates inbound connection. Transport identifies peer during authentication, checks trust score, rejects connection. No resources allocated, no routing table interaction.

38. **Blocked peer skipped in lookup results**:
    - Blocked peer appears in `FIND_NODE` response. Local node checks trust, finds it below `BLOCK_THRESHOLD`. Peer silently skipped — not dialed.

39. **Blocked peer re-admission via lookup discovery after trust recovery**:
    - Previously blocked peer's trust decays back above `BLOCK_THRESHOLD`. Peer appears in `FIND_NODE` response. Local node dials, authenticates, and admits through normal admission flow.

### Bootstrap Tests

40. **Cold start populates routing table**:
    - Empty routing table. Bootstrap peers respond to `FIND_NODE(self)`. Returned peers admitted. Self-lookup expands neighborhood.

41. **Warm restart from cache**:
    - Close group cache loaded into trust subsystem and dial queue. Cached peers dialed and authenticated successfully. Admitted via standard admission flow. Self-lookup refines.

42. **Warm restart with stale cache**:
    - All cached peers unreachable. Falls back to bootstrap peers. Routing table eventually populated.

43. **Close group cache save/load roundtrip**:
    - Save K closest peers + trust scores. Restart. Load cache. Trust scores match (no decay for offline time). Addresses preserved.

44. **Cold start emits BootstrapComplete on lookup completion**:
    - Empty routing table. Bootstrap peers contacted, self-lookup and bucket refreshes run. When all bootstrap lookups complete, `BootstrapComplete { num_peers }` emitted with correct routing table size. Event fires exactly once.

45. **Warm restart emits BootstrapComplete**:
    - Close group cache loaded. Cached peers dialed. Self-lookup and bucket refreshes complete. `BootstrapComplete` emitted. Event fires exactly once regardless of cold/warm path.

46. **Auto re-bootstrap on routing table depletion**:
    - All peers blocked or departed. `routing_table_size()` drops below `AUTO_REBOOTSTRAP_THRESHOLD`. Bootstrap process automatically triggered. Bootstrap peers dialed, self-lookup runs. Routing table repopulated. `BootstrapComplete` emitted.

### Security Tests

47. **IP diversity blocks Sybil cluster**:
    - Attacker attempts to insert 10 peers from one IP. Only 2 admitted per scope. Remaining 8 rejected.

48. **Subnet diversity limits concentration**:
    - Attacker attempts to fill a bucket from one `/24`. At most 5 admitted (K/4). Remaining rejected.

49. **Trust protection prevents eclipse displacement (live peers)**:
    - Attacker generates IDs closer to target. Existing well-trusted peers (≥ 0.7) with `last_seen` within `LIVE_THRESHOLD` hold their slots. Attacker can only displace low-trust, stale, or empty slots.

50. **Stale trust-protected peer displaced by attacker**:
    - Existing well-trusted peer (≥ 0.7) has `last_seen` older than `LIVE_THRESHOLD`. Attacker with closer ID displaces it via swap-closer. This is correct behavior — a stale peer should not block a live candidate, even if the candidate is an attacker. The live candidate will be evaluated on its own behavior going forward.

51. **Unauthenticated peer rejected**:
    - Peer returned by `FIND_NODE` but not yet authenticated. Not admitted to routing table. Must complete handshake first.

52. **Blocked peer messages dropped**:
    - Peer below block threshold sends DHT message. Message silently dropped. No routing table interaction.

### Consumer Trust Reporting Tests

53. **Consumer reward improves trust**:
    - Peer starts at neutral trust (0.5). Consumer reports `ApplicationSuccess(1.0)`. Trust score increases above 0.5 (exact value determined by EMA smoothing factor). Peer remains in routing table.

54. **Consumer penalty degrades trust to blocking**:
    - Peer starts at neutral trust (0.5). Consumer reports repeated `ApplicationFailure(3.0)` events. Trust score decreases with each event. After sufficient events, score drops below `BLOCK_THRESHOLD` (0.15). Peer is evicted from routing table and blocked (Section 7.4).

55. **Consumer penalty triggers blocking and eviction**:
    - Peer is in routing table with trust slightly above `BLOCK_THRESHOLD`. Consumer reports `ApplicationFailure(weight)` sufficient to push score below `BLOCK_THRESHOLD`. Peer is immediately evicted from routing table, disconnected at transport layer, and blocked from re-admission. `PeerRemoved` event emitted.

56. **Consumer event for peer not in routing table**:
    - Peer has no routing table entry. Consumer reports `ApplicationFailure(2.0)`. Trust engine records the event and updates the EMA score (decreases from neutral 0.5). Routing table is unchanged. If the peer later attempts admission, the recorded low trust may cause rejection (Section 7.1 step 4).

57. **Consumer rewards restore trust protection**:
    - Peer has trust below `TRUST_PROTECTION_THRESHOLD` (0.7). Consumer reports enough `ApplicationSuccess` events to push the EMA above 0.7. Peer now resists swap-closer eviction (Invariant 8, if also live).

58. **Consumer and internal events combine in same EMA**:
    - Peer has moderate trust. Consumer reports `ApplicationSuccess(1.0)` then `ApplicationFailure(3.0)`. Both feed the same EMA. The weighted failure has more influence than the unit-weight success, so the net score decreases.

59. **Consumer trust query reflects all event sources**:
    - Peer has trust shaped by a mix of internal and consumer-reported events, all processed through the same EMA. `peer_trust(P)` returns the single EMA-derived score.

60. **Higher weight produces larger score impact**:
    - Two peers start at identical neutral trust. Consumer reports `ApplicationFailure(1.0)` for peer A and `ApplicationFailure(5.0)` for peer B. Peer B's trust decreases more than peer A's. Both decreases are bounded by EMA smoothing.

61. **Weight clamping at MAX_CONSUMER_WEIGHT**:
    - Consumer reports `ApplicationFailure(100.0)` with `MAX_CONSUMER_WEIGHT = 5.0`. Weight is clamped to 5.0. Score impact is identical to `ApplicationFailure(5.0)`.

62. **Zero and negative weights rejected**:
    - Consumer reports `ApplicationFailure(0.0)`. Event is rejected (no-op). Trust score unchanged. Consumer reports `ApplicationSuccess(-1.0)`. Event is rejected (no-op). Trust score unchanged.

63. **Time decay applies to consumer events**:
    - Consumer reports `ApplicationFailure(3.0)` for a peer. Trust decreases. Peer has no further interactions for an extended period. Trust decays back toward neutral (0.5). Consumer-reported events do not persist indefinitely — they are subject to the same time decay as internal events.

## 16. Acceptance Criteria for This Design

The design is logically acceptable for implementation when:

1. All invariants in Section 5 can be expressed as executable assertions.
2. Every scenario in Section 15 has deterministic pass/fail expectations.
3. IP diversity, trust protection, and swap-closer interact without deadlock or starvation under all tested topologies.
4. Bootstrap, warm restart, and churn scenarios produce stable routing table states within bounded time.
5. Security properties (Sybil resistance, eclipse resistance, poisoning resistance) degrade gracefully rather than failing catastrophically.
