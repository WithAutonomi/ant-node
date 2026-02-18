# Record Replication Design

## Overview

This document describes how record replication works in a Kademlia-based decentralized storage network with one-time payments and permanent storage. There is no publisher republishing, no ongoing payments, and no erasure coding. Records are fully replicated across multiple nodes. The replication system keeps records durable despite continuous node churn.

Standard Kademlia replication is designed for ephemeral data with TTLs and publisher-driven republishing. This design replaces that with a multi-tiered, pull-based, churn-aware scheme built for permanent storage without a publisher.

This design is for the node-level replication pipeline implemented in `saorsa-node`. It does **not** use `saorsa-core`'s replication manager APIs.

## Key Differences from Standard Kademlia

| Standard Kademlia | This Design |
|---|---|
| Publisher must republish every hour | No publisher involvement after initial upload |
| Records expire after 24 hours | Records are permanent |
| Push full records to k closest nodes | Push key lists, receivers pull what they need |
| Single republish timer | Three replication tiers at different timescales |
| Fixed replication to k closest | Dynamic responsible distance range based on network density |
| Accept stores from anyone | Sender validation, quorum requirement, range checks |
| No verification of stored data | Batched random-range chunk proofs with burst audits |
| No concept of node quality | Bad node detection with eviction |
| Blind reaction to topology changes | Churn-aware triggering with restart suppression |

## Core Constants

| Constant | Value | Purpose |
|---|---|---|
| `CLOSE_GROUP_SIZE` | 8 | Closest-peer set size used for replication lookups |
| `REPLICATION_FACTOR` | 8 | Maximum number of nodes holding each record (when network has capacity) |
| `MIN_REPLICATION_FACTOR` | 4 | Floor replication factor under storage pressure |
| `MAX_RECORDS_COUNT` | `storage.max_chunks` when `> 0` | Max records per node before considered full (capacity-managed mode only) |
| `PERIODIC_REPLICATION_INTERVAL_MAX_S` | 180 | Upper bound of randomised interval replication timer |
| `MIN_REPLICATION_INTERVAL_S` | 30 | Global cooldown between replication runs |
| `MAX_PARALLEL_FETCH` | 5 | Concurrent record fetch limit (normal operation) |
| `MAX_PARALLEL_FETCH_BOOTSTRAP` | 20 | Concurrent record fetch limit during bootstrap sync |
| `MAX_PARALLEL_QUORUM_CHECKS` | 16 | Concurrent receiver-side quorum verifications |
| `REPLICATION_KEYS_PAGE_TARGET_BYTES` | 262,144 (256 KiB) | Target serialized size for key-list pages |
| `REPLICATION_KEYS_PAGE_MAX_KEYS` | 4096 | Hard upper bound of keys in one key-list page |
| `FETCH_TIMEOUT` | 20s | Per-fetch timeout |
| `PENDING_TIMEOUT` | 900s (15 min) | Time-to-live for unfetched entries |
| `QUORUM_RESPONSE_TIMEOUT` | 3s | Receiver-side quorum probe deadline for unknown keys |
| `QUORUM_RETRY_BACKOFF` | 60s | Backoff before re-probing a key after failed quorum |
| `REPLICATION_TIMEOUT` | 45s | Per-target deduplication window |
| `REPLICATION_DEADLINE_SECS` | 4 days | Network-wide replication cycle duration |
| `NETWORK_WIDE_REPLICATION_INTERVAL` | 15 min | How often network-wide replication fires |
| `REPLICATION_SENDER_CLOSE_GROUP_THRESHOLD` | `CLOSE_GROUP_SIZE` (8) | Sender must be in close group to be a valid replication source |
| `CLOSE_GROUP_TRACKING_LIMIT` | 20 | Peers tracked for churn suppression |
| `CLOSE_GROUP_RESTART_SUPPRESSION` | 90s | Suppression window for peer restart detection |
| `AUDIT_RANGE_BYTES` | 4096 | Random byte-range size per challenged chunk |
| `AUDIT_BATCH_SIZE` | 8 | Number of chunks challenged per normal audit |
| `AUDIT_BURST_BATCH_SIZE` | 32 | Number of chunks challenged per burst audit |
| `AUDIT_RESPONSE_TIMEOUT` | 5s | Max time for full batched audit response |
| `AUDIT_ESCALATION_THRESHOLD` | 3 in 10 min | Failed normal audits before escalating to burst mode |
| `BURST_AUDIT_REPLICATION_FAILURES` | 1 | Failed burst audit emits one `ReplicationFailure` |

**Capacity model alignment (current codebase):**
- Source of truth for capacity is `StorageConfig.max_chunks` (`src/config.rs`), not a hard-coded replication constant.
- Current default is `max_chunks = 0` (unlimited). In this mode, the node reports `Unbounded` capacity and still influences dynamic RF as low pressure.
- Dynamic RF uses both finite-capacity and unbounded-capacity reports.
- Recommended production profile: set an explicit finite `storage.max_chunks` (for example, 16384) so capacity pressure and dynamic RF are observable.

**Wire-size safety constraint:**
- The ANT chunk protocol decoder enforces a maximum wire message size of 5 MiB (`src/ant_protocol/chunk.rs`, `MAX_WIRE_MESSAGE_SIZE`).
- Replication key-list exchange must use pagination/chunking and never send unbounded key vectors in one message.

## Architecture: Three Replication Tiers

The system uses three complementary replication modes operating at different timescales. Each tier catches failures that the others miss.

```
Tier 1: Interval Replication    (every 90-180s)     Neighbour sync
Tier 2: Fresh Replication       (immediate)          New upload fast-path
Tier 3: Network-Wide Replication (every 15 min)      Proactive repair
```

### Tier 1: Interval Replication

**Purpose:** Keep nearby nodes synchronised with each other.

**Triggers:**
- A periodic timer fires every 90-180 seconds (randomised per node to prevent synchronisation spikes across the network)
- A peer is added to the routing table (new node joined the neighbourhood)
- A peer is removed from the routing table (node left)

**Flow:**

```
1. Node gathers all its local record keys
2. Selects up to `effective_rf` closest peers within responsible distance range
3. For each selected peer, split keys into pages (`<= REPLICATION_KEYS_PAGE_MAX_KEYS`, target `REPLICATION_KEYS_PAGE_TARGET_BYTES` serialized)
4. Send paginated `ChunkMessageBody::ReplicationOfferRequest` pages (`offer_id`, `page_index`, `has_more`)
5. Receiver diffs each page against its own store and accumulates unknown keys per `offer_id`
6. After the final page (`has_more = false`), receiver starts quorum checks for accumulated unknown keys using `ReplicationPresenceRequest`
7. If quorum passes, receiver queues the key in its ReplicationFetcher
8. ReplicationFetcher sends `ChunkMessageBody::ReplicatedRecordGetRequest` to a quorum-confirmed holder
9. Received records are validated and stored
```

**Key property:** Only key lists are pushed, not full records. Receivers pull what they need. This is bandwidth-efficient because most neighbours already hold most of the same records.

**Paging requirement:** Tier 1 key lists are always paged. Receivers may discard malformed page streams (for example, duplicate or out-of-order `page_index` for the same `offer_id`).

**Rate limiting:**
- **Global cooldown (30s):** If interval replication ran within the last 30 seconds, skip. Prevents rapid-fire replication from multiple routing table events.
- **Per-target dedup (45s):** Track which peers were recently sent to. Don't re-send to the same peer within the dedup window.
- **Restart suppression (90s):** A `CloseGroupTracker` monitors the closest 20 peers. If a peer is removed and quickly re-added (node restart), suppress replication for 90 seconds. Only trigger on genuine topology changes.

### Tier 2: Fresh Replication

**Purpose:** Quickly replicate newly uploaded data to its full replication factor without waiting for the next interval timer.

**Trigger:** A node receives and validates a new record from a client upload.

**Flow:**

```
1. Node stores the record locally
2. Sends `ChunkMessageBody::FreshReplicationOfferRequest` to `effective_rf` closest peers for that record's address
3. Message includes payment proof so receivers can verify the record is legitimately paid for
4. Receivers validate payment and fetch the record immediately
```

**Key property:** Fresh records bypass the normal quorum requirement (see Sybil Resistance below) because they carry payment proof. They also bypass the parallel fetch capacity limit and are fetched immediately without queueing.

**Payment rule for Tier 2:** `FreshReplicationOfferRequest` must include `ProofOfPayment` for each key. A fresh-replication fetch is rejected if proof is missing or invalid.

### Tier 3: Network-Wide Replication

**Purpose:** Proactive repair. Actively verifies that records exist at their target close group and replicates to any nodes that are missing them. This is the most thorough mode and catches anything interval replication missed.

**Trigger:** A background timer fires every 15 minutes.

**Flow:**

```
1. Check record store for records not yet verified
2. Calculate how many keys to process this cycle (paced across a 4-day deadline)
3. For each selected record:
   a. Kademlia lookup: find the CLOSE_GROUP_SIZE closest peers to the record's address
   b. Query each peer via `ChunkMessageBody::ReplicationPresenceRequest`: "Do you have this record?"
   c. For any peer that does NOT have it: send `ChunkMessageBody::ReplicationOfferRequest` directly to that peer
      (receiver validates via its own quorum check before fetching)
   d. Let `holders` be peers that answered "present" for the record.
      If `holders < ceil(effective_rf / 2)`, mark the record as severely under-replicated and prioritise immediate repair
```

**Pacing:** The 4-day deadline ensures all records are verified within a complete cycle. The number of keys processed per 15-minute interval is dynamically calculated:
- Few records: space them out evenly across the deadline
- Many records: process proportionally more per interval

**Replica-count prioritisation:** Each Tier 3 query reveals how many close group peers hold the record. This count is stored per record and used to prioritise future batches:

1. After querying a record, store its observed replica count and timestamp
2. When selecting the next batch, sort by last-observed replica count ascending — records with the fewest replicas are checked first
3. Records never scanned (new to the store) are assigned default priority (assume they are at `effective_rf`)
4. If a record is found below `MIN_REPLICATION_FACTOR` during a batch, repair it immediately — do not wait for the next pacing interval

This ensures that the most vulnerable records are always verified and repaired first. After the first full cycle, the node has replica counts for all its records and can focus repair effort where it matters most.

**Severe shortfall handling:** A record with `holders < ceil(effective_rf / 2)` is treated as severe under-replication. This increases repair priority only; it does not relax receiver sender-validation rules.

## Receiver-Side Filtering

When a node receives a replication key list, it applies these filters in order before fetching anything:

### 1. Source Validation

The sender must be a known peer in the node's close group (`CLOSE_GROUP_SIZE` closest peers). Reject replication from distant or unknown nodes.

**Rationale:** Prevents random nodes across the network from flooding a node with replication requests. Only neighbours who should plausibly hold the same records can trigger replication.

### 2. Already Stored

Skip keys already present in the local record store.

### 3. Already Pending

Skip keys already queued for fetch or already in `PendingVerify`.

### 4. Range Check

Only accept records within the node's responsible distance range. Records too far away in XOR space are another node's responsibility.

### 5. Receiver-Driven Quorum Verification (Sybil Resistance)

For unknown keys (not already stored and not already pending), the receiver actively verifies the offer by querying close-group peers.
The required quorum scales with the current dynamic replication target:

`quorum_threshold = floor(effective_rf / 2) + 1`

With `effective_rf` in `[MIN_REPLICATION_FACTOR, REPLICATION_FACTOR]` = `[4, 8]`, this yields:
- `effective_rf = 8` -> `quorum_threshold = 5`
- `effective_rf = 7` -> `quorum_threshold = 4`
- `effective_rf = 6` -> `quorum_threshold = 4`
- `effective_rf = 5` -> `quorum_threshold = 3`
- `effective_rf = 4` -> `quorum_threshold = 3`

**Flow for one unknown key:**
1. Enter `PendingVerify` (deduped per key) and send `ReplicationPresenceRequest { key }` to close-group peers
2. Wait up to `QUORUM_RESPONSE_TIMEOUT`
3. If positives reach `quorum_threshold`, mark key `QuorumVerified` and queue for fetch
4. Fetch from one of the positive responders (not necessarily the original offer sender)
5. If quorum fails, drop from pending verification and apply `QUORUM_RETRY_BACKOFF`

**Rationale:** Keeps anti-injection quorum checks in place while avoiding repair deadlock when `effective_rf` is reduced under storage pressure.

**Exception:** Tier 2 (fresh replication) bypasses this requirement because it carries payment proof, which serves as an alternative trust signal.

### Receiver Verification State Machine

```
Idle
  -> OfferReceived
OfferReceived
  -> FilterRejected (source/range/already-stored/already-pending)
  -> PendingVerify
PendingVerify
  -> QuorumVerified      (>= quorum_threshold before timeout)
  -> QuorumFailed        (< quorum_threshold at timeout/all responses)
QuorumVerified
  -> QueuedForFetch
QueuedForFetch
  -> Fetching
Fetching
  -> Stored              (all validation checks pass)
  -> FetchFailed         (timeout/invalid response)
QuorumFailed
  -> Backoff             (QUORUM_RETRY_BACKOFF)
```

## Responsible Distance Range

Every 15 seconds, each node recalculates the XOR address range it is responsible for:

```
1. Estimate network size from K-bucket occupancy
2. Network density = MAX_ADDRESS_SPACE / estimated_network_size
3. Responsible distance = density * CLOSE_GROUP_SIZE
4. Take max(responsible_distance, distance_to_(CLOSE_GROUP_SIZE + 2)th_closest_peer)
5. Apply as cutoff to both the record store and the replication fetcher
```

**Effect:** In a small network, each node covers more address space. As the network grows, each node's responsibility shrinks. Records beyond the responsible distance are not accepted via replication and can be pruned from the store during garbage collection.

## Fetch Scheduling (ReplicationFetcher)

The `ReplicationFetcher` manages the queue of records waiting to be fetched:

```
ReplicationFetcher {
    to_be_fetched:    HashMap<(RecordKey, ValidationType, PeerId), Timeout>
    on_going_fetches: HashMap<(RecordKey, ValidationType), (PeerId, Timeout)>
    distance_range:   Option<Distance>
    farthest_acceptable_distance: Option<Distance>
    peers_scores:     HashMap<PeerId, (VecDeque<bool>, Instant)>
    initial_replicates: HashMap<(Address, ValidationType), HashSet<PeerId>>
    quorum_pending:   HashMap<(Address, ValidationType), QuorumState>
}
```

**Scheduling rules:**
- **Max parallel fetches: 5.** No more than 5 concurrent record downloads. Additional keys queue in `to_be_fetched`.
- **Max parallel quorum checks: 16.** No more than 16 simultaneous `PendingVerify` quorum probes.
- **Closest-first ordering:** The fetch queue is sorted by XOR distance to self before selecting the next batch. The most relevant records are fetched first.
- **Fetch timeout: 20 seconds.** If a fetch does not complete within 20 seconds, it is considered failed. The slot is freed and the holder is marked as a failed source.
- **Pending timeout: 15 minutes.** Entries in `to_be_fetched` that are not fetched within 15 minutes are discarded.
- **Quorum gate:** Unknown keys are queued for fetch only after quorum verification succeeds (Tier 2 is the only bypass).

**Full node behaviour (`storage.max_chunks > 0`):** When the record store reaches `MAX_RECORDS_COUNT` and a new record arrives within the responsible distance range:
- Evict the farthest stored record that is **outside** the current responsible distance range (this record is now another, closer node's responsibility)
- Accept the new record in its place
- If no stored records are outside the responsible range, the node cannot accept the new record (the dynamic replication factor should make this rare — see below)
- Periodically prune records that have drifted outside the responsible range as the network grows and ranges shrink

If `storage.max_chunks == 0` (unlimited), this full-node path does not apply and the node reports `Unbounded` capacity in replication offers.

## Dynamic Replication Factor

The replication factor is not fixed — it scales down as the network's storage capacity tightens, and recovers as capacity frees up. This prevents the network from grinding to a halt when nodes approach their storage limits.

### Close Group Pressure (From Capacity Signals)

Each node reports a capacity signal to close group peers during Tier 1 interval replication alongside key lists:

```
if storage.max_chunks > 0:
    holder_capacity = Finite { fullness: record_count / storage.max_chunks }
else:
    holder_capacity = Unbounded
```

Map each received capacity signal to a pressure sample:

```
Finite { fullness } -> clamp(fullness, 0.0, 1.0)
Unbounded          -> 0.0
```

Compute **close group pressure** using a robust estimator across the `CLOSE_GROUP_SIZE` closest peers:

```
close_group_pressure = median(pressure_samples)
```

### Effective Replication Factor

The effective replication factor is linearly interpolated between `REPLICATION_FACTOR` and `MIN_REPLICATION_FACTOR` based on close group pressure:

```
if capacity_reports < floor(CLOSE_GROUP_SIZE / 2) + 1:
    effective_rf = REPLICATION_FACTOR                    // pressure unknown
else if close_group_pressure <= 0.5:
    effective_rf = REPLICATION_FACTOR                    // 8
else if close_group_pressure >= 0.9:
    effective_rf = MIN_REPLICATION_FACTOR                // 4
else:
    // Linear scale between 50% and 90% pressure
    pressure = (close_group_pressure - 0.5) / 0.4
    effective_rf = round(REPLICATION_FACTOR - pressure * (REPLICATION_FACTOR - MIN_REPLICATION_FACTOR))
```

| Close group pressure | Effective RF |
|---|---|
| ≤ 50% | 8 |
| 60% | 7 |
| 70% | 6 |
| 80% | 5 |
| ≥ 90% | 4 |

### Where It Applies

All three replication tiers use `effective_rf` instead of the static `REPLICATION_FACTOR`:

- **Tier 1:** Send key lists to `effective_rf` closest peers instead of `REPLICATION_FACTOR`
- **Tier 2:** Fresh-replicate new records to `effective_rf` closest peers
- **Tier 3:** When verifying a record's replication, the target replica count is `effective_rf`, not `REPLICATION_FACTOR`

### Recovery

When capacity frees up (new nodes join, responsible ranges shrink, out-of-range records are pruned), close group pressure drops and `effective_rf` rises. Tier 3 network-wide replication naturally detects under-replicated records (records with fewer holders than the current `effective_rf`) and replicates them to additional peers.

### Why This Works With Out-of-Range Eviction

The two mechanisms are complementary:

1. **Dynamic RF reduces inflow.** Fewer replicas per record means each node receives fewer replication requests, slowing the rate at which nodes fill up.
2. **Out-of-range eviction creates outflow.** As the network grows or stabilises, responsible ranges shrink and records at the edges drift outside range, becoming evictable.
3. **Together they prevent the deadlock** where every node is full, all records are within range, and nothing can be evicted. Reducing RF from 8 to 4 halves the per-record storage footprint across the network, which means fewer records per node, which means more records drift outside responsible ranges, which means more can be evicted.

## Bad Node Detection

Track replication failures per peer to identify and evict misbehaving nodes:

### Failure Tracking

When a fetch from a peer times out (20 seconds), or a burst audit fails:
1. Record a `ReplicationFailure` against that peer
2. Remove all other pending fetches from that peer (they are likely to fail too)
3. Fire a local replication-failure event (`FailedToFetchHolders` for fetch failures; audit-failure event for audits)

### Eviction

If a peer accumulates **3 `ReplicationFailure` events within 5 minutes**:
1. Consider the peer a bad node
2. Evict it from the routing table
3. Block future replication from that peer

Eviction is a local decision based on direct observation only. There is no gossip about bad nodes — each node independently detects and evicts misbehaving peers through its own fetch timeouts and challenge failures. This prevents a malicious node from poisoning another node's reputation across the network by broadcasting false accusations.

### False Positive Prevention

Before recording a `ReplicationFailure`, check whether the record has since been stored locally (e.g., fetched from a different peer). If so, the failure is stale — do not penalise the peer.

## Proof of Storage (Verification)

Nodes periodically verify that neighbours actually store chunks they claim to hold. The primary threat is the **outsourcing attack**: a node that does not store data locally and fetches it from another node only when challenged.

### Batched Random-Range Audit

Chunks are stored as whole files on disk. Verification challenges random byte ranges within those chunks.

```
1. Challenger creates `challenge_id` and random `nonce`
2. Challenger selects X chunks the target should hold
3. For each selected chunk, challenger picks random (offset, length)
   where `length = AUDIT_RANGE_BYTES` (or remaining bytes if near end)
4. Challenger sends one batched audit request with all challenge items
5. Target reads each requested byte range from local chunk files
6. For each item, target computes:
   proof_i = SHA3-256(
       "saorsa-repl-proof-v1" ||
       challenge_id ||
       target_peer_id ||
       chunk_address ||
       offset || length ||
       chunk_bytes[offset..offset+length] ||
       nonce
   )
7. Target returns all proofs in a single batched response
8. Challenger recomputes proofs from local copies and verifies all items
```

**Replay resistance:** Binding proofs to `challenge_id`, `nonce`, and `target_peer_id` prevents replay across time, across peers, or across different challenge sets.

**Important:** Never use only `hash(chunk_address || nonce || peer_id)` as a proof. `chunk_address` is public and does not prove possession of content bytes.

### Audit Modes

- **Normal audit:** `AUDIT_BATCH_SIZE` items per audit.
- **Burst audit:** `AUDIT_BURST_BATCH_SIZE` items when a node repeatedly fails normal audits.
- **Deadline:** The full batched response must arrive before `AUDIT_RESPONSE_TIMEOUT`.

### Failure and Escalation

- Audit failure conditions: timeout, missing proof item, invalid proof item, malformed response.
- `AUDIT_ESCALATION_THRESHOLD` failed normal audits within 10 minutes triggers burst mode for that peer.
- A failed burst audit emits `BURST_AUDIT_REPLICATION_FAILURES` `ReplicationFailure` event(s).
- Eviction remains local and unchanged: accumulated `ReplicationFailure` events drive bad-node eviction.

### Why This Works

- Honest nodes can read X random ranges from local disk and hash them quickly.
- Outsourcing nodes must fetch unpredictable ranges from third parties during the challenge window, which adds extra network latency/bandwidth pressure and fails more often under batched deadlines.
- Verification uses only local observations; no cross-peer timing sharing or gossip is required.

## Protocol Messages

Replication is implemented as a planned extension of the existing ANT chunk protocol (`ChunkMessage` + `ChunkMessageBody`) in this repository. It does not introduce a separate `Cmd::`/`Query::` transport layer.

### ANT Replication Message Families (Planned)

```
ChunkMessageBody::ReplicationOfferRequest {
    holder: NetworkAddress,
    offer_id: [u8; 16],    // stable ID across pages in one offer stream
    page_index: u32,       // 0-based, strictly increasing per offer_id
    has_more: bool,        // false marks the final page
    keys: Vec<(NetworkAddress, ValidationType)>,
    holder_capacity: CapacitySignal,
}
ChunkMessageBody::ReplicationOfferResponse { ... }

ChunkMessageBody::FreshReplicationOfferRequest {
    holder: NetworkAddress,
    keys: Vec<(NetworkAddress, DataType, ValidationType, Option<ProofOfPayment>)>,
}
ChunkMessageBody::FreshReplicationOfferResponse { ... }

ChunkMessageBody::ReplicatedRecordGetRequest {
    key: RecordKey,
}
ChunkMessageBody::ReplicatedRecordGetResponse { ... }

ChunkMessageBody::ReplicationPresenceRequest {
    key: RecordKey,
}
ChunkMessageBody::ReplicationPresenceResponse {
    present: bool,
}

ChunkMessageBody::ReplicationKeyListRequest {
    range: Distance,
    cursor: Option<Vec<u8>>, // opaque pagination cursor from prior response
    limit: u32,              // requested max keys for this page (<= REPLICATION_KEYS_PAGE_MAX_KEYS)
}
ChunkMessageBody::ReplicationKeyListResponse {
    keys: Vec<(NetworkAddress, ValidationType)>,
    next_cursor: Option<Vec<u8>>, // None means pagination complete
}

ChunkMessageBody::ReplicationAuditRequest {
    challenge_id: [u8; 16],
    nonce: [u8; 32],
    target_peer_id: NetworkAddress,
    items: Vec<(RecordKey, u32, u32)>, // (key, offset, length)
}
ChunkMessageBody::ReplicationAuditResponse {
    challenge_id: [u8; 16],
    proofs: Vec<[u8; 32]>,
}
```

Where:

```
enum CapacitySignal {
    Finite { fullness: f32 }, // clamped to [0.0, 1.0]
    Unbounded,                // storage.max_chunks == 0
}
```

For key-list paging, senders must enforce:
- page-size target of `REPLICATION_KEYS_PAGE_TARGET_BYTES` serialized bytes
- hard key-count cap of `REPLICATION_KEYS_PAGE_MAX_KEYS`
- total wire size below protocol `MAX_WIRE_MESSAGE_SIZE` (5 MiB)

`ReplicationPresenceRequest/Response` is used in two places:
- Tier 3 proactive scans (auditor asks peers whether they hold a key)
- Receiver-driven quorum verification (offer receiver confirms unknown keys before fetch)

## Payment Validation Modes

Replication uses two payment-validation paths:

1. **Fresh path (Tier 2): proof-required**
   - Trust signal: cryptographic `ProofOfPayment`
   - Transport: proof is carried in `FreshReplicationOfferRequest`
   - Rule: receiver must verify proof before storing

2. **Repair path (Tier 1/Tier 3): quorum-authorized**
   - Trust signal: receiver-side quorum (`floor(effective_rf / 2) + 1` positive presence responses)
   - Transport: replicated pull (`ReplicatedRecordGet*`) does not require payment proof material
   - Rule: receiver only fetches after quorum success, then applies normal integrity/range/type checks before store

This separation avoids requiring payment proof on routine repair traffic while preserving anti-injection protection through receiver-side quorum confirmation.

## Record Validation on Storage

When a fetched record arrives, validate it before writing to the local store:

1. **Type check:** Record type is known and well-formed (Chunk, GraphEntry, Pointer, Scratchpad, etc.)
2. **Integrity check:** Content hash matches the record's address (content-addressable integrity)
3. **Payment authorization check:** one of:
   - Tier 2: valid `ProofOfPayment` is present and verified
   - Tier 1/Tier 3: key passed receiver-side quorum verification
4. **Range check:** The record is within the node's responsible distance range

Only after all checks pass is the record written to disk.

## Churn Handling

### Close Group Tracker

A `CloseGroupTracker` monitors the closest 20 peers and their behaviour:

```
CloseGroupTracker {
    self_address: NetworkAddress,
    close_peers: BTreeSet<(Distance, PeerId)>,    // closest 20
    tracked_entries: HashMap<PeerId, BehaviourEntry>,
}
```

**Replication directives:** When a peer is added or removed, the tracker returns one of:

| Directive | Meaning | Action |
|---|---|---|
| `Trigger` | Genuine topology change | Run interval replication |
| `Skip` | Restart detected (remove + quick re-add) | Suppress for 90 seconds |
| `Ignore` | Peer too far away to matter | Do nothing |

### Why Restart Suppression Matters

Without suppression, a node restarting generates two events (remove + add), each triggering replication to all neighbours. In a network with normal operational restarts, this creates unnecessary bandwidth spikes. The 90-second suppression window allows the restarted node to rejoin without triggering a replication storm.

## New Node Bootstrapping

When a new node joins the network, it has an empty record store but is immediately responsible for a range of the keyspace. Rather than waiting for neighbours to push key lists during their next Tier 1 cycle (up to 180 seconds away), the new node actively bootstraps its store.

### Bootstrap Flow

```
1. New node joins the network and populates its routing table via Kademlia
2. Computes its responsible distance range
3. Sends `ChunkMessageBody::ReplicationKeyListRequest { range, cursor: None, limit = REPLICATION_KEYS_PAGE_MAX_KEYS }` to all CLOSE_GROUP_SIZE closest peers
4. For each peer, continues paging with returned `next_cursor` until `next_cursor = None`
5. Cross-references aggregated responses: keys reported by >= `floor(effective_rf / 2) + 1` peers
   are accepted (same quorum rule as normal replication, resolved in one paged round)
6. Queues all accepted keys in the ReplicationFetcher with MAX_PARALLEL_FETCH_BOOTSTRAP (20)
   concurrent fetch slots instead of the normal MAX_PARALLEL_FETCH (5)
7. Once all queued keys have been fetched (or failed), bootstrap is complete —
   the node drops to normal MAX_PARALLEL_FETCH and enters standard Tier 1 operation
```

### Why Active Bootstrap

Without active bootstrapping, the new node depends on neighbours' Tier 1 timers firing (up to 180s), followed by quorum agreement building across multiple independent Tier 1 cycles from different peers. A node could sit partially empty for several minutes while records in its range have reduced replication.

Active bootstrapping resolves quorum agreement in a single round (by querying all close group peers simultaneously) and uses an elevated fetch limit to sync quickly. The trust model is identical to normal operation — the same quorum requirement applies.

### Interaction With Other Tiers

- **Tier 1** triggers normally when neighbours detect the new node in their routing table. Any keys discovered through Tier 1 that were not in the bootstrap set are handled via the standard ReplicationFetcher path.
- **Tier 2** works immediately — the new node can receive and process fresh replication for new uploads from the moment it joins.
- **Tier 3** begins its first cycle after the node has been running for one `NETWORK_WIDE_REPLICATION_INTERVAL` (15 minutes), by which time bootstrap should be complete.

## Design Anti-Patterns (What NOT to Do)

- **Do NOT use Kademlia's built-in record republishing.** It is designed for ephemeral data with TTLs and publisher-driven refresh. It will expire your permanent records.
- **Do NOT push full records during interval replication.** Push key lists only. Let receivers pull what they need. Pushing full records wastes bandwidth when neighbours already hold most records.
- **Do NOT trigger replication on every routing table change.** Use cooldowns (30s global, 45s per-target) and restart suppression (90s) to batch changes.
- **Do NOT repair eagerly on every node departure.** Many departures are transient (restarts, temporary network issues). The interval timer and network-wide replication will catch genuine losses.
- **Do NOT accept replication from any node.** Validate sender distance (sender must be in close group) and require quorum agreement for unknown records.
- **Do NOT send unbounded key lists.** Always paginate Tier 1 offers and bootstrap key-list responses.
- **Do NOT fetch records outside the responsible distance range.** Each node should only store records it is geometrically responsible for.
- **Do NOT treat all fetches equally.** Fresh records with payment proof get priority. Regular replication fetches are queued, sorted closest-first, and limited to 5 concurrent.
- **Do NOT use a fixed replication factor when nodes are full.** A static RF causes cascading rejection when the network is at capacity. Scale RF down (to `MIN_REPLICATION_FACTOR`) based on close group pressure from capacity signals to reduce storage pressure, and evict records outside the responsible distance range to make room.
- **Do NOT gossip about bad nodes.** A "node X is bad" message from one peer is unverifiable and trivially abusable for reputation poisoning. Each node must detect and evict bad peers based on its own direct observations (fetch timeouts, challenge failures) only.

## Summary

```
          Frequency       Scope              Mechanism           Purpose
Tier 1    90-180s         Closest peers       Paged key-list diff + quorum probe  Neighbour sync
Tier 2    Immediate       Record close group  Payment-verified    New upload propagation
Tier 3    15 min          Network-wide        Query + push        Proactive repair

Protection      Mechanism
Sybil           Receiver-driven quorum check (need floor(effective_rf/2)+1 positive responses)
Bad nodes       Failure tracking + eviction after 3 failures in 5 min
Bandwidth       Paged key-list diffing, cooldowns, parallel fetch limit, closest-first ordering
Churn           Restart suppression, adaptive distance range, severe-shortfall repair prioritisation
Bootstrap       Active paged key-list query + quorum agreement in one round, elevated fetch parallelism
Verification    Batched random-range chunk proofs with burst audits
Full nodes      Out-of-range eviction, dynamic RF (8→4) based on close group pressure
```
