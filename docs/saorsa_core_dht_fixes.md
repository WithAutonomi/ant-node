# saorsa-core DHT Fixes Required for Merkle Payment Close Group Stability

## Problem Statement

Merkle payments require that independently querying the DHT for the "closest nodes to address X" returns the same set of nodes regardless of which node performs the query. Our testing shows this invariant breaks at scale because **saorsa-core's DHT routing tables are severely underpopulated**.

### Measured Data (ant-node e2e tests, localhost, no churn, no geo-filtering)

| Network Size | Transport Connections | DHT Routing Table Discovery | Gap |
|-------------|----------------------|----------------------------|-----|
| 25 nodes | 22.7/25 (90.8%) | 12.2/25 (48.8%) | 42% |
| 100 nodes | ~95/100 | 13.3/100 (13.3%) | ~82% |

Nodes are **connected** to nearly all peers at the transport layer, but the **DHT routing table** only incorporates a fraction of them. This gap is the root cause of close group instability.

### Impact on Merkle Payments

At 100 nodes with a close group size of K=5:
- Average ground truth overlap: 88.3% (some nodes return wrong closest peers)
- Minimum overlap: 52% (some addresses get only ~2.6/5 correct closest nodes)
- Client-to-verifier Jaccard agreement: 80.1% (only 15% exact matches)
- Payment failure rate: ~5% of addresses

At 1000+ nodes, this will be significantly worse.

## Root Cause Analysis

The DHT routing table and the transport connection table are decoupled in saorsa-core. Specifically:

1. **Transport connects eagerly** -- when a node joins, the transport layer (QUIC) establishes connections to discovered peers quickly. By the time the network stabilizes, each node is connected to ~90% of peers.

2. **DHT populates lazily** -- the Kademlia routing table only adds entries when a node is encountered during a DHT operation (`find_closest_nodes`, `put_value`, etc.). Peers that are transport-connected but never encountered during a DHT walk are invisible to the routing table.

3. **No routing table seeding from transport** -- when a new transport connection is established, the connected peer is NOT automatically added to the DHT routing table. This is the core gap.

4. **No periodic routing table refresh** -- standard Kademlia implementations perform periodic bucket refresh (RFC: "each node refreshes buckets it hasn't looked up in the last hour by picking a random ID in the bucket range and doing a find_node"). saorsa-core does not appear to implement this.

## Proposed Fixes in saorsa-core

### Fix 1: Seed DHT routing table from transport connections (Critical)

When a new transport connection is established to a peer, automatically insert that peer into the DHT routing table if the appropriate k-bucket has space (or if the peer is closer than the furthest entry in a full bucket).

```
Event: Transport connection established to peer P
Action:
  1. Compute XOR distance between self and P
  2. Determine which k-bucket P belongs to
  3. If bucket has space: insert P
  4. If bucket is full: ping the least-recently-seen entry
     - If stale: evict and insert P
     - If alive: discard P (standard Kademlia eviction)
```

This is standard Kademlia behavior described in the original paper (Maymounkov & Mazieres, 2002, Section 2.2). The key insight is that "contacts that have been around longer are more likely to remain" -- but a contact that is transport-connected is by definition reachable.

**Expected impact**: Routing table discovery should match transport connectivity (~90%), eliminating the 42-82% gap.

### Fix 2: Periodic k-bucket refresh (Important)

Implement the standard Kademlia bucket refresh protocol:

```
Every REFRESH_INTERVAL (e.g., 60 seconds):
  For each k-bucket that hasn't had a lookup in the last REFRESH_INTERVAL:
    1. Generate a random node ID within the bucket's range
    2. Perform find_closest_nodes(random_id, K)
    3. The lookup itself will populate routing table entries
```

This ensures that even if Fix 1 misses some peers (e.g., peers that join after initial transport connection), the routing table stays fresh through periodic exploration.

**Expected impact**: Prevents routing table staleness over time, especially important during churn.

### Fix 3: Expose routing table contents via API (Nice-to-have)

Currently there is no way for ant-node to inspect the DHT routing table contents. Adding an API would enable:
- Monitoring routing table health
- Debugging close group issues
- Testing routing table completeness

Suggested API additions to `P2PNode`:

```rust
impl P2PNode {
    /// Get the number of entries in the DHT routing table.
    pub fn routing_table_size(&self) -> usize;

    /// Get all peer IDs in the DHT routing table.
    pub fn routing_table_peers(&self) -> Vec<PeerId>;

    /// Get routing table bucket occupancy (for monitoring).
    pub fn routing_table_bucket_stats(&self) -> Vec<BucketStats>;
}

pub struct BucketStats {
    pub index: usize,
    pub entries: usize,
    pub capacity: usize,
    pub last_refreshed: Option<Instant>,
}
```

### Rejected: `find_closest_nodes_local`

A local-only lookup (returning closest nodes from the routing table without a network walk) was considered but **rejected**. With routing tables at 13-17% discovery, the local view is fundamentally incomplete -- the "closest" nodes in the local table may not be the actual closest nodes in the network. Using this for close group decisions would produce the exact inaccuracy this work is trying to eliminate.

A local-only lookup would only be safe **after Fix 1** (routing table seeded from transport connections), at which point routing tables would reflect ~90% of the network and local results would be reliable. Until then, iterative network lookups are the only way to get accurate closest-node results.

## Workarounds Currently in ant-node

Until saorsa-core implements these fixes, ant-node uses the following workarounds:

1. **DHT refresh background task** (`src/node.rs`) -- every 30 seconds, performs 5 random `find_closest_nodes` lookups to populate the routing table through iterative exploration. This improved discovery from 13.3% to 16.7% at 100 nodes.

2. **Multi-lookup close group confirmation** (`src/close_group.rs`) -- instead of a single DHT lookup, performs 3 independent lookups (each following different iterative paths) and requires 2/3 agreement. This partially compensates for incomplete routing tables since different lookups may discover different peers.

3. **Close group check on quotes and PUTs** (`src/storage/handler.rs`) -- both quote and PUT handlers verify the node is in the close group before responding, preventing the quote-pay-refuse failure path.

4. **Merkle candidate verification** (`src/payment/verifier.rs`) -- during merkle payment verification, the verifier checks that the winner pool candidates are actually the closest nodes to the data address via DHT lookup.

These workarounds are effective but inherently limited. They cannot compensate for the fundamental gap between transport connectivity (90%) and routing table discovery (13-17%). Fix 1 in saorsa-core would eliminate this gap entirely.

## Priority

1. **Fix 1 (routing table seeding)** -- Critical. This single change would likely resolve 90%+ of close group instability. Standard Kademlia behavior.
2. **Fix 2 (bucket refresh)** -- Important. Prevents staleness over time. Standard Kademlia behavior.
3. **Fix 3 (routing table API)** -- Nice-to-have for monitoring and debugging.

## Validation

After implementing Fix 1 and Fix 2, re-run the ant-node close group stability tests:

```bash
cargo test --test e2e --features test-utils close_group_stability -- --nocapture
```

Expected results:
- Routing table discovery: should be >80% (up from 13-17%)
- Ground truth overlap at 100 nodes: should be >95% (up from 88%)
- Quoting vs verification Jaccard at 100 nodes: should be >95% (up from 80%)
- Payment failure rate: should be <1% (down from ~5%)

## References

- Maymounkov, P. & Mazieres, D. (2002). "Kademlia: A Peer-to-peer Information System Based on the XOR Metric." Section 2.2 (k-bucket maintenance), Section 2.5 (bucket refresh).
- Wang, L. & Kangasharju, J. (2013). "Measuring Large-Scale Distributed Systems: Case of BitTorrent Mainline DHT." IEEE P2P 2013.
- ant-node PR #45: Close group stability tests and workarounds.
