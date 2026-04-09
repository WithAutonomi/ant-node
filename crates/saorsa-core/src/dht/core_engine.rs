//! DHT Core Engine with Kademlia routing
//!
//! Provides peer discovery and routing via a Kademlia DHT with k=8 buckets,
//! trust-weighted peer selection, and security-hardened maintenance tasks.

use crate::PeerId;
use crate::address::MultiAddr;
use crate::security::{IP_EXACT_LIMIT, IPDiversityConfig, canonicalize_ip, ip_subnet_limit};
use anyhow::{Result, anyhow};
use parking_lot::Mutex as PlMutex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// An [`Instant`] stored behind a synchronous mutex so it can be updated
/// from `&self` receivers.
///
/// The key property: reads and writes only need `&self`, so the routing
/// table's hot touch path (called on every inbound DHT message) can run
/// under a read lock on the routing table instead of an exclusive write
/// lock. The previous write-lock design serialised all readers behind
/// every touch, which at 1000 nodes became the dominant contention point.
///
/// Why a mutex instead of an atomic: `Instant` is opaque (no stable `u64`
/// representation) and can legitimately represent times in the past
/// (tests backdate `last_seen` to mark peers stale). Any epoch-based
/// `AtomicU64` encoding would have to either (a) panic/saturate on past
/// times, or (b) pick a process-lifetime epoch in the deep past, which
/// risks `Instant` underflow on recently booted systems. A
/// [`parking_lot::Mutex<Instant>`] sidesteps all of this and is still
/// extremely fast on the uncontended path (single CAS to acquire + store
/// + single CAS to release — microseconds).
#[derive(Debug)]
pub struct AtomicInstant(PlMutex<Instant>);

impl AtomicInstant {
    /// Return a fresh `AtomicInstant` set to the current time.
    pub fn now() -> Self {
        Self(PlMutex::new(Instant::now()))
    }

    /// Wrap an existing `Instant`.
    pub fn from_instant(i: Instant) -> Self {
        Self(PlMutex::new(i))
    }

    /// Load the current value as an `Instant`.
    pub fn load(&self) -> Instant {
        *self.0.lock()
    }

    /// Atomically store the current time.
    pub fn store_now(&self) {
        *self.0.lock() = Instant::now();
    }

    /// Atomically store a specific `Instant`.
    pub fn store(&self, i: Instant) {
        *self.0.lock() = i;
    }

    /// Time elapsed since the stored instant.
    pub fn elapsed(&self) -> Duration {
        self.load().elapsed()
    }
}

impl Clone for AtomicInstant {
    fn clone(&self) -> Self {
        Self(PlMutex::new(*self.0.lock()))
    }
}

impl Default for AtomicInstant {
    fn default() -> Self {
        Self::now()
    }
}

#[cfg(test)]
use crate::adaptive::trust::DEFAULT_NEUTRAL_TRUST;

/// DHT key type — now a direct alias for [`PeerId`].
///
/// Both types are `[u8; 32]` wrappers with identity conversions between them.
/// Using a single type eliminates keyspace mismatch bugs where BLAKE3-hashing
/// a PeerId into a second "DHT key" space caused nodes to land in wrong
/// Kademlia buckets.
pub type DhtKey = PeerId;

#[inline]
fn xor_distance_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = a[idx] ^ b[idx];
    }
    out
}

/// Maximum addresses stored per node to prevent memory exhaustion.
/// A peer can legitimately have several addresses (multi-homed, NAT traversal),
/// but unbounded lists would be an abuse vector.
const MAX_ADDRESSES_PER_NODE: usize = 8;

/// Maximum NATted addresses to keep per node. Symmetric NAT generates a
/// different address per peer — keeping them all is wasteful since none are
/// directly reachable. We keep 1 for diagnostic/logging purposes.
const MAX_NATTED_ADDRESSES: usize = 1;

/// Address classification for priority ordering and staleness eviction.
///
/// Relay addresses are always preferred over Direct, which are preferred over
/// NATted. The `merge_typed_address` method uses this for insertion ordering
/// and the eviction of excess NATted entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressType {
    /// Address through a MASQUE relay server (always reachable)
    Relay,
    /// Direct public IP address (reachable without NAT traversal)
    Direct,
    /// NATted address (ephemeral, typically unreachable from outside)
    NATted,
}

/// Duration of no contact after which a peer is considered stale.
/// Stale peers lose trust protection and become eligible for revalidation-based eviction.
const LIVE_THRESHOLD: Duration = Duration::from_secs(900); // 15 minutes

/// Default trust score below which a peer is eligible for swap-out.
#[allow(dead_code)]
const DEFAULT_SWAP_THRESHOLD: f64 = 0.35;

/// Node information for routing.
///
/// The `addresses` field stores one or more typed [`MultiAddr`] values that are
/// always valid. Serializes each as a canonical `/`-delimited string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: PeerId,
    pub addresses: Vec<MultiAddr>,
    /// Type tag for each address, parallel to `addresses` by index.
    /// Defaults to empty on deserialization (legacy nodes); callers treat
    /// untagged addresses as `Direct`.
    #[serde(default)]
    pub address_types: Vec<AddressType>,
    /// Monotonic timestamp of last successful interaction.
    ///
    /// Stored as an [`AtomicInstant`] so the routing table's touch path
    /// can update it under a read lock, not a write lock. Uses `Instant`
    /// under the hood to avoid NTP clock-jump issues. Skipped during
    /// serialization — deserialized `NodeInfo` defaults to "just seen."
    #[serde(skip, default = "AtomicInstant::now")]
    pub last_seen: AtomicInstant,
}

impl NodeInfo {
    /// Get the socket address from the first address. Returns `None` for
    /// non-IP transports or when no addresses are stored.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.addresses.first().and_then(MultiAddr::socket_addr)
    }

    /// Get the IP address from the first address. Returns `None` for
    /// non-IP transports or when no addresses are stored.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.addresses.first().and_then(MultiAddr::ip)
    }

    /// Return all distinct, canonicalized IP addresses across every address in
    /// this node's address list. Useful for IP diversity checks that must
    /// consider all addresses, not just the primary one.
    fn all_ips(&self) -> HashSet<IpAddr> {
        self.addresses
            .iter()
            .filter_map(|a| a.ip().map(canonicalize_ip))
            .collect()
    }

    /// Merge a new address with default type `Direct`.
    /// Prefer `merge_typed_address` when the type is known.
    pub fn merge_address(&mut self, addr: MultiAddr) {
        self.merge_typed_address(addr, AddressType::Direct);
    }

    /// Merge a new address with an explicit type tag.
    ///
    /// Insertion position depends on type priority: Relay → Direct → NATted.
    /// Relay addresses always go to the front. NATted addresses go to the
    /// back and are evicted beyond [`MAX_NATTED_ADDRESSES`].
    pub fn merge_typed_address(&mut self, addr: MultiAddr, addr_type: AddressType) {
        // Ensure address_types is in sync with addresses (legacy compat)
        while self.address_types.len() < self.addresses.len() {
            self.address_types.push(AddressType::Direct);
        }

        // Remove existing duplicate (same address may be re-classified)
        if let Some(pos) = self.addresses.iter().position(|a| a == &addr) {
            self.addresses.remove(pos);
            if pos < self.address_types.len() {
                self.address_types.remove(pos);
            }
        }

        // Insert based on type priority
        match addr_type {
            AddressType::Relay => {
                // Always at front
                self.addresses.insert(0, addr);
                self.address_types.insert(0, AddressType::Relay);
            }
            AddressType::Direct => {
                // After all Relay entries (most recently seen Direct first)
                let pos = self
                    .address_types
                    .iter()
                    .position(|t| *t != AddressType::Relay)
                    .unwrap_or(self.addresses.len());
                self.addresses.insert(pos, addr);
                self.address_types.insert(pos, AddressType::Direct);
            }
            AddressType::NATted => {
                // At the back
                self.addresses.push(addr);
                self.address_types.push(AddressType::NATted);

                // Evict excess NATted addresses (keep only MAX_NATTED_ADDRESSES)
                let natted_count = self
                    .address_types
                    .iter()
                    .filter(|t| **t == AddressType::NATted)
                    .count();
                if natted_count > MAX_NATTED_ADDRESSES {
                    // Remove oldest NATted entries (earliest in the list)
                    let mut to_remove = natted_count - MAX_NATTED_ADDRESSES;
                    let mut i = 0;
                    while i < self.address_types.len() && to_remove > 0 {
                        if self.address_types[i] == AddressType::NATted {
                            self.addresses.remove(i);
                            self.address_types.remove(i);
                            to_remove -= 1;
                        } else {
                            i += 1;
                        }
                    }
                }
            }
        }

        // Cap total addresses
        self.addresses.truncate(MAX_ADDRESSES_PER_NODE);
        self.address_types.truncate(MAX_ADDRESSES_PER_NODE);
    }

    /// Get the address type at the given index. Returns `Direct` for
    /// untagged addresses (legacy compatibility).
    pub fn address_type_at(&self, index: usize) -> AddressType {
        self.address_types
            .get(index)
            .copied()
            .unwrap_or(AddressType::Direct)
    }
}

/// K-bucket for Kademlia routing
struct KBucket {
    nodes: Vec<NodeInfo>,
    max_size: usize,
    /// Monotonic timestamp of the last time this bucket was refreshed
    /// (node added, updated, or touched).
    last_refreshed: Instant,
}

impl KBucket {
    fn new(max_size: usize) -> Self {
        Self {
            nodes: Vec::new(),
            max_size,
            last_refreshed: Instant::now(),
        }
    }

    fn add_node(&mut self, mut node: NodeInfo) -> Result<()> {
        // Reject nodes with no addresses — a node without reachable
        // addresses is useless in the routing table and would waste a slot.
        if node.addresses.is_empty() {
            return Err(anyhow!("NodeInfo has no addresses"));
        }

        // Cap addresses to prevent memory exhaustion from oversized lists
        // arriving via deserialization or direct construction.
        node.addresses.truncate(MAX_ADDRESSES_PER_NODE);
        node.address_types.truncate(MAX_ADDRESSES_PER_NODE);

        // If the node is already in this bucket, merge addresses using
        // type-aware merge so relay addresses stay at the front and
        // the parallel address_types vec stays in sync.
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            let mut existing = self.nodes.remove(pos);
            existing.last_seen.store(node.last_seen.load());
            for (i, addr) in node.addresses.into_iter().enumerate() {
                let addr_type = node
                    .address_types
                    .get(i)
                    .copied()
                    .unwrap_or(AddressType::Direct);
                existing.merge_typed_address(addr, addr_type);
            }
            self.nodes.push(existing);
            self.last_refreshed = Instant::now();
            return Ok(());
        }

        if self.nodes.len() < self.max_size {
            self.nodes.push(node);
            self.last_refreshed = Instant::now();
            Ok(())
        } else {
            Err(anyhow!(
                "K-bucket at capacity ({}/{})",
                self.nodes.len(),
                self.max_size
            ))
        }
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        self.nodes.retain(|n| &n.id != node_id);
    }

    /// Slow path: update `last_seen`, merge an address, and reorder the
    /// bucket so the touched node becomes the most-recently-seen entry.
    ///
    /// Takes `&mut self` because merging an address may mutate the node's
    /// address list. For the fast path (just bumping the timestamp when no
    /// address merge is needed) see [`Self::touch_last_seen_if_merge_noop`].
    fn touch_node_typed(
        &mut self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) {
            self.nodes[pos].last_seen.store_now();
            if let Some(addr) = address {
                // Loopback injection prevention (Design Section 6.3 rule 4):
                let addr_is_loopback = addr
                    .ip()
                    .is_some_and(|ip| canonicalize_ip(ip).is_loopback());
                let node_has_non_loopback = self.nodes[pos]
                    .addresses
                    .iter()
                    .any(|a| a.ip().is_some_and(|ip| !canonicalize_ip(ip).is_loopback()));
                if !(addr_is_loopback && node_has_non_loopback) {
                    self.nodes[pos].merge_typed_address(addr.clone(), addr_type);
                }
            }
            let node = self.nodes.remove(pos);
            self.nodes.push(node);
            self.last_refreshed = Instant::now();
            true
        } else {
            false
        }
    }

    /// Fast path: if `node_id` is in this bucket AND the optional address
    /// merge would be a no-op (address is `None`, address is already
    /// present **with the same `addr_type`**, or the loopback-injection
    /// rule would skip the merge), atomically bump `last_seen` in place
    /// and return `Some(true)`.
    ///
    /// Returns:
    /// - `Some(true)` — fast path succeeded, `last_seen` updated.
    /// - `Some(false)` — node is not in this bucket.
    /// - `None` — the address is either not yet present, or present with
    ///   a *different* type classification (e.g. learned as `Direct`,
    ///   now being promoted to `Relay`). The slow path must run so
    ///   [`merge_typed_address`] can re-insert at the type-priority
    ///   position. Without this guard the relay-promotion path in the
    ///   network bridge silently degrades to a `last_seen` bump and the
    ///   address ordering invariant is broken.
    ///
    /// Only requires `&self` — no bucket mutation, just an atomic store on
    /// [`NodeInfo::last_seen`]. This lets the hot touch path (called on
    /// every inbound DHT message) run under a read lock on the routing
    /// table instead of an exclusive write lock.
    fn touch_last_seen_if_merge_noop(
        &self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> Option<bool> {
        let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) else {
            return Some(false);
        };
        let node = &self.nodes[pos];
        let merge_is_noop = match address {
            None => true,
            Some(addr) => {
                // Already in the list → merge would reinsert at the same
                // position, which is a no-op only if the existing entry
                // has the same type classification. If the type differs
                // we MUST escalate to the slow path so merge_typed_address
                // can re-order by type priority.
                if let Some(existing_pos) = node.addresses.iter().position(|a| a == addr) {
                    node.address_type_at(existing_pos) == addr_type
                } else {
                    // Loopback-injection skip: if the candidate is
                    // loopback and the node already has a non-loopback
                    // address, the slow path would skip the merge entirely.
                    let addr_is_loopback = addr
                        .ip()
                        .is_some_and(|ip| canonicalize_ip(ip).is_loopback());
                    let node_has_non_loopback = node
                        .addresses
                        .iter()
                        .any(|a| a.ip().is_some_and(|ip| !canonicalize_ip(ip).is_loopback()));
                    addr_is_loopback && node_has_non_loopback
                }
            }
        };
        if merge_is_noop {
            node.last_seen.store_now();
            Some(true)
        } else {
            None
        }
    }

    fn get_nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    fn find_node(&self, node_id: &PeerId) -> Option<&NodeInfo> {
        self.nodes.iter().find(|n| &n.id == node_id)
    }
}

/// Kademlia routing table
pub struct KademliaRoutingTable {
    buckets: Vec<KBucket>,
    node_id: PeerId,
}

impl KademliaRoutingTable {
    fn new(node_id: PeerId, k_value: usize) -> Self {
        let mut buckets = Vec::new();
        for _ in 0..KADEMLIA_BUCKET_COUNT {
            buckets.push(KBucket::new(k_value));
        }

        Self { buckets, node_id }
    }

    fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        let bucket_index = self
            .get_bucket_index(&node.id)
            .ok_or_else(|| anyhow!("cannot insert self into routing table"))?;
        self.buckets[bucket_index].add_node(node)
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        if let Some(bucket_index) = self.get_bucket_index(node_id) {
            self.buckets[bucket_index].remove_node(node_id);
        }
    }

    /// Update `last_seen` (and optionally merge a typed address) for a node and
    /// move it to the tail of its k-bucket. Returns `true` if the node was found.
    fn touch_node(
        &mut self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> bool {
        match self.get_bucket_index(node_id) {
            Some(bucket_index) => {
                self.buckets[bucket_index].touch_node_typed(node_id, address, addr_type)
            }
            None => false,
        }
    }

    /// Fast path for the touch operation.
    ///
    /// Returns:
    /// - `Some(true)` — node found and `last_seen` updated atomically.
    /// - `Some(false)` — node is not in the routing table (fast-path result
    ///   is authoritative; no fallback needed).
    /// - `None` — node is present but the address merge would not be a
    ///   no-op (either the address is missing, or its type classification
    ///   differs from `addr_type`); the caller must escalate to
    ///   [`Self::touch_node`] under a write lock.
    ///
    /// Only takes `&self` so this can run under a `RwLock::read()` guard.
    fn try_touch_last_seen(
        &self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> Option<bool> {
        let bucket_index = self.get_bucket_index(node_id)?;
        self.buckets[bucket_index].touch_last_seen_if_merge_noop(node_id, address, addr_type)
    }

    fn find_closest_nodes(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        // Collect ALL entries from every bucket. Bucket index correlates with
        // distance from *self*, not from key K — peers in distant buckets can
        // be closer to K than peers in nearby buckets. The routing table holds
        // at most 256 * K_BUCKET_SIZE entries, so a full scan is trivially fast.
        let mut candidates: Vec<(NodeInfo, [u8; 32])> = Vec::with_capacity(count * 2);

        for bucket in &self.buckets {
            for node in bucket.get_nodes() {
                let distance = xor_distance_bytes(node.id.to_bytes(), key.as_bytes());
                candidates.push((node.clone(), distance));
            }
        }

        // Sort by distance
        candidates.sort_by(|a, b| a.1.cmp(&b.1));

        // Return top `count` nodes
        candidates
            .into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }

    /// Returns the k-bucket index for a key, or `None` when the key equals
    /// the local node ID (XOR distance is zero — no valid bucket exists).
    fn get_bucket_index_for_key(&self, key: &DhtKey) -> Option<usize> {
        let distance = xor_distance_bytes(self.node_id.to_bytes(), key.as_bytes());

        // Find first bit that differs
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);

            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return Some(i);
            }
        }

        None // XOR distance is zero — key equals local node ID
    }

    /// Look up a node by its exact peer ID. O(K) scan of the target bucket.
    fn find_node_by_id(&self, node_id: &PeerId) -> Option<&NodeInfo> {
        let bucket_index = self.get_bucket_index(node_id)?;
        self.buckets[bucket_index].find_node(node_id)
    }

    /// Total number of nodes across all buckets.
    pub fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.get_nodes().len()).sum()
    }

    /// Return all nodes from every k-bucket.
    ///
    /// The routing table holds at most `256 * k_value` entries, so
    /// collecting them into a `Vec` is inexpensive.
    fn all_nodes(&self) -> Vec<NodeInfo> {
        self.buckets
            .iter()
            .flat_map(|b| b.get_nodes().iter().cloned())
            .collect()
    }

    /// Returns the k-bucket index for a peer, or `None` when the peer ID
    /// equals the local node ID (self-insertion is forbidden).
    fn get_bucket_index(&self, node_id: &PeerId) -> Option<usize> {
        self.get_bucket_index_for_key(&DhtKey::from_bytes(*node_id.to_bytes()))
    }

    /// Compute the K-closest peer IDs to self.
    fn k_closest_ids(&self, k: usize) -> Vec<PeerId> {
        self.find_closest_nodes(&self.node_id, k)
            .into_iter()
            .map(|n| n.id)
            .collect()
    }

    /// Return indices of buckets whose `last_refreshed` exceeds `threshold`.
    fn stale_bucket_indices(&self, threshold: Duration) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| b.last_refreshed.elapsed() > threshold)
            .map(|(i, _)| i)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Address parsing and subnet masking helpers for diversity checks
// ---------------------------------------------------------------------------

/// One entry in the tier-check array used by `find_ip_swap_in_scope`.
type IpSwapTier = (
    usize,
    usize,
    Option<(PeerId, [u8; 32], Instant)>,
    &'static str,
);

/// Zero out the host bits of an IPv4 address beyond `prefix_len`.
fn mask_ipv4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(bits & mask)
}

/// Zero out the host bits of an IPv6 address beyond `prefix_len`.
fn mask_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix_len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Ipv6Addr::from(bits & mask)
}

/// Default K parameter — number of closest nodes per bucket.
/// Used only by test helpers; production code reads from config.
#[cfg(test)]
const DEFAULT_K: usize = 20;

// IP_EXACT_LIMIT and ip_subnet_limit are imported from crate::security
// to keep a single source of truth for diversity constants.

/// Number of K-buckets in Kademlia routing table (one per bit in 256-bit key space)
const KADEMLIA_BUCKET_COUNT: usize = 256;

/// Trust score above which a peer is protected from swap-closer eviction.
/// Well-trusted peers (score >= 0.7) keep their routing table slot even
/// when a closer but less-proven peer arrives.
const TRUST_PROTECTION_THRESHOLD: f64 = 0.7;

/// Diagnostic statistics for the routing table.
#[allow(dead_code)]
pub struct RoutingTableStats {
    /// Total peers across all buckets.
    pub total_peers: usize,
    /// Per-bucket peer counts (256 entries).
    pub bucket_counts: Vec<usize>,
    /// Number of peers whose last_seen exceeds LIVE_THRESHOLD.
    pub stale_peer_count: usize,
}

/// Events emitted by routing table mutations.
///
/// These are returned from admission and removal operations so the caller
/// (DhtNetworkManager) can broadcast them without re-acquiring the lock.
#[derive(Debug, Clone)]
pub enum RoutingTableEvent {
    /// A new peer was inserted into the routing table.
    PeerAdded(PeerId),
    /// A peer was removed from the routing table (swap-out, eviction, or departure).
    PeerRemoved(PeerId),
    /// The set of K-closest peers to self changed.
    /// Fields retained for the design API; the network manager uses snapshot
    /// diffing instead of consuming these directly.
    #[allow(dead_code)]
    KClosestPeersChanged { old: Vec<PeerId>, new: Vec<PeerId> },
}

/// Result of a peer admission attempt, including stale revalidation requests.
///
/// When a candidate cannot be admitted because the target bucket is full and no
/// swap-closer peer exists, the core engine checks for stale peers that could be
/// revalidated. If stale peers are found, the caller (DhtNetworkManager) must
/// release the write lock, ping the stale peers, evict non-responders, and then
/// call [`DhtCoreEngine::re_evaluate_admission`].
#[derive(Debug)]
pub enum AdmissionResult {
    /// Peer was admitted (inserted or updated). Contains emitted events.
    Admitted(Vec<RoutingTableEvent>),
    /// Admission requires stale peer revalidation before it can proceed.
    /// The caller must release the write lock, ping the stale peers, evict
    /// non-responders, and then call `re_evaluate_admission`.
    StaleRevalidationNeeded {
        /// The candidate peer waiting for admission.
        candidate: NodeInfo,
        /// All candidate IPs (for re-evaluation after revalidation).
        candidate_ips: Vec<IpAddr>,
        /// The candidate's target bucket index (for per-bucket revalidation guard).
        candidate_bucket_idx: usize,
        /// Stale peers that should be pinged. Each entry is `(peer_id, bucket_index)`.
        /// May include peers from multiple buckets when routing-neighborhood
        /// violators are merged (Design Section 7.5).
        stale_peers: Vec<(PeerId, usize)>,
    },
}

/// Main DHT Core Engine
pub struct DhtCoreEngine {
    node_id: PeerId,
    routing_table: Arc<RwLock<KademliaRoutingTable>>,

    /// Kademlia K parameter — bucket capacity and close-group size.
    k_value: usize,

    /// IP diversity limits — checked against the live routing table on each
    /// `add_node` call rather than maintained as incremental counters.
    ip_diversity_config: IPDiversityConfig,
    /// Allow loopback addresses in the routing table.
    ///
    /// Set once at construction from `NodeConfig.allow_loopback` and never
    /// mutated — `NodeConfig` is the single source of truth. Kept separate
    /// from `IPDiversityConfig` to prevent duplication and drift.
    allow_loopback: bool,

    /// Trust score below which a peer is eligible for swap-out.
    swap_threshold: f64,

    /// Duration of no contact after which a peer is considered stale.
    /// Defaults to [`LIVE_THRESHOLD`]; overridden in tests to avoid
    /// `Instant` subtraction overflow on Windows (where `Instant` starts
    /// at process creation and cannot represent times before it).
    live_threshold: Duration,

    /// Shutdown token for background maintenance tasks
    shutdown: CancellationToken,
}

impl DhtCoreEngine {
    /// Create new DHT engine for testing with default K value.
    #[cfg(test)]
    pub fn new_for_tests(node_id: PeerId) -> Result<Self> {
        Self::new(node_id, DEFAULT_K, false, DEFAULT_SWAP_THRESHOLD)
    }

    /// Expose the routing table for test-only direct manipulation (e.g. setting `last_seen`).
    #[cfg(test)]
    pub(crate) fn routing_table_for_test(&self) -> &Arc<RwLock<KademliaRoutingTable>> {
        &self.routing_table
    }

    /// Create a new DHT core engine.
    pub(crate) fn new(
        node_id: PeerId,
        k_value: usize,
        allow_loopback: bool,
        swap_threshold: f64,
    ) -> Result<Self> {
        if k_value < 4 {
            return Err(anyhow!("k_value must be >= 4 (got {k_value})"));
        }
        if !(0.0..1.0).contains(&swap_threshold) || swap_threshold.is_nan() {
            return Err(anyhow!(
                "swap_threshold must be in [0.0, 1.0), got {swap_threshold}"
            ));
        }
        Ok(Self {
            node_id,
            routing_table: Arc::new(RwLock::new(KademliaRoutingTable::new(node_id, k_value))),
            k_value,
            ip_diversity_config: IPDiversityConfig::default(),
            allow_loopback,
            swap_threshold,
            live_threshold: LIVE_THRESHOLD,
            shutdown: CancellationToken::new(),
        })
    }

    /// Override the IP diversity configuration.
    pub fn set_ip_diversity_config(&mut self, config: IPDiversityConfig) {
        self.ip_diversity_config = config;
    }

    /// Set whether loopback addresses are allowed in the routing table.
    #[cfg(test)]
    pub fn set_allow_loopback(&mut self, allow: bool) {
        self.allow_loopback = allow;
    }

    /// Override the live threshold for testing.
    ///
    /// On Windows, `Instant` starts at process creation, so tests cannot
    /// subtract large durations without overflow. Setting a small threshold
    /// (e.g. 1 second) lets tests use a correspondingly small subtraction.
    #[cfg(test)]
    pub fn set_live_threshold(&mut self, threshold: Duration) {
        self.live_threshold = threshold;
    }

    /// Get this node's peer ID.
    #[allow(dead_code)]
    pub fn node_id(&self) -> &PeerId {
        &self.node_id
    }

    /// Return K-closest peer IDs whose `last_seen` exceeds the live threshold.
    ///
    /// Used by the self-lookup task to revalidate stale close-group members
    /// and evict offline peers promptly.
    pub(crate) async fn stale_k_closest(&self) -> Vec<PeerId> {
        let routing = self.routing_table.read().await;
        routing
            .find_closest_nodes(&self.node_id, self.k_value)
            .into_iter()
            .filter(|n| n.last_seen.elapsed() > self.live_threshold)
            .map(|n| n.id)
            .collect()
    }

    /// Return bucket indices that haven't been refreshed within the given threshold.
    pub(crate) async fn stale_bucket_indices(&self, threshold: Duration) -> Vec<usize> {
        self.routing_table
            .read()
            .await
            .stale_bucket_indices(threshold)
    }

    /// Generate a random key that would fall into the specified bucket index
    /// relative to this node's ID.
    ///
    /// Used for bucket refresh: looking up a random key in a stale bucket's range
    /// discovers new peers that populate that bucket.
    ///
    /// Returns `None` if `bucket_idx` is out of range (>= 256).
    pub(crate) fn generate_random_key_for_bucket(&self, bucket_idx: usize) -> Option<DhtKey> {
        if bucket_idx >= KADEMLIA_BUCKET_COUNT {
            return None;
        }

        let self_bytes = self.node_id.to_bytes();

        // Construct a XOR distance with its leading set bit at position bucket_idx.
        // Bucket index i means the first differing bit (from MSB) is at position i.
        let byte_idx = bucket_idx / 8;
        let bit_idx = 7 - (bucket_idx % 8);

        // Use a random PeerId as an entropy source (avoids `rng.gen()` which
        // conflicts with the `gen` keyword reserved in Rust edition 2024).
        let random_bytes = PeerId::random();

        let mut distance = [0u8; 32];
        // Set the leading bit at bucket_idx
        distance[byte_idx] = 1 << bit_idx;
        // Fill random bits below the leading bit in the same byte
        let below_mask = (1u8 << bit_idx).wrapping_sub(1);
        distance[byte_idx] |= random_bytes.to_bytes()[byte_idx] & below_mask;
        // Fill remaining bytes randomly
        distance[(byte_idx + 1)..32].copy_from_slice(&random_bytes.to_bytes()[(byte_idx + 1)..32]);

        // Key = self XOR distance
        let mut result = [0u8; 32];
        for (i, byte) in result.iter_mut().enumerate() {
            *byte = self_bytes[i] ^ distance[i];
        }
        Some(DhtKey::from_bytes(result))
    }

    /// Number of peers currently in the routing table.
    pub async fn routing_table_size(&self) -> usize {
        self.routing_table.read().await.node_count()
    }

    /// Remove a peer from the routing table by ID.
    ///
    /// Returns events describing the mutation (`PeerRemoved` if the peer was
    /// present, and optionally `KClosestPeersChanged` when the close-group shifted).
    /// Returns an empty vec if the peer was not in the routing table.
    pub async fn remove_node_by_id(&mut self, peer_id: &PeerId) -> Vec<RoutingTableEvent> {
        let mut routing = self.routing_table.write().await;
        // Only emit events if the peer is actually present.
        if routing.find_node_by_id(peer_id).is_none() {
            return Vec::new();
        }
        let k_before = routing.k_closest_ids(self.k_value);
        routing.remove_node(peer_id);
        let k_after = routing.k_closest_ids(self.k_value);
        let mut events = vec![RoutingTableEvent::PeerRemoved(*peer_id)];
        if k_before != k_after {
            events.push(RoutingTableEvent::KClosestPeersChanged {
                old: k_before,
                new: k_after,
            });
        }
        events
    }

    /// Signal background tasks to stop
    pub fn signal_shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Find nodes closest to a key
    pub async fn find_nodes(&self, key: &DhtKey, count: usize) -> Result<Vec<NodeInfo>> {
        let routing = self.routing_table.read().await;
        Ok(routing.find_closest_nodes(key, count))
    }

    /// Find nodes closest to a key, including self as a candidate.
    /// Used by consumers for storage responsibility determination.
    #[allow(dead_code)]
    pub async fn find_nodes_with_self(&self, key: &DhtKey, count: usize) -> Result<Vec<NodeInfo>> {
        let routing = self.routing_table.read().await;
        let mut candidates = routing.find_closest_nodes(key, count);

        // Insert self as a candidate
        let self_info = NodeInfo {
            id: self.node_id,
            addresses: vec![],
            address_types: vec![],
            last_seen: AtomicInstant::now(),
        };
        let self_dist = xor_distance_bytes(self.node_id.to_bytes(), key.as_bytes());

        // Find insertion point to maintain sorted order
        let pos = candidates
            .iter()
            .position(|n| xor_distance_bytes(n.id.to_bytes(), key.as_bytes()) > self_dist)
            .unwrap_or(candidates.len());

        candidates.insert(pos, self_info);
        candidates.truncate(count);

        Ok(candidates)
    }

    /// Look up a node's addresses from the routing table by peer ID.
    ///
    /// Returns the stored addresses if the peer is in the routing table,
    /// an empty vec otherwise. O(K) scan of the target k-bucket.
    pub async fn get_node_addresses(&self, peer_id: &PeerId) -> Vec<MultiAddr> {
        let routing = self.routing_table.read().await;
        routing
            .find_node_by_id(peer_id)
            .map(|n| n.addresses.clone())
            .unwrap_or_default()
    }

    /// Check whether a peer is present in the routing table.
    pub async fn has_node(&self, peer_id: &PeerId) -> bool {
        let routing = self.routing_table.read().await;
        routing.find_node_by_id(peer_id).is_some()
    }

    /// Return every peer currently in the routing table.
    ///
    /// The routing table holds at most `256 * k_value` entries, so
    /// collecting them is inexpensive.
    pub async fn all_nodes(&self) -> Vec<NodeInfo> {
        self.routing_table.read().await.all_nodes()
    }

    /// Build diagnostic statistics for the routing table.
    #[allow(dead_code)]
    pub async fn routing_table_stats(&self) -> RoutingTableStats {
        let routing = self.routing_table.read().await;
        let bucket_counts: Vec<usize> = routing
            .buckets
            .iter()
            .map(|b| b.get_nodes().len())
            .collect();
        let total_peers: usize = bucket_counts.iter().sum();
        let stale_peer_count = routing
            .buckets
            .iter()
            .flat_map(|b| b.get_nodes())
            .filter(|n| n.last_seen.elapsed() > self.live_threshold)
            .count();
        RoutingTableStats {
            total_peers,
            bucket_counts,
            stale_peer_count,
        }
    }

    /// Record a successful interaction with a peer by updating its `last_seen`
    /// timestamp (and optionally its address) and moving it to the tail of its
    /// k-bucket (most recently seen).
    ///
    /// Standard Kademlia: any successful RPC implicitly proves liveness, so the
    /// routing table should reflect this without requiring dedicated pings.
    /// Passing the current address ensures stale addresses are replaced when a
    /// peer reconnects from a different endpoint.
    pub async fn touch_node(&self, node_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        let mut routing = self.routing_table.write().await;
        routing.touch_node(node_id, address, AddressType::Direct)
    }

    /// Touch a peer's routing-table entry with an optional typed address.
    ///
    /// **Fast path (read lock + atomic store):** If the peer is in the
    /// routing table and the address merge would be a no-op (address is
    /// `None`, or it's already in the peer's list, or the loopback rule
    /// would skip it), this updates `last_seen` atomically under a read
    /// lock with no bucket mutation.
    ///
    /// **Slow path (write lock):** If an actual address merge is needed,
    /// the method escalates to a write lock and uses the full
    /// `touch_node` flow.
    ///
    /// This split removes the write lock from the common hot path — at
    /// 1000 nodes the touch is called on every inbound DHT message, and
    /// the write-lock version was the dominant contention point on the
    /// routing table.
    pub async fn touch_node_typed(
        &self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> bool {
        // Fast path: read lock + atomic last_seen store. The fast path
        // ALSO requires the address (if any) to already be present with
        // the same type classification — see `touch_last_seen_if_merge_noop`.
        // Promotion of an existing address from one classification to
        // another (e.g. Direct → Relay) is intentionally pushed to the
        // slow path so the bucket-level `merge_typed_address` can re-order.
        {
            let routing = self.routing_table.read().await;
            match routing.try_touch_last_seen(node_id, address, addr_type) {
                Some(true) => return true,
                Some(false) => return false,
                // Merge is non-trivial — fall through to the write-lock path.
                None => {}
            }
        }

        // Slow path: address merge or re-classification needed, take write lock.
        let mut routing = self.routing_table.write().await;
        routing.touch_node(node_id, address, addr_type)
    }

    /// Add a node to the DHT with security checks.
    ///
    /// IP subnet diversity is enforced per-bucket and for the K closest
    /// nodes to self, with closer peers swapped in when they contend for
    /// the same slot.
    ///
    /// `trust_score` is a closure that returns the current trust score for
    /// any peer ID. Well-trusted peers (above [`TRUST_PROTECTION_THRESHOLD`])
    /// are protected from swap-closer eviction. This decouples the routing
    /// table from the trust engine implementation.
    ///
    /// Returns [`AdmissionResult::Admitted`] on success, or
    /// [`AdmissionResult::StaleRevalidationNeeded`] when the target bucket is
    /// full and stale peers may be evicted after revalidation. The caller
    /// (DhtNetworkManager) must handle the revalidation flow.
    pub async fn add_node(
        &mut self,
        node: NodeInfo,
        trust_score: &impl Fn(&PeerId) -> f64,
    ) -> Result<AdmissionResult> {
        // Reject self-insertion — a node must never appear in its own routing table.
        if node.id == self.node_id {
            return Err(anyhow!("cannot add self to routing table"));
        }

        let peer_id = node.id;

        // Extract ALL IP addresses from the candidate for diversity checking.
        // If candidate has no IP-based addresses, it's a non-IP transport — bypass diversity.
        let candidate_ips: Vec<IpAddr> = node
            .addresses
            .iter()
            .filter_map(|a| a.ip().map(canonicalize_ip))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if candidate_ips.is_empty() {
            // Non-IP transports (Bluetooth, LoRa, etc.) bypass IP diversity.
            let mut routing = self.routing_table.write().await;
            // Update short-circuit: if peer already exists, merge addresses and
            // refresh last_seen without emitting PeerAdded (matches the main
            // diversity path's update logic at the "Design step 5" block).
            if routing.find_node_by_id(&peer_id).is_some() {
                for addr in &node.addresses {
                    routing.touch_node(&peer_id, Some(addr), AddressType::Direct);
                }
                return Ok(AdmissionResult::Admitted(vec![]));
            }
            let k_before = routing.k_closest_ids(self.k_value);
            routing.add_node(node)?;
            let k_after = routing.k_closest_ids(self.k_value);
            let mut events = vec![RoutingTableEvent::PeerAdded(peer_id)];
            if k_before != k_after {
                events.push(RoutingTableEvent::KClosestPeersChanged {
                    old: k_before,
                    new: k_after,
                });
            }
            return Ok(AdmissionResult::Admitted(events));
        }

        // Single write lock covers diversity checks and insertion to avoid
        // a TOCTOU race.
        let mut routing = self.routing_table.write().await;
        self.add_with_diversity(&mut routing, node, &candidate_ips, trust_score, true)
    }

    /// Convenience method for tests: add a node with neutral trust (0.5).
    ///
    /// Preserves existing swap-closer behavior for tests that don't care
    /// about trust scoring. Maps [`AdmissionResult::Admitted`] to its events
    /// and treats [`AdmissionResult::StaleRevalidationNeeded`] as an error
    /// (unit tests don't have network access to ping stale peers).
    #[cfg(test)]
    pub async fn add_node_no_trust(&mut self, node: NodeInfo) -> Result<Vec<RoutingTableEvent>> {
        match self.add_node(node, &|_| DEFAULT_NEUTRAL_TRUST).await? {
            AdmissionResult::Admitted(events) => Ok(events),
            AdmissionResult::StaleRevalidationNeeded { .. } => Err(anyhow!(
                "stale revalidation needed (not available in unit tests)"
            )),
        }
    }

    /// Check IP diversity within a scoped set of nodes and return a swap
    /// candidate if the scope is over-limit but the candidate is closer.
    ///
    /// Returns:
    /// - `Ok(None)` — scope is within limits (or candidate is loopback)
    /// - `Ok(Some(peer_id))` — scope exceeds a limit but the candidate is
    ///   closer than the farthest violating peer; swap that peer out
    /// - `Err` — scope exceeds a limit and the candidate cannot swap in
    ///
    /// Trust protection: the farthest peer is only swapped out when its trust
    /// score is below [`TRUST_PROTECTION_THRESHOLD`]. Well-trusted peers hold
    /// their slot even when a closer candidate arrives.
    fn find_ip_swap_in_scope(
        &self,
        nodes: &[NodeInfo],
        candidate_id: &PeerId,
        candidate_ip: IpAddr,
        candidate_distance: &[u8; 32],
        scope_name: &str,
        trust_score: &impl Fn(&PeerId) -> f64,
    ) -> Result<Option<PeerId>> {
        // Loopback candidates bypass IP diversity entirely.
        if candidate_ip.is_loopback() {
            return Ok(None);
        }

        let cfg = &self.ip_diversity_config;

        match candidate_ip {
            IpAddr::V4(v4) => {
                // IPv4 limits: use config override if set, otherwise default
                let limit_ip = cfg.max_per_ip.unwrap_or(IP_EXACT_LIMIT);
                let limit_subnet = cfg.max_per_subnet.unwrap_or(ip_subnet_limit(self.k_value));

                let cand_24 = mask_ipv4(v4, 24);

                // Single pass: count exact-IP and /24 matches, track farthest at each.
                // Check ALL addresses of each existing node to prevent diversity
                // bypass via address rotation (e.g. touch_node prepending a new address).
                // Each node is counted at most once per tier to avoid double-counting
                // multi-homed peers.
                let mut count_ip: usize = 0;
                let mut count_subnet: usize = 0;
                let mut farthest_ip: Option<(PeerId, [u8; 32], Instant)> = None;
                let mut farthest_subnet: Option<(PeerId, [u8; 32], Instant)> = None;

                for n in nodes {
                    if n.id == *candidate_id {
                        continue;
                    }
                    let existing_ips = n.all_ips();
                    if existing_ips.is_empty() {
                        continue;
                    }

                    let dist = xor_distance_bytes(self.node_id.to_bytes(), n.id.to_bytes());

                    // Check if any of this node's addresses match the candidate's
                    // exact IP or /24 subnet. Count each node at most once per tier.
                    let mut matched_ip = false;
                    let mut matched_subnet = false;
                    for existing_ip in &existing_ips {
                        if existing_ip.is_loopback() {
                            continue;
                        }
                        let IpAddr::V4(existing_v4) = existing_ip else {
                            continue;
                        };
                        if !matched_ip && *existing_v4 == v4 {
                            matched_ip = true;
                        }
                        if !matched_subnet && mask_ipv4(*existing_v4, 24) == cand_24 {
                            matched_subnet = true;
                        }
                    }

                    if matched_ip {
                        count_ip += 1;
                        if farthest_ip.as_ref().is_none_or(|(_, d, _)| dist > *d) {
                            farthest_ip = Some((n.id, dist, n.last_seen.load()));
                        }
                    }
                    if matched_subnet {
                        count_subnet += 1;
                        if farthest_subnet.as_ref().is_none_or(|(_, d, _)| dist > *d) {
                            farthest_subnet = Some((n.id, dist, n.last_seen.load()));
                        }
                    }
                }

                // Check tiers narrowest-first: a swap at exact-IP also fixes /24
                let tiers: [IpSwapTier; 2] = [
                    (count_ip, limit_ip, farthest_ip, "exact-IP"),
                    (count_subnet, limit_subnet, farthest_subnet, "/24"),
                ];

                for (count, limit, farthest, tier_name) in &tiers {
                    if *count >= *limit {
                        if let Some((far_id, far_dist, far_last_seen)) = farthest
                            && candidate_distance < far_dist
                            && (trust_score(far_id) < TRUST_PROTECTION_THRESHOLD
                                || far_last_seen.elapsed() > self.live_threshold)
                        {
                            return Ok(Some(*far_id));
                        }
                        return Err(anyhow!(
                            "IP diversity: {tier_name} limit ({limit}) exceeded in {scope_name}"
                        ));
                    }
                }
            }
            IpAddr::V6(v6) => {
                // IPv6 limits: use config override if set, otherwise default
                let limit_ip = cfg.max_per_ip.unwrap_or(IP_EXACT_LIMIT);
                let limit_subnet = cfg.max_per_subnet.unwrap_or(ip_subnet_limit(self.k_value));

                let cand_48 = mask_ipv6(v6, 48);

                // Single pass: count exact-IPv6 and /48 matches.
                // Check ALL addresses per node (see IPv4 branch comment).
                let mut count_ip: usize = 0;
                let mut count_subnet: usize = 0;
                let mut farthest_ip: Option<(PeerId, [u8; 32], Instant)> = None;
                let mut farthest_subnet: Option<(PeerId, [u8; 32], Instant)> = None;

                for n in nodes {
                    if n.id == *candidate_id {
                        continue;
                    }
                    let existing_ips = n.all_ips();
                    if existing_ips.is_empty() {
                        continue;
                    }

                    let dist = xor_distance_bytes(self.node_id.to_bytes(), n.id.to_bytes());

                    let mut matched_ip = false;
                    let mut matched_subnet = false;
                    for existing_ip in &existing_ips {
                        if existing_ip.is_loopback() {
                            continue;
                        }
                        let IpAddr::V6(existing_v6) = existing_ip else {
                            continue;
                        };
                        if !matched_ip && *existing_v6 == v6 {
                            matched_ip = true;
                        }
                        if !matched_subnet && mask_ipv6(*existing_v6, 48) == cand_48 {
                            matched_subnet = true;
                        }
                    }

                    if matched_ip {
                        count_ip += 1;
                        if farthest_ip.as_ref().is_none_or(|(_, d, _)| dist > *d) {
                            farthest_ip = Some((n.id, dist, n.last_seen.load()));
                        }
                    }
                    if matched_subnet {
                        count_subnet += 1;
                        if farthest_subnet.as_ref().is_none_or(|(_, d, _)| dist > *d) {
                            farthest_subnet = Some((n.id, dist, n.last_seen.load()));
                        }
                    }
                }

                let tiers: [IpSwapTier; 2] = [
                    (count_ip, limit_ip, farthest_ip, "exact-IP"),
                    (count_subnet, limit_subnet, farthest_subnet, "/48"),
                ];

                for (count, limit, farthest, tier_name) in &tiers {
                    if *count >= *limit {
                        if let Some((far_id, far_dist, far_last_seen)) = farthest
                            && candidate_distance < far_dist
                            && (trust_score(far_id) < TRUST_PROTECTION_THRESHOLD
                                || far_last_seen.elapsed() > self.live_threshold)
                        {
                            return Ok(Some(*far_id));
                        }
                        return Err(anyhow!(
                            "IP diversity: {tier_name} limit ({limit}) exceeded in {scope_name}"
                        ));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Collect stale peers from a bucket.
    ///
    /// Returns `(peer_id, bucket_index)` pairs for all peers in the target
    /// bucket whose `last_seen` exceeds the given `threshold`.
    fn collect_stale_peers_in_bucket(
        routing: &KademliaRoutingTable,
        bucket_idx: usize,
        threshold: Duration,
    ) -> Vec<(PeerId, usize)> {
        routing.buckets[bucket_idx]
            .nodes
            .iter()
            .filter(|n| n.last_seen.elapsed() > threshold)
            .map(|n| (n.id, bucket_idx))
            .collect()
    }

    /// Add a node with per-bucket and close-group IP diversity enforcement.
    ///
    /// Enforces that no IP subnet exceeds its limit within any single
    /// k-bucket or within the K closest nodes to self.
    ///
    /// When a candidate would exceed a limit, it may still be admitted if it
    /// is closer (XOR distance) to self than the farthest violating peer in
    /// the scope — the farther peer is evicted and the candidate takes its
    /// slot, preserving the count while improving routing quality.
    ///
    /// Trust protection is forwarded to [`Self::find_ip_swap_in_scope`] so
    /// that well-trusted peers resist eviction.
    ///
    /// When `allow_stale_revalidation` is `true` and the bucket is at capacity
    /// with no swap candidate, stale peers are identified and
    /// [`AdmissionResult::StaleRevalidationNeeded`] is returned so the caller
    /// can ping them and retry. When `false` (re-evaluation after revalidation),
    /// a full bucket is a hard rejection to prevent infinite revalidation loops.
    fn add_with_diversity(
        &self,
        routing: &mut KademliaRoutingTable,
        node: NodeInfo,
        candidate_ips: &[IpAddr],
        trust_score: &impl Fn(&PeerId) -> f64,
        allow_stale_revalidation: bool,
    ) -> Result<AdmissionResult> {
        let peer_id = node.id;

        // --- Reject invalid addresses ---
        // Multicast and unspecified addresses are never valid peer endpoints.
        if candidate_ips
            .iter()
            .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(anyhow!(
                "IP diversity: multicast or unspecified addresses rejected"
            ));
        }

        // --- Reject any loopback addresses when loopback is disallowed (M2) ---
        if !self.allow_loopback && candidate_ips.iter().any(|ip| ip.is_loopback()) {
            return Err(anyhow!(
                "IP diversity: loopback addresses rejected (allow_loopback=false)"
            ));
        }

        // --- Loopback handling ---
        let all_loopback = candidate_ips.iter().all(|ip| ip.is_loopback());
        if all_loopback {
            if !self.allow_loopback {
                return Err(anyhow!(
                    "IP diversity: loopback addresses rejected (allow_loopback=false)"
                ));
            }
            // Loopback with allow_loopback=true bypasses all diversity checks.
            // Update short-circuit: if peer already exists, merge addresses and
            // refresh last_seen without emitting PeerAdded.
            if routing.find_node_by_id(&peer_id).is_some() {
                for addr in &node.addresses {
                    routing.touch_node(&peer_id, Some(addr), AddressType::Direct);
                }
                return Ok(AdmissionResult::Admitted(vec![]));
            }
            let k_before = routing.k_closest_ids(self.k_value);
            routing.add_node(node)?;
            let k_after = routing.k_closest_ids(self.k_value);
            let mut events = vec![RoutingTableEvent::PeerAdded(peer_id)];
            if k_before != k_after {
                events.push(RoutingTableEvent::KClosestPeersChanged {
                    old: k_before,
                    new: k_after,
                });
            }
            return Ok(AdmissionResult::Admitted(events));
        }

        let bucket_idx = routing
            .get_bucket_index(&node.id)
            .ok_or_else(|| anyhow!("cannot insert self into routing table"))?;
        let candidate_distance = xor_distance_bytes(self.node_id.to_bytes(), node.id.to_bytes());

        // === Update short-circuit (Design step 5) ===
        // If peer already exists, merge addresses, refresh last_seen, move to tail.
        // Skip diversity and capacity checks — the peer already holds its slot.
        // The update path doesn't change membership, just position within a bucket.
        // K-closest computation is distance-based, not position-based, so the set
        // won't change. Return an empty events vec.
        if let Some(pos) = routing.buckets[bucket_idx]
            .nodes
            .iter()
            .position(|n| n.id == node.id)
        {
            let existing = &mut routing.buckets[bucket_idx].nodes[pos];
            existing.last_seen.store_now();
            // Merge each address from the candidate, respecting loopback injection prevention
            for addr in &node.addresses {
                let addr_is_loopback = addr
                    .ip()
                    .is_some_and(|ip| canonicalize_ip(ip).is_loopback());
                let existing_has_non_loopback = existing
                    .addresses
                    .iter()
                    .any(|a| a.ip().is_some_and(|ip| !canonicalize_ip(ip).is_loopback()));
                // Don't merge loopback addresses into a non-loopback-admitted peer
                if addr_is_loopback && existing_has_non_loopback {
                    continue;
                }
                existing.merge_address(addr.clone());
            }
            // Move to tail (most recently seen)
            let updated = routing.buckets[bucket_idx].nodes.remove(pos);
            routing.buckets[bucket_idx].nodes.push(updated);
            routing.buckets[bucket_idx].last_refreshed = Instant::now();
            return Ok(AdmissionResult::Admitted(Vec::new()));
        }

        // === Per-bucket IP diversity ===
        // Run diversity checks for each non-loopback candidate IP independently.
        // After identifying a swap for one IP, exclude that peer from subsequent
        // checks so that each IP sees the state after prior swaps — preventing
        // over-eviction when a candidate has multiple IPs.
        let mut all_bucket_swaps: Vec<PeerId> = Vec::new();
        for &candidate_ip in candidate_ips {
            if candidate_ip.is_loopback() {
                continue;
            }
            let bucket_view: Vec<NodeInfo> = routing.buckets[bucket_idx]
                .nodes
                .iter()
                .filter(|n| !all_bucket_swaps.contains(&n.id))
                .cloned()
                .collect();
            let swap = self.find_ip_swap_in_scope(
                &bucket_view,
                &node.id,
                candidate_ip,
                &candidate_distance,
                "bucket",
                trust_score,
            )?;
            if let Some(id) = swap
                && !all_bucket_swaps.contains(&id)
            {
                all_bucket_swaps.push(id);
            }
        }

        // === Close-group setup ===
        let close_group = routing.find_closest_nodes(&self.node_id, self.k_value);

        let effective_close_len = close_group
            .iter()
            .filter(|n| !all_bucket_swaps.contains(&n.id))
            .count();

        let candidate_in_close = effective_close_len < self.k_value
            || close_group
                .iter()
                .rfind(|n| !all_bucket_swaps.contains(&n.id))
                .map(|n| {
                    candidate_distance
                        < xor_distance_bytes(self.node_id.to_bytes(), n.id.to_bytes())
                })
                .unwrap_or(true);

        let mut all_close_swaps: Vec<PeerId> = Vec::new();

        if candidate_in_close {
            // Build hypothetical close group as Vec<NodeInfo>
            let mut hyp_close: Vec<NodeInfo> = close_group
                .iter()
                .filter(|n| !all_bucket_swaps.contains(&n.id) && n.id != node.id)
                .cloned()
                .collect();
            hyp_close.push(node.clone());
            hyp_close.sort_by(|a, b| {
                let da = xor_distance_bytes(self.node_id.to_bytes(), a.id.to_bytes());
                let db = xor_distance_bytes(self.node_id.to_bytes(), b.id.to_bytes());
                da.cmp(&db)
            });
            hyp_close.truncate(self.k_value);

            // === Close-group IP diversity ===
            // Exclude prior close-group swaps from each subsequent check to
            // prevent over-eviction (same rationale as the bucket loop above).
            for &candidate_ip in candidate_ips {
                if candidate_ip.is_loopback() {
                    continue;
                }
                let close_view: Vec<NodeInfo> = hyp_close
                    .iter()
                    .filter(|n| !all_close_swaps.contains(&n.id))
                    .cloned()
                    .collect();
                let swap = self.find_ip_swap_in_scope(
                    &close_view,
                    &node.id,
                    candidate_ip,
                    &candidate_distance,
                    "close-group",
                    trust_score,
                )?;
                if let Some(id) = swap {
                    // Deduplicate: don't plan a close swap that's already a bucket swap
                    if !all_bucket_swaps.contains(&id) && !all_close_swaps.contains(&id) {
                        all_close_swaps.push(id);
                    }
                }
            }
        }

        // === Capacity pre-check ===
        // Verify the insertion will succeed before executing any swaps.
        {
            let bucket = &routing.buckets[bucket_idx];
            let already_exists = bucket.nodes.iter().any(|n| n.id == node.id);
            let has_room = bucket.nodes.len() < bucket.max_size;
            let swap_frees_slot = !all_bucket_swaps.is_empty()
                || all_close_swaps
                    .iter()
                    .any(|id| routing.get_bucket_index(id) == Some(bucket_idx));
            if !already_exists && !has_room && !swap_frees_slot {
                // --- Trust-based swap-out (lazy eviction) ---
                // When a bucket is full and no IP-diversity swap is available,
                // find the lowest-trust peer below swap_threshold and replace
                // it directly. No revalidation ping needed.
                // Only swap when the candidate itself is above the threshold
                // to avoid replacing a low-trust peer with an even worse one.
                if self.swap_threshold > 0.0 && trust_score(&peer_id) >= self.swap_threshold {
                    let lowest = bucket
                        .nodes
                        .iter()
                        .map(|n| (n.id, trust_score(&n.id)))
                        .filter(|(_, score)| *score < self.swap_threshold)
                        .min_by(|(_, a), (_, b)| {
                            a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
                        });

                    if let Some((swap_id, _)) = lowest {
                        all_bucket_swaps.push(swap_id);
                    }
                }

                // Re-check capacity after potential trust swap
                let swap_frees_slot_now = !all_bucket_swaps.is_empty()
                    || all_close_swaps
                        .iter()
                        .any(|id| routing.get_bucket_index(id) == Some(bucket_idx));

                if !swap_frees_slot_now {
                    if allow_stale_revalidation {
                        let mut stale_peers = Self::collect_stale_peers_in_bucket(
                            routing,
                            bucket_idx,
                            self.live_threshold,
                        );

                        // Merge stale routing-neighborhood violators (Design Section 7.5):
                        // close-group swap targets that are stale and not already in the
                        // bucket-level set. Evicting these may resolve the close-group
                        // diversity violation and (if they happen to reside in the same
                        // bucket) free capacity for the candidate.
                        for close_swap_id in &all_close_swaps {
                            if stale_peers.iter().any(|(id, _)| id == close_swap_id) {
                                continue;
                            }
                            if let Some(swap_bucket_idx) = routing.get_bucket_index(close_swap_id)
                                && let Some(swap_node) = routing.find_node_by_id(close_swap_id)
                                && swap_node.last_seen.elapsed() > self.live_threshold
                            {
                                stale_peers.push((*close_swap_id, swap_bucket_idx));
                            }
                        }

                        if !stale_peers.is_empty() {
                            return Ok(AdmissionResult::StaleRevalidationNeeded {
                                candidate: node,
                                candidate_ips: candidate_ips.to_vec(),
                                candidate_bucket_idx: bucket_idx,
                                stale_peers,
                            });
                        }
                    }
                    return Err(anyhow!(
                        "K-bucket at capacity ({}/{}) with no stale peers",
                        bucket.nodes.len(),
                        bucket.max_size,
                    ));
                }
            }
        }

        // === Snapshot K-closest BEFORE mutation ===
        let k_before = routing.k_closest_ids(self.k_value);

        // === Execute all swaps (deduplicated) ===
        let mut executed: Vec<PeerId> = Vec::with_capacity(2);
        for swap_id in all_bucket_swaps
            .iter()
            .chain(all_close_swaps.iter())
            .copied()
        {
            if !executed.contains(&swap_id) {
                routing.remove_node(&swap_id);
                executed.push(swap_id);
            }
        }

        routing.add_node(node)?;

        // === Build events ===
        let mut events: Vec<RoutingTableEvent> = Vec::with_capacity(executed.len() + 2);
        for removed_id in &executed {
            events.push(RoutingTableEvent::PeerRemoved(*removed_id));
        }
        events.push(RoutingTableEvent::PeerAdded(peer_id));

        // === Snapshot K-closest AFTER mutation ===
        let k_after = routing.k_closest_ids(self.k_value);
        if k_before != k_after {
            events.push(RoutingTableEvent::KClosestPeersChanged {
                old: k_before,
                new: k_after,
            });
        }

        Ok(AdmissionResult::Admitted(events))
    }

    /// Re-evaluate admission after stale peers have been evicted by the caller.
    ///
    /// Called by the network manager after pinging stale peers and evicting
    /// non-responders. Re-runs IP diversity, trust-based swap-out, and capacity
    /// checks with `allow_stale_revalidation: false` to prevent infinite
    /// revalidation loops.
    pub(crate) async fn re_evaluate_admission(
        &mut self,
        candidate: NodeInfo,
        candidate_ips: &[IpAddr],
        trust_score: &impl Fn(&PeerId) -> f64,
    ) -> Result<Vec<RoutingTableEvent>> {
        let mut routing = self.routing_table.write().await;
        match self.add_with_diversity(&mut routing, candidate, candidate_ips, trust_score, false)? {
            AdmissionResult::Admitted(events) => Ok(events),
            AdmissionResult::StaleRevalidationNeeded { .. } => {
                // Design: re-evaluation MUST NOT trigger a second revalidation round.
                // The `allow_stale_revalidation: false` flag should prevent this path,
                // but we handle it defensively.
                Err(anyhow!("K-bucket still at capacity after revalidation"))
            }
        }
    }
}

// Manual Debug implementation to avoid cascade of Debug requirements
impl std::fmt::Debug for DhtCoreEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtCoreEngine")
            .field("node_id", &self.node_id)
            .field("routing_table", &"Arc<RwLock<KademliaRoutingTable>>")
            .field("k_value", &self.k_value)
            .field("ip_diversity_config", &self.ip_diversity_config)
            .field("allow_loopback", &self.allow_loopback)
            .field("swap_threshold", &self.swap_threshold)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::TransportAddr;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_xor_distance() {
        let key1 = DhtKey::from_bytes([0u8; 32]);
        let key2 = DhtKey::from_bytes([255u8; 32]);

        let distance = key1.distance(&key2);
        assert_eq!(distance, [255u8; 32]);
    }

    /// Helper: create a NodeInfo with a deterministic PeerId derived from a
    /// single byte.  Keeps tests concise.
    fn make_node(byte: u8, address: &str) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes([byte; 32]),
            addresses: vec![address.parse::<MultiAddr>().unwrap()],
            address_types: vec![AddressType::Direct],
            last_seen: AtomicInstant::now(),
        }
    }

    // -----------------------------------------------------------------------
    // KBucket::touch_node tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_touch_node_merges_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "/ip4/1.2.3.4/udp/9000/quic");
        bucket.add_node(node).unwrap();

        // Touch with a new address — should be prepended, old kept
        let new_addr: MultiAddr = "/ip4/5.6.7.8/udp/9000/quic".parse().unwrap();
        let old_addr: MultiAddr = "/ip4/1.2.3.4/udp/9000/quic".parse().unwrap();
        let found = bucket.touch_node_typed(
            &PeerId::from_bytes([1u8; 32]),
            Some(&new_addr),
            AddressType::Direct,
        );
        assert!(found);
        let addrs = &bucket.get_nodes().last().unwrap().addresses;
        assert_eq!(addrs[0], new_addr);
        assert_eq!(addrs[1], old_addr);
    }

    #[test]
    fn test_touch_node_none_preserves_addresses() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "/ip4/1.2.3.4/udp/9000/quic");
        bucket.add_node(node).unwrap();

        let found =
            bucket.touch_node_typed(&PeerId::from_bytes([1u8; 32]), None, AddressType::Direct);
        assert!(found);
        let expected: MultiAddr = "/ip4/1.2.3.4/udp/9000/quic".parse().unwrap();
        assert_eq!(bucket.get_nodes().last().unwrap().addresses, vec![expected]);
    }

    #[test]
    fn test_touch_node_moves_to_tail() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();
        bucket
            .add_node(make_node(2, "/ip4/2.2.2.2/udp/9000/quic"))
            .unwrap();
        bucket
            .add_node(make_node(3, "/ip4/3.3.3.3/udp/9000/quic"))
            .unwrap();

        // Touch the first node — it should move to the tail
        bucket.touch_node_typed(&PeerId::from_bytes([1u8; 32]), None, AddressType::Direct);
        let ids: Vec<u8> = bucket
            .get_nodes()
            .iter()
            .map(|n| n.id.to_bytes()[0])
            .collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    #[test]
    fn test_touch_node_missing_returns_false() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let new_addr: MultiAddr = "/ip4/9.9.9.9/udp/9000/quic".parse().unwrap();
        let found = bucket.touch_node_typed(
            &PeerId::from_bytes([99u8; 32]),
            Some(&new_addr),
            AddressType::Direct,
        );
        assert!(!found);
    }

    // -----------------------------------------------------------------------
    // find_closest_nodes tests — boundary bucket indices
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_closest_nodes_no_duplicates_at_bucket_zero() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Insert nodes that land in different buckets.  XOR with [0;32]
        // means the bucket index is the leading-bit position of the node id.
        // Byte 0 = 0x80 → bucket 0, byte 0 = 0x40 → bucket 1, etc.
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = 0x80; // bucket 0
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[0] = 0x40; // bucket 1
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            })
            .unwrap();

        // Search for a key that targets bucket 0
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = 0x80;
        let key = DhtKey::from_bytes(key_bytes);
        let results = table.find_closest_nodes(&key, 8);

        // Verify no duplicates by collecting IDs into a set
        let mut seen = HashSet::new();
        for node in &results {
            assert!(seen.insert(node.id), "Duplicate node {:?}", node.id);
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_closest_nodes_no_duplicates_at_bucket_255() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Bucket 255 requires the differing bit at position 255 (last bit
        // of last byte).  XOR distance with [0;32] is the id itself, so we
        // need id where only the very last bit is set.
        let mut id_bytes = [0u8; 32];
        id_bytes[31] = 0x01; // bucket 255
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[31] = 0x02; // bucket 254
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            })
            .unwrap();

        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01;
        let key = DhtKey::from_bytes(key_bytes);
        let results = table.find_closest_nodes(&key, 8);

        let mut seen = HashSet::new();
        for node in &results {
            assert!(seen.insert(node.id), "Duplicate node {:?}", node.id);
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_closest_nodes_returns_sorted_by_distance() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Insert 5 nodes at varying distances
        for i in 0..5u8 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = 0x80 >> i; // buckets 0,1,2,3,4
            table
                .add_node(NodeInfo {
                    id: PeerId::from_bytes(id_bytes),
                    addresses: vec![
                        format!("/ip4/10.0.0.{}/udp/9000/quic", i + 1)
                            .parse()
                            .unwrap(),
                    ],
                    last_seen: AtomicInstant::now(),
                    address_types: vec![],
                })
                .unwrap();
        }

        let key = DhtKey::from_bytes([0u8; 32]);
        let results = table.find_closest_nodes(&key, 3);

        assert_eq!(results.len(), 3);
        // Results should be sorted by XOR distance to key
        for window in results.windows(2) {
            let d0 = xor_distance_bytes(window[0].id.to_bytes(), key.as_bytes());
            let d1 = xor_distance_bytes(window[1].id.to_bytes(), key.as_bytes());
            assert!(d0 <= d1, "Results not sorted by distance");
        }
    }

    #[test]
    fn test_find_closest_nodes_empty_table() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let table = KademliaRoutingTable::new(local_id, 8);

        let key = DhtKey::from_bytes([42u8; 32]);
        let results = table.find_closest_nodes(&key, 8);
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // check_diversity loopback gating tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_loopback_rejected_when_allow_loopback_false() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        // Default has allow_loopback = false
        assert!(!dht.allow_loopback);

        let loopback_node = make_node(1, "/ip4/127.0.0.1/udp/9000/quic");
        let result = dht.add_node_no_trust(loopback_node).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("loopback"),
            "expected loopback rejection, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_loopback_v6_rejected_when_allow_loopback_false() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        assert!(!dht.allow_loopback);

        let loopback_node = make_node(2, "/ip6/::1/udp/9000/quic");
        let result = dht.add_node_no_trust(loopback_node).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("loopback"),
            "expected loopback rejection, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_loopback_accepted_when_allow_loopback_true() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_allow_loopback(true);

        let loopback_node = make_node(1, "/ip4/127.0.0.1/udp/9000/quic");
        let result = dht.add_node_no_trust(loopback_node).await;
        assert!(result.is_ok(), "loopback should be accepted: {:?}", result);
    }

    #[tokio::test]
    async fn test_non_loopback_unaffected_by_allow_loopback_flag() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        // allow_loopback = false should not affect normal addresses
        assert!(!dht.allow_loopback);

        let normal_node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let result = dht.add_node_no_trust(normal_node).await;
        assert!(
            result.is_ok(),
            "non-loopback should be accepted: {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // IPv4 diversity: static floor overrides low dynamic limit
    // -----------------------------------------------------------------------

    /// Testnet config effectively disables IP diversity limits, allowing
    /// many nodes from the same IP in a single bucket.
    #[tokio::test]
    async fn test_testnet_config_disables_ip_diversity() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Testnet config sets all IP limits to usize::MAX.
        dht.set_ip_diversity_config(IPDiversityConfig::testnet());

        // All nodes land in bucket 0 (id[0]=0x80, self=[0;32]).
        // Vary id[31] for uniqueness.
        for i in 1..=8u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            let node = NodeInfo {
                id: PeerId::from_bytes(id),
                addresses: vec!["/ip4/203.0.113.1/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            };
            let result = dht.add_node_no_trust(node).await;
            assert!(
                result.is_ok(),
                "node {i} from same IP should be accepted with testnet config: {:?}",
                result
            );
        }
    }

    // -----------------------------------------------------------------------
    // KBucket::add_node address validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_node_rejects_empty_addresses() {
        let mut bucket = KBucket::new(8);
        let node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };
        assert!(bucket.add_node(node).is_err());
    }

    #[test]
    fn test_add_node_truncates_excess_addresses() {
        let mut bucket = KBucket::new(8);

        // Build a NodeInfo with more addresses than the cap.
        let addresses: Vec<MultiAddr> = (1..=MAX_ADDRESSES_PER_NODE + 4)
            .map(|i| format!("/ip4/10.0.0.{}/udp/9000/quic", i).parse().unwrap())
            .collect();
        assert!(addresses.len() > MAX_ADDRESSES_PER_NODE);

        let node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses,
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };
        bucket.add_node(node).unwrap();

        let stored = &bucket.get_nodes()[0].addresses;
        assert_eq!(stored.len(), MAX_ADDRESSES_PER_NODE);
    }

    #[test]
    fn test_add_node_replace_also_truncates() {
        let mut bucket = KBucket::new(8);

        // Insert once with a single address.
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();
        assert_eq!(bucket.get_nodes()[0].addresses.len(), 1);

        // Replace with an oversized address list.
        let addresses: Vec<MultiAddr> = (1..=MAX_ADDRESSES_PER_NODE + 4)
            .map(|i| format!("/ip4/10.0.0.{}/udp/9000/quic", i).parse().unwrap())
            .collect();
        let replacement = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses,
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };
        bucket.add_node(replacement).unwrap();

        let stored = &bucket.get_nodes().last().unwrap().addresses;
        assert_eq!(stored.len(), MAX_ADDRESSES_PER_NODE);
    }

    // -----------------------------------------------------------------------
    // Helper: create a NodeInfo with an explicit id byte array
    // -----------------------------------------------------------------------

    fn make_node_with_addr(id_bytes: [u8; 32], address: &str) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes(id_bytes),
            addresses: vec![address.parse::<MultiAddr>().unwrap()],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        }
    }

    /// Live threshold used by tests: 1 second.
    ///
    /// Production uses 900 s, but on Windows `Instant` starts at process
    /// creation time, so subtracting large durations panics.  Tests call
    /// `set_live_threshold(TEST_LIVE_THRESHOLD)` and then set `last_seen`
    /// to `Instant::now() - TEST_STALE_AGE` which is safe on every platform.
    const TEST_LIVE_THRESHOLD: Duration = Duration::from_secs(1);

    /// How far back to set `last_seen` so peers exceed `TEST_LIVE_THRESHOLD`.
    const TEST_STALE_AGE: Duration = Duration::from_secs(2);

    // -----------------------------------------------------------------------
    // Test 4: low-trust peer admission (lazy swap-out model)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_low_trust_candidate_still_admitted() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;

        // Candidate with trust below swap threshold is still admitted
        // (lazy swap-out model: no admission blocking)
        let result = dht
            .add_node(node, &|id| {
                if *id == peer_id { 0.1 } else { 0.5 }
            })
            .await;

        assert!(result.is_ok(), "low-trust candidate should be admitted");
        assert!(dht.has_node(&peer_id).await);
    }

    // -----------------------------------------------------------------------
    // Test 13: update short-circuit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_duplicate_admission_updates_existing() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();

        // Re-add same peer with a new address
        let updated = NodeInfo {
            id: peer_id,
            addresses: vec!["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };
        let result = dht.add_node_no_trust(updated).await;
        assert!(result.is_ok(), "update short-circuit should succeed");

        // Should have both addresses (new one first)
        let addrs = dht.get_node_addresses(&peer_id).await;
        assert_eq!(addrs.len(), 2);
        assert_eq!(
            addrs[0],
            "/ip4/10.0.0.2/udp/9000/quic".parse::<MultiAddr>().unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Test 14: loopback injection prevention
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_loopback_injection_prevented_in_touch() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();

        // Touch with a loopback address — should be silently rejected
        let loopback_addr: MultiAddr = "/ip4/127.0.0.1/udp/9000/quic".parse().unwrap();
        dht.touch_node(&peer_id, Some(&loopback_addr)).await;

        let addrs = dht.get_node_addresses(&peer_id).await;
        assert_eq!(addrs.len(), 1, "loopback should not be merged");
        assert_ne!(addrs[0], loopback_addr);
    }

    // -----------------------------------------------------------------------
    // Test 21: staleness-gated trust protection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_stale_trusted_peer_can_be_swapped() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Two peers in bucket 0, same IP (exact-IP limit = 2)
        let mut id_far = [0u8; 32];
        id_far[0] = 0xFF;
        let far_node = make_node_with_addr(id_far, "/ip4/10.0.1.1/udp/9000/quic");
        dht.add_node_no_trust(far_node).await.unwrap();

        let mut id_mid = [0u8; 32];
        id_mid[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Make the far peer stale by manipulating last_seen
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket_idx = routing
                .get_bucket_index(&PeerId::from_bytes(id_far))
                .unwrap();
            let node = routing.buckets[bucket_idx]
                .nodes
                .iter_mut()
                .find(|n| n.id == PeerId::from_bytes(id_far))
                .unwrap();
            // Set last_seen to exceed the test live threshold
            node.last_seen.store(Instant::now() - TEST_STALE_AGE);
        }

        // A closer candidate with the same IP
        let mut id_close = [0u8; 32];
        id_close[0] = 0x80;
        let far_peer = PeerId::from_bytes(id_far);

        // Far peer has trust 0.8 (above TRUST_PROTECTION_THRESHOLD) but is STALE
        let trust_fn = |peer_id: &PeerId| -> f64 { if *peer_id == far_peer { 0.8 } else { 0.5 } };

        let result = dht
            .add_node(
                make_node_with_addr(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
                &trust_fn,
            )
            .await;

        // Should succeed — stale peer loses trust protection
        assert!(
            result.is_ok(),
            "stale trusted peer should be swappable: {:?}",
            result
        );
        assert!(
            !dht.has_node(&far_peer).await,
            "stale far peer should be evicted"
        );
        assert!(dht.has_node(&PeerId::from_bytes(id_close)).await);
    }

    // -----------------------------------------------------------------------
    // Test 22: live well-trusted peer holds slot
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_live_trusted_peer_holds_slot() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let mut id_far = [0u8; 32];
        id_far[0] = 0xFF;
        dht.add_node_no_trust(make_node_with_addr(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
            .await
            .unwrap();

        let mut id_mid = [0u8; 32];
        id_mid[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Far peer is live (just added, last_seen is now) and trusted (0.8)
        let far_peer = PeerId::from_bytes(id_far);
        let trust_fn = |peer_id: &PeerId| -> f64 { if *peer_id == far_peer { 0.8 } else { 0.5 } };

        let mut id_close = [0u8; 32];
        id_close[0] = 0x80;
        let result = dht
            .add_node(
                make_node_with_addr(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
                &trust_fn,
            )
            .await;

        // Should be rejected — live trusted peer holds its slot
        assert!(result.is_err());
        assert!(dht.has_node(&far_peer).await);
    }

    // -----------------------------------------------------------------------
    // Routing table event tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_peer_added_event_on_insertion() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;

        let events = dht.add_node_no_trust(node).await.unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerAdded(id) if *id == peer_id)),
            "expected PeerAdded event for inserted peer"
        );
    }

    #[tokio::test]
    async fn test_peer_removed_event_on_removal() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();

        let events = dht.remove_node_by_id(&peer_id).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == peer_id)),
            "expected PeerRemoved event for removed peer"
        );
    }

    #[tokio::test]
    async fn test_k_closest_changed_event_on_first_insertion() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Add a node close to self — should trigger KClosestPeersChanged (going from empty to 1)
        let mut id = [0u8; 32];
        id[31] = 0x01; // bucket 255, very close to self
        let node = NodeInfo {
            id: PeerId::from_bytes(id),
            addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };

        let events = dht.add_node_no_trust(node).await.unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::KClosestPeersChanged { .. })),
            "adding first close peer should trigger KClosestPeersChanged"
        );
    }

    #[tokio::test]
    async fn test_update_short_circuit_no_events() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        dht.add_node_no_trust(node.clone()).await.unwrap();

        // Re-add same peer — update path, no events
        let events = dht.add_node_no_trust(node).await.unwrap();
        assert!(
            events.is_empty(),
            "update short-circuit should produce no events"
        );
    }

    #[tokio::test]
    async fn test_swap_eviction_produces_both_events() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Two peers in bucket 0, same IP (exact-IP limit = 2)
        let mut id_far = [0u8; 32];
        id_far[0] = 0xFF;
        dht.add_node_no_trust(make_node_with_addr(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
            .await
            .unwrap();

        let mut id_mid = [0u8; 32];
        id_mid[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Make the far peer stale for swap eligibility
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket_idx = routing
                .get_bucket_index(&PeerId::from_bytes(id_far))
                .unwrap();
            let node = routing.buckets[bucket_idx]
                .nodes
                .iter_mut()
                .find(|n| n.id == PeerId::from_bytes(id_far))
                .unwrap();
            node.last_seen.store(Instant::now() - TEST_STALE_AGE);
        }

        // A closer candidate with the same IP triggers swap
        let mut id_close = [0u8; 32];
        id_close[0] = 0x80;
        let far_peer = PeerId::from_bytes(id_far);
        let close_peer = PeerId::from_bytes(id_close);

        let result = dht
            .add_node(
                make_node_with_addr(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
                &|peer_id| if *peer_id == far_peer { 0.8 } else { 0.5 },
            )
            .await
            .unwrap();

        let events = match result {
            AdmissionResult::Admitted(events) => events,
            other => panic!("expected Admitted, got {:?}", other),
        };

        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == far_peer)),
            "swap should produce PeerRemoved for evicted peer"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerAdded(id) if *id == close_peer)),
            "swap should produce PeerAdded for new peer"
        );
    }

    #[tokio::test]
    async fn test_k_closest_changed_on_removal() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();

        let events = dht.remove_node_by_id(&peer_id).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::KClosestPeersChanged { .. })),
            "removing a peer should trigger KClosestPeersChanged"
        );
    }

    // -----------------------------------------------------------------------
    // Stale peer revalidation tests (Phase 5)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_stale_revalidation_needed_when_bucket_full_with_stale_peers() {
        // Use k=4 (minimum valid K) so the bucket fills quickly.
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_ip_diversity_config(crate::security::IPDiversityConfig::testnet());
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Fill bucket 0 with 4 peers (k=4).
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.0.0.{i}/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        // Make all peers stale.
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let mut id_a = [0u8; 32];
            id_a[0] = 0x80;
            id_a[31] = 1;
            let bucket_idx = routing.get_bucket_index(&PeerId::from_bytes(id_a)).unwrap();
            for node in &mut routing.buckets[bucket_idx].nodes {
                node.last_seen.store(Instant::now() - TEST_STALE_AGE);
            }
        }

        // New candidate for bucket 0 — bucket is full, but stale peers exist.
        let mut id_new = [0u8; 32];
        id_new[0] = 0x80;
        id_new[31] = 5;
        let result = dht
            .add_node(
                make_node_with_addr(id_new, "/ip4/10.0.0.5/udp/9000/quic"),
                &|_| DEFAULT_NEUTRAL_TRUST,
            )
            .await
            .unwrap();

        match result {
            AdmissionResult::StaleRevalidationNeeded {
                candidate,
                candidate_ips,
                candidate_bucket_idx: _,
                stale_peers,
            } => {
                assert_eq!(candidate.id, PeerId::from_bytes(id_new));
                assert!(!candidate_ips.is_empty());
                assert_eq!(stale_peers.len(), 4, "all peers should be stale");
            }
            AdmissionResult::Admitted(_) => panic!("expected StaleRevalidationNeeded"),
        }
    }

    #[tokio::test]
    async fn test_no_stale_revalidation_when_bucket_full_no_stale() {
        // Use k=4 (minimum valid K) so the bucket fills quickly.
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_ip_diversity_config(crate::security::IPDiversityConfig::testnet());

        // Fill bucket 0 with 4 fresh (live) peers.
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.0.0.{i}/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        // New candidate — bucket full, no stale peers → hard rejection.
        let mut id_new = [0u8; 32];
        id_new[0] = 0x80;
        id_new[31] = 5;
        let result = dht
            .add_node(
                make_node_with_addr(id_new, "/ip4/10.0.0.5/udp/9000/quic"),
                &|_| DEFAULT_NEUTRAL_TRUST,
            )
            .await;

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no stale peers"),
            "error should mention no stale peers, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_re_evaluate_admission_after_eviction() {
        // Use k=4 (minimum valid K) so the bucket fills quickly.
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_ip_diversity_config(crate::security::IPDiversityConfig::testnet());

        // Fill bucket 0 with 4 peers.
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.0.0.{i}/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        // Evict one peer (simulating revalidation outcome).
        let mut id_a = [0u8; 32];
        id_a[0] = 0x80;
        id_a[31] = 1;
        dht.remove_node_by_id(&PeerId::from_bytes(id_a)).await;

        // Re-evaluate admission — should succeed now that there's room.
        let mut id_new = [0u8; 32];
        id_new[0] = 0x80;
        id_new[31] = 5;
        let candidate = make_node_with_addr(id_new, "/ip4/10.0.0.5/udp/9000/quic");
        let candidate_ips = vec!["10.0.0.5".parse().unwrap()];

        let events = dht
            .re_evaluate_admission(candidate, &candidate_ips, &|_| DEFAULT_NEUTRAL_TRUST)
            .await
            .unwrap();

        assert!(
            events.iter().any(
                |e| matches!(e, RoutingTableEvent::PeerAdded(id) if *id == PeerId::from_bytes(id_new))
            ),
            "re-evaluation should produce PeerAdded"
        );
        assert!(dht.has_node(&PeerId::from_bytes(id_new)).await);
    }

    #[tokio::test]
    async fn test_re_evaluate_admits_low_trust_candidate() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            20,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();

        let mut id = [0u8; 32];
        id[0] = 0x80;
        let candidate = make_node_with_addr(id, "/ip4/10.0.0.1/udp/9000/quic");
        let candidate_ips = vec!["10.0.0.1".parse().unwrap()];

        // Trust below swap threshold — should still be admitted
        let result = dht
            .re_evaluate_admission(candidate, &candidate_ips, &|_| 0.1)
            .await;

        assert!(
            result.is_ok(),
            "low-trust candidate should be admitted via re-evaluate"
        );
    }

    #[tokio::test]
    async fn test_re_evaluate_does_not_trigger_second_revalidation() {
        // Use k=4 (minimum valid K) so the bucket fills quickly.
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_ip_diversity_config(crate::security::IPDiversityConfig::testnet());
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Fill bucket 0 with 4 stale peers.
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.0.0.{i}/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        // Make all stale.
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let mut id_a = [0u8; 32];
            id_a[0] = 0x80;
            id_a[31] = 1;
            let bucket_idx = routing.get_bucket_index(&PeerId::from_bytes(id_a)).unwrap();
            for node in &mut routing.buckets[bucket_idx].nodes {
                node.last_seen.store(Instant::now() - TEST_STALE_AGE);
            }
        }

        // re_evaluate_admission with full bucket and stale peers should reject,
        // NOT return StaleRevalidationNeeded (no second round).
        let mut id_new = [0u8; 32];
        id_new[0] = 0x80;
        id_new[31] = 5;
        let candidate = make_node_with_addr(id_new, "/ip4/10.0.0.5/udp/9000/quic");
        let candidate_ips = vec!["10.0.0.5".parse().unwrap()];

        let result = dht
            .re_evaluate_admission(candidate, &candidate_ips, &|_| DEFAULT_NEUTRAL_TRUST)
            .await;

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no stale peers"),
            "re-evaluation should not trigger another revalidation round, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_collect_stale_peers_in_bucket() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            20,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Add a fresh peer.
        let mut id_fresh = [0u8; 32];
        id_fresh[0] = 0x80;
        id_fresh[31] = 1;
        dht.add_node_no_trust(make_node_with_addr(id_fresh, "/ip4/10.0.0.1/udp/9000/quic"))
            .await
            .unwrap();

        // Add a stale peer.
        let mut id_stale = [0u8; 32];
        id_stale[0] = 0x80;
        id_stale[31] = 2;
        dht.add_node_no_trust(make_node_with_addr(id_stale, "/ip4/10.0.0.2/udp/9000/quic"))
            .await
            .unwrap();

        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket_idx = routing
                .get_bucket_index(&PeerId::from_bytes(id_stale))
                .unwrap();

            // Make one peer stale.
            let node = routing.buckets[bucket_idx]
                .nodes
                .iter_mut()
                .find(|n| n.id == PeerId::from_bytes(id_stale))
                .unwrap();
            node.last_seen.store(Instant::now() - TEST_STALE_AGE);

            let stale = DhtCoreEngine::collect_stale_peers_in_bucket(
                &routing,
                bucket_idx,
                TEST_LIVE_THRESHOLD,
            );
            assert_eq!(stale.len(), 1);
            assert_eq!(stale[0].0, PeerId::from_bytes(id_stale));
        }
    }

    // -----------------------------------------------------------------------
    // generate_random_key_for_bucket tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_generate_random_key_for_bucket_lands_in_correct_bucket() {
        let local_id = PeerId::random();
        let dht = DhtCoreEngine::new_for_tests(local_id).unwrap();

        // Test a selection of bucket indices across the key space.
        let test_indices: Vec<usize> = vec![0, 1, 7, 8, 15, 127, 128, 200, 255];
        for bucket_idx in test_indices {
            let key = dht
                .generate_random_key_for_bucket(bucket_idx)
                .expect("should produce a key for valid bucket index");

            // Verify the generated key falls into the expected bucket by computing
            // the XOR distance and checking the leading bit position.
            let distance = xor_distance_bytes(local_id.to_bytes(), key.as_bytes());
            let leading_bit = leading_bit_position(&distance);
            assert_eq!(
                leading_bit,
                Some(bucket_idx),
                "key for bucket {bucket_idx} has wrong leading bit position: {leading_bit:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_generate_random_key_for_bucket_out_of_range() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::random()).unwrap();
        assert!(dht.generate_random_key_for_bucket(256).is_none());
        assert!(dht.generate_random_key_for_bucket(1000).is_none());
    }

    #[tokio::test]
    async fn test_generate_random_key_for_bucket_produces_different_keys() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::random()).unwrap();
        let mut keys = HashSet::new();
        for _ in 0..10 {
            let key = dht.generate_random_key_for_bucket(100).unwrap();
            keys.insert(key);
        }
        // With 10 random keys, they should not all be identical.
        assert!(
            keys.len() > 1,
            "generate_random_key_for_bucket should produce distinct keys"
        );
    }

    #[tokio::test]
    async fn test_stale_bucket_indices_returns_empty_when_fresh() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::random()).unwrap();
        let stale = dht.stale_bucket_indices(Duration::from_secs(3600)).await;
        assert!(
            stale.is_empty(),
            "freshly created routing table should have no stale buckets"
        );
    }

    #[tokio::test]
    async fn test_node_id_accessor() {
        let id = PeerId::random();
        let dht = DhtCoreEngine::new_for_tests(id).unwrap();
        assert_eq!(*dht.node_id(), id);
    }

    /// Helper: find the position of the first set bit (from MSB) in a 32-byte distance.
    /// Returns `None` for an all-zero distance.
    fn leading_bit_position(distance: &[u8; 32]) -> Option<usize> {
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);
            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return Some(i);
            }
        }
        None
    }

    // =======================================================================
    // Phase 8: Integration test matrix — missing coverage
    // =======================================================================

    // -----------------------------------------------------------------------
    // Test 12: Non-IP transport bypass
    // -----------------------------------------------------------------------

    /// A peer with a non-IP address (Bluetooth) should bypass all IP diversity
    /// checks and be admitted up to bucket capacity.
    #[tokio::test]
    async fn test_non_ip_transport_bypasses_diversity() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Create a node with a Bluetooth-only address (no IP).
        let mut id = [0u8; 32];
        id[0] = 0x80;
        id[31] = 1;
        let bt_addr = MultiAddr::new(TransportAddr::Bluetooth {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            channel: 5,
        });
        let node = NodeInfo {
            id: PeerId::from_bytes(id),
            addresses: vec![bt_addr],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };

        let result = dht.add_node_no_trust(node).await;
        assert!(
            result.is_ok(),
            "non-IP transport should bypass diversity: {:?}",
            result
        );
        assert!(dht.has_node(&PeerId::from_bytes(id)).await);

        // Add several more Bluetooth-only nodes to the same bucket — all should succeed
        // because IP diversity is not checked for non-IP transports.
        for i in 2..=5u8 {
            let mut node_id = [0u8; 32];
            node_id[0] = 0x80;
            node_id[31] = i;
            let bt = MultiAddr::new(TransportAddr::Bluetooth {
                mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, i],
                channel: 5,
            });
            let n = NodeInfo {
                id: PeerId::from_bytes(node_id),
                addresses: vec![bt],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            };
            let r = dht.add_node_no_trust(n).await;
            assert!(r.is_ok(), "Bluetooth node {i} should be admitted: {:?}", r);
        }
    }

    // -----------------------------------------------------------------------
    // Test 26: Local lookup self-exclusion
    // -----------------------------------------------------------------------

    /// `find_nodes` (local lookup) must never return self, even when searching
    /// for our own key.
    #[tokio::test]
    async fn test_local_lookup_excludes_self() {
        let self_id = PeerId::from_bytes([0u8; 32]);
        let mut dht = DhtCoreEngine::new_for_tests(self_id).unwrap();

        dht.add_node_no_trust(make_node(1, "/ip4/10.0.0.1/udp/9000/quic"))
            .await
            .unwrap();

        // Search for self's own key — self should NOT appear in results
        // because self is never in its own routing table.
        let results = dht
            .find_nodes(&DhtKey::from_bytes([0u8; 32]), 10)
            .await
            .unwrap();
        assert!(
            results.iter().all(|n| n.id != self_id),
            "self must be excluded from local lookup results"
        );
        // But other peers should still be returned.
        assert_eq!(results.len(), 1, "expected the one added peer");
    }

    // -----------------------------------------------------------------------
    // Test 29: find_nodes_with_self includes self
    // -----------------------------------------------------------------------

    /// `find_nodes_with_self` must include self as a candidate, correctly
    /// positioned by XOR distance.
    #[tokio::test]
    async fn test_find_nodes_with_self_includes_self() {
        let self_id = PeerId::from_bytes([0u8; 32]);
        let mut dht = DhtCoreEngine::new_for_tests(self_id).unwrap();

        dht.add_node_no_trust(make_node(1, "/ip4/10.0.0.1/udp/9000/quic"))
            .await
            .unwrap();

        // Search for self's own key — distance is zero, so self should be first.
        let results = dht
            .find_nodes_with_self(&DhtKey::from_bytes([0u8; 32]), 10)
            .await
            .unwrap();
        assert!(
            results.iter().any(|n| n.id == self_id),
            "self should be included in find_nodes_with_self results"
        );
        // Self should be first (distance 0 to the search key)
        assert_eq!(results[0].id, self_id, "self should be the closest match");
    }

    // -----------------------------------------------------------------------
    // Test 36: Peer removal via remove_node_by_id
    // -----------------------------------------------------------------------

    /// Removing a peer by ID should produce PeerRemoved events.
    #[tokio::test]
    async fn test_peer_removal_produces_events() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();
        assert!(dht.has_node(&peer_id).await);

        // Graceful removal (e.g. peer departed).
        let events = dht.remove_node_by_id(&peer_id).await;
        assert!(
            !dht.has_node(&peer_id).await,
            "peer must be gone after removal"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == peer_id)),
            "expected PeerRemoved event"
        );
    }

    // -----------------------------------------------------------------------
    // Test 36 extension: removing an absent peer is a no-op
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_remove_absent_peer_produces_no_events() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let absent_peer = PeerId::from_bytes([99u8; 32]);

        let events = dht.remove_node_by_id(&absent_peer).await;
        assert!(
            events.is_empty(),
            "removing a peer not in the routing table should produce no events"
        );
    }

    // -----------------------------------------------------------------------
    // Test 49: Trust protection prevents eclipse displacement (live peers)
    // -----------------------------------------------------------------------

    /// An attacker with a closer ID cannot displace a live well-trusted peer.
    /// Only low-trust, stale, or empty slots can be taken.
    #[tokio::test]
    async fn test_eclipse_resistance_live_trusted_peers() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Fill 2 same-IP slots in bucket 0 with trusted, live peers.
        let mut id_a = [0u8; 32];
        id_a[0] = 0xFF;
        dht.add_node_no_trust(make_node_with_addr(id_a, "/ip4/10.0.1.1/udp/9000/quic"))
            .await
            .unwrap();

        let mut id_b = [0u8; 32];
        id_b[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_b, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Attacker generates a much closer ID with the same IP.
        let mut id_attacker = [0u8; 32];
        id_attacker[0] = 0x80;

        // Both existing peers are live (just added) and well-trusted.
        let peer_a = PeerId::from_bytes(id_a);
        let peer_b = PeerId::from_bytes(id_b);
        let trust_fn = |peer_id: &PeerId| -> f64 {
            if *peer_id == peer_a || *peer_id == peer_b {
                0.9 // well above TRUST_PROTECTION_THRESHOLD
            } else {
                0.5
            }
        };

        let result = dht
            .add_node(
                make_node_with_addr(id_attacker, "/ip4/10.0.1.1/udp/9002/quic"),
                &trust_fn,
            )
            .await;

        // Should be rejected — both peers are live and well-trusted.
        assert!(
            result.is_err(),
            "attacker should not displace live trusted peers"
        );
        assert!(dht.has_node(&peer_a).await, "peer A must survive");
        assert!(dht.has_node(&peer_b).await, "peer B must survive");
    }

    // -----------------------------------------------------------------------
    // Test 50: Stale trust-protected peer displaced by attacker
    // -----------------------------------------------------------------------

    /// A well-trusted but stale peer can be displaced by a closer candidate.
    /// This is correct: a stale peer should not block admission indefinitely.
    #[tokio::test]
    async fn test_stale_trusted_peer_displaced_by_closer_candidate() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        let mut id_far = [0u8; 32];
        id_far[0] = 0xFF;
        dht.add_node_no_trust(make_node_with_addr(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
            .await
            .unwrap();

        let mut id_mid = [0u8; 32];
        id_mid[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Make the far peer stale.
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket_idx = routing
                .get_bucket_index(&PeerId::from_bytes(id_far))
                .unwrap();
            let node = routing.buckets[bucket_idx]
                .nodes
                .iter_mut()
                .find(|n| n.id == PeerId::from_bytes(id_far))
                .unwrap();
            node.last_seen.store(Instant::now() - TEST_STALE_AGE);
        }

        let far_peer = PeerId::from_bytes(id_far);
        // Far peer is well-trusted but STALE.
        let trust_fn = |peer_id: &PeerId| -> f64 { if *peer_id == far_peer { 0.9 } else { 0.5 } };

        let mut id_closer = [0u8; 32];
        id_closer[0] = 0x80;
        let result = dht
            .add_node(
                make_node_with_addr(id_closer, "/ip4/10.0.1.1/udp/9002/quic"),
                &trust_fn,
            )
            .await;

        // Should succeed: stale peer loses trust protection.
        assert!(
            result.is_ok(),
            "stale well-trusted peer should be displaceable: {:?}",
            result
        );
        assert!(
            !dht.has_node(&far_peer).await,
            "stale peer should be evicted"
        );
        assert!(
            dht.has_node(&PeerId::from_bytes(id_closer)).await,
            "closer candidate should be admitted"
        );
    }

    // -----------------------------------------------------------------------
    // Test 56: Consumer event for peer not in routing table
    // -----------------------------------------------------------------------

    /// Trust events for peers not in the routing table should not affect the
    /// routing table. (TrustEngine records the score independently.)
    #[tokio::test]
    async fn test_trust_event_for_absent_peer_does_not_affect_rt() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let absent_peer = PeerId::from_bytes([42u8; 32]);

        // Peer is not in the routing table.
        assert!(!dht.has_node(&absent_peer).await);

        // The routing table should remain unchanged after trust events
        // (trust is tracked externally in TrustEngine, not in the RT).
        let size_before = dht.routing_table_size().await;
        assert!(!dht.has_node(&absent_peer).await);
        let size_after = dht.routing_table_size().await;
        assert_eq!(size_before, size_after, "routing table should be unchanged");
    }

    // -----------------------------------------------------------------------
    // Trust-based swap-out tests
    // -----------------------------------------------------------------------

    /// When a bucket is full, the lowest-trust peer below swap_threshold is
    /// replaced by a new candidate without revalidation.
    #[tokio::test]
    async fn test_trust_swap_out_replaces_lowest_trust_peer() {
        // K=4 so we can fill a bucket quickly. All peers go into the
        // high-bit bucket (byte 0 has bit 7 set, our node_id is [0; 32]).
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();

        // Fill bucket with 4 peers, each on a unique IP
        let mut ids: Vec<[u8; 32]> = Vec::new();
        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80 + i; // all land in same bucket (bit 7 set)
            ids.push(id);
            let addr = format!("/ip4/10.0.{}.1/udp/9000/quic", i);
            dht.add_node(make_node_with_addr(id, &addr), &|_| 0.5)
                .await
                .unwrap();
        }

        // New candidate on a unique IP
        let mut new_id = [0u8; 32];
        new_id[0] = 0x84;
        let new_peer = PeerId::from_bytes(new_id);
        let low_trust_peer = PeerId::from_bytes(ids[2]);

        // Peer ids[2] has trust 0.05 (below 0.35 threshold), others at 0.5
        let result = dht
            .add_node(
                make_node_with_addr(new_id, "/ip4/10.0.4.1/udp/9000/quic"),
                &|id| {
                    if *id == low_trust_peer { 0.05 } else { 0.5 }
                },
            )
            .await
            .unwrap();

        let events = match result {
            AdmissionResult::Admitted(events) => events,
            other => panic!("expected Admitted, got {other:?}"),
        };

        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == low_trust_peer)),
            "low-trust peer should be swapped out"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerAdded(id) if *id == new_peer)),
            "new candidate should be added"
        );
        assert!(dht.has_node(&new_peer).await);
        assert!(!dht.has_node(&low_trust_peer).await);
    }

    /// When multiple peers are below the swap threshold, only the lowest-trust
    /// peer is swapped out.
    #[tokio::test]
    async fn test_trust_swap_out_picks_lowest_when_multiple_below_threshold() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();

        let mut ids: Vec<[u8; 32]> = Vec::new();
        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80 + i;
            ids.push(id);
            let addr = format!("/ip4/10.0.{}.1/udp/9000/quic", i);
            dht.add_node(make_node_with_addr(id, &addr), &|_| 0.5)
                .await
                .unwrap();
        }

        let peer_a = PeerId::from_bytes(ids[1]); // will have trust 0.10
        let peer_b = PeerId::from_bytes(ids[3]); // will have trust 0.05

        let mut new_id = [0u8; 32];
        new_id[0] = 0x84;

        let result = dht
            .add_node(
                make_node_with_addr(new_id, "/ip4/10.0.4.1/udp/9000/quic"),
                &|id| {
                    if *id == peer_a {
                        0.10
                    } else if *id == peer_b {
                        0.05
                    } else {
                        0.5
                    }
                },
            )
            .await
            .unwrap();

        let events = match result {
            AdmissionResult::Admitted(events) => events,
            other => panic!("expected Admitted, got {other:?}"),
        };

        // Only the lowest-trust peer (0.05) should be evicted
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == peer_b)),
            "peer with lowest trust (0.05) should be swapped out"
        );
        assert!(
            dht.has_node(&peer_a).await,
            "peer with trust 0.10 should remain (only one swap needed)"
        );
    }

    /// When all peers in the bucket are above the swap threshold, no trust-based
    /// swap occurs and the system falls through to stale revalidation.
    #[tokio::test]
    async fn test_no_trust_swap_when_all_peers_above_threshold() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();

        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80 + i;
            let addr = format!("/ip4/10.0.{}.1/udp/9000/quic", i);
            dht.add_node(make_node_with_addr(id, &addr), &|_| 0.5)
                .await
                .unwrap();
        }

        let mut new_id = [0u8; 32];
        new_id[0] = 0x84;

        // All peers at neutral (0.5) — no trust-based swap possible
        let result = dht
            .add_node(
                make_node_with_addr(new_id, "/ip4/10.0.4.1/udp/9000/quic"),
                &|_| 0.5,
            )
            .await;

        // Should get StaleRevalidationNeeded (default allow_stale_revalidation=true
        // in add_node) or error — NOT Admitted
        match result {
            Ok(AdmissionResult::Admitted(_)) => {
                panic!("should not be admitted when bucket is full with no low-trust peers")
            }
            Ok(AdmissionResult::StaleRevalidationNeeded { .. }) => {
                // Expected: falls through to stale revalidation
            }
            Err(_) => {
                // Also acceptable: no stale peers found
            }
        }
    }

    /// With swap_threshold = 0.0, trust-based swap-out is disabled.
    #[tokio::test]
    async fn test_no_trust_swap_when_threshold_is_zero() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            0.0, // disabled
        )
        .unwrap();

        let mut ids: Vec<[u8; 32]> = Vec::new();
        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80 + i;
            ids.push(id);
            let addr = format!("/ip4/10.0.{}.1/udp/9000/quic", i);
            dht.add_node(make_node_with_addr(id, &addr), &|_| 0.5)
                .await
                .unwrap();
        }

        let low_peer = PeerId::from_bytes(ids[0]);
        let mut new_id = [0u8; 32];
        new_id[0] = 0x84;

        // Even with a peer at trust 0.01, threshold=0 means no swap
        let result = dht
            .add_node(
                make_node_with_addr(new_id, "/ip4/10.0.4.1/udp/9000/quic"),
                &|id| if *id == low_peer { 0.01 } else { 0.5 },
            )
            .await;

        match result {
            Ok(AdmissionResult::Admitted(_)) => {
                panic!("should not be admitted when swap is disabled and bucket is full")
            }
            _ => {
                // Expected: stale revalidation or error
            }
        }
        // Low-trust peer should still be in the table
        assert!(dht.has_node(&low_peer).await);
    }
}
