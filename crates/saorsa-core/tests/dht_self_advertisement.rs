// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Regression tests for the addresses a node publishes about itself in the DHT.
//!
//! These tests pin the contract that `DhtNetworkManager::local_dht_node()` is
//! the only place where a node decides what addresses to advertise about
//! itself, and that those addresses must always survive a receiving peer's
//! `dialable_addresses()` filter.
//!
//! The production failure mode this guards against is a node telling other
//! peers "you can reach me at <unspecified-or-zero-port>", which is silently
//! filtered out by every consumer's `dialable_addresses()` check and makes
//! the node invisible to DHT-based peer discovery.
//!
//! Concretely, the production path is:
//!
//! 1. Peer A queries the DHT for peer B.
//! 2. The DHT response contains B's self-entry, built by
//!    `DhtNetworkManager::local_dht_node()`.
//! 3. A's `dialable_addresses()` filter rejects any unspecified IP
//!    (`0.0.0.0`, `[::]`) and any non-QUIC entry. Port 0 is also undialable.
//! 4. If every address in B's self-entry is filtered out, A cannot reach B
//!    via the DHT — it can only reach B via static bootstrap config or a
//!    pre-existing in-memory connection.
//!
//! These tests assert (3) succeeds against (2) using the public
//! `find_closest_nodes_local_with_self()` API, which is the same code path the
//! DHT response handler invokes.
//!
//! ## Address sources
//!
//! `local_dht_node()` has exactly two sources:
//!
//! - **Loopback / specific-IP listen binds**: when the transport is bound to
//!   a non-wildcard address (e.g. `127.0.0.1:<port>` from `local: true`
//!   mode), the bound address is published directly. This path is exercised
//!   by the single-node `local_mode_*` tests below.
//! - **OBSERVED_ADDRESS frames**: when the transport is bound to a wildcard
//!   (`0.0.0.0` / `[::]`), the bound address is *not* published. Instead the
//!   node waits until at least one peer connects and reports back via QUIC's
//!   OBSERVED_ADDRESS extension. This path is exercised by the two-node
//!   `wildcard_*` tests below.
//!
//! ## Why we don't substitute wildcards with `primary_local_ip()`
//!
//! An earlier iteration of this fix substituted `0.0.0.0` with the host's
//! primary outbound interface IP (via the standard `UdpSocket::connect`
//! trick). That worked for VPS / public-IP hosts and for LAN deployments,
//! but for home-NAT deployments it published an RFC1918 LAN address that
//! internet peers cannot route to — wasting connection attempts on
//! guaranteed-failed dials. The current design publishes nothing until
//! OBSERVED_ADDRESS arrives, which is honest and self-correcting.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use saorsa_core::{Key, MultiAddr, NodeConfig, P2PNode};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

/// How many results to ask for from the local closest-nodes query. Any value
/// >= 1 is fine; we only care that the local self-entry is included.
const QUERY_COUNT: usize = 8;

/// Brief delay after `start()` to let the listener bind. The two_node_messaging
/// integration tests use the same value.
const POST_START_DELAY: Duration = Duration::from_millis(50);

/// Maximum time to wait for an OBSERVED_ADDRESS frame to arrive after a
/// peer connection completes its handshake. In practice the frame arrives
/// within tens of milliseconds; the budget is generous to absorb scheduler
/// jitter on slow CI.
const OBSERVED_ADDRESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Polling interval for waiting on the observed external address.
const OBSERVED_ADDRESS_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Hard timeout on `connect_peer` and identity exchange in two-node tests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Loopback-mode config used for the single-node local-bind tests.
fn local_mode_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

/// Public-mode (wildcard bind) config used for the two-node OBSERVED_ADDRESS
/// tests and the empty-self-entry contract test.
fn wildcard_mode_config() -> NodeConfig {
    NodeConfig::builder()
        .local(false)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

/// Returns the entry for `peer_id` from a list of `DHTNode`s, or panics with a
/// descriptive message. We assert this entry exists separately from the
/// dialability assertions so a missing self-entry is reported clearly.
fn extract_self_entry(
    nodes: &[saorsa_core::DHTNode],
    peer_id: &saorsa_core::PeerId,
) -> saorsa_core::DHTNode {
    nodes
        .iter()
        .find(|n| n.peer_id == *peer_id)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "find_closest_nodes_local_with_self did not return the local node \
                 (peer_id={peer_id:?}); this means local_dht_node() was not invoked"
            )
        })
}

/// Returns true if the given `MultiAddr` would survive `dialable_addresses()`'s
/// filter — i.e. it is a QUIC address with a specified IP and a non-zero port.
///
/// Mirrors the rejection rules in
/// `saorsa-core/src/dht_network_manager.rs::dialable_addresses`.
fn is_dialable(addr: &MultiAddr) -> bool {
    let Some(sa) = addr.dialable_socket_addr() else {
        return false; // not QUIC
    };
    if sa.ip().is_unspecified() {
        return false; // 0.0.0.0 / [::]
    }
    if sa.port() == 0 {
        return false; // OS-assigned placeholder, never dialable
    }
    true
}

/// Fetches the local self-entry from the node's DHT manager.
async fn fetch_self_entry(node: &P2PNode) -> saorsa_core::DHTNode {
    let key: Key = [0u8; 32];
    let nodes = node
        .dht_manager()
        .find_closest_nodes_local_with_self(&key, QUERY_COUNT)
        .await;
    extract_self_entry(&nodes, node.peer_id())
}

/// Polls `transport.observed_external_address()` until it returns `Some` or
/// the timeout expires. Returns the observed address, or `None` if it never
/// arrived.
async fn wait_for_observed_external_address(
    node: &P2PNode,
    deadline: Duration,
) -> Option<SocketAddr> {
    let result = timeout(deadline, async {
        loop {
            if let Some(addr) = node.transport().observed_external_address() {
                return addr;
            }
            tokio::time::sleep(OBSERVED_ADDRESS_POLL_INTERVAL).await;
        }
    })
    .await;
    result.ok()
}

/// Polls `transport.cached_observed_external_address()` (cache-only,
/// bypassing the live read) until it returns `Some` or the timeout expires.
///
/// Tests use this to wait for the broadcast `ExternalAddressDiscovered`
/// event to be processed by the forwarder and recorded in the cache. The
/// event is fired by saorsa-transport's `poll_discovery_task` on a 1-second
/// tick, so a generous timeout is needed even though the live read may
/// already return a value within tens of milliseconds.
async fn wait_for_cached_observed_address(
    node: &P2PNode,
    deadline: Duration,
) -> Option<SocketAddr> {
    let result = timeout(deadline, async {
        loop {
            if let Some(addr) = node.transport().cached_observed_external_address() {
                return addr;
            }
            tokio::time::sleep(OBSERVED_ADDRESS_POLL_INTERVAL).await;
        }
    })
    .await;
    result.ok()
}

// ---------------------------------------------------------------------------
// Single-node tests: loopback bind path
// ---------------------------------------------------------------------------

/// **PRIMARY REGRESSION TEST FOR THE LOOPBACK BIND PATH.**
///
/// A node bound to a specific loopback address (`local: true` →
/// `127.0.0.1:<bound_port>`) must publish that address directly in its DHT
/// self-entry. The published port must be the *actually-bound* port — not
/// `0`, not the configured port (which is also `0`). If this test fails,
/// peers performing DHT FIND_NODE for this node will receive zero usable
/// addresses and will be unable to connect.
///
/// On the broken codebase this test failed because `local_dht_node()` read
/// from `NodeConfig::listen_addrs()` (a static `(port, ipv6, local)`
/// derivation that returns the configured port — `0` for `--port 0`) instead
/// of from the runtime-bound listener addresses.
#[tokio::test]
async fn local_mode_publishes_dialable_loopback_address() {
    let node = P2PNode::new(local_mode_config())
        .await
        .expect("P2PNode::new should succeed");
    node.start().await.expect("node.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    let self_entry = fetch_self_entry(&node).await;

    assert!(
        !self_entry.addresses.is_empty(),
        "local DHT self-entry has no addresses at all — peers will see this node \
         as having zero contact information"
    );

    let dialable: Vec<&MultiAddr> = self_entry
        .addresses
        .iter()
        .filter(|a| is_dialable(a))
        .collect();

    assert!(
        !dialable.is_empty(),
        "local DHT self-entry has {} address(es) but NONE are dialable: {:?}\n\
         \n\
         This is the root cause of sporadic NAT traversal failure: every address \
         in the self-entry will be filtered out by dialable_addresses() on the \
         receiving peer, so DHT-based peer discovery for this node always returns \
         no contactable address.\n\
         \n\
         Fix: DhtNetworkManager::local_dht_node() must read from the runtime \
         transport state (transport.listen_addrs() and \
         transport.observed_external_address()) instead of NodeConfig::listen_addrs() \
         (which is a pure derivation that returns wildcards in Public mode and \
         zero ports for --port 0).",
        self_entry.addresses.len(),
        self_entry.addresses,
    );

    node.stop().await.expect("node.stop() should succeed");
}

/// The runtime `listen_addrs` read from the transport's RwLock should match
/// the addresses published in the DHT self-entry for loopback binds. If they
/// diverge, the DHT is advertising stale or incorrect contact information.
///
/// This test catches the case where someone "fixes" `local_dht_node()` by
/// reading from the static `NodeConfig` instead of from the live transport
/// state, which would produce a result that's still wrong but in a different
/// way (e.g. the configured port instead of the bound port).
#[tokio::test]
async fn local_mode_published_self_entry_matches_runtime_listen_addrs() {
    let node = P2PNode::new(local_mode_config())
        .await
        .expect("P2PNode::new should succeed");
    node.start().await.expect("node.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    // What the transport actually bound to (real ports on a specific IP).
    let runtime_addrs = node.listen_addrs().await;

    // What the node tells the rest of the network about itself.
    let self_entry = fetch_self_entry(&node).await;

    // The published ports must be the actually-bound ports — not 0, and not
    // some statically configured value that might differ from what the OS
    // chose.
    let runtime_ports: Vec<u16> = runtime_addrs
        .iter()
        .filter_map(MultiAddr::port)
        .filter(|p| *p != 0)
        .collect();

    assert!(
        !runtime_ports.is_empty(),
        "transport.listen_addrs() returned no non-zero ports — the listener \
         did not bind successfully"
    );

    let published_ports: Vec<u16> = self_entry
        .addresses
        .iter()
        .filter_map(MultiAddr::port)
        .collect();

    for port in &runtime_ports {
        assert!(
            published_ports.contains(port),
            "published self-entry does not include the actually-bound port {port}; \
             runtime ports = {runtime_ports:?}, published ports = {published_ports:?}\n\
             \n\
             local_dht_node() is reading from the static NodeConfig instead of \
             from the runtime transport state — peers will dial the wrong port."
        );
    }

    node.stop().await.expect("node.stop() should succeed");
}

/// A node configured with `local: true` (loopback mode) must never publish a
/// port-0 address. Port 0 is the kernel's "pick any port" placeholder; it is
/// never a valid destination.
#[tokio::test]
async fn local_mode_never_publishes_port_zero() {
    let node = P2PNode::new(local_mode_config())
        .await
        .expect("P2PNode::new should succeed");
    node.start().await.expect("node.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    let self_entry = fetch_self_entry(&node).await;

    let zero_port_addrs: Vec<&MultiAddr> = self_entry
        .addresses
        .iter()
        .filter(|a| a.port() == Some(0))
        .collect();

    assert!(
        zero_port_addrs.is_empty(),
        "local DHT self-entry contains {} address(es) with port 0: {:?}\n\
         \n\
         Port 0 is the placeholder the kernel uses for 'pick any port'; it is \
         never a valid destination. Publishing it to the DHT means peers will \
         try to dial port 0 and fail.",
        zero_port_addrs.len(),
        zero_port_addrs,
    );

    node.stop().await.expect("node.stop() should succeed");
}

// ---------------------------------------------------------------------------
// Single-node tests: wildcard bind contract
// ---------------------------------------------------------------------------

/// **CONTRACT: a wildcard-bound node with no observation publishes nothing.**
///
/// When the transport is bound to `0.0.0.0:<port>` (the production default
/// for VPS / cloud deployments) and no peer has yet connected to send an
/// OBSERVED_ADDRESS frame, `local_dht_node()` must return an empty
/// `addresses` vec — *not* the wildcard, *not* a guessed LAN IP, *not* the
/// configured port-0 placeholder.
///
/// This pins the "don't lie when you don't know" contract: it is better to
/// publish no contact information than to publish bind-side wildcards or
/// LAN-only addresses that internet peers cannot route to. Once the bootstrap
/// dial completes and the first OBSERVED_ADDRESS frame arrives, future
/// queries return the real address (see the `wildcard_*_two_nodes` tests
/// below).
#[tokio::test]
async fn wildcard_bind_with_no_peers_publishes_empty_self_entry() {
    let node = P2PNode::new(wildcard_mode_config())
        .await
        .expect("P2PNode::new should succeed");
    node.start().await.expect("node.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    let self_entry = fetch_self_entry(&node).await;

    assert!(
        self_entry.addresses.is_empty(),
        "wildcard-bound node with no peers should publish an empty self-entry, \
         but published {} address(es): {:?}\n\
         \n\
         This is a regression: a freshly-started node must not lie about its \
         contact information. The acceptable sources are (1) the transport's \
         observed_external_address() — None until a peer connects, or (2) a \
         specific-IP bind — N/A for wildcard. Anything else (wildcard \
         substitution, primary outbound interface IP, etc.) risks publishing \
         an address that internet peers cannot route to.",
        self_entry.addresses.len(),
        self_entry.addresses,
    );

    node.stop().await.expect("node.stop() should succeed");
}

// ---------------------------------------------------------------------------
// Two-node tests: OBSERVED_ADDRESS path
// ---------------------------------------------------------------------------

/// Build a loopback dial target for a wildcard-bound node. The node's
/// `listen_addrs()` returns `0.0.0.0:<bound_port>` (not directly dialable),
/// so we substitute `127.0.0.1` as the destination IP — the kernel routes
/// loopback traffic to the wildcard-bound socket.
async fn loopback_dial_target_for(node: &P2PNode) -> MultiAddr {
    let port = node
        .listen_addrs()
        .await
        .into_iter()
        .find_map(|a| a.dialable_socket_addr())
        .expect("wildcard-bound node should have an IPv4 listen address")
        .port();
    assert_ne!(port, 0, "bound port must be non-zero after start()");
    MultiAddr::quic(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
}

/// **PRIMARY REGRESSION TEST FOR THE OBSERVED_ADDRESS PATH.**
///
/// Two wildcard-bound (`0.0.0.0:0`) nodes connect to each other over
/// loopback. After the QUIC handshake completes and OBSERVED_ADDRESS frames
/// flow, each side learns its post-NAT (here: post-loopback) reflexive
/// address. The published DHT self-entry must then include that observed
/// address as a dialable entry.
///
/// This is the contract that makes Public-mode deployments work: a fresh
/// VPS node binds to `0.0.0.0:10000`, dials a bootstrap peer, and the
/// bootstrap's OBSERVED_ADDRESS frame fills in the node's public IP. From
/// that point forward, every DHT query for this node returns its public
/// IP:port.
///
/// If this test fails, sporadic NAT traversal failure will return: peers
/// querying the DHT for a wildcard-bound node will receive empty addresses
/// even after the node has been observed.
#[tokio::test]
async fn wildcard_bind_publishes_observed_address_after_peer_connection() {
    let node_a = P2PNode::new(wildcard_mode_config())
        .await
        .expect("node_a creation should succeed");
    let node_b = P2PNode::new(wildcard_mode_config())
        .await
        .expect("node_b creation should succeed");

    node_a.start().await.expect("node_a.start() should succeed");
    node_b.start().await.expect("node_b.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    // node_b's listen_addrs returns 0.0.0.0:<bound_port> — substitute
    // 127.0.0.1 to produce a dialable address.
    let dial_target = loopback_dial_target_for(&node_b).await;

    let channel_id = timeout(CONNECT_TIMEOUT, node_a.connect_peer(&dial_target))
        .await
        .expect("connect should not timeout")
        .expect("connect should succeed");

    let _peer_b = timeout(
        CONNECT_TIMEOUT,
        node_a.wait_for_peer_identity(&channel_id, CONNECT_TIMEOUT),
    )
    .await
    .expect("identity exchange should not timeout")
    .expect("identity exchange should succeed");

    // Wait for the OBSERVED_ADDRESS frame to populate node_a's reflexive
    // address. This is the moment the wildcard-bind path becomes useful.
    let observed = wait_for_observed_external_address(&node_a, OBSERVED_ADDRESS_TIMEOUT).await;

    assert!(
        observed.is_some(),
        "node_a should have received an OBSERVED_ADDRESS frame from node_b within \
         {OBSERVED_ADDRESS_TIMEOUT:?} of identity exchange, but observed_external_address() \
         is still None.\n\
         \n\
         Either the saorsa-transport address-discovery extension is not emitting \
         OBSERVED_ADDRESS frames after handshake completion, or the frames are \
         not being plumbed through to TransportHandle::observed_external_address(). \
         Check src/transport/saorsa_transport_adapter.rs and the saorsa-transport \
         connection layer."
    );
    let observed = observed.unwrap();

    let self_entry = fetch_self_entry(&node_a).await;

    assert!(
        !self_entry.addresses.is_empty(),
        "node_a's DHT self-entry should contain at least the observed address \
         {observed} after peer connection, but is empty"
    );

    let dialable: Vec<&MultiAddr> = self_entry
        .addresses
        .iter()
        .filter(|a| is_dialable(a))
        .collect();

    assert!(
        !dialable.is_empty(),
        "node_a's self-entry has {} address(es) but NONE are dialable: {:?}\n\
         observed external address = {observed}",
        self_entry.addresses.len(),
        self_entry.addresses,
    );

    let observed_multi = MultiAddr::quic(observed);
    assert!(
        self_entry.addresses.contains(&observed_multi),
        "node_a's self-entry does not include the observed external address \
         {observed}.\n\
         Published addresses: {:?}\n\
         \n\
         local_dht_node() is failing to read from \
         transport.observed_external_address(). Without this, wildcard-bound \
         nodes have no way to advertise themselves to the DHT.",
        self_entry.addresses,
    );

    node_a.stop().await.expect("node_a.stop() should succeed");
    node_b.stop().await.expect("node_b.stop() should succeed");
}

/// **REGRESSION TEST FOR THE OBSERVED-ADDRESS CACHE FALLBACK.**
///
/// `saorsa-transport` exposes the live observed external address only via
/// active connections — when every connection drops, the live read returns
/// `None`. Without a fallback, a node that briefly loses connectivity
/// disappears from the DHT until reconnection.
///
/// `TransportHandle::observed_external_address()` therefore consults a
/// cache populated by `P2pEvent::ExternalAddressDiscovered` events. After
/// a connection drop the cache should still serve the most-recently-observed
/// address, keeping the node visible to DHT queries.
///
/// This test:
///
/// 1. Connects two wildcard-bound nodes over loopback.
/// 2. Waits for OBSERVED_ADDRESS to populate `node_a`'s reflexive address.
/// 3. Records the observed value.
/// 4. Stops `node_b`, which drops the only connection on `node_a`.
/// 5. Waits for `node_a` to see zero connected peers (the live source is
///    now empty).
/// 6. Asserts `node_a.transport().observed_external_address()` still
///    returns the same address — proving the cache fallback engaged.
/// 7. Asserts `node_a`'s DHT self-entry still publishes the observed
///    address, completing the end-to-end contract.
#[tokio::test]
async fn observed_address_cache_serves_fallback_after_connection_drop() {
    let node_a = P2PNode::new(wildcard_mode_config())
        .await
        .expect("node_a creation should succeed");
    let node_b = P2PNode::new(wildcard_mode_config())
        .await
        .expect("node_b creation should succeed");

    node_a.start().await.expect("node_a.start() should succeed");
    node_b.start().await.expect("node_b.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    let dial_target = loopback_dial_target_for(&node_b).await;
    let channel_id = timeout(CONNECT_TIMEOUT, node_a.connect_peer(&dial_target))
        .await
        .expect("connect should not timeout")
        .expect("connect should succeed");
    let _peer_b = timeout(
        CONNECT_TIMEOUT,
        node_a.wait_for_peer_identity(&channel_id, CONNECT_TIMEOUT),
    )
    .await
    .expect("identity exchange should not timeout")
    .expect("identity exchange should succeed");

    // Step 2-3: wait for the OBSERVED_ADDRESS frame to flow all the way
    // through to the cache. The live read can return a value as soon as
    // the QUIC connection has stored an observed address, but the cache is
    // populated by the broadcast `ExternalAddressDiscovered` event which
    // is fired by saorsa-transport's `poll_discovery_task` on a 1-second
    // tick. We poll the cache-only accessor so we know the broadcast event
    // has been received and recorded *before* we disconnect.
    let observed = wait_for_cached_observed_address(&node_a, OBSERVED_ADDRESS_TIMEOUT)
        .await
        .expect(
            "ExternalAddressDiscovered event should reach the observed-address cache \
             within the timeout. If this fails, either saorsa-transport's \
             poll_discovery_task is not firing the broadcast event, or the \
             ExternalAddressDiscovered branch in spawn_peer_address_update_forwarder \
             is not feeding the cache.",
        );

    // Sanity check: while connected, the live read agrees with the cache.
    assert_eq!(
        node_a.transport().observed_external_address(),
        Some(observed),
        "live + cache should agree on the observed address while connected"
    );

    // Step 4: stop node_b. This drops the QUIC connection node_a was using
    // as its only live source of observed-address data.
    node_b.stop().await.expect("node_b.stop() should succeed");

    // Step 5: wait for node_a to notice it has no live peers. Without this,
    // the live `dual_node.get_observed_external_address()` may still return
    // Some(...) because saorsa-transport's connection cleanup is async.
    let drained = timeout(CONNECT_TIMEOUT, async {
        loop {
            if node_a.connected_peers().await.is_empty() {
                return;
            }
            tokio::time::sleep(OBSERVED_ADDRESS_POLL_INTERVAL).await;
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "node_a should observe zero connected peers within {CONNECT_TIMEOUT:?} \
         after stopping node_b"
    );

    // Step 6: the live source is now empty, so any value returned by
    // `observed_external_address()` must be coming from the cache. It must
    // match the address we recorded while the connection was live.
    let after_drop = node_a.transport().observed_external_address();
    assert_eq!(
        after_drop,
        Some(observed),
        "observed_external_address() should still return the cached value \
         {observed} after every live connection has dropped, but returned {after_drop:?}.\n\
         \n\
         Either the ExternalAddressDiscovered forwarder is not feeding the \
         cache (check spawn_peer_address_update_forwarder in \
         saorsa_transport_adapter.rs), or the fallback path in \
         TransportHandle::observed_external_address() is not consulting it."
    );

    // Step 7: end-to-end — the DHT self-entry must still include the
    // observed address, so peers querying us via the DHT can still find us
    // even though we have no live connections.
    let self_entry = fetch_self_entry(&node_a).await;
    let observed_multi = MultiAddr::quic(observed);
    assert!(
        self_entry.addresses.contains(&observed_multi),
        "node_a's DHT self-entry should still include the cached observed \
         address {observed} after the live connection dropped.\n\
         Published addresses: {:?}",
        self_entry.addresses,
    );

    node_a.stop().await.expect("node_a.stop() should succeed");
}
