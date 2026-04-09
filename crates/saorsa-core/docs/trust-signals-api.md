# Trust Signals API Reference

## Overview

saorsa-core provides a response-rate trust system for tracking node reliability.
The trust system is owned by `AdaptiveDHT`, which is the sole authority on peer trust scores.

Core only records penalties — successful responses are the expected baseline
and do not warrant a reward. Positive trust signals are the consumer's
responsibility via `TrustEvent::ApplicationSuccess`.

The trust system enables:
- **Sybil resistance**: Malicious nodes are downscored automatically
- **Binary blocking**: Peers below the block threshold are evicted and rejected
- **Self-healing**: Time decay moves blocked peers back toward neutral over days
- **Live eviction**: Peers below trust threshold are evicted from the routing table immediately

## Quick Start

```rust
use saorsa_core::{P2PNode, TrustEvent};

// Consumer rewards peer after successful application-level operation:
node.report_trust_event(&peer_id, TrustEvent::ApplicationSuccess(1.0)).await;

// Report a connection failure (penalty):
node.report_trust_event(&peer_id, TrustEvent::ConnectionFailed).await;

// Check peer trust before operations:
let trust = node.peer_trust(&peer_id);
if trust < 0.3 {
    tracing::warn!("Low trust peer: {peer_id}");
}
```

## P2PNode Trust Methods

### `report_trust_event(peer_id, event)`

Report a trust event for a peer. Core penalties (connection failures) are
recorded automatically by the DHT layer. Consumers use this API to report
application-level outcomes (rewards and additional penalties).

```rust
pub async fn report_trust_event(&self, peer_id: &PeerId, event: TrustEvent)
```

### `peer_trust(peer_id)`

Get the current trust score for a peer (0.0 to 1.0). Returns 0.5 for unknown peers.

```rust
pub fn peer_trust(&self, peer_id: &PeerId) -> f64
```

### `trust_engine()`

Get the underlying TrustEngine for advanced operations.

```rust
pub fn trust_engine(&self) -> &Arc<TrustEngine>
```

## TrustEvent Enum

Core only records penalties. Rewards are the consumer's responsibility via
`ApplicationSuccess`. Successful responses are the expected baseline and
are not rewarded.

| Event | Severity | Description | Where it fires |
|-------|----------|-------------|----------------|
| `ConnectionFailed` | 1x penalty (core) | Could not establish connection | `send_request()` error, `send_dht_request()` RPC failure |
| `ConnectionTimeout` | 1x penalty (core) | Connection attempt timed out | `send_request()` timeout, `send_dht_request()` RPC timeout |
| `ApplicationSuccess(w)` | Weighted reward (consumer) | Peer completed an application-level task | Consumer code |
| `ApplicationFailure(w)` | Weighted penalty (consumer) | Peer failed an application-level task | Consumer code |

Note: Peer disconnects are normal connection lifecycle — they do not affect trust.

## Peer Blocking

Peers whose trust score falls below `block_threshold` are:
- **Evicted** from the DHT routing table (via EvictionManager)
- **Blocked** from sending DHT messages (silently dropped)
- **Rejected** from re-entering the routing table on reconnect

```rust
use saorsa_core::AdaptiveDhtConfig;

let config = AdaptiveDhtConfig {
    block_threshold: 0.15,  // Block peers below 15% trust
    ..Default::default()
};
```

DHT routing uses pure Kademlia XOR distance — trust does not influence peer selection order.

## Architecture

```
P2PNode
    │
    ├── report_trust_event(peer, event) ──► AdaptiveDHT ──► TrustEngine
    │                                           │
    ├── peer_trust(peer) ◄────────────── TrustEngine.score()
    │
    └── DHT operations ──► DhtNetworkManager ──► TrustEngine
                           (records per-peer outcomes internally)
```

- **TrustEngine** is the sole authority on peer trust scores
- **AdaptiveDHT** owns TrustEngine and DhtNetworkManager
- **DhtNetworkManager** records trust penalties for DHT operations (failed lookups, dial failures)
- **P2PNode** exposes `report_trust_event()` for consumer rewards and additional penalties
