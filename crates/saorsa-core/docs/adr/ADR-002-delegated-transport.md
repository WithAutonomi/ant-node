# ADR-002: Delegated Transport via saorsa-transport

## Status

Accepted

## Context

P2P networking requires robust transport infrastructure including:

- **Connection management**: Establishing, maintaining, and pooling connections
- **NAT traversal**: Hole punching, STUN/TURN for peers behind NAT
- **Protocol negotiation**: Version handshakes, capability exchange
- **Bootstrap discovery**: Finding initial peers to join the network
- **Cryptographic transport**: TLS 1.3 or equivalent security

Building these from scratch would require:
- Years of development and hardening
- Ongoing maintenance for protocol evolution
- Extensive testing across diverse network conditions
- Security audits for cryptographic implementations

The MaidSafe ecosystem has developed `saorsa-transport`, a battle-tested QUIC implementation with:
- Native NAT traversal (path validation, hole punching)
- Post-quantum cryptography integration
- Bootstrap cache management
- Connection pooling and multiplexing

## Decision

We **delegate all transport-layer concerns to saorsa-transport**, treating it as our transport foundation. Saorsa-core focuses on higher-level P2P semantics while saorsa-transport handles:

### Delegated Responsibilities

```
┌──────────────────────────────────────────────────────────────────┐
│                        saorsa-core                                │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │ • DHT routing & replication                                   ││
│  │ • Identity & presence management                              ││
│  │ • Trust computation (EigenTrust)                              ││
│  │ • Storage placement & orchestration                           ││
│  │ • Upper-layer applications (saorsa-node)                      ││
│  └──────────────────────────────────────────────────────────────┘│
│                              │                                    │
│                              ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │                 Thin Adapter Layer                            ││
│  │  • AntQuicAdapter (src/transport/saorsa_transport_adapter.rs)         ││
│  │  • BootstrapManager wrapper (src/bootstrap/manager.rs)        ││
│  │  • Connection event translation                               ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                         saorsa-transport                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │
│  │ QUIC Streams   │  │ NAT Traversal  │  │ Bootstrap Cache    │  │
│  │ • Bidirectional│  │ • Path Valid.  │  │ • Peer discovery   │  │
│  │ • Multiplexed  │  │ • Hole punching│  │ • Quality metrics  │  │
│  │ • Flow control │  │ • Relay support│  │ • Contact merging  │  │
│  └────────────────┘  └────────────────┘  └────────────────────┘  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │
│  │ Connection Pool│  │ TLS 1.3 + PQC  │  │ Endpoint Mgmt      │  │
│  │ • LRU eviction │  │ • ML-KEM-768   │  │ • Multi-listener   │  │
│  │ • Health checks│  │ • X25519 hybrid│  │ • Port selection   │  │
│  └────────────────┘  └────────────────┘  └────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### Integration Pattern

The adapter layer translates between saorsa-core abstractions and saorsa-transport primitives:

```rust
// src/transport/saorsa_transport_adapter.rs
pub struct AntQuicAdapter {
    endpoint: Endpoint,
    connections: ConnectionPool,
    event_tx: broadcast::Sender<ConnectionEvent>,
}

impl AntQuicAdapter {
    /// Connect to a peer, handling NAT traversal automatically
    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        // saorsa-transport handles:
        // - Path validation for NAT traversal
        // - TLS handshake with PQC
        // - Connection pooling
        self.endpoint.connect(addr).await
    }

    /// Send message to peer
    pub async fn send(&self, peer: &PeerId, msg: &[u8]) -> Result<()> {
        let conn = self.get_or_connect(peer).await?;
        let mut stream = conn.open_uni().await?;
        stream.write_all(msg).await?;
        Ok(())
    }
}
```

### Bootstrap Cache Delegation

The `BootstrapManager` wraps saorsa-transport's cache while adding Sybil protection:

```rust
// src/bootstrap/manager.rs
pub struct BootstrapManager {
    cache: Arc<AntBootstrapCache>,      // Delegated to saorsa-transport
    rate_limiter: JoinRateLimiter,       // Saorsa Sybil protection
    diversity_enforcer: IPDiversityEnforcer, // Saorsa Sybil protection
}

impl BootstrapManager {
    /// Add contact with Sybil protection
    pub async fn add_contact(&self, addr: SocketAddr) -> Result<()> {
        // Saorsa-specific protection
        self.rate_limiter.check_rate(addr.ip())?;
        self.diversity_enforcer.check_diversity(addr.ip())?;

        // Delegate storage to saorsa-transport
        self.cache.add_contact(addr.into()).await
    }
}
```

### Version Compatibility

We track saorsa-transport versions explicitly and test against specific releases:

| saorsa-core | saorsa-transport | Features |
|-------------|----------|----------|
| 0.11.x      | 0.21.x   | Full PQC, placement system, threshold crypto |
| 0.10.x      | 0.20.x   | Full PQC, unified config |
| 0.5.x       | 0.14.x   | Unified config, PQC integration |
| 0.3.x       | 0.10.x   | Basic QUIC, NAT traversal |

## Consequences

### Positive

1. **Reduced maintenance**: Transport bugs fixed upstream benefit us automatically
2. **Battle-tested code**: saorsa-transport is used in production MaidSafe networks
3. **NAT traversal**: Complex hole-punching logic provided out-of-box
4. **PQC integration**: Post-quantum TLS without cryptographic expertise
5. **Focus**: We concentrate on P2P semantics, not transport mechanics
6. **Performance**: Optimized QUIC implementation with connection pooling

### Negative

1. **Version coupling**: saorsa-transport upgrades may require adapter changes
2. **Feature constraints**: Limited to saorsa-transport's capabilities
3. **Debugging complexity**: Transport issues require saorsa-transport knowledge
4. **Build dependency**: Larger dependency tree

### Neutral

1. **API stability**: saorsa-transport follows semver; breaking changes are versioned
2. **Testing**: Integration tests must use real saorsa-transport (no mocks for transport)

## Alternatives Considered

### Build Custom QUIC Stack

Implement QUIC from scratch using quinn as a base.

**Rejected because**:
- 12-18 months additional development
- Ongoing maintenance burden
- NAT traversal is particularly complex
- Security risk from custom crypto

### Use libp2p

Adopt libp2p's transport abstractions.

**Rejected because**:
- Heavy dependency with many transitive crates
- Rust implementation less mature than Go version
- Different design philosophy (more opinionated)
- No native PQC support

### Use TCP with Custom Framing

Fall back to TCP for simplicity.

**Rejected because**:
- No multiplexing without additional protocol
- NAT traversal much harder (no hole punching)
- Higher latency for small messages
- Missing flow control primitives

### WebRTC Data Channels

Use WebRTC for browser compatibility.

**Rejected because**:
- Complex signaling requirements
- Higher overhead for server-to-server
- Less suitable for persistent connections
- We use saorsa-webrtc separately for browser peers

## Migration Notes

When upgrading saorsa-transport versions:

1. Review saorsa-transport CHANGELOG for breaking changes
2. Update adapter layer for API changes
3. Test NAT traversal scenarios
4. Verify bootstrap cache compatibility
5. Run full integration test suite

## References

- [saorsa-transport Repository](https://github.com/maidsafe/saorsa-transport)
- [saorsa-transport ADRs](../../../saorsa-transport/docs/adr/)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
- [Quinn QUIC Implementation](https://github.com/quinn-rs/quinn)
- [ADR-008: Bootstrap Cache Delegation](./ADR-008-bootstrap-delegation.md)
