# ADR-001: Multi-Layer P2P Architecture

## Status

Accepted

## Context

Building a decentralized peer-to-peer network requires managing complexity across multiple concerns: transport protocols, distributed storage, identity management, trust computation, and application-level semantics. Traditional P2P systems often conflate these layers, leading to:

- **Tight coupling**: Transport changes require modifications throughout the stack
- **Testing difficulty**: Cannot test DHT logic without real network connections
- **Upgrade complexity**: Protocol upgrades cascade through the entire system
- **Code duplication**: Common patterns reimplemented across modules

We needed an architecture that enables:
1. Independent evolution of each layer
2. Testability at each level of abstraction
3. Clear boundaries for security auditing
4. Flexible composition for different deployment scenarios

## Decision

We adopt a **multi-layer architecture** with clearly defined boundaries and interfaces:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                            │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │  Chat   │  │ Discuss │  │ Projects │  │ Storage Manager  │   │
│  └────┬────┘  └────┬────┘  └────┬─────┘  └────────┬─────────┘   │
│       └────────────┴───────────┬┴─────────────────┘             │
├─────────────────────────────────┼───────────────────────────────┤
│                     Identity Layer                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────────┐ │
│  │ PQC Identities  │  │ Device Registry │  │ Presence System   │ │
│  └────────┬────────┘  └────────┬────────┘  └─────────┬─────────┘ │
│          └────────────────────┼─────────────────────┘           │
├───────────────────────────────┼─────────────────────────────────┤
│                     Trust & Placement Layer                      │
│  ┌──────────────┐  ┌───────────────────┐  ┌───────────────────┐ │
│  │  EigenTrust  │  │ Placement Engine  │  │ Geographic Router │ │
│  └──────┬───────┘  └─────────┬─────────┘  └─────────┬─────────┘ │
│         └────────────────────┼──────────────────────┘           │
├──────────────────────────────┼──────────────────────────────────┤
│                     DHT Layer                                    │
│  ┌───────────────┐  ┌────────────────┐  ┌─────────────────────┐ │
│  │ Kademlia Core │  │ Witness System │  │ DHT Network Manager │ │
│  └───────┬───────┘  └───────┬────────┘  └──────────┬──────────┘ │
│          └──────────────────┼──────────────────────┘            │
├─────────────────────────────┼───────────────────────────────────┤
│                     Adaptive Layer                               │
│  ┌───────────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │ Multi-Armed Bandit│  │ Q-Learning    │  │ Churn Predictor │  │
│  └─────────┬─────────┘  └───────┬───────┘  └────────┬────────┘  │
│            └────────────────────┼───────────────────┘           │
├─────────────────────────────────┼───────────────────────────────┤
│                     Transport Layer                              │
│  ┌─────────────────────────────┴─────────────────────────────┐  │
│  │                    saorsa-transport (QUIC + PQC)                   │  │
│  │  ┌────────────┐  ┌────────────────┐  ┌─────────────────┐   │  │
│  │  │ Connection │  │ NAT Traversal  │  │ Bootstrap Cache │   │  │
│  │  └────────────┘  └────────────────┘  └─────────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                     Security Layer (Cross-Cutting)               │
│  ┌──────────────┐  ┌─────────────────┐  ┌────────────────────┐  │
│  │ PQC (ML-DSA) │  │ Trust/Validation│  │ Secure Memory      │  │
│  └──────────────┘  └─────────────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

#### 1. Transport Layer (`src/transport/`, delegated to saorsa-transport)

Handles all network I/O:
- QUIC connection management with connection pooling
- NAT traversal (STUN/TURN, hole punching)
- Bootstrap cache for peer discovery
- Post-quantum TLS via ML-KEM key exchange

**Interface to upper layers**: `Connection`, `Endpoint`, stream abstractions

#### 2. Adaptive Layer (`src/adaptive/`)

Provides intelligent routing decisions:
- Thompson Sampling for strategy selection
- Q-Learning for cache optimization
- Churn prediction for proactive replication
- Multiple routing strategies (Kademlia, Hyperbolic, Trust-based)

**Interface**: `RoutingDecision`, `StrategyRecommendation`

#### 3. DHT Layer (`src/dht/`, `src/dht_network_manager/`)

Manages distributed hash table operations:
- Kademlia routing with K=8 replication
- Witness-based Byzantine fault tolerance
- Record versioning and conflict resolution
- Geographic-aware peer selection

**Interface**: `DhtNetworkManager`, `Key`, `Record`

#### 4. Trust & Placement Layer (`src/placement/`, `src/security/`)

Ensures reliable storage placement:
- EigenTrust reputation computation
- Weighted node selection formula
- Geographic diversity enforcement
- Audit and repair systems

**Interface**: `PlacementEngine`, `PlacementDecision`

#### 5. Identity Layer (`src/identity/`, `src/fwid/`)

Manages cryptographic identities:
- ML-DSA-65 key pairs for signing
- Multi-device registration
- Presence and availability tracking

**Interface**: `NodeIdentity`, `DeviceRegistry`

#### 6. Application Layer (upper-level, e.g. saorsa-node)

Provides user-facing functionality above saorsa-core:
- Application-specific data types and business logic
- User messaging and collaboration (outside this crate)
- Automatic storage strategy selection via saorsa-core APIs

**Interface**: Domain-specific managers in upper layers

#### 7. Security Layer (Cross-cutting)

Applied throughout the stack:
- Post-quantum cryptography (ML-DSA-65, ML-KEM-768)
- Secure memory management
- Rate limiting and validation

### Inter-Layer Communication

Layers communicate through well-defined Rust traits and async channels:

```rust
// Example: DHT layer exposes operations to upper layers
pub trait DhtOperations {
    async fn store(&self, key: Key, value: Record) -> Result<()>;
    async fn get(&self, key: &Key) -> Result<Option<Record>>;
    async fn get_closest_peers(&self, key: &Key, count: usize) -> Vec<PeerInfo>;
}

// Placement layer uses DHT operations
impl PlacementEngine {
    pub async fn place_data(&self, data: &[u8]) -> Result<PlacementDecision> {
        let candidates = self.dht.get_closest_peers(&key, self.config.k).await;
        let selected = self.select_by_reputation(candidates).await?;
        // ...
    }
}
```

### Dependency Direction

Dependencies flow downward only:
- Application → Identity → Trust/Placement → DHT → Adaptive → Transport
- Security layer is injected at each level

This ensures:
- Lower layers have no knowledge of higher layers
- Each layer can be tested in isolation
- Upgrades propagate in a controlled manner

## Consequences

### Positive

1. **Testability**: Each layer can be unit tested with mock dependencies
2. **Flexibility**: Transport can be swapped (e.g., TCP fallback) without changing DHT logic
3. **Security auditing**: Clear boundaries make security reviews tractable
4. **Parallel development**: Teams can work on different layers simultaneously
5. **Performance isolation**: Bottlenecks are easier to identify and optimize

### Negative

1. **Indirection overhead**: Cross-layer calls add minimal latency
2. **Learning curve**: Developers must understand the full architecture
3. **Boilerplate**: Interface definitions add code volume
4. **Coordination**: Changes spanning layers require careful planning

### Neutral

1. **Documentation burden**: Each layer requires separate documentation
2. **Version management**: Layer interfaces must be versioned independently

## Alternatives Considered

### Monolithic Architecture

A single module handling all P2P concerns.

**Rejected because**:
- Testing requires full network setup
- Security audits are more complex
- Code reuse is limited

### Microservices / Process Isolation

Separate OS processes for each layer communicating via IPC.

**Rejected because**:
- Latency overhead for frequent cross-layer calls
- Memory overhead from separate processes
- Deployment complexity
- Rust's safety guarantees reduce need for process isolation

### Actor Model

Using an actor framework (like Actix) throughout.

**Rejected because**:
- Adds runtime complexity
- Makes debugging more difficult
- Rust's async/await provides sufficient concurrency
- Actor semantics don't map well to all layers

## References

- [Clean Architecture (Robert C. Martin)](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
- [libp2p Modularity](https://docs.libp2p.io/concepts/introduction/overview/)
- [Kademlia DHT Paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
