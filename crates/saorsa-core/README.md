# Saorsa Core

[![CI](https://github.com/dirvine/saorsa-core-foundation/actions/workflows/rust.yml/badge.svg)](https://github.com/dirvine/saorsa-core-foundation/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/saorsa-core.svg)](https://crates.io/crates/saorsa-core)
[![Documentation](https://docs.rs/saorsa-core/badge.svg)](https://docs.rs/saorsa-core)

Core P2P networking library for Saorsa platform with DHT, QUIC transport, dual-stack endpoints (IPv6+IPv4), and post-quantum cryptography.

## Documentation

- **API Reference**: see [docs/API.md](docs/API.md) - Comprehensive API documentation with examples
- **Architecture Decision Records**: see [docs/adr/](docs/adr/) - Design decisions and rationale
- **Security Model**: see [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) - Network security and anti-Sybil protections
- Architecture overview: see [ARCHITECTURE.md](ARCHITECTURE.md)
- Contributor guide: see [AGENTS.md](AGENTS.md)

## Architecture Decision Records (ADRs)

Key design decisions are documented in [docs/adr/](docs/adr/):

| ADR | Title | Description |
|-----|-------|-------------|
| [ADR-001](docs/adr/ADR-001-multi-layer-architecture.md) | Multi-Layer P2P Architecture | Layered design separating transport, DHT, identity, and application concerns |
| [ADR-002](docs/adr/ADR-002-delegated-transport.md) | Delegated Transport | Using saorsa-transport for QUIC transport, NAT traversal, and bootstrap cache |
| [ADR-003](docs/adr/ADR-003-pure-post-quantum-crypto.md) | Pure Post-Quantum Cryptography | ML-DSA-65 and ML-KEM-768 without classical fallbacks |
| [ADR-006](docs/adr/ADR-006-eigentrust-reputation.md) | Trust System | Response-rate scoring for Sybil resistance |
| [ADR-008](docs/adr/ADR-008-bootstrap-delegation.md) | Bootstrap Cache Delegation | Delegating bootstrap to saorsa-transport with Sybil protection |
| [ADR-009](docs/adr/ADR-009-sybil-protection.md) | Sybil Protection | Multi-layered defense against identity attacks |
| [ADR-012](docs/adr/ADR-012-identity-without-pow.md) | Identity without PoW | Pure cryptographic identity using ML-DSA |

## Features

- **P2P NAT Traversal**: True peer-to-peer connectivity with automatic NAT traversal (saorsa-transport 0.21.x)
- **DHT (Distributed Hash Table)**: Peer phonebook and routing with geographic awareness
- **QUIC Transport**: High-performance networking with saorsa-transport
- **Post-Quantum Cryptography**: Future-ready cryptographic algorithms (ML-DSA-65, ML-KEM-768)
- **Trust System**: Response-rate scoring with time decay and binary peer blocking

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
saorsa-core = "0.16.0"
```

### Basic P2P Node

```rust
use saorsa_core::{NodeConfig, P2PNode};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create and start a P2P node
    let config = NodeConfig::default();
    let node = P2PNode::new(config).await?;
    node.run().await?;

    Ok(())
}
```

### P2P NAT Traversal

saorsa-core includes full NAT traversal support in the transport and network layers, enabling direct peer-to-peer connections. User-facing messaging examples live in saorsa-node, while this crate provides the transport and DHT primitives.

### Data Replication (saorsa-node)

saorsa-core does **not** replicate application data. saorsa-node:
- Stores chunks locally and tracks replica sets.
- Selects target peers using saorsa-core's adaptive routing outputs.
- Replicates via `send_message` and reports success/failure back to the TrustEngine.
- Reacts to churn events from `DhtNetworkManager::subscribe_events()` and re-replicates.

## Architecture

### Core Components

1. **Network Layer**: QUIC-based P2P networking with automatic NAT traversal (saorsa-transport 0.26)
2. **DHT**: Kademlia-based peer phonebook with geographic awareness
3. **Trust System**: Response-rate scoring with time decay and binary peer blocking

### Cryptographic Architecture

Saorsa Core implements a pure post-quantum cryptographic approach for maximum security:

- **Post-quantum signatures**: ML-DSA-65 (FIPS 204) for quantum-resistant digital signatures (~128-bit quantum security)
- **PQC Encryption**: saorsa-pqc primitives for key encapsulation and signatures
- **Key Exchange**: ML-KEM-768 (FIPS 203) for quantum-resistant key encapsulation (~128-bit quantum security)
- **Hashing**: BLAKE3 for fast, secure content addressing
- **Transport Security**: QUIC with TLS 1.3 and PQC cipher suites
- **No Legacy Support**: Pure PQC implementation with no classical cryptographic fallbacks

### Recent Changes

- Removed all Proof-of-Work (PoW) usage (identity, adaptive, DHT, error types, CLI).
- Removed placement/storage orchestration system (now a phonebook-only DHT).
- Implemented dual-stack listeners (IPv6 + IPv4) and Happy Eyeballs dialing.

### Data Flow

```
Application
    ↓
Network API
    ↓
DHT Phonebook + Geographic Routing
    ↓
QUIC Transport (saorsa-transport)
    ↓
Internet
```

## Configuration

```rust
use saorsa_core::NetworkConfig;

let config = NetworkConfig {
    listen_port: 9000,
    bootstrap_nodes: vec![
        "bootstrap1.example.com:9000".parse()?,
        "bootstrap2.example.com:9000".parse()?,
    ],
    ..Default::default()
};
```

## Feature Flags

No feature flags — all functionality is always enabled. DHT, QUIC transport (saorsa-transport),
and post-quantum cryptography are included unconditionally.

## Performance

Saorsa Core is designed for high performance:

- **Concurrent Operations**: Tokio-based async runtime
- **Memory Efficiency**: Zero-copy operations where possible
- **Network Optimization**: QUIC with congestion control

## Security

Saorsa Core implements defense-in-depth security designed for adversarial decentralized environments.

**For complete security documentation, see [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).**

### Cryptographic Foundation

- **Post-Quantum Signatures**: ML-DSA-65 (FIPS 204) for quantum-resistant digital signatures (~128-bit quantum security)
- **Key Exchange**: ML-KEM-768 (FIPS 203) for quantum-resistant key encapsulation
- **Symmetric Encryption**: Provided by upper layers; saorsa-core focuses on PQC key exchange and signatures
- **Hashing**: BLAKE3 for fast, secure content addressing
- **Pure PQC**: No classical cryptographic fallbacks - quantum-resistant from the ground up

### Network Protection

| Protection | Implementation |
|------------|----------------|
| **Node Monitoring** | Automatic eviction after 3 consecutive failures |
| **Reputation System** | Response-rate scoring with time decay |
| **Sybil Resistance** | IP diversity limits (/64: 1, /48: 3, /32: 10, ASN: 20) |
| **Geographic Diversity** | Regional diversity in routing |
| **Routing Validation** | Trust-based peer blocking and eviction |

### Anti-Centralization

The network enforces geographic and infrastructure diversity to prevent centralization:

```
┌───────────────────────────────────────────────────┐
│           Geographic Diversity Distribution        │
├───────────────────────────────────────────────────┤
│  Region A      Region B      Region C      ...    │
│  (max 2)       (max 2)       (max 2)              │
│     │             │             │                 │
│     └─────────────┼─────────────┘                 │
│                   ▼                               │
│    Selection prefers 3+ regions                   │
│    (prevents regional collusion)                  │
└───────────────────────────────────────────────────┘
```

- **ASN Diversity**: Max 20 nodes per autonomous system
- **Hosting Provider Limits**: Stricter limits (halved) for known VPS/cloud providers
- **Eclipse Detection**: Continuous routing table diversity monitoring

## Development

### Building

```bash
# Standard build
cargo build --release

# With all features
cargo build --all-features
```

### Testing

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test '*'
```

### Linting

```bash
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used
cargo fmt --all
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Style

- Follow Rust 2024 idioms
- Use `cargo fmt` for formatting
- Ensure `cargo clippy` passes
- Add documentation for public APIs
- Include tests for all new features

## License

This project is dual-licensed:

- **AGPL-3.0**: Open source license for open source projects
- **Commercial**: Commercial license for proprietary projects

For commercial licensing, contact: david@saorsalabs.com

## Dependencies

### Core Dependencies
- `tokio` - Async runtime
- `futures` - Future utilities
- `serde` - Serialization
- `anyhow` - Error handling
- `tracing` - Logging

### Networking
- `saorsa-transport` (0.26) - QUIC transport with P2P NAT traversal

### Cryptography
- `saorsa-pqc` - Post-quantum cryptography (ML-DSA, ML-KEM)
- `blake3` - Hashing
- `rand` - Random number generation

See `Cargo.toml` for complete dependency list.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Support

- **Issues**: [GitHub Issues](https://github.com/dirvine/saorsa-core-foundation/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dirvine/saorsa-core-foundation/discussions)
- **Email**: david@saorsalabs.com

---

**Saorsa Labs Limited** - Building the decentralized future
