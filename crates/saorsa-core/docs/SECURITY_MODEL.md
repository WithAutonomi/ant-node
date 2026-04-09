# Saorsa Core Security Model

This document provides a comprehensive overview of the security architecture, threat mitigations, and network protections implemented in Saorsa Core.

> Note: Attestation and witness subsystems are currently out of scope for saorsa-core. Any legacy references below are historical and will be revised.

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Cryptographic Foundation](#cryptographic-foundation)
3. [Node Monitoring & Eviction](#node-monitoring--eviction)
4. [EigenTrust++ Reputation System](#eigentrust-reputation-system)
5. [Data Storage Verification](#data-storage-verification)
6. [Anti-Sybil & Geographic Protections](#anti-sybil--geographic-protections)
7. [Byzantine Fault Tolerance](#byzantine-fault-tolerance)
8. [Network Security Controls](#network-security-controls)
9. [Security Properties Summary](#security-properties-summary)

---

## Executive Summary

Saorsa Core implements a defense-in-depth security architecture designed for decentralized networks operating in adversarial environments. The system provides:

- **Post-quantum cryptography** with ML-DSA-65 signatures and ML-KEM-768 key exchange
- **Multi-layer node monitoring** with automatic eviction of misbehaving nodes
- **EigenTrust++ reputation** for trust-weighted routing and storage decisions
- **Geographic diversity enforcement** to prevent centralization and collusion
- **Byzantine fault tolerance** with configurable f-out-of-3f+1 security model
- **Data integrity verification** using BLAKE3 content hashes

---

## Cryptographic Foundation

### Post-Quantum Algorithms

All cryptographic operations use NIST-standardized post-quantum algorithms:

| Function | Algorithm | Security Level |
|----------|-----------|----------------|
| Digital Signatures | ML-DSA-65 (FIPS 204) | NIST Level 3 (~128-bit quantum) |
| Key Encapsulation | ML-KEM-768 (FIPS 203) | NIST Level 3 (~128-bit quantum) |
| Symmetric Encryption | Upper-layer responsibility | N/A |
| Hashing | BLAKE3 | 256-bit |

### Identity Binding

Node identities are cryptographically bound to their network addresses:

```
NodeId = BLAKE3(serialize(ML-DSA-65 public key))
```

This binding is verified during:
- Node join operations
- Message authentication
- Routing validation and trust-based admission
- Data storage challenges

---

## Node Monitoring & Eviction

### Liveness Tracking

The routing maintenance system continuously monitors node health through the `NodeLivenessState` tracker:

```rust
pub struct NodeLivenessState {
    pub consecutive_failures: u32,      // Tracked per-node
    pub last_success: Option<Instant>,  // For staleness detection
    pub total_failures: u32,            // Historical record
    pub total_successes: u32,           // For response rate calculation
}
```

**Monitoring Triggers:**
- Every DHT operation (GET, PUT, FIND_NODE)
- Periodic health pings (configurable interval)
- Validation responses

### Eviction Criteria

Nodes are automatically evicted when any threshold is exceeded:

| Eviction Reason | Default Threshold | Configuration |
|-----------------|-------------------|---------------|
| Consecutive Failures | 3 failures | `max_consecutive_failures` |
| Low Trust Score | < 0.15 | `min_trust_threshold` |
| Close Group Rejection | Consensus | BFT threshold |
| Staleness | Configurable | `stale_timeout` |

### Eviction Manager

The `EvictionManager` coordinates all eviction decisions:

```rust
pub enum EvictionReason {
    ConsecutiveFailures(u32),    // Communication failures
    LowTrust(String),            // EigenTrust score below threshold
    FailedAttestation,           // Data challenge failure
    CloseGroupRejection,         // Consensus-based removal
    Stale,                       // No activity timeout
}
```

**Recovery Mechanism:** A single successful interaction resets the consecutive failure counter, allowing nodes to recover from transient issues.

---

## EigenTrust++ Reputation System

### Trust Score Calculation

The EigenTrust++ implementation computes global trust scores through iterative power iteration:

```
Trust Score = α * (local trust) + (1-α) * (global trust)
```

**Parameters:**
- Alpha (teleportation factor): 0.4
- Decay rate: 0.99 per epoch
- Convergence threshold: 1e-6
- Maximum iterations: 100

### Multi-Factor Trust Assessment

Trust scores incorporate multiple behavioral dimensions:

| Factor | Weight | Description |
|--------|--------|-------------|
| Response Rate | 0.40 | Fraction of queries answered successfully |
| Uptime | 0.20 | Continuous availability measurement |
| Storage Performance | 0.15 | Data availability and retrieval speed |
| Bandwidth | 0.15 | Network contribution capacity |
| Compute | 0.10 | Processing capability for attestations |

### Trust Integration Points

Trust scores influence:
1. **Routing Decisions**: Higher-trust nodes preferred for query forwarding
2. **Storage Placement**: Data replicated to trusted nodes first
3. **Witness Selection**: Only nodes above minimum trust can witness
4. **Eviction Priority**: Low-trust nodes evicted first during capacity constraints

---

## Data Storage Verification

Note: Application data storage and retrieval are handled in **saorsa-node**. saorsa-core
tracks availability outcomes via trust signals to downscore nodes that fail to serve
expected data.

### Nonce-Based Attestation Challenges

Data integrity is verified through cryptographic attestation using the formula:

```
Response = BLAKE3(nonce || data)
```

**Security Properties:**
- **Nonce freshness**: Random 32-byte nonces prevent precomputation
- **Binding**: Response cryptographically bound to actual data
- **Efficiency**: BLAKE3 enables fast verification at scale

### Challenge Protocol

```
1. Challenger generates random nonce
2. Challenger sends challenge(nonce, data_key) to holder
3. Holder computes BLAKE3(nonce || stored_data)
4. Holder returns signed response
5. Challenger verifies response matches expected hash
```

### Attestation Failure Handling

| Failure Count | Action |
|---------------|--------|
| 1 | Warning logged, node flagged |
| 2+ | Node marked for eviction |
| Repeated | Permanent blacklist consideration |

---

## Anti-Sybil & Geographic Protections

### IP Diversity Enforcement

The `IPDiversityEnforcer` prevents network concentration through subnet-level limits:

| Subnet Level | Default Limit | Purpose |
|--------------|---------------|---------|
| /64 (Host) | 1 node | Single allocation |
| /48 (Site) | 3 nodes | Organization limit |
| /32 (ISP) | 10 nodes | Provider diversity |
| ASN | 20 nodes | Network diversity |

**Stricter Limits for Known Providers:**
- Hosting providers: Limits halved
- VPN providers: Limits halved
- Known bad actors: Blocked entirely

### Geographic Diversity

The witness selection system enforces geographic distribution:

```rust
pub struct WitnessSelectionCriteria {
    pub min_regions: usize,           // Minimum 3 distinct regions
    pub max_per_region: usize,        // Maximum 2 per region
    pub exclude_same_asn: bool,       // Avoid same network provider
    pub prefer_low_latency: bool,     // Performance optimization
}
```

**Anti-Centralization Protections:**
- Minimum 3 geographic regions for witness quorum
- Cross-jurisdiction distribution for legal resilience
- ASN diversity to prevent infrastructure-level attacks

### Eclipse Attack Detection

The routing table monitors for eclipse attack patterns:

```rust
pub struct EclipseDetector {
    pub min_diversity_score: f64,        // Minimum 0.5
    pub max_subnet_concentration: f64,   // Maximum 20%
    pub routing_table_analysis: bool,    // Continuous monitoring
}
```

**Detection Triggers:**
- Routing table diversity score < 0.5
- Single subnet exceeds 20% of known nodes
- Rapid churn from single source

---

## Byzantine Fault Tolerance

### BFT Configuration

The system implements a configurable f-out-of-3f+1 Byzantine fault tolerance model:

| Parameter | Default | Description |
|-----------|---------|-------------|
| f (fault tolerance) | 2 | Maximum Byzantine nodes tolerated |
| Required Confirmations | 5 (2f+1) | Minimum for consensus |
| Witness Count | 7 (3f+1) | Total witnesses selected |

### Close Group Consensus

DHT operations requiring consensus use close group validation:

```
1. Select 3f+1 closest nodes to key
2. Broadcast operation to all members
3. Collect signed responses
4. Require 2f+1 matching responses
5. Reject if threshold not met
```

### Witness Attestation Protocol

```
┌─────────────────────────────────────────────────────────────┐
│                 Witness Attestation Flow                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Client ──────► Select 7 Witnesses (diverse regions)      │
│                         │                                   │
│                         ▼                                   │
│              Challenge All Witnesses in Parallel            │
│                         │                                   │
│                         ▼                                   │
│              Collect Signed Attestations                    │
│                         │                                   │
│                         ▼                                   │
│              Verify ≥5 Valid Responses                      │
│                         │                                   │
│                         ▼                                   │
│              Accept if Quorum Met + Geographic Diverse      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Network Security Controls

### Rate Limiting

Multi-level rate limiting prevents abuse:

| Scope | Limit | Window |
|-------|-------|--------|
| Per Node | 100 requests | 1 minute |
| Per IP | 500 requests | 1 minute |
| Join Requests | 20 | 1 hour |
| Global | Configurable | Configurable |

### Input Validation

All external inputs are validated:
- Address format verification
- Size limit enforcement (DHT records ≤ 512 bytes)
- Path sanitization
- API input validation

### Memory Safety

Sensitive cryptographic material protected:
- Secure memory pools for keys
- Zeroization on drop
- Platform-specific memory protection

### Observability

Security events are logged and metriced:
- Structured audit events
- Prometheus metrics integration
- Eviction reason tracking
- Attack pattern detection alerts

---

## Security Properties Summary

| Property | Guarantee | Implementation |
|----------|-----------|----------------|
| **Quantum Resistance** | NIST Level 3 | ML-DSA-65, ML-KEM-768 |
| **Byzantine Tolerance** | f=2 of 3f+1 | Configurable witness quorum |
| **Sybil Resistance** | IP diversity + Trust | Multi-level subnet limits |
| **Geographic Distribution** | Min 3 regions | Witness selection criteria |
| **Eclipse Prevention** | Diversity scoring | Continuous routing analysis |
| **Data Integrity** | Nonce-based attestation | BLAKE3(nonce \|\| data) |
| **Node Accountability** | EigenTrust++ | Multi-factor reputation |
| **Forward Secrecy** | Fresh nonces | Per-operation context |
| **Non-Repudiation** | Signed attestations | Cryptographic audit trail |

---

## Future Hardening

Planned security enhancements:

1. **Unified Rate Limiter**: Shared rate limiting across all network layers
2. **Monotonic Counters**: Full anti-replay protection integration
3. **ASN/GeoIP Provider**: Production caching and policy hooks
4. **Hardware Security Module**: Optional HSM support for key storage
5. **Formal Verification**: Critical path formal proofs

---

## Contact

For security concerns or vulnerability reports:
- Email: david@saorsalabs.com
- Security advisories: See GitHub Security tab

---

*Copyright 2024 Saorsa Labs Limited*
*SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial*
