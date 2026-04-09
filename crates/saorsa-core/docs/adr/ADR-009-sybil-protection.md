# ADR-009: Sybil Protection Mechanisms

## Status

Accepted

## Context

The **Sybil attack** is the fundamental threat to decentralized systems. An adversary creates many pseudonymous identities to:

- **Control routing**: Dominate key regions in the DHT
- **Eclipse honest nodes**: Surround targets with malicious peers
- **Manipulate consensus**: Outvote honest participants
- **Poison caches**: Fill bootstrap caches with attacker nodes
- **Corrupt reputation**: Collude to boost malicious scores

Without identity binding (like proof-of-work or real-world identity), any node can create unlimited identities. We need defense-in-depth:

> "No single mechanism defeats Sybil attacks; only layered defenses provide meaningful protection."

## Decision

We implement **multi-layered Sybil protection** combining six complementary mechanisms:

### Defense Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                     Sybil Defense Stack                          │
│                                                                  │
│  Layer 6: Application-Level Verification                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • Human verification for high-value operations           │   │
│  │ • Social vouching (trusted introductions)                │   │
│  │ • Multi-device attestation                               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Layer 5: Entangled Attestation                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • Software integrity verification                        │   │
│  │ • Attestation chains for provenance                      │   │
│  │ • Binary hash verification                               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Layer 4: EigenTrust Reputation                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • Iterative trust computation                            │   │
│  │ • Trust decay over time                                  │   │
│  │ • Pre-trusted anchor nodes                               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Layer 3: Geographic Diversity                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • Multi-region witness requirements                      │   │
│  │ • IP diversity enforcement                               │   │
│  │ • BGP-based geolocation                                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Layer 2: Rate Limiting                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • Per-IP join limits                                     │   │
│  │ • Per-subnet join limits                                 │   │
│  │ • Time-window throttling                                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Layer 1: Cryptographic Identity                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • ML-DSA-65 key binding                                  │   │
│  │ • No proof-of-work (see ADR-012)                         │   │
│  │ • Identity persistence via DHT                           │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 1: Cryptographic Identity

Every identity is bound to an ML-DSA-65 keypair:

```rust
// Identity cannot be forged without private key
pub struct Identity {
    pub public_key: MlDsaPublicKey,  // 1,952 bytes
    pub created_at: SystemTime,
}

// All operations require signature
pub struct SignedOperation {
    pub operation: Operation,
    pub signature: MlDsaSignature,  // 3,309 bytes
}
```

**Cost to attacker**: Must generate unique keypairs (computationally cheap but storage-heavy at ~6KB per identity).

### Layer 2: Rate Limiting

```rust
// src/rate_limit.rs

pub struct JoinRateLimiter {
    /// Sliding window counters
    per_ip: SlidingWindowCounter,
    per_subnet24: SlidingWindowCounter,
    per_subnet16: SlidingWindowCounter,
}

impl JoinRateLimiter {
    pub fn check_rate(&self, ip: IpAddr) -> Result<(), JoinRateLimitError> {
        // Limit: 5 joins per IP per minute
        if self.per_ip.count(ip) >= 5 {
            return Err(JoinRateLimitError::IpRateExceeded);
        }

        // Limit: 20 joins per /24 subnet per minute
        let subnet24 = extract_ipv4_subnet_24(ip);
        if self.per_subnet24.count(subnet24) >= 20 {
            return Err(JoinRateLimitError::SubnetRateExceeded);
        }

        // Limit: 100 joins per /16 subnet per hour
        let subnet16 = extract_ipv4_subnet_16(ip);
        if self.per_subnet16.count_hourly(subnet16) >= 100 {
            return Err(JoinRateLimitError::SubnetRateExceeded);
        }

        Ok(())
    }
}
```

**Cost to attacker**: Must control IPs across many subnets; cloud providers typically allocate from limited /16 ranges.

### Layer 3: Geographic Diversity

```rust
// src/security/ip_diversity.rs

pub struct IPDiversityEnforcer {
    config: IPDiversityConfig,
    subnet_counts: HashMap<u32, usize>,
}

impl IPDiversityEnforcer {
    /// Enforce maximum concentration from any subnet
    pub fn check_diversity(&self, new_ip: IpAddr) -> bool {
        let subnet8 = extract_ipv4_subnet_8(new_ip);
        let current = self.subnet_counts.get(&subnet8).copied().unwrap_or(0);
        let total = self.get_total_count();

        // Max 25% from any /8
        let ratio = (current + 1) as f64 / (total + 1) as f64;
        ratio <= self.config.max_per_slash8
    }
}

// Witness selection requires geographic spread
pub struct WitnessRequirements {
    /// Minimum distinct regions (e.g., 3 of [Europe, Americas, Asia, Oceania])
    pub min_regions: usize,

    /// Maximum witnesses from same /16 subnet
    pub max_same_subnet: usize,
}
```

**Cost to attacker**: Must have infrastructure in multiple geographic regions; significantly increases attack cost.

### Layer 4: EigenTrust Reputation

See [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md).

**Key properties**:
- New identities start with zero trust
- Trust propagates only through interactions with trusted nodes
- Pre-trusted nodes anchor the network
- Collusion is diluted by honest majority

```rust
// Minimum trust for privileged operations
pub const MIN_WITNESS_TRUST: f64 = 0.3;
pub const MIN_STORAGE_TRUST: f64 = 0.2;
pub const MIN_ROUTING_TRUST: f64 = 0.1;
```

**Cost to attacker**: Must maintain sustained good behavior to build trust; any malicious action damages score.

### Layer 5: Entangled Attestation

See [ADR-010: Entangled Attestation System](./ADR-010-entangled-attestation.md).

```rust
// Verify peer is running approved software
pub async fn verify_peer_attestation(&self, peer: &PeerId) -> AttestationResult {
    let attestation = self.request_attestation(peer).await?;

    // Check software hash is in approved set
    if !self.approved_hashes.contains(&attestation.binary_hash) {
        return AttestationResult::UnapprovedSoftware;
    }

    // Verify attestation chain
    self.verify_chain(&attestation.chain)?;

    AttestationResult::Verified
}
```

**Cost to attacker**: Must either run approved software (limiting attack surface) or forge attestations (cryptographically infeasible).

### Layer 6: Application-Level Verification

For high-value operations:

```rust
pub enum VerificationLevel {
    /// No additional verification (routine operations)
    None,

    /// Require multi-device confirmation
    MultiDevice,

    /// Require social vouching from trusted contacts
    SocialVouch { min_vouches: usize },

    /// Require human verification (CAPTCHA, etc.)
    HumanVerification,
}

// High-value operations (implemented in saorsa-node) should require stronger verification.
// saorsa-core provides the verification and trust primitives; upper layers enforce policy.
```

### Attack Scenarios and Defenses

| Attack | Defense Layers | Mitigation |
|--------|---------------|------------|
| Mass identity creation | Rate limiting, Diversity | Throttled per IP/subnet |
| VPN/Tor rotation | Geographic diversity | Requires multi-region presence |
| Cloud provider attack | Subnet limits | /16 and /8 concentration limits |
| Colluding nodes | EigenTrust | Trust doesn't transfer between colluders |
| Modified client | Attestation | Unapproved software rejected |
| Eclipse attack | Witness diversity | Witnesses from multiple regions |
| Bootstrap poisoning | Rate limits + Diversity | Cannot flood cache |

## Consequences

### Positive

1. **Defense in depth**: No single point of failure
2. **Graduated protection**: Stronger verification for higher stakes
3. **Adaptable**: Can tune parameters based on observed attacks
4. **No PoW**: Accessible without specialized hardware
5. **Composable**: Layers can be added/removed independently

### Negative

1. **Complexity**: Multiple interacting systems
2. **Latency**: Some checks add round-trips
3. **False positives**: Legitimate users may trigger limits
4. **Tuning required**: Parameters need adjustment over time
5. **Determined attackers**: Nation-state level resources can still attack

### Neutral

1. **Monitoring overhead**: Must track metrics across all layers
2. **Documentation burden**: Each layer needs explanation

## Economic Analysis

**Attack costs** (rough estimates for 1000-node Sybil attack):

| Resource | Requirement | Estimated Cost |
|----------|-------------|----------------|
| IP addresses | 50+ /24 subnets | $500-5000/month |
| Geographic presence | 3+ regions | $300-1000/month |
| Compute | 1000 VMs | $1000-5000/month |
| Time | Build trust | 3-6 months |
| **Total** | | **$5000-15000 + 6 months** |

**Without protections**:
- Same attack: ~$500/month (single data center)
- Time: Minutes

## Alternatives Considered

### Proof-of-Work Identity

Require computational puzzle for identity creation.

**Rejected because**:
- Energy intensive (environmental concern)
- Favors specialized hardware (centralization)
- Poor user experience
- ASICs commoditize the cost

### Proof-of-Stake

Require token deposit for identity.

**Rejected because**:
- Requires cryptocurrency infrastructure
- Wealth concentration risk
- Regulatory complexity
- Barrier to entry

### Trusted Third Parties

Use certificate authorities for identity.

**Rejected because**:
- Centralization risk
- Single points of compromise
- Conflicts with P2P philosophy

### Social Graphs Only

Rely entirely on web-of-trust.

**Rejected because**:
- Bootstrap problem for new users
- Social engineering vulnerabilities
- Doesn't scale

## References

- [The Sybil Attack (Douceur, 2002)](https://www.microsoft.com/en-us/research/wp-content/uploads/2002/01/IPTPS2002.pdf)
- [SybilGuard: Defending Against Sybil Attacks](https://dl.acm.org/doi/10.1145/1159913.1159945)
- [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md)
- [ADR-010: Entangled Attestation System](./ADR-010-entangled-attestation.md)
- [ADR-012: Identity without Proof-of-Work](./ADR-012-identity-without-pow.md)
