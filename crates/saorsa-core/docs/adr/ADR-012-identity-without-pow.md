# ADR-012: Identity without Proof-of-Work

## Status

Accepted

## Context

Decentralized identity systems must balance accessibility against Sybil resistance. Common approaches include:

### Proof-of-Work (PoW)

Bitcoin and many cryptocurrencies require computational puzzles to create identities or transactions:
- **Pros**: Costly to create many identities
- **Cons**:
  - Energy intensive (environmental impact)
  - Favors specialized hardware (ASICs)
  - Centralizes power to those who can afford hardware
  - Poor user experience (wait times)
  - Doesn't prevent motivated attackers with resources

### Proof-of-Stake (PoS)

Requires locking tokens as collateral:
- **Pros**: Energy efficient, slashing for misbehavior
- **Cons**:
  - Requires cryptocurrency infrastructure
  - Wealth concentration ("rich get richer")
  - Barrier to entry for new users
  - Regulatory complexity

### Federated Identity

Relies on trusted identity providers:
- **Pros**: Proven, scalable
- **Cons**:
  - Centralization
  - Single points of compromise
  - Privacy concerns
  - Not truly decentralized

We wanted identity creation that is:
1. **Instant**: No waiting for puzzles or confirmations
2. **Free**: No token requirement
3. **Accessible**: Works on any device
4. **Secure**: Cryptographically bound
5. **Sybil-resistant**: Through other mechanisms (see ADR-009)

## Decision

We use **pure cryptographic identity** based on ML-DSA-65 key pairs, without any proof-of-work requirement. Sybil resistance is achieved through complementary mechanisms.

### Identity Structure

```rust
// src/identity/mod.rs

/// User identity bound to ML-DSA-65 keypair
pub struct UserIdentity {
    /// ML-DSA-65 public key (1,952 bytes)
    pub public_key: MlDsaPublicKey,

    /// Identity creation timestamp
    pub created_at: SystemTime,

    /// Optional display name
    pub display_name: Option<String>,

    /// Device list
    pub devices: Vec<Device>,
}

/// Device associated with an identity
pub struct Device {
    /// Unique device identifier
    pub id: DeviceId,

    /// Device type
    pub device_type: DeviceType,

    /// Device-specific public key
    pub public_key: MlDsaPublicKey,

    /// Network endpoint
    pub endpoint: Endpoint,

    /// Available storage
    pub storage_gb: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum DeviceType {
    /// Interactive device (phone, laptop)
    Active,

    /// Always-on storage node
    Headless,
}
```

### Identity Registration

Identity registration is now implemented in **saorsa-node**. saorsa-core only
provides peer discovery/phonebook and trust scoring; higher layers handle
identity records and their storage.

### Why No Proof-of-Work?

#### 1. Identity Creation is Not the Security Boundary

In Saorsa, identity creation is intentionally cheap. **Security comes from what you do with the identity**, not from creating it:

| Action | Security Mechanism |
|--------|-------------------|
| Create identity | None (instant, free) |
| Join routing | Rate limiting, IP diversity |
| Store data | EigenTrust reputation |
| Become witness | Trust threshold (τ > 0.3) |
| High-value ops | Multi-device verification |

An attacker can create millions of identities, but they're all **worthless** until they build reputation through sustained good behavior.

#### 2. PoW Doesn't Prevent Motivated Attackers

Consider the economics:

| PoW Cost | Attacker Budget | Result |
|----------|----------------|--------|
| $0.01/identity | $10,000 | 1,000,000 identities |
| $1.00/identity | $10,000 | 10,000 identities |
| $100/identity | $10,000 | 100 identities |

Even expensive PoW doesn't stop well-funded attackers. Meanwhile, it excludes legitimate users with limited resources.

#### 3. PoW Centralizes Power

Effective PoW requires:
- Access to cheap electricity
- Specialized hardware (ASICs, GPUs)
- Technical expertise

This naturally centralizes identity creation to:
- Mining pools
- Data centers in cheap-power regions
- Hardware manufacturers

This conflicts with our goal of decentralization and accessibility.

#### 4. Environmental Concerns

Bitcoin's PoW consumes approximately 120+ TWh annually—more than many countries. Even "lightweight" PoW is wasteful when alternatives exist.

### Sybil Resistance Without PoW

Instead of PoW, we layer multiple defenses (see ADR-009):

```
┌─────────────────────────────────────────────────────────────────┐
│           Sybil Resistance Stack (No PoW)                        │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 1: Cryptographic Binding                           │   │
│  │ • ML-DSA-65 keypair per identity                         │   │
│  │ • Cannot forge signatures                                │   │
│  │ • Storage cost: ~6KB per identity                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 2: Rate Limiting                                   │   │
│  │ • 5 joins per IP per minute                              │   │
│  │ • 20 joins per /24 subnet per minute                     │   │
│  │ • 100 joins per /16 subnet per hour                      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 3: Geographic Diversity                            │   │
│  │ • Max 25% from any /8 subnet                             │   │
│  │ • Max 10% from any /16 subnet                            │   │
│  │ • Min 5 distinct /16 subnets                             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 4: EigenTrust Reputation                           │   │
│  │ • New identities start at trust = 0                      │   │
│  │ • Must earn trust through behavior                       │   │
│  │ • Privileged operations require trust > threshold        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 5: Attestation & Verification                      │   │
│  │ • Software integrity verification                        │   │
│  │ • Multi-device confirmation for high-value ops           │   │
│  │ • Social vouching from trusted contacts                  │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Trust Bootstrapping

New identities face the "cold start" problem. We address this through:

1. **Pre-trusted bootstrap nodes**: Provide initial trust anchors
2. **Low-risk operations**: New identities can perform basic operations
3. **Gradual trust building**: Reputation grows through successful interactions
4. **Social introduction**: Existing trusted users can vouch for new users

```rust
// Trust thresholds for different operations
pub const TRUST_ROUTING: f64 = 0.1;      // Participate in routing
pub const TRUST_STORAGE: f64 = 0.2;      // Store data for others
pub const TRUST_WITNESS: f64 = 0.3;      // Act as witness
pub const TRUST_BOOTSTRAP: f64 = 0.5;    // Serve as bootstrap node

// New identity capabilities
impl UserIdentity {
    pub fn capabilities(&self, trust_score: f64) -> Capabilities {
        Capabilities {
            can_route: trust_score >= TRUST_ROUTING,
            can_store: trust_score >= TRUST_STORAGE,
            can_witness: trust_score >= TRUST_WITNESS,
            can_bootstrap: trust_score >= TRUST_BOOTSTRAP,
        }
    }
}
```

## Consequences

### Positive

1. **Instant onboarding**: Users can join immediately
2. **No hardware requirements**: Works on any device
3. **Energy efficient**: No wasted computation
4. **Accessible**: No cost barrier to entry
5. **Privacy**: No need to reveal resources or stake

### Negative

1. **Easy identity creation**: Attackers can create many identities
2. **Reputation dependency**: Security relies on EigenTrust working correctly
3. **Cold start**: New users have limited capabilities
4. **Complexity**: Multiple defense layers to maintain

### Neutral

1. **Different security model**: Security from behavior, not creation cost
2. **Trust dynamics**: Network security is emergent, not guaranteed

## Comparison with Alternatives

| Aspect | PoW | PoS | Saorsa |
|--------|-----|-----|--------|
| Creation cost | High (compute) | High (stake) | Free |
| Creation time | Minutes-hours | Instant | Instant |
| Hardware needs | Specialized | Token wallet | Any |
| Energy use | High | Low | Minimal |
| Sybil resistance | Creation | Economic | Behavioral |
| Accessibility | Poor | Medium | High |

## Future Considerations

If behavioral Sybil resistance proves insufficient, we can add:

1. **Lightweight PoW** (e.g., 1-second delay) as optional layer
2. **Stake-based tiers** for premium features
3. **Social graph verification** with explicit trust attestations

These would supplement, not replace, the current approach.

## References

- [The Sybil Attack (Douceur)](https://www.microsoft.com/en-us/research/wp-content/uploads/2002/01/IPTPS2002.pdf)
- [Bitcoin Energy Consumption](https://digiconomist.net/bitcoin-energy-consumption/)
- [EigenTrust Paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf)
- [ADR-003: Pure Post-Quantum Cryptography](./ADR-003-pure-post-quantum-crypto.md)
- [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md)
- [ADR-009: Sybil Protection Mechanisms](./ADR-009-sybil-protection.md)
