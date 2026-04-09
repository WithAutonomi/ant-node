# ADR-010: Entangled Attestation System

## Status

Accepted

## Context

In a decentralized network, how do we verify that remote peers are running legitimate, unmodified software?

**Threats from malicious software**:
- Modified clients that steal data
- Clients that don't follow protocol rules
- Backdoored binaries that leak keys
- Clients that selectively censor or corrupt data

Traditional approaches have limitations:
- **Code signing**: Only verifies publisher, not runtime behavior
- **TPM attestation**: Requires hardware, complex to verify remotely
- **Reproducible builds**: Verifies build process, not runtime

We needed a system that:
1. Verifies software integrity without trusted hardware
2. Creates accountability chains
3. Works in decentralized environments
4. Allows for software updates with sunset periods

## Decision

We implement **Entangled Attestation**, a software integrity verification system using cryptographic attestation chains.

### Core Concept

Every node maintains an **attestation chain** linking:
1. The binary hash of the running software
2. The identity (ML-DSA public key) of the node
3. Attestations from other nodes vouching for this node
4. Timestamp proving chain freshness

```
┌─────────────────────────────────────────────────────────────────┐
│                    Attestation Chain                             │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Genesis Block (Self-Attestation)                          │  │
│  │ • binary_hash: blake3(saorsa-node-v0.4.0)                │  │
│  │ • node_id: PeerId(abc123...)                             │  │
│  │ • timestamp: 2024-01-15T10:00:00Z                        │  │
│  │ • signature: ML-DSA-65 signature over above              │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Peer Attestation #1                                       │  │
│  │ • attester: PeerId(def456...)                            │  │
│  │ • attester_binary: blake3(saorsa-node-v0.4.0)            │  │
│  │ • attestee: PeerId(abc123...)                            │  │
│  │ • attestee_binary: blake3(saorsa-node-v0.4.0)            │  │
│  │ • timestamp: 2024-01-15T10:05:00Z                        │  │
│  │ • signature: attester's ML-DSA signature                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Peer Attestation #2                                       │  │
│  │ • attester: PeerId(ghi789...)                            │  │
│  │ • ...                                                     │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Entangled Attestation System                  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │               Approved Binary Registry                    │   │
│  │  • Approved hashes for each version                      │   │
│  │  • Platform-specific (linux-x64, darwin-arm64, etc.)     │   │
│  │  • Sunset timestamps (old versions expire)               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌──────────────────────────┼──────────────────────────────┐    │
│  │                   Prover                │                │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │ generate_attestation()                          │    │    │
│  │  │ • Hash running binary                           │    │    │
│  │  │ • Sign with node's ML-DSA key                   │    │    │
│  │  │ • Include recent attestations from others       │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│  ┌──────────────────────────┼──────────────────────────────┐    │
│  │                  Verifier               │                │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │ verify_attestation()                            │    │    │
│  │  │ • Check binary hash against approved list       │    │    │
│  │  │ • Verify all signatures in chain                │    │    │
│  │  │ • Check timestamps are fresh                    │    │    │
│  │  │ • Verify attesters are trusted peers            │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

```rust
// src/attestation/mod.rs

/// Identifier for a software version
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntangledId {
    /// BLAKE3 hash of the binary
    pub binary_hash: [u8; 32],

    /// Version string (e.g., "0.4.0")
    pub version: String,

    /// Platform (e.g., "linux-x86_64")
    pub platform: String,
}

/// Sunset timestamp after which a version is rejected
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SunsetTimestamp {
    /// The software version
    pub version: String,

    /// Datetime after which this version is no longer accepted
    pub sunset_at: SystemTime,

    /// Grace period for connections in progress
    pub grace_period: Duration,
}

/// Single attestation in the chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    /// Who is being attested
    pub attestee: PeerId,

    /// Binary hash of attestee
    pub attestee_binary: [u8; 32],

    /// Who is attesting
    pub attester: PeerId,

    /// Binary hash of attester (self-attestation)
    pub attester_binary: [u8; 32],

    /// When attestation was created
    pub timestamp: SystemTime,

    /// ML-DSA signature by attester
    pub signature: MlDsaSignature,
}

/// Complete attestation result
#[derive(Clone, Debug)]
pub enum AttestationResult {
    /// Attestation verified successfully
    Verified {
        binary_hash: [u8; 32],
        version: String,
        chain_length: usize,
    },

    /// Binary hash not in approved list
    UnapprovedBinary { hash: [u8; 32] },

    /// Version has been sunset
    SunsetVersion { version: String, sunset_at: SystemTime },

    /// Signature verification failed
    InvalidSignature { at_index: usize },

    /// Attestation chain too old
    StaleAttestation { age: Duration },

    /// Insufficient trusted attesters
    InsufficientTrust { have: usize, need: usize },
}

impl AttestationVerifier {
    /// Verify a peer's attestation chain
    pub async fn verify(&self, peer: &PeerId) -> AttestationResult {
        // 1. Request attestation from peer
        let chain = self.request_attestation(peer).await?;

        // 2. Verify binary hash is approved
        let binary_hash = chain.self_attestation.binary_hash;
        let version = self.approved_registry.get_version(&binary_hash);

        match version {
            None => return AttestationResult::UnapprovedBinary { hash: binary_hash },
            Some(v) if self.is_sunset(&v) => {
                return AttestationResult::SunsetVersion {
                    version: v.clone(),
                    sunset_at: self.get_sunset_time(&v),
                };
            }
            Some(v) => v,
        };

        // 3. Verify signatures in chain
        for (i, attestation) in chain.attestations.iter().enumerate() {
            if !self.verify_signature(attestation) {
                return AttestationResult::InvalidSignature { at_index: i };
            }
        }

        // 4. Check chain freshness
        let age = SystemTime::now()
            .duration_since(chain.self_attestation.timestamp)
            .unwrap_or(Duration::MAX);

        if age > self.config.max_attestation_age {
            return AttestationResult::StaleAttestation { age };
        }

        // 5. Verify trusted attesters
        let trusted_count = chain.attestations
            .iter()
            .filter(|a| self.trust_manager.get_score(&a.attester) >= MIN_ATTESTER_TRUST)
            .count();

        if trusted_count < self.config.min_trusted_attesters {
            return AttestationResult::InsufficientTrust {
                have: trusted_count,
                need: self.config.min_trusted_attesters,
            };
        }

        AttestationResult::Verified {
            binary_hash,
            version: version.to_string(),
            chain_length: chain.attestations.len(),
        }
    }
}
```

### Enforcement Modes

```rust
/// How strictly to enforce attestation
#[derive(Clone, Copy, Debug, Default)]
pub enum EnforcementMode {
    /// Log failures but allow connections (development)
    Permissive,

    /// Warn on failures, allow with degraded trust
    #[default]
    Advisory,

    /// Reject connections from unattested peers
    Strict,
}

impl AttestationConfig {
    pub fn development() -> Self {
        Self {
            mode: EnforcementMode::Permissive,
            min_trusted_attesters: 0,
            max_attestation_age: Duration::from_secs(86400 * 30), // 30 days
            ..Default::default()
        }
    }

    pub fn production() -> Self {
        Self {
            mode: EnforcementMode::Strict,
            min_trusted_attesters: 2,
            max_attestation_age: Duration::from_secs(3600), // 1 hour
            ..Default::default()
        }
    }
}
```

### Version Sunset Process

When releasing new versions:

1. **Publish new binary** with hash added to approved registry
2. **Set sunset date** for old version (e.g., 30 days)
3. **Grace period**: Old version warns but connects for 7 days after sunset
4. **Hard cutoff**: Old version rejected entirely

```rust
// Example sunset schedule
const SUNSET_SCHEDULE: &[SunsetTimestamp] = &[
    SunsetTimestamp {
        version: "0.3.0",
        sunset_at: /* 2024-02-15 */,
        grace_period: Duration::from_secs(86400 * 7),
    },
    SunsetTimestamp {
        version: "0.4.0",
        sunset_at: /* 2024-04-01 */,
        grace_period: Duration::from_secs(86400 * 7),
    },
];
```

### Binary Hash Computation

```rust
/// Compute hash of the running binary
pub fn compute_binary_hash() -> Result<[u8; 32]> {
    let exe_path = std::env::current_exe()?;
    let binary_data = std::fs::read(&exe_path)?;

    // Use BLAKE3 for speed (hashing large binaries)
    let hash = blake3::hash(&binary_data);
    Ok(*hash.as_bytes())
}
```

## Consequences

### Positive

1. **Software integrity**: Detects modified binaries
2. **Accountability**: Attestation chains show who vouched for whom
3. **Version management**: Controlled deprecation of old versions
4. **No hardware dependency**: Works without TPM or secure enclaves
5. **Decentralized**: No central authority required

### Negative

1. **Hash distribution**: Must distribute approved hashes securely
2. **Binary reproducibility**: Ideally builds are reproducible
3. **Platform complexity**: Separate hashes per platform
4. **Honest majority assumption**: Compromised majority can attest anything

### Neutral

1. **Attestation overhead**: Additional messages during handshake
2. **Chain storage**: Must persist attestation chains

## Security Analysis

### What It Protects Against

| Threat | Protection |
|--------|------------|
| Modified binary | Hash won't match approved list |
| Old vulnerable version | Sunset mechanism forces updates |
| Fake attestation | ML-DSA signatures verify identity |
| Stale attestation replay | Timestamp freshness checks |
| Untrusted attesters | Minimum trusted attester requirement |

### What It Doesn't Protect Against

| Threat | Limitation |
|--------|------------|
| Source code backdoor | Hash verifies binary, not source |
| Compromised build system | Need reproducible builds |
| Runtime memory attacks | Static attestation, not runtime |
| Majority collusion | Assumes honest majority |

## Alternatives Considered

### TPM/SGX Attestation

Use hardware security modules.

**Rejected because**:
- Requires specific hardware
- Complex remote verification
- Not universally available
- Intel SGX has known vulnerabilities

### Code Signing Only

Rely on publisher signatures.

**Rejected because**:
- Publisher key compromise affects all users
- No runtime verification
- No version sunset mechanism

### Reproducible Builds Only

Ensure builds are reproducible.

**Complementary**: We encourage reproducible builds but don't require them; attestation works with any build.

### Blockchain-Based Registry

Store approved hashes on blockchain.

**Rejected because**:
- Adds dependency on blockchain
- Consensus overhead
- Simple hash list is sufficient

## References

- [Remote Attestation](https://en.wikipedia.org/wiki/Trusted_Computing#Remote_attestation)
- [Reproducible Builds](https://reproducible-builds.org/)
- [BLAKE3 Hash Function](https://github.com/BLAKE3-team/BLAKE3)
- [ADR-009: Sybil Protection Mechanisms](./ADR-009-sybil-protection.md)
