# ADR-003: Pure Post-Quantum Cryptography

## Status

Accepted

## Context

The cryptographic foundation of any P2P network determines its long-term security posture. We face a critical decision:

### The Quantum Threat

Cryptographically Relevant Quantum Computers (CRQCs) pose an existential threat to classical asymmetric cryptography:

- **RSA**: Broken by Shor's algorithm
- **ECDSA/EdDSA**: Broken by Shor's algorithm
- **ECDH/X25519**: Broken by Shor's algorithm
- **AES-256**: Weakened but still viable (Grover's algorithm, 2^128 effective security)

Timeline estimates vary, but "harvest now, decrypt later" attacks mean data encrypted today with classical algorithms may be decrypted when CRQCs become available.

### NIST Post-Quantum Standards

In 2024, NIST finalized three post-quantum cryptographic standards:

1. **ML-KEM (FIPS 203)**: Module-Lattice Key Encapsulation Mechanism (formerly Kyber)
2. **ML-DSA (FIPS 204)**: Module-Lattice Digital Signature Algorithm (formerly Dilithium)
3. **SLH-DSA (FIPS 205)**: Stateless Hash-Based Digital Signature Algorithm

### The Hybrid Question

Many organizations adopt a "hybrid" approach combining classical and post-quantum algorithms:

```
Hybrid: Classical_Sign(PQ_Sign(message)) + Classical_KEM || PQ_KEM
```

Arguments for hybrid:
- Hedge against PQC implementation bugs
- Regulatory compliance with classical requirements
- Conservative migration path

Arguments against hybrid:
- Increased complexity and attack surface
- Larger key/signature sizes
- Performance overhead
- Classical algorithms provide no security against quantum attacks

## Decision

We adopt **pure post-quantum cryptography** without classical fallbacks:

### Algorithm Selection

| Use Case | Algorithm | Security Level | Key Size | Signature/Ciphertext Size |
|----------|-----------|----------------|----------|---------------------------|
| Identity Signing | ML-DSA-65 | NIST Level 3 | 1,952 B pub / 4,032 B priv | 3,309 B |
| Key Exchange | ML-KEM-768 | NIST Level 3 | 1,184 B pub / 2,400 B priv | 1,088 B ciphertext |
| Symmetric Encryption | ChaCha20-Poly1305 | 256-bit | 32 B | N/A |
| Hashing | BLAKE3 | 256-bit | N/A | 32 B |

### Rationale for Pure PQC

1. **No Legacy Constraints**: Saorsa is a new network without deployed classical infrastructure
2. **Future-Proofing**: Data stored today will be retrievable for decades
3. **Simplicity**: One code path, not two
4. **Reduced Attack Surface**: Fewer algorithms = fewer potential vulnerabilities
5. **Performance**: Avoid hybrid overhead

### Implementation via saorsa-pqc and saorsa-transport

Post-quantum cryptography is provided by two sources:

#### 1. saorsa-pqc (Identity Layer)

```rust
use saorsa_pqc::{MlDsa65, MlKem768, MlDsaOperations, MlKemOperations};

// Identity key generation
let (signing_pk, signing_sk) = MlDsa65::generate_keypair()?;

// Sign identity claims
let signature = MlDsa65::sign(&signing_sk, message)?;
let valid = MlDsa65::verify(&signing_pk, message, &signature)?;

// Key exchange for secure channels
let (kem_pk, kem_sk) = MlKem768::generate_keypair()?;
let (ciphertext, shared_secret) = MlKem768::encapsulate(&kem_pk)?;
let decapsulated = MlKem768::decapsulate(&kem_sk, &ciphertext)?;
```

#### 2. saorsa-transport (Transport Layer)

Transport-level PQC is handled by saorsa-transport's TLS integration:

```rust
// saorsa-transport configures PQC automatically
let config = QuicConfig {
    pqc_enabled: true,  // Default: true
    // ML-KEM-768 for key exchange
    // X25519 available as fallback for compatibility
};
```

### Key Hierarchy

```
Master Seed (256-bit, derived from user password via Argon2id)
    │
    ├── Identity Keys (ML-DSA-65)
    │   ├── Primary signing key
    │   └── Device-specific signing keys
    │
    ├── Exchange Keys (ML-KEM-768)
    │   ├── Long-term exchange key
    │   └── Ephemeral session keys
    │
    └── Symmetric Keys (ChaCha20-Poly1305)
        ├── Storage encryption keys
        └── Message encryption keys
```

### Migration Path

For future algorithm agility (e.g., if ML-DSA-65 is broken):

1. **Algorithm identifiers**: All signatures include algorithm ID prefix
2. **Key versioning**: Keys include generation/version metadata
3. **Dual-signing period**: New algorithm signs alongside old during transition
4. **Sunset timestamps**: Old signatures rejected after transition period

```rust
// Algorithm-agile signature format
pub struct VersionedSignature {
    pub algorithm: SignatureAlgorithm,  // ML_DSA_65, SLH_DSA_256, etc.
    pub version: u8,
    pub signature: Vec<u8>,
}
```

## Consequences

### Positive

1. **Quantum resistance**: Secure against known quantum algorithms
2. **NIST compliance**: Using finalized FIPS standards
3. **Simplicity**: Single cryptographic path
4. **Future-proof**: No need for later quantum migration
5. **Performance**: ML-DSA/ML-KEM are efficient lattice schemes

### Negative

1. **Key sizes**: ML-DSA-65 keys are ~2KB (vs 32B for Ed25519)
2. **Signature sizes**: 3.3KB signatures increase bandwidth
3. **No classical interop**: Cannot communicate with classical-only systems
4. **Young algorithms**: Less cryptanalysis history than RSA/ECDSA
5. **Library maturity**: PQC libraries less battle-tested

### Neutral

1. **Hardware support**: No dedicated PQC hardware yet (pure software)
2. **Standardization**: FIPS 203/204/205 are final standards
3. **Implementation quality**: Using audited implementations (pqcrypto crate)

## Size Impact Analysis

| Operation | Classical (Ed25519) | Post-Quantum (ML-DSA-65) | Increase |
|-----------|---------------------|--------------------------|----------|
| Public Key | 32 bytes | 1,952 bytes | 61x |
| Private Key | 64 bytes | 4,032 bytes | 63x |
| Signature | 64 bytes | 3,309 bytes | 52x |
| KEM Public Key | 32 bytes (X25519) | 1,184 bytes (ML-KEM-768) | 37x |
| Ciphertext | 32 bytes | 1,088 bytes | 34x |

**Mitigation strategies**:
- Cache frequently-used public keys
- Batch signatures where possible
- Compress signatures in storage (ML-DSA compresses well)
- Use symmetric keys for ongoing communication (PQC only for key establishment)

## Alternatives Considered

### Hybrid Classical + PQC

Run both Ed25519 and ML-DSA in parallel.

**Rejected because**:
- Doubled complexity
- No real security benefit (classical provides 0 quantum security)
- Performance overhead
- We have no legacy compatibility requirements

### Hash-Based Signatures (SLH-DSA)

Use SPHINCS+/SLH-DSA instead of ML-DSA.

**Rejected for primary use because**:
- Larger signatures (17-50KB)
- Slower signing (10-100x slower than ML-DSA)
- Stateless variant has size trade-offs

**Retained as backup**: SLH-DSA available for algorithm agility if ML-DSA is broken.

### Classical Only with Migration Plan

Stay classical now, migrate to PQC later.

**Rejected because**:
- "Harvest now, decrypt later" threat
- Migration is disruptive to operational networks
- New network = opportunity to start secure

### NTRU-Based Schemes

Use NTRU instead of lattice-based ML-KEM.

**Rejected because**:
- Not selected by NIST for standardization
- Less implementation availability
- Similar security/performance profile to ML-KEM

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [Post-Quantum Cryptography Migration](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3624258/post-quantum-cryptography-migration/)
- [pqcrypto Rust Crate](https://crates.io/crates/pqcrypto)
- [saorsa-pqc Documentation](../../../saorsa-pqc/)
