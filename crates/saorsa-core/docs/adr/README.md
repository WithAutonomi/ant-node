# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) documenting the key technical decisions made in the saorsa-core project.

## What is an ADR?

An Architecture Decision Record (ADR) is a document that captures an important architectural decision made along with its context and consequences. ADRs help:

- **Document rationale**: Explain *why* decisions were made, not just *what* was decided
- **Preserve institutional knowledge**: New team members can understand historical context
- **Enable informed changes**: Future modifications can consider original constraints
- **Facilitate review**: Stakeholders can evaluate decisions against requirements

## ADR Index

### Core Architecture

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [ADR-001](./ADR-001-multi-layer-architecture.md) | Multi-Layer P2P Architecture | Accepted | Layered design separating transport, DHT, identity, and application concerns |
| [ADR-002](./ADR-002-delegated-transport.md) | Delegated Transport via saorsa-transport | Accepted | Using saorsa-transport for QUIC transport, NAT traversal, and bootstrap cache |
| [ADR-003](./ADR-003-pure-post-quantum-crypto.md) | Pure Post-Quantum Cryptography | Accepted | ML-DSA-65 and ML-KEM-768 without classical fallbacks |

### Identity

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [ADR-012](./ADR-012-identity-without-pow.md) | Identity without Proof-of-Work | Accepted | Pure cryptographic identity using ML-DSA |

### Security & Trust

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [ADR-005](./ADR-005-skademlia-witness-protocol.md) | S/Kademlia Witness Protocol | Accepted | Byzantine fault-tolerant DHT operations |
| [ADR-006](./ADR-006-eigentrust-reputation.md) | EigenTrust Reputation System | Accepted | Iterative trust computation for Sybil resistance |
| [ADR-009](./ADR-009-sybil-protection.md) | Sybil Protection Mechanisms | Accepted | Multi-layered defense against identity attacks |
| [ADR-010](./ADR-010-entangled-attestation.md) | Entangled Attestation System | Accepted | Software integrity verification via attestation chains |

### Network Intelligence

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [ADR-007](./ADR-007-adaptive-networking.md) | Adaptive Networking with ML | Accepted | Machine learning for dynamic routing optimization |
| [ADR-008](./ADR-008-bootstrap-delegation.md) | Bootstrap Cache Delegation | Accepted | Delegating bootstrap to saorsa-transport with Sybil protection |

### Messaging

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [ADR-013](./ADR-013-no-offline-delivery-v1.md) | No Offline Message Delivery (v1) | Accepted | 1-hour TTL limit without extended offline delivery (future reconsideration) |

## ADR Template

When creating new ADRs, use this template:

```markdown
# ADR-XXX: Title

## Status

Proposed | Accepted | Deprecated | Superseded by [ADR-YYY](./ADR-YYY-title.md)

## Context

What is the issue that we're seeing that is motivating this decision or change?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

### Positive
- What becomes easier?

### Negative
- What becomes more difficult?

### Neutral
- What other changes might this precipitate?

## Alternatives Considered

What other options were evaluated?

## References

- Links to relevant documentation, RFCs, papers
```

## Decision Lifecycle

1. **Proposed**: Under discussion, not yet approved
2. **Accepted**: Approved and implemented
3. **Deprecated**: No longer recommended, but may still exist in codebase
4. **Superseded**: Replaced by a newer decision

## Contributing

When proposing changes to architecture:

1. Create a new ADR with status "Proposed"
2. Open a PR for discussion
3. Update status to "Accepted" once approved
4. If changing an existing decision, update the old ADR to "Superseded"

## Further Reading

- [Architectural Decision Records](https://adr.github.io/)
- [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
