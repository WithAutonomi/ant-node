# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for this repository.

## Rules

1. Use `ADR-NNNN-short-title.md` names with four-digit numbers.
2. New ADRs start as `Proposed`.
3. `Accepted` ADRs are immutable. If the decision changes, create a new ADR and mark the old ADR as superseded by reference, not by editing its accepted content.
4. Architectural PRs must add or update an ADR before merge.
5. Reviews must check ADR correctness, evidence, trade-offs, and compliance — not just presence.

## Template

Use [`TEMPLATE.md`](./TEMPLATE.md).

## Tooling

See [`TOOLING.md`](./TOOLING.md) for `adrs`, `adr-kit`, and AI harness setup.

## Index

- [ADR-0001: Adopt Architecture Decision Records](./ADR-0001-adopt-architecture-decision-records.md)
- [ADR-0002: Gossip-triggered contiguous-subtree storage audit](./ADR-0002-gossip-triggered-contiguous-subtree-audit.md)
- [ADR-0003: Full-node detection, penalisation, and eviction](./ADR-0003-full-node-detection-and-eviction.md)
- [ADR-0004: Commitment-bound quote pricing](./ADR-0004-commitment-bound-quote-pricing.md)
- [ADR-0005: Replication repair hardening under churn, load, and shutdown](./ADR-0005-replication-repair-hardening.md)
- [ADR-0006: Close-group pricing for the receiver-side revenue floor](./ADR-0006-receiver-side-revenue-floor.md)
- [ADR-0007: Cap the Windows LMDB map head-room](./ADR-0007-windows-lmdb-map-headroom-cap.md)
- [ADR-0008: Storage economics and the quoting + payment protocol](./ADR-0008-storage-economics-and-payment-protocol.md)
- [ADR-0009: Subtree-audit proof shape and protocol family](./ADR-0009-audit-proof-shape-and-protocol-families.md)
- [ADR-0010: Restrict the beta upgrade channel to `-beta.*` pre-releases](./ADR-0010-beta-upgrade-channel-semantics.md)
- [ADR-0011: Capacity-gated source discovery in the replication verification cycle](./ADR-0011-capacity-gated-source-discovery.md)
- [ADR-0012: Back off and report once when a verification round finds no holder](./ADR-0012-unresolved-verification-retry-backoff.md)
- [ADR-0013: Direct browser clients over WebRTC Direct](./ADR-0013-direct-browser-clients-over-webrtc-direct.md)
- [ADR-0014: One File Per Chunk, and Retiring LMDB Without Losing Data](./ADR-0014-file-based-chunk-store-and-lmdb-retirement.md)
