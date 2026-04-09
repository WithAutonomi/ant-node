# Architecture Overview

This repository is a Rust library crate that provides a modular, post‑quantum secure P2P foundation. It favors clear boundaries, strict linting (no panics in lib code), and testable components.

## Goals & Scope
- Reliable QUIC transport, DHT routing, and dual‑stack endpoints (IPv6 + IPv4).
- Strong security defaults using saorsa‑pqc, safe memory, and validation.
- Extensible higher‑level applications live above this crate (saorsa-node).

## Layered Architecture
- Transport & Networking: `transport/`, `network/` (QUIC, NAT traversal, events, dual‑stack listeners, Happy Eyeballs dialing).
- Routing & Discovery: `dht/`, `dht_network_manager/`, `peer_record/`.
- Security: `quantum_crypto/`, `security.rs`.
- Trust: `adaptive/` (response-rate scoring with time decay, binary peer blocking).
- Application Modules: provided by upper layers (not in this crate).
- Cross‑cutting: `validation.rs`, `config.rs`, `error.rs`.

## Module Map (selected)
- Core exports live in `src/lib.rs`; add new modules there and keep names `snake_case`.
- PQC: `quantum_crypto/` exports saorsa‑pqc types and compatibility shims.

## Data Flow
```
[Upper-layer apps (saorsa-node)]
          |        commands/events
          v
     [network]  <->  [dht_network_manager]  <->  [dht]
          |                                        ^
      [transport (QUIC)]                     [adaptive]
          ^                               (trust scoring,
     [validation|security]                 peer blocking)
```

saorsa-core is a peer phonebook with trust enforcement: it handles peer discovery,
response-rate trust scoring with time decay, and binary peer blocking. Application
data storage and replication are handled by saorsa-node via `send_message`-style APIs.

## Concurrency & Errors
- Async with `tokio`; prefer `Send + Sync` types and bounded channels where applicable.
- Errors use `thiserror`/`anyhow` in tests; return precise errors in library code.
- Logging with `tracing`; avoid `unwrap/expect/panic` in lib paths (CI enforces).

## Observability & Testing
- Tests: unit tests in modules (`#[cfg(test)]` blocks).

## Build Targets
- Library only.
- Use `./scripts/local_ci.sh` to run a safe, end‑to‑end local CI.
