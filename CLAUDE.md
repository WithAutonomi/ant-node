# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ant-node is the core P2P network node binary for the Autonomi ecosystem. It provides the decentralized storage and networking foundation using post-quantum cryptography.

## Development Commands

### Building and Testing
```bash
# Build the project
cargo build --release

# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Format and lint
cargo fmt --all
cargo clippy --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
```

### Running the Node
```bash
# Run as bootstrap node (default port)
cargo run --release -- --listen 0.0.0.0:10000 --bootstrap

# Run additional instance (use any port in range 10000-10999)
cargo run --release -- --listen 0.0.0.0:10001

# Run with debug logging
RUST_LOG=debug cargo run --release -- --listen 0.0.0.0:10000
```

## Code Standards

### NO PANICS IN PRODUCTION CODE
- No `.unwrap()` - Use `?` operator or `.ok_or()`
- No `.expect()` - Use `.context()` from `anyhow`
- No `panic!()` - Return `Result` instead
- **Exception**: Test code may use these for assertions

### Payment Verification Policy
**Payment verification is always on — there is no way to disable it.**

- All new chunk storage requires EVM payment verification on Arbitrum
- There is no `--disable-payment-verification` flag or `enabled` config field
- `rewards_address` is required — node startup fails without one
- Previously-paid chunks are cached and do not require re-verification
- Test code bypasses EVM by pre-populating the cache via `PaymentVerifier::cache_insert()` (only available behind `#[cfg(test)]` or the `test-utils` feature)

See `src/payment/verifier.rs` for implementation details.

---

## CRITICAL: Autonomi Network Infrastructure & Port Isolation

### Infrastructure Documentation
Full infrastructure documentation is available at: `docs/infrastructure/INFRASTRUCTURE.md`

This includes:
- All 9 VPS nodes across 3 cloud providers (DigitalOcean, Hetzner, Vultr)
- Bootstrap node endpoints and IP addresses
- Firewall configurations and SSH access
- Systemd service templates

### PORT ISOLATION - MANDATORY

**Production ant-node instances use UDP port range 10000-10999 exclusively.**

| Service | UDP Port Range | Default | Description |
|---------|----------------|---------|-------------|
| ant-quic | 9000-9999 | 9000 | QUIC transport layer |
| **ant-node** | **10000-10999** | **10000** | Core P2P network nodes (THIS PROJECT) |
| communitas | 11000-11999 | 11000 | Collaboration platform nodes |
| **ant-node tests** | **20000-60000** | **random** | E2E test isolation (local only) |

**Note:** The E2E test suite uses ports 20000-60000 with random allocation to prevent conflicts between parallel test runs and local development instances. Production deployments MUST use 10000-10999.

### DO NOT DISTURB OTHER NETWORKS

When testing or developing ant-node:

1. **ONLY use ports 10000-10999** for ant-node services
2. **NEVER** kill processes on ports 9000-9999 or 11000-11999
3. **NEVER** restart services outside our port range
4. **NEVER** modify firewall rules for other port ranges

```bash
# CORRECT - ant-node operations (within 10000-10999)
cargo run --release -- --listen 0.0.0.0:10000
cargo run --release -- --listen 0.0.0.0:10001  # Second instance OK
```

### Bootstrap Peers Configuration

Production bootstrap peer addresses are defined in `config/bootstrap_peers.toml`.
This file is shipped alongside the binary in release archives and is auto-discovered
on startup when no `--bootstrap` CLI argument is provided.

### Before Any VPS Operations
1. Verify you're targeting ports 10000-10999 only
2. Double-check service names contain "ant-node"
3. Never run broad `pkill` commands that could affect other services
