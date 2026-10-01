# ant-node (repo: saorsa-node)

The crate and binary are named `ant-node` (lib `ant_node`); the repo is still
`saorsa-node`. It is the Autonomi network storage node: post-quantum P2P
networking via `saorsa-core` / `saorsa-transport`, chunk storage, replication and
audits, and EVM payment verification. A second binary, `ant-devnet`, runs local
devnets.

## Reference docs
- Design: `docs/DESIGN.md`; replication: `docs/REPLICATION_DESIGN.md`
- Testnets: `docs/TESTNET_DEPLOYMENT.md`, `docs/WEBRTC_DIRECT_TESTNET.md`
- Infrastructure / VPS / bootstrap nodes: `docs/infrastructure/`
- ADRs: `docs/adr/` (rules in `docs/adr/README.md`, template `TEMPLATE.md`)

## Build and test
No justfile. CI (`.github/workflows/ci.yml`) runs:
- `cargo fmt --all -- --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo doc --all-features --no-deps`
- `cargo test --lib --features test-utils` and `cargo test --lib --no-default-features`
- `cargo check --lib --no-default-features --locked` and
  `cargo build --release --no-default-features`
- E2E: `cargo test --test e2e --features test-utils -- --test-threads=1`, plus
  individual `poc_*` tests with `--features test-utils`

Features: `default = ["logging", "webrtc-direct"]`. `webrtc-direct` is the
direct-browser transport (ADR-0015); `--no-default-features` must keep building
as a native-only node. `test-utils` exposes test helpers to integration tests.

Tests that bind ports use random ports in **20000-60000** so they never collide
with real nodes on 10000-10999.

Running a node: `cargo run --release --bin ant-node -- --port 10000 --rewards-address <addr>`
(flags also read `ANT_*` env vars; see `src/bin/ant-node/cli.rs`). With no
`--bootstrap`, peers are auto-discovered from `bootstrap_peers.toml`
(`config/bootstrap_peers.toml` ships alongside the binary in release archives).

## Payment verification is always on
- All new chunk storage requires EVM payment verification (default network
  `arbitrum-one`). There is no flag or config field to disable it.
- A rewards address is required; startup fails without one.
- Previously-paid chunks are cached and not re-verified.
- Tests bypass EVM by pre-populating that cache with
  `PaymentVerifier::cache_insert()` (only under `#[cfg(test)]` or `test-utils`).
  See `src/payment/verifier.rs`.

## Layout
`src/node.rs` (node assembly), `payment/` (quotes, pricing, verifier, wallet),
`replication/` (admission, audits, commitments, neighbour sync, quorum),
`storage/` (chunk store), `web_rtc*` (browser transport), `upgrade/`
(self-update), `ant_protocol/`, `devnet.rs`.

## Architecture decisions
Before changing architecture, protocols, storage formats, crypto, network
behaviour, public APIs, data models or operational invariants, check
`docs/adr/`. New or changed decisions go in a Proposed ADR. Accepted ADRs are
immutable (supersede instead; CI `adr-governance` enforces this) and only humans
mark an ADR Accepted.

## Pull requests
CI (`linear-link` and `pr-template` checks) rejects PRs that don't follow
`.github/PULL_REQUEST_TEMPLATE.md`:
- Fill every section; ask if a value can't be determined.
- Link Linear with a **closing** word in the `## Linear issue` section:
  `Closes V2-123` (or fix/resolve/complete/implement, any tense; a `linear.app`
  URL works as the key). A bare key does not link; linking-only words (`ref`,
  `part of`, `towards`, `relates to`) attach without moving the issue to Merged.
- Tick exactly one Risk tier and one Semver impact box (a human confirms them).
  Tier 2/3 needs an ADR link.
