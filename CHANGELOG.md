# Changelog

All notable changes to the `ant-node` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] — Unreleased

### Changed

The wire-protocol surface previously owned by `ant-node` has moved to
the new [`ant-protocol`] crate. All previously-exported paths continue
to resolve via re-exports, so existing downstream imports keep working
unchanged.

[`ant-protocol`]: https://crates.io/crates/ant-protocol

- `ant_node::ant_protocol` — now re-exports from `ant_protocol::chunk`.
  Both `ant_node::ant_protocol::ChunkMessage` and
  `ant_node::ant_protocol::chunk::ChunkMessage` resolve.
- `ant_node::client` — `compute_address`, `peer_id_to_xor_name`,
  `xor_distance`, `DataChunk`, `ChunkStats`, `XorName`, and
  `send_and_await_chunk_response` now re-export from
  `ant_protocol::{data_types, chunk_protocol}`.
  `hex_node_id_to_encoded_peer_id` stays as node-owned code.
- `ant_node::payment::proof`, `ant_node::payment::single_node` — now
  re-export from `ant_protocol::payment::{proof, single_node}`.
- `ant_node::payment::{verify_quote_content, verify_quote_signature,
  verify_merkle_candidate_signature}` — now re-export from
  `ant_protocol::payment::verify`.
- `ant_node::devnet::{DevnetManifest, DevnetEvmInfo}` — now re-export
  from `ant_protocol::devnet_manifest`. JSON format unchanged.

### Security

- `ant_protocol::SingleNodePayment::verify` (used via
  `ant_node::payment::PaymentVerifier`) now rejects proofs whose median
  quote has zero price or zero paid amount. Previously a malicious
  client could have submitted a zero-priced median, and the on-chain
  `completedPayments >= 0` check would have trivially succeeded.
- `ant_node::payment::PaymentVerifier` now rejects unknown
  `ProofType` tag bytes (including future variants added on an
  `ant-protocol` minor bump) instead of silently accepting them.

### Added

- Re-export of the `chunk` submodule from `ant-protocol` so
  `ant_node::ant_protocol::chunk::<item>` paths keep resolving for
  downstream callers that used the longer path.

### Deprecation notice

`ant_node::ant_protocol`, `ant_node::client` (except for the node-only
`hex_node_id_to_encoded_peer_id`), `ant_node::payment::{proof,
single_node}`, and `ant_node::payment::verify_*` will be removed in a
future 0.x release once the wider ecosystem has migrated to
`ant_protocol::*` directly. No timeline yet.
