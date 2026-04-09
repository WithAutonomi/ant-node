// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Transport Layer
//!
//! This module provides native saorsa-transport integration for the P2P Foundation.
//!
//! Use `saorsa_transport_adapter::P2PNetworkNode` directly for all networking needs.

// Native saorsa-transport integration with advanced NAT traversal and PQC support
pub mod saorsa_transport_adapter;

// DHT protocol handler for SharedTransport integration
pub mod dht_handler;

// Observed-address cache: records `ExternalAddressDiscovered` events from the
// transport layer and serves as a frequency- and recency-aware fallback when
// no live connection has an observation.
pub(crate) mod observed_address_cache;
