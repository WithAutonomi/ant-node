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

// Enforce no unwrap/expect/panic in production code only (tests can use them)
#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![cfg_attr(not(test), warn(clippy::expect_used))]
#![cfg_attr(not(test), warn(clippy::panic))]
// Allow unused_async as many functions are async for API consistency
#![allow(clippy::unused_async)]

//! # Saorsa Core
//!
//! A next-generation peer-to-peer networking foundation built in Rust.
//!
//! ## Features
//!
//! - QUIC-based transport with NAT traversal
//! - IPv4-first with simple addressing
//! - Kademlia DHT for distributed routing
//! - Post-quantum cryptography (ML-DSA-65, ML-KEM-768)

#![allow(missing_docs)]
#![allow(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

// Internal modules — used by the crate but not exposed publicly.
pub(crate) mod adaptive;
pub(crate) mod address;
pub(crate) mod bgp_geo_provider;
pub(crate) mod bootstrap;
pub(crate) mod dht;
pub(crate) mod dht_network_manager;
pub(crate) mod error;
pub(crate) mod network;
pub(crate) mod quantum_crypto;
pub(crate) mod rate_limit;
pub(crate) mod security;
pub(crate) mod transport;
pub(crate) mod transport_handle;
pub(crate) mod validation;

/// User identity and privacy system (public — accessed via path by saorsa-node).
pub mod identity;

// ---------------------------------------------------------------------------
// Public re-exports — only items that saorsa-node consumes.
// ---------------------------------------------------------------------------

// Networking
pub use address::MultiAddr;
pub use network::{NodeConfig, NodeMode, P2PEvent, P2PNode};

// DHT types — peer discovery, routing, and network events
pub use dht::Key;
pub use dht_network_manager::{DHTNode, DhtNetworkEvent};

// Bootstrap
pub use bootstrap::{BootstrapConfig, BootstrapManager, BootstrapStats};
pub use bootstrap::{CachedCloseGroupPeer, CloseGroupCache};

// Trust & Adaptive DHT
pub use adaptive::dht::{AdaptiveDhtConfig, TrustEvent};
pub use adaptive::trust::{TrustEngine, TrustRecord};

// Security
pub use security::IPDiversityConfig;

// Post-quantum cryptography
pub use quantum_crypto::MlDsa65;

// Canonical peer identity (also accessible via identity::peer_id::PeerId)
pub use identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Crate-internal re-exports — used by sibling modules via `crate::Result` etc.
// ---------------------------------------------------------------------------
pub(crate) use error::{P2PError, P2pResult as Result};

/// Default capacity for broadcast and mpsc event channels throughout the system.
pub(crate) const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 1000;
