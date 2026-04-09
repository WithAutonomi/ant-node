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

//! Cryptographic Identity Module
//!
//! Provides cryptographic node identity for the P2P network using post-quantum
//! ML-DSA signatures. This module handles peer identity (NodeIdentity), NOT
//! user-facing identity management (which was removed).
//!
//! # Core Types
//!
//! - `NodeIdentity`: Cryptographic identity with ML-DSA keypair
//! - `PeerId`: 32-byte hash of public key
//!
//! # Identity Restart System
//!
//! Enables nodes to detect when their identity doesn't "fit" a DHT close group
//! and automatically regenerate with a new identity.

pub mod node_identity;
pub mod peer_id;

pub use node_identity::{IdentityData, NodeIdentity};
pub use peer_id::{PEER_ID_BYTE_LEN, PeerId, PeerIdParseError};
