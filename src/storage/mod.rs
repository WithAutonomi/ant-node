//! Storage subsystem for chunk persistence.
//!
//! This module provides content-addressed LMDB storage for chunks,
//! along with a protocol handler that integrates with saorsa-core's
//! `Protocol` trait for automatic message routing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │        AntProtocol (implements Protocol trait)        │
//! ├─────────────────────────────────────────────────────────┤
//! │  protocol_id() = "saorsa/ant/chunk/v1"                  │
//! │                                                         │
//! │  handle(peer_id, data) ──▶ decode AntProtocolMessage │
//! │                                   │                     │
//! │         ┌─────────────────────────┼─────────────────┐  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteRequest           ChunkPutRequest    ChunkGetRequest
//! │         │                         │                 │  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteGenerator          PaymentVerifier   LmdbStorage│
//! │         │                         │                 │  │
//! │         └─────────────────────────┴─────────────────┘  │
//! │                           │                             │
//! │                 return Ok(Some(response_bytes))         │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use saorsa_node::storage::{AntProtocol, LmdbStorage, LmdbStorageConfig};
//!
//! // Create storage
//! let config = LmdbStorageConfig::default();
//! let storage = LmdbStorage::new(config).await?;
//!
//! // Create protocol handler
//! let protocol = AntProtocol::new(storage, payment_verifier, quote_generator);
//!
//! // Register with saorsa-core
//! listener.register_protocol(protocol).await?;
//! ```

mod handler;
mod lmdb;

pub use crate::ant_protocol::XorName;
pub use handler::AntProtocol;
pub use lmdb::{LmdbStorage, LmdbStorageConfig, StorageStats};
