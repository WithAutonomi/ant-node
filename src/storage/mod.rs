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
//! │  protocol_id() = "autonomi.ant.chunk.v1"                  │
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
//! use std::sync::Arc;
//! use ant_node::storage::{AntProtocol, LmdbStorage, LmdbStorageConfig};
//!
//! // Create storage
//! let config = LmdbStorageConfig::default();
//! let storage = Arc::new(LmdbStorage::new(config).await?);
//!
//! // Create protocol handler
//! let protocol = AntProtocol::new(storage, Arc::new(payment_verifier), Arc::new(quote_generator));
//!
//! // Register with saorsa-core
//! listener.register_protocol(protocol).await?;
//! ```

mod handler;
pub(crate) mod lmdb;
mod shared;

use async_trait::async_trait;
use std::path::Path;

pub use crate::ant_protocol::XorName;
pub use handler::AntProtocol;
pub(crate) use handler::ChunkRequestContext;
pub use lmdb::{LmdbStorage, LmdbStorageConfig, StorageStats};
pub use shared::{SharedChunkStore, SharedChunkStoreBase, SharedChunkStoreConfig};

/// The logical chunk-store view used by one node identity.
///
/// Standalone nodes use [`LmdbStorage`] directly. A multi-identity daemon
/// gives every identity a [`SharedChunkStore`] view: membership and pruning
/// stay identity-scoped while the content-addressed bytes are stored once.
#[async_trait]
pub trait ChunkStore: Send + Sync {
    /// Store bytes and make this identity an owner of the address.
    async fn put(&self, address: &XorName, content: &[u8]) -> crate::error::Result<bool>;

    /// Read and verify bytes visible to this identity.
    async fn get(&self, address: &XorName) -> crate::error::Result<Option<Vec<u8>>>;

    /// Whether this identity owns the address.
    ///
    /// # Errors
    ///
    /// Returns an error when the ownership catalogue cannot be read.
    fn exists(&self, address: &XorName) -> crate::error::Result<bool>;

    /// Drop this identity's ownership. Shared implementations retain the
    /// physical bytes while another local identity still owns them.
    async fn delete(&self, address: &XorName) -> crate::error::Result<bool>;

    /// Storage operation statistics.
    fn stats(&self) -> StorageStats;

    /// Number of records visible to this identity.
    ///
    /// # Errors
    ///
    /// Returns an error when storage metadata cannot be read.
    fn current_chunks(&self) -> crate::error::Result<u64>;

    /// Root used for identity-scoped metadata.
    fn root_dir(&self) -> &Path;

    /// All records visible to this identity.
    async fn all_keys(&self) -> crate::error::Result<Vec<XorName>>;

    /// Read bytes without content-address verification.
    async fn get_raw(&self, address: &XorName) -> crate::error::Result<Option<Vec<u8>>>;

    /// Cheap preflight for accepting another physical blob.
    ///
    /// # Errors
    ///
    /// Returns an error when no configured volume can safely accept a write.
    fn check_capacity(&self) -> crate::error::Result<()>;

    /// Adopt already-present physical bytes without downloading them.
    async fn acquire_local(&self, _address: &XorName) -> crate::error::Result<bool> {
        Ok(false)
    }

    /// Wait for outstanding blocking storage work to finish.
    async fn wait_idle(&self);
}

#[async_trait]
impl ChunkStore for LmdbStorage {
    async fn put(&self, address: &XorName, content: &[u8]) -> crate::error::Result<bool> {
        self.put(address, content).await
    }

    async fn get(&self, address: &XorName) -> crate::error::Result<Option<Vec<u8>>> {
        self.get(address).await
    }

    fn exists(&self, address: &XorName) -> crate::error::Result<bool> {
        self.exists(address)
    }

    async fn delete(&self, address: &XorName) -> crate::error::Result<bool> {
        self.delete(address).await
    }

    fn stats(&self) -> StorageStats {
        self.stats()
    }

    fn current_chunks(&self) -> crate::error::Result<u64> {
        self.current_chunks()
    }

    fn root_dir(&self) -> &Path {
        self.root_dir()
    }

    async fn all_keys(&self) -> crate::error::Result<Vec<XorName>> {
        self.all_keys().await
    }

    async fn get_raw(&self, address: &XorName) -> crate::error::Result<Option<Vec<u8>>> {
        self.get_raw(address).await
    }

    fn check_capacity(&self) -> crate::error::Result<()> {
        self.check_capacity()
    }

    async fn wait_idle(&self) {
        self.wait_idle().await;
    }
}
