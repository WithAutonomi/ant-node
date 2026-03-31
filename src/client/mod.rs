//! Protocol helpers for ant-node client operations.
//!
//! This module provides low-level protocol support for client-node communication.
//! For high-level client operations, use the `ant-client` crate instead.
//!
//! # Architecture
//!
//! This module contains:
//!
//! 1. **Protocol message handlers**: Send/await pattern for chunks
//! 2. **Data types**: Common types like `XorName`, `DataChunk`, address computation
//!
//! # Migration Note
//!
//! The `QuantumClient` has been deprecated and consolidated into `ant-client::Client`.
//! Use `ant-client` for all client operations.
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_client::Client; // Use ant-client instead of QuantumClient
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // High-level client API
//!     let client = Client::connect(&bootstrap_peers, Default::default()).await?;
//!
//!     // Store data with payment
//!     let address = client.chunk_put(bytes::Bytes::from("hello world")).await?;
//!
//!     // Retrieve data
//!     let chunk = client.chunk_get(&address).await?;
//!
//!     Ok(())
//! }
//! ```

mod chunk_protocol;
mod data_types;

pub use chunk_protocol::send_and_await_chunk_response;
pub use data_types::{
    compute_address, peer_id_to_xor_name, xor_distance, ChunkStats, DataChunk, XorName,
};

// Re-export hex_node_id_to_encoded_peer_id for payment operations
use crate::error::{Error, Result};
use evmlib::EncodedPeerId;

/// Convert a hex-encoded 32-byte node ID to an [`EncodedPeerId`].
///
/// Peer IDs are 64-character hex strings representing 32 raw bytes.
/// This function decodes the hex string and wraps the raw bytes directly
/// into an `EncodedPeerId`.
///
/// # Errors
///
/// Returns an error if the hex string is invalid or not exactly 32 bytes.
pub fn hex_node_id_to_encoded_peer_id(hex_id: &str) -> Result<EncodedPeerId> {
    let raw_bytes = hex::decode(hex_id)
        .map_err(|e| Error::Payment(format!("Invalid hex peer ID '{hex_id}': {e}")))?;
    let bytes: [u8; 32] = raw_bytes.try_into().map_err(|v: Vec<u8>| {
        let len = v.len();
        Error::Payment(format!("Peer ID must be 32 bytes, got {len}"))
    })?;
    Ok(EncodedPeerId::new(bytes))
}
