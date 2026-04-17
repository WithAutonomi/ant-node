//! Protocol helpers for ant-node client operations.
//!
//! This module provides low-level protocol support for client-node
//! communication. For high-level client operations, use the `ant-client`
//! crate instead.
//!
//! # Architecture
//!
//! As of 0.11, the shared protocol types and helpers live in the
//! [`ant_protocol`] crate. This module re-exports them so existing
//! callers of `ant_node::client::*` continue to compile; new code
//! should prefer `ant_protocol::*` directly.
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_client::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::connect(&bootstrap_peers, Default::default()).await?;
//!     let address = client.chunk_put(bytes::Bytes::from("hello world")).await?;
//!     let chunk = client.chunk_get(&address).await?;
//!     Ok(())
//! }
//! ```

pub use ant_protocol::chunk_protocol::send_and_await_chunk_response;
pub use ant_protocol::data_types::{
    compute_address, peer_id_to_xor_name, xor_distance, ChunkStats, DataChunk,
};
pub use ant_protocol::XorName;

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
