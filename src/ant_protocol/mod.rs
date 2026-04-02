//! ANT protocol implementation for the Autonomi network.
//!
//! This module implements the wire protocol for storing and retrieving
//! data on the Autonomi network.
//!
//! # Data Types
//!
//! The ANT protocol supports a single data type:
//!
//! - **Chunk**: Immutable, content-addressed data (hash == address)
//!
//! # Protocol Overview
//!
//! The protocol uses postcard serialization for compact, fast encoding.
//! Each data type has its own message types for PUT/GET operations.
//!
//! ## Chunk Messages
//!
//! - `ChunkPutRequest` / `ChunkPutResponse` - Store chunks
//! - `ChunkGetRequest` / `ChunkGetResponse` - Retrieve chunks
//! - `ChunkQuoteRequest` / `ChunkQuoteResponse` - Request storage quotes
//!
//! ## Payment Flow
//!
//! 1. Client requests a quote via `ChunkQuoteRequest`
//! 2. Node returns signed `PaymentQuote` in `ChunkQuoteResponse`
//! 3. Client pays on Arbitrum via `PaymentVault.payForQuotes()`
//! 4. Client sends `ChunkPutRequest` with `payment_proof`
//! 5. Node verifies payment and stores chunk
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_node::ant_protocol::{ChunkMessage, ChunkPutRequest, ChunkGetRequest};
//!
//! // Create a PUT request
//! let address = compute_address(&data);
//! let request = ChunkPutRequest::with_payment(address, data, payment_proof);
//! let message = ChunkMessage::PutRequest(request);
//! let bytes = message.encode()?;
//!
//! // Decode a response
//! let response = ChunkMessage::decode(&response_bytes)?;
//! ```

pub mod chunk;

/// Number of nodes in a Kademlia close group.
///
/// Clients fetch quotes from the `CLOSE_GROUP_SIZE` closest nodes to a target
/// address and select the median-priced quote for payment.
pub const CLOSE_GROUP_SIZE: usize = 5;

/// Minimum number of close group members that must agree for a decision to be valid.
///
/// This is a simple majority: `(CLOSE_GROUP_SIZE / 2) + 1`.
pub const CLOSE_GROUP_MAJORITY: usize = (CLOSE_GROUP_SIZE / 2) + 1;

// Re-export chunk types for convenience
pub use chunk::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteResponse, MerkleCandidateQuoteRequest,
    MerkleCandidateQuoteResponse, ProtocolError, XorName, CHUNK_PROTOCOL_ID, DATA_TYPE_CHUNK,
    MAX_CHUNK_SIZE, MAX_WIRE_MESSAGE_SIZE, PROOF_TAG_MERKLE, PROOF_TAG_SINGLE_NODE,
    PROTOCOL_VERSION, XORNAME_LEN,
};
