//! Wire protocol re-exports from the [`ant_protocol`] crate.
//!
//! This module existed as first-party ant-node code until version 0.11.
//! The wire contract now lives in the [`ant_protocol`] crate so
//! `ant-client` and `ant-node` can evolve their release cycles
//! independently. Everything this module previously exported is
//! re-exported below verbatim, including the `chunk` submodule path so
//! downstream callers of `ant_node::ant_protocol::chunk::*` keep working.
//!
//! Internal ant-node code can keep using `crate::ant_protocol::…`; the
//! imports resolve to the same types they always did. New code should
//! prefer `ant_protocol::…` directly.

// Re-export the submodule so `ant_node::ant_protocol::chunk::*` keeps
// resolving. Using the fully-qualified path `::ant_protocol::chunk`
// disambiguates from `crate::ant_protocol` (this module).
pub use ::ant_protocol::chunk;

pub use ::ant_protocol::chunk::{
    settlement_compatibility, ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody,
    ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteRequestV2, ChunkQuoteResponse,
    MerkleCandidateQuoteRequest, MerkleCandidateQuoteRequestV2, MerkleCandidateQuoteResponse,
    ProtocolError, SettlementCompatibility, XorName, CHUNK_PROTOCOL_ID, CLOSE_GROUP_MAJORITY,
    CLOSE_GROUP_SIZE, CURRENT_SETTLEMENT_VERSION, DATA_TYPE_CHUNK, MAX_CHUNK_SIZE,
    MAX_WIRE_MESSAGE_SIZE, MIN_SUPPORTED_SETTLEMENT_VERSION, PROOF_TAG_MERKLE,
    PROOF_TAG_SINGLE_NODE, PROTOCOL_VERSION, XORNAME_LEN,
};
