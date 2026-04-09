//! Network Integration Layer for DHT v2
//!
//! Bridges DHT operations with saorsa-core transport infrastructure, providing
//! efficient protocol handling, connection management, and network optimization.

use crate::PeerId;
use crate::dht::core_engine::{DhtKey, NodeInfo};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// DHT protocol messages (peer phonebook only — no data storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessage {
    // Node Discovery
    FindNode { target: DhtKey, count: usize },

    // Network Management
    Ping { timestamp: u64 },
    Join { node_info: NodeInfo },
    Leave { node_id: PeerId },
}

/// DHT protocol responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtResponse {
    // Discovery Responses
    FindNodeReply {
        nodes: Vec<NodeInfo>,
        distances: Vec<u32>,
    },

    // Management Responses
    Pong {
        timestamp: u64,
    },
    JoinAck {
        routing_info: RoutingInfo,
        neighbors: Vec<NodeInfo>,
    },
    LeaveAck {
        confirmed: bool,
    },

    // Error Responses
    Error {
        code: ErrorCode,
        message: String,
        retry_after: Option<Duration>,
    },
}

/// Error codes for DHT operations
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ErrorCode {
    Timeout,
    ConnectionFailed,
    InvalidMessage,
    NodeNotFound,
    Overloaded,
    InternalError,
}

/// Routing information for new nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingInfo {
    pub bootstrap_nodes: Vec<NodeInfo>,
    pub network_size: usize,
    pub protocol_version: u32,
}
