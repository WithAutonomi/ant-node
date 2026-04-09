// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! DHT Protocol Handler for SharedTransport
//!
//! This module implements the `ProtocolHandler` trait from saorsa-transport
//! for routing DHT-related streams to the appropriate handlers.
//!
//! ## Stream Types Handled
//!
//! | Type | Byte | Purpose |
//! |------|------|---------|
//! | DhtQuery | 0x10 | FIND_NODE, Ping requests |

use async_trait::async_trait;
use bytes::Bytes;
use saorsa_transport::link_transport::{LinkError, LinkResult, ProtocolHandler, StreamType};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, trace, warn};

use crate::dht::core_engine::DhtCoreEngine;
use crate::dht::network_integration::{DhtMessage, DhtResponse, ErrorCode};

#[allow(dead_code)]
/// DHT stream types handled by this handler.
///
/// Only DhtQuery remains — store and replication are handled by the
/// application layer (saorsa-node).
const DHT_STREAM_TYPES: &[StreamType] = &[StreamType::DhtQuery];

/// DHT protocol handler for SharedTransport.
///
/// Routes incoming DHT streams to the appropriate handlers based on stream type:
/// - DhtQuery: Handles FIND_NODE, Ping requests (peer phonebook)
#[allow(dead_code)]
pub struct DhtStreamHandler {
    /// Reference to the DHT engine for processing requests.
    dht_engine: Arc<RwLock<DhtCoreEngine>>,
    /// Handler name for logging.
    name: String,
}

#[allow(dead_code)]
impl DhtStreamHandler {
    /// Create a new DHT stream handler.
    ///
    /// # Arguments
    ///
    /// * `dht_engine` - The DHT engine to process requests
    pub fn new(dht_engine: Arc<RwLock<DhtCoreEngine>>) -> Self {
        Self {
            dht_engine,
            name: "DhtStreamHandler".to_string(),
        }
    }

    /// Create a new DHT stream handler with a custom name.
    pub fn with_name(dht_engine: Arc<RwLock<DhtCoreEngine>>, name: impl Into<String>) -> Self {
        Self {
            dht_engine,
            name: name.into(),
        }
    }

    /// Handle a DHT query request.
    async fn handle_query(
        &self,
        remote_addr: SocketAddr,
        data: Bytes,
    ) -> LinkResult<Option<Bytes>> {
        trace!(remote_addr = %remote_addr, size = data.len(), "Processing DHT query");

        let message: DhtMessage = postcard::from_bytes(&data)
            .map_err(|e| LinkError::Internal(format!("Failed to deserialize query: {e}")))?;

        let response = self.process_message(message).await?;

        let response_bytes = postcard::to_stdvec(&response)
            .map_err(|e| LinkError::Internal(format!("Failed to serialize response: {e}")))?;

        Ok(Some(Bytes::from(response_bytes)))
    }

    /// Process a DHT message and return the response.
    async fn process_message(&self, message: DhtMessage) -> LinkResult<DhtResponse> {
        match message {
            DhtMessage::FindNode { target, count } => {
                let engine = self.dht_engine.read().await;

                match engine.find_nodes(&target, count).await {
                    Ok(nodes) => {
                        debug!(target = ?target, count = nodes.len(), "DHT find_node completed");
                        Ok(DhtResponse::FindNodeReply {
                            nodes,
                            distances: Vec::new(),
                        })
                    }
                    Err(e) => {
                        warn!(target = ?target, error = %e, "DHT find_node failed");
                        Ok(DhtResponse::Error {
                            code: ErrorCode::NodeNotFound,
                            message: format!("FindNode failed: {e}"),
                            retry_after: None,
                        })
                    }
                }
            }

            DhtMessage::Ping { timestamp } => {
                debug!("DHT ping received");
                Ok(DhtResponse::Pong { timestamp })
            }

            DhtMessage::Join { node_info, .. } => {
                debug!(node = ?node_info.id, "DHT join request");
                Ok(DhtResponse::JoinAck {
                    routing_info: crate::dht::network_integration::RoutingInfo {
                        bootstrap_nodes: vec![],
                        network_size: 0,
                        protocol_version: 1,
                    },
                    neighbors: vec![],
                })
            }

            DhtMessage::Leave { node_id, .. } => {
                debug!(node = ?node_id, "DHT leave notification");
                Ok(DhtResponse::LeaveAck { confirmed: true })
            }
        }
    }
}

#[async_trait]
impl ProtocolHandler for DhtStreamHandler {
    fn stream_types(&self) -> &[StreamType] {
        DHT_STREAM_TYPES
    }

    async fn handle_stream(
        &self,
        remote_addr: SocketAddr,
        _public_key: Option<&[u8]>,
        stream_type: StreamType,
        data: Bytes,
    ) -> LinkResult<Option<Bytes>> {
        match stream_type {
            StreamType::DhtQuery => self.handle_query(remote_addr, data).await,
            _ => {
                error!(
                    stream_type = %stream_type,
                    "Unexpected stream type routed to DHT handler"
                );
                Err(LinkError::InvalidStreamType(stream_type.as_byte()))
            }
        }
    }

    async fn handle_datagram(
        &self,
        remote_addr: SocketAddr,
        _public_key: Option<&[u8]>,
        stream_type: StreamType,
        data: Bytes,
    ) -> LinkResult<()> {
        trace!(
            remote_addr = %remote_addr,
            stream_type = %stream_type,
            size = data.len(),
            "DHT datagram received (ignored)"
        );
        Ok(())
    }

    async fn shutdown(&self) -> LinkResult<()> {
        debug!(handler = %self.name, "DHT handler shutting down");
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// DHT-specific stream type mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhtStreamType {
    /// Query operations (FIND_NODE, Ping).
    Query,
}

impl DhtStreamType {
    /// Convert to the saorsa-transport StreamType.
    pub fn to_stream_type(self) -> StreamType {
        match self {
            Self::Query => StreamType::DhtQuery,
        }
    }

    /// Determine the appropriate stream type for a DHT message.
    pub fn for_message(_message: &DhtMessage) -> Self {
        Self::Query
    }
}

impl From<DhtStreamType> for StreamType {
    fn from(dht_type: DhtStreamType) -> Self {
        dht_type.to_stream_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_stream_types() {
        assert_eq!(DHT_STREAM_TYPES.len(), 1);
        assert!(DHT_STREAM_TYPES.contains(&StreamType::DhtQuery));
    }

    #[test]
    fn test_dht_stream_type_conversion() {
        assert_eq!(DhtStreamType::Query.to_stream_type(), StreamType::DhtQuery);
    }
}
