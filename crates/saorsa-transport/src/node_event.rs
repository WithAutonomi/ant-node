// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Unified events for P2P nodes
//!
//! This module provides [`NodeEvent`] - a single event type that covers
//! all significant node activities including connections, NAT detection,
//! relay sessions, and data transfer.
//!
//! # Example
//!
//! ```rust,ignore
//! use saorsa_transport::Node;
//!
//! let node = Node::new().await?;
//! let mut events = node.subscribe();
//!
//! tokio::spawn(async move {
//!     while let Ok(event) = events.recv().await {
//!         match event {
//!             NodeEvent::PeerConnected { peer_id, .. } => {
//!                 println!("Connected to: {:?}", peer_id);
//!             }
//!             NodeEvent::NatTypeDetected { nat_type } => {
//!                 println!("NAT type: {:?}", nat_type);
//!             }
//!             _ => {}
//!         }
//!     }
//! });
//! ```

use std::net::SocketAddr;

use crate::node_status::NatType;
use crate::transport::TransportAddr;

/// Reason for peer disconnection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Normal graceful shutdown
    Graceful,
    /// Connection timeout
    Timeout,
    /// Connection reset by peer
    Reset,
    /// Application-level close
    ApplicationClose,
    /// Idle timeout
    Idle,
    /// Transport error
    TransportError(String),
    /// Unknown reason
    Unknown,
}

impl std::fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Graceful => write!(f, "graceful shutdown"),
            Self::Timeout => write!(f, "connection timeout"),
            Self::Reset => write!(f, "connection reset"),
            Self::ApplicationClose => write!(f, "application close"),
            Self::Idle => write!(f, "idle timeout"),
            Self::TransportError(e) => write!(f, "transport error: {}", e),
            Self::Unknown => write!(f, "unknown reason"),
        }
    }
}

/// Unified event type for all node activities
///
/// Subscribe to these events via `node.subscribe()` to monitor
/// all significant node activities in real-time.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    // --- Peer Events ---
    /// A peer connected successfully
    PeerConnected {
        /// The peer's address (supports all transport types)
        addr: TransportAddr,
        /// The peer's public key bytes (ML-DSA-65 SPKI), if available from TLS handshake
        public_key: Option<Vec<u8>>,
        /// Whether this is a direct connection (vs relayed)
        direct: bool,
    },

    /// A peer disconnected
    PeerDisconnected {
        /// The peer's address
        addr: SocketAddr,
        /// Reason for disconnection
        reason: DisconnectReason,
    },

    /// Connection attempt failed
    ConnectionFailed {
        /// Target address that failed
        addr: SocketAddr,
        /// Error message
        error: String,
    },

    // --- NAT Events ---
    /// External address discovered
    ///
    /// This is the address as seen by other peers.
    ExternalAddressDiscovered {
        /// The discovered external address (supports all transport types)
        addr: TransportAddr,
    },

    /// NAT type detected
    NatTypeDetected {
        /// The detected NAT type
        nat_type: NatType,
    },

    /// NAT traversal completed
    NatTraversalComplete {
        /// The address of the peer we traversed to
        addr: SocketAddr,
        /// Whether traversal was successful
        success: bool,
        /// Connection method used
        method: TraversalMethod,
    },

    // --- Relay Events ---
    /// Started relaying for a peer
    RelaySessionStarted {
        /// The address of the peer we're relaying for
        addr: SocketAddr,
    },

    /// Stopped relaying for a peer
    RelaySessionEnded {
        /// The address of the peer we were relaying for
        addr: SocketAddr,
        /// Total bytes forwarded during session
        bytes_forwarded: u64,
    },

    // --- Coordination Events ---
    /// Started coordinating NAT traversal for peers
    CoordinationStarted {
        /// Address of peer A in the coordination
        addr_a: SocketAddr,
        /// Address of peer B in the coordination
        addr_b: SocketAddr,
    },

    /// NAT traversal coordination completed
    CoordinationComplete {
        /// Address of peer A in the coordination
        addr_a: SocketAddr,
        /// Address of peer B in the coordination
        addr_b: SocketAddr,
        /// Whether coordination was successful
        success: bool,
    },

    // --- Data Events ---
    /// Data received from a peer
    DataReceived {
        /// The address of the peer that sent data
        addr: SocketAddr,
        /// Stream ID (for multiplexed connections)
        stream_id: u64,
        /// Number of bytes received
        bytes: usize,
    },

    /// Data sent to a peer
    DataSent {
        /// The address of the peer we sent data to
        addr: SocketAddr,
        /// Stream ID
        stream_id: u64,
        /// Number of bytes sent
        bytes: usize,
    },
}

/// Method used for NAT traversal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraversalMethod {
    /// Direct connection (no NAT or easy NAT)
    Direct,
    /// Hole punching succeeded
    HolePunch,
    /// Connection via relay
    Relay,
    /// Port prediction for symmetric NAT
    PortPrediction,
}

impl std::fmt::Display for TraversalMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::HolePunch => write!(f, "hole punch"),
            Self::Relay => write!(f, "relay"),
            Self::PortPrediction => write!(f, "port prediction"),
        }
    }
}

impl NodeEvent {
    /// Check if this is a connection event
    pub fn is_connection_event(&self) -> bool {
        matches!(
            self,
            Self::PeerConnected { .. }
                | Self::PeerDisconnected { .. }
                | Self::ConnectionFailed { .. }
        )
    }

    /// Check if this is a NAT-related event
    pub fn is_nat_event(&self) -> bool {
        matches!(
            self,
            Self::ExternalAddressDiscovered { .. }
                | Self::NatTypeDetected { .. }
                | Self::NatTraversalComplete { .. }
        )
    }

    /// Check if this is a relay event
    pub fn is_relay_event(&self) -> bool {
        matches!(
            self,
            Self::RelaySessionStarted { .. } | Self::RelaySessionEnded { .. }
        )
    }

    /// Check if this is a coordination event
    pub fn is_coordination_event(&self) -> bool {
        matches!(
            self,
            Self::CoordinationStarted { .. } | Self::CoordinationComplete { .. }
        )
    }

    /// Check if this is a data event
    pub fn is_data_event(&self) -> bool {
        matches!(self, Self::DataReceived { .. } | Self::DataSent { .. })
    }

    /// Get the socket address associated with this event (if any).
    ///
    /// For `PeerConnected`, this converts the `TransportAddr` to a `SocketAddr`
    /// using `to_synthetic_socket_addr()`.
    pub fn addr(&self) -> Option<SocketAddr> {
        match self {
            Self::PeerConnected { addr, .. } => Some(addr.to_synthetic_socket_addr()),
            Self::PeerDisconnected { addr, .. } => Some(*addr),
            Self::NatTraversalComplete { addr, .. } => Some(*addr),
            Self::RelaySessionStarted { addr } => Some(*addr),
            Self::RelaySessionEnded { addr, .. } => Some(*addr),
            Self::DataReceived { addr, .. } => Some(*addr),
            Self::DataSent { addr, .. } => Some(*addr),
            _ => None,
        }
    }
}

// Import P2pDisconnectReason for the From implementation
use crate::p2p_endpoint::DisconnectReason as P2pDisconnectReason;

/// Convert P2pDisconnectReason to NodeDisconnectReason (DisconnectReason in node_event)
///
/// This provides an idiomatic conversion between the two disconnect reason types
/// used at different API layers.
impl From<P2pDisconnectReason> for DisconnectReason {
    fn from(reason: P2pDisconnectReason) -> Self {
        match reason {
            P2pDisconnectReason::Normal => Self::Graceful,
            P2pDisconnectReason::Timeout => Self::Timeout,
            P2pDisconnectReason::ProtocolError(e) => Self::TransportError(e),
            P2pDisconnectReason::AuthenticationFailed => {
                Self::TransportError("authentication failed".to_string())
            }
            P2pDisconnectReason::ConnectionLost => Self::Reset,
            P2pDisconnectReason::RemoteClosed => Self::ApplicationClose,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr() -> SocketAddr {
        "127.0.0.1:9000".parse().unwrap()
    }

    #[test]
    fn test_peer_connected_event() {
        let event = NodeEvent::PeerConnected {
            addr: TransportAddr::Udp(test_addr()),
            public_key: None,
            direct: true,
        };

        assert!(event.is_connection_event());
        assert!(!event.is_nat_event());
        assert_eq!(event.addr(), Some(test_addr()));
    }

    #[test]
    fn test_peer_disconnected_event() {
        let event = NodeEvent::PeerDisconnected {
            addr: test_addr(),
            reason: DisconnectReason::Graceful,
        };

        assert!(event.is_connection_event());
        assert_eq!(event.addr(), Some(test_addr()));
    }

    #[test]
    fn test_nat_type_detected_event() {
        let event = NodeEvent::NatTypeDetected {
            nat_type: NatType::FullCone,
        };

        assert!(event.is_nat_event());
        assert!(!event.is_connection_event());
        assert!(event.addr().is_none());
    }

    #[test]
    fn test_relay_session_events() {
        let start = NodeEvent::RelaySessionStarted { addr: test_addr() };

        let end = NodeEvent::RelaySessionEnded {
            addr: test_addr(),
            bytes_forwarded: 1024,
        };

        assert!(start.is_relay_event());
        assert!(end.is_relay_event());
        assert!(!start.is_connection_event());
    }

    #[test]
    fn test_coordination_events() {
        let addr_a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        let start = NodeEvent::CoordinationStarted { addr_a, addr_b };

        let complete = NodeEvent::CoordinationComplete {
            addr_a,
            addr_b,
            success: true,
        };

        assert!(start.is_coordination_event());
        assert!(complete.is_coordination_event());
    }

    #[test]
    fn test_data_events() {
        let recv = NodeEvent::DataReceived {
            addr: test_addr(),
            stream_id: 1,
            bytes: 1024,
        };

        let send = NodeEvent::DataSent {
            addr: test_addr(),
            stream_id: 1,
            bytes: 512,
        };

        assert!(recv.is_data_event());
        assert!(send.is_data_event());
        assert!(!recv.is_connection_event());
    }

    #[test]
    fn test_disconnect_reason_display() {
        assert_eq!(
            format!("{}", DisconnectReason::Graceful),
            "graceful shutdown"
        );
        assert_eq!(
            format!("{}", DisconnectReason::Timeout),
            "connection timeout"
        );
        assert_eq!(
            format!("{}", DisconnectReason::TransportError("test".to_string())),
            "transport error: test"
        );
    }

    #[test]
    fn test_traversal_method_display() {
        assert_eq!(format!("{}", TraversalMethod::Direct), "direct");
        assert_eq!(format!("{}", TraversalMethod::HolePunch), "hole punch");
        assert_eq!(format!("{}", TraversalMethod::Relay), "relay");
        assert_eq!(
            format!("{}", TraversalMethod::PortPrediction),
            "port prediction"
        );
    }

    #[test]
    fn test_events_are_clone() {
        let event = NodeEvent::PeerConnected {
            addr: TransportAddr::Udp(test_addr()),
            public_key: None,
            direct: true,
        };

        let cloned = event.clone();
        assert!(cloned.is_connection_event());
    }

    #[test]
    fn test_events_are_debug() {
        let event = NodeEvent::NatTypeDetected {
            nat_type: NatType::Symmetric,
        };

        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("NatTypeDetected"));
        assert!(debug_str.contains("Symmetric"));
    }

    #[test]
    fn test_connection_failed_event() {
        let event = NodeEvent::ConnectionFailed {
            addr: test_addr(),
            error: "connection refused".to_string(),
        };

        assert!(event.is_connection_event());
        assert!(event.addr().is_none());
    }

    #[test]
    fn test_external_address_discovered() {
        let event = NodeEvent::ExternalAddressDiscovered {
            addr: TransportAddr::Udp("1.2.3.4:9000".parse().unwrap()),
        };

        assert!(event.is_nat_event());
        assert!(event.addr().is_none());
    }
}
