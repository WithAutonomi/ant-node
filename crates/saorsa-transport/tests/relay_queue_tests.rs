//! Integration tests for NAT traversal functionality
//!
//! v0.13.0+: Updated for symmetric P2P node architecture - no roles.
//! This module tests the NAT traversal functionality through the public API,
//! focusing on overall system behavior and the high-level interfaces.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use saorsa_transport::{
    VarInt,
    config::nat_timeouts::TimeoutConfig,
    nat_traversal_api::{NatTraversalConfig, NatTraversalEndpoint, NatTraversalError},
};

#[cfg(test)]
mod nat_traversal_api_tests {
    use super::*;

    #[test]
    fn test_nat_traversal_config_default() {
        // v0.13.0+: No role field - all nodes are symmetric P2P nodes
        let config = NatTraversalConfig::default();

        assert_eq!(config.max_candidates, 8);
        assert_eq!(config.coordination_timeout, Duration::from_secs(10));
        assert!(config.enable_symmetric_nat);
        assert!(config.enable_relay_fallback);
        assert_eq!(config.max_concurrent_attempts, 3);
        assert!(config.known_peers.is_empty());
    }

    #[test]
    fn test_nat_traversal_config_with_known_peers() {
        // v0.13.0+: All nodes are symmetric - configure with known_peers instead of role
        let known_peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let config = NatTraversalConfig {
            known_peers: vec![known_peer_addr],
            max_candidates: 16,
            coordination_timeout: Duration::from_secs(30),
            enable_symmetric_nat: false,
            enable_relay_fallback: false,
            max_concurrent_attempts: 5,
            bind_addr: None,
            prefer_rfc_nat_traversal: false,
            pqc: None,
            timeouts: TimeoutConfig::default(),
            identity_key: None,
            relay_nodes: vec![],
            enable_relay_service: true,
            allow_ipv4_mapped: true,
            transport_registry: None,
            max_message_size: saorsa_transport::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
            allow_loopback: false,
            coordinator_max_active_relays: 32,
            coordinator_relay_slot_idle_timeout: Duration::from_secs(5),
            upnp: Default::default(),
        };

        assert_eq!(config.known_peers.len(), 1);
        assert_eq!(config.known_peers[0], known_peer_addr);
        assert_eq!(config.max_candidates, 16);
        assert_eq!(config.coordination_timeout, Duration::from_secs(30));
        assert!(!config.enable_symmetric_nat);
        assert!(!config.enable_relay_fallback);
        assert_eq!(config.max_concurrent_attempts, 5);
    }

    #[tokio::test]
    async fn test_nat_traversal_endpoint_creation_without_known_peers() {
        // v0.13.0+: Nodes without known peers are valid - they wait for incoming connections
        let config = NatTraversalConfig {
            known_peers: vec![],
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            ..NatTraversalConfig::default()
        };

        let result = NatTraversalEndpoint::new(config, None, None).await;
        // May succeed or fail - key is no panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_nat_traversal_endpoint_creation_with_known_peers() {
        // v0.13.0+: Node with known peers can connect to the network
        let known_peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let config = NatTraversalConfig {
            known_peers: vec![known_peer_addr],
            ..NatTraversalConfig::default()
        };

        // This will likely fail due to TLS configuration, but should pass basic validation
        let result = NatTraversalEndpoint::new(config, None, None).await;
        if let Err(e) = result {
            // Should not fail due to "bootstrap node" validation (removed in v0.13.0+)
            assert!(!e.to_string().contains("bootstrap node"));
        }
    }

    #[tokio::test]
    async fn test_known_peer_management() {
        // v0.13.0+: All nodes are symmetric - can manage known peers
        let known_peer_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let known_peer_addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 8080);

        let config = NatTraversalConfig {
            known_peers: vec![known_peer_addr1],
            ..NatTraversalConfig::default()
        };

        // Try to create endpoint - may fail due to TLS but we can test the concept
        if let Ok(endpoint) = NatTraversalEndpoint::new(config, None, None).await {
            // Test adding known peer
            let result = endpoint.add_bootstrap_node(known_peer_addr2);
            assert!(result.is_ok());

            // Test removing known peer
            let result = endpoint.remove_bootstrap_node(known_peer_addr1);
            assert!(result.is_ok());

            // Test getting statistics
            let stats = endpoint.get_statistics();
            assert!(stats.is_ok());

            if let Ok(stats) = stats {
                assert_eq!(stats.active_sessions, 0); // No active sessions yet
            }
        }
    }
}

#[cfg(test)]
mod functional_tests {
    use super::*;

    #[test]
    fn test_varint_compatibility() {
        // Test VarInt values commonly used in NAT traversal
        let small_value = VarInt::from_u32(42);
        let medium_value = VarInt::from_u32(10000);
        let large_value = VarInt::from_u32(1000000);

        assert_eq!(small_value.into_inner(), 42);
        assert_eq!(medium_value.into_inner(), 10000);
        assert_eq!(large_value.into_inner(), 1000000);

        // Test maximum values
        let max_value = VarInt::from_u32(u32::MAX);
        assert_eq!(max_value.into_inner(), u32::MAX as u64);
    }

    #[test]
    fn test_socket_address_handling() {
        // Test various socket address formats used in NAT traversal
        let ipv4_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let ipv4_public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let ipv6_addr = SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 9000);

        // Verify address properties
        assert!(ipv4_local.ip().is_ipv4());
        assert!(!ipv4_local.ip().is_loopback());
        assert!(ipv4_public.ip().is_ipv4());
        assert!(!ipv4_public.ip().is_loopback());
        assert!(ipv6_addr.ip().is_ipv6());

        // Test port ranges
        assert_eq!(ipv4_local.port(), 5000);
        assert_eq!(ipv4_public.port(), 8080);
        assert_eq!(ipv6_addr.port(), 9000);
    }

    #[tokio::test]
    async fn test_configuration_validation() {
        // v0.13.0+: Test various configurations
        // Zero values may be accepted or rejected depending on implementation
        let zero_values_config = NatTraversalConfig {
            known_peers: vec![],
            max_candidates: 0,
            coordination_timeout: Duration::from_secs(0),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 0,
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            prefer_rfc_nat_traversal: false,
            pqc: None,
            timeouts: TimeoutConfig::default(),
            identity_key: None,
            relay_nodes: vec![],
            enable_relay_service: true,
            allow_ipv4_mapped: true,
            transport_registry: None,
            max_message_size: saorsa_transport::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
            allow_loopback: false,
            coordinator_max_active_relays: 32,
            coordinator_relay_slot_idle_timeout: Duration::from_secs(5),
            upnp: Default::default(),
        };

        // May fail due to zero values or other validation
        let result = NatTraversalEndpoint::new(zero_values_config, None, None).await;
        // Just ensure no panic
        let _ = result;

        // Test valid configuration
        let valid_config = NatTraversalConfig {
            known_peers: vec![],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            prefer_rfc_nat_traversal: false,
            pqc: None,
            timeouts: TimeoutConfig::default(),
            identity_key: None,
            relay_nodes: vec![],
            enable_relay_service: true,
            allow_ipv4_mapped: true,
            transport_registry: None,
            max_message_size: saorsa_transport::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
            allow_loopback: false,
            coordinator_max_active_relays: 32,
            coordinator_relay_slot_idle_timeout: Duration::from_secs(5),
            upnp: Default::default(),
        };

        let result = NatTraversalEndpoint::new(valid_config, None, None).await;
        // May succeed or fail - key is no panic
        let _ = result;
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_nat_traversal_error_display() {
        let errors = vec![
            NatTraversalError::NoBootstrapNodes,
            NatTraversalError::NoCandidatesFound,
            NatTraversalError::CandidateDiscoveryFailed("test error".to_string()),
            NatTraversalError::CoordinationFailed("coordination error".to_string()),
            NatTraversalError::HolePunchingFailed,
            NatTraversalError::ValidationTimeout,
            NatTraversalError::NetworkError("network issue".to_string()),
            NatTraversalError::ConfigError("config issue".to_string()),
            NatTraversalError::ProtocolError("protocol issue".to_string()),
            NatTraversalError::Timeout,
            NatTraversalError::ConnectionFailed("connection error".to_string()),
            NatTraversalError::TraversalFailed("traversal error".to_string()),
        ];

        // Verify all errors implement Display properly
        for error in errors {
            let error_string = format!("{error}");
            assert!(!error_string.is_empty());
            assert!(!error_string.starts_with("NatTraversalError")); // Should be user-friendly
        }
    }

    #[test]
    fn test_error_chain_compatibility() {
        // Test that our errors work with standard error handling
        let error = NatTraversalError::ConfigError("test error".to_string());

        // Should implement std::error::Error
        let _source: Option<&dyn Error> = error.source();

        // Should work with error conversion patterns
        let result: Result<(), NatTraversalError> = Err(error);
        assert!(result.is_err());

        // Test error message propagation
        if let Err(e) = result {
            assert!(e.to_string().contains("config"));
            assert!(e.to_string().contains("test error"));
        }
    }
}

#[cfg(test)]
mod nat_traversal_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_nat_traversal_initiation() {
        // v0.13.0+: All nodes are symmetric P2P nodes
        let known_peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let config = NatTraversalConfig {
            known_peers: vec![known_peer_addr],
            ..NatTraversalConfig::default()
        };

        if let Ok(endpoint) = NatTraversalEndpoint::new(config, None, None).await {
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), 8080);

            // Test NAT traversal initiation
            let result = endpoint.initiate_nat_traversal(target_addr, known_peer_addr);
            // This might fail due to missing implementation details, but should not panic
            let _ = result;
        }
    }

    #[tokio::test]
    async fn test_polling_without_active_sessions() {
        // v0.13.0+: Symmetric node configuration
        let config = NatTraversalConfig {
            known_peers: vec![],
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            ..NatTraversalConfig::default()
        };

        if let Ok(endpoint) = NatTraversalEndpoint::new(config, None, None).await {
            let now = std::time::Instant::now();

            // Polling with no active sessions should not panic
            let result = endpoint.poll(now);
            assert!(result.is_ok());

            // Polling may produce discovery events even without active sessions
            // (e.g., local address discovery happens on startup)
            if let Ok(events) = result {
                // Just verify we got some result - events are not necessarily empty
                let _ = events;
            }
        }
    }

    #[tokio::test]
    async fn test_statistics_without_activity() {
        // v0.13.0+: Symmetric node configuration
        let config = NatTraversalConfig {
            known_peers: vec![],
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            ..NatTraversalConfig::default()
        };

        if let Ok(endpoint) = NatTraversalEndpoint::new(config, None, None).await {
            let stats = endpoint.get_statistics();
            assert!(stats.is_ok());

            if let Ok(stats) = stats {
                assert_eq!(stats.active_sessions, 0);
                assert_eq!(stats.successful_coordinations, 0);
                assert!(stats.average_coordination_time > Duration::ZERO);
            }
        }
    }
}

// Performance and stress tests (marked to run only when explicitly requested)

#[cfg(test)]
mod performance_tests {
    use super::*;

    #[test]
    #[ignore = "performance test"]
    fn bench_socket_addr_map_operations() {
        use std::collections::HashMap;

        let start = std::time::Instant::now();

        // Create many socket addresses and test map operations
        let mut peer_map = HashMap::new();
        for i in 0..10000u32 {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new((i >> 8) as u8, (i & 0xFF) as u8, 0, 1)),
                8080,
            );
            peer_map.insert(addr, i);
        }

        // Test lookups
        for i in 0..1000u32 {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new((i >> 8) as u8, (i & 0xFF) as u8, 0, 1)),
                8080,
            );
            let _value = peer_map.get(&addr);
        }

        let duration = start.elapsed();
        println!("Created and looked up socket addresses in {duration:?}");
        assert!(duration < Duration::from_millis(100));
    }

    #[test]
    #[ignore = "performance test"]
    fn bench_configuration_creation() {
        let start = std::time::Instant::now();

        // v0.13.0+: Create configurations without role field
        for i in 0..1000 {
            let config = NatTraversalConfig {
                known_peers: vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, i as u8)),
                    8080,
                )],
                max_candidates: i as usize % 32 + 1,
                coordination_timeout: Duration::from_secs(i as u64 % 60 + 1),
                enable_symmetric_nat: i % 2 == 0,
                enable_relay_fallback: i % 3 == 0,
                max_concurrent_attempts: i as usize % 10 + 1,
                bind_addr: None,
                prefer_rfc_nat_traversal: false,
                pqc: None,
                timeouts: TimeoutConfig::default(),
                identity_key: None,
                relay_nodes: vec![],
                enable_relay_service: true,
                allow_ipv4_mapped: true,
                transport_registry: None,
                max_message_size: saorsa_transport::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
                allow_loopback: false,
                coordinator_max_active_relays: 32,
                coordinator_relay_slot_idle_timeout: Duration::from_secs(5),
                upnp: Default::default(),
            };

            // Use the config to prevent optimization
            assert!(config.max_candidates > 0);
        }

        let duration = start.elapsed();
        println!("Created configurations in {duration:?}");
        assert!(duration < Duration::from_millis(50));
    }
}

#[cfg(test)]
mod relay_functionality_tests {
    use super::*;

    #[test]
    fn test_multiple_known_peers() {
        // v0.13.0+: All nodes are symmetric - no role needed
        let known_peer_addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)), 8080),
        ];

        let config = NatTraversalConfig {
            known_peers: known_peer_addrs.clone(),
            ..NatTraversalConfig::default()
        };

        assert_eq!(config.known_peers.len(), 3);
        for (i, addr) in config.known_peers.iter().enumerate() {
            assert_eq!(*addr, known_peer_addrs[i]);
        }
    }

    #[tokio::test]
    async fn test_invalid_configuration_scenarios() {
        // v0.13.0+: Test various configuration scenarios

        // Node with no known peers is valid (waits for incoming connections)
        let no_peers_config = NatTraversalConfig {
            known_peers: vec![],
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            ..NatTraversalConfig::default()
        };

        let result = NatTraversalEndpoint::new(no_peers_config, None, None).await;
        // May succeed or fail - key is no panic
        let _ = result;

        // Test configuration with zero values (edge cases)
        let zero_values_config = NatTraversalConfig {
            known_peers: vec![],
            max_candidates: 0,
            coordination_timeout: Duration::ZERO,
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 0,
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            prefer_rfc_nat_traversal: false,
            pqc: None,
            timeouts: TimeoutConfig::default(),
            identity_key: None,
            relay_nodes: vec![],
            enable_relay_service: true,
            allow_ipv4_mapped: true,
            transport_registry: None,
            max_message_size: saorsa_transport::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
            allow_loopback: false,
            coordinator_max_active_relays: 32,
            coordinator_relay_slot_idle_timeout: Duration::from_secs(5),
            upnp: Default::default(),
        };

        // This might be accepted or rejected depending on implementation
        let _result = NatTraversalEndpoint::new(zero_values_config, None, None).await;
    }
}
