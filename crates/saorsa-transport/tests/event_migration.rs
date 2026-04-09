// Copyright 2024 Saorsa Labs Ltd.
// Licensed under GPL v3. See LICENSE-GPL.

//! Event Address Migration Integration Tests (Phase 2.2 Task 9)
//!
//! End-to-end tests for event address migration from SocketAddr to TransportAddr.
//! Validates the entire event pipeline with new address types.

use saorsa_transport::transport::TransportAddr;
use saorsa_transport::{P2pConfig, P2pEndpoint, P2pEvent};

/// Default BLE L2CAP PSM (Protocol/Service Multiplexer) value.
/// Defined locally because the canonical constant is behind the `ble` feature gate.
const DEFAULT_BLE_L2CAP_PSM: u16 = 0x0080;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

/// Test that P2pEndpoint emits events with TransportAddr
#[tokio::test]
async fn test_event_pipeline_uses_transport_addr() {
    // Create endpoint
    let config = P2pConfig::builder()
        .fast_timeouts()
        .build()
        .expect("valid config");

    let endpoint = match P2pEndpoint::new(config).await {
        Ok(ep) => ep,
        Err(_) => {
            // Skip test if endpoint creation fails (e.g., no network)
            return;
        }
    };

    // Subscribe to events
    let mut events = endpoint.subscribe();

    // The subscription channel is set up - verify we can receive events
    // In a real scenario, connecting to a peer would generate PeerConnected events
    // For now, verify the channel is working and event types are correct

    // Drop endpoint to trigger shutdown (which may emit events)
    endpoint.shutdown().await;

    // Verify we can receive any events that were emitted
    // This tests that the event system works with TransportAddr
    while let Ok(result) = timeout(Duration::from_millis(100), events.recv()).await {
        if let Ok(event) = result {
            // All events should be valid P2pEvent variants
            match event {
                P2pEvent::PeerConnected { addr, .. } => {
                    // Verify addr is TransportAddr
                    let _: TransportAddr = addr;
                }
                P2pEvent::ExternalAddressDiscovered { addr } => {
                    // Verify addr is TransportAddr
                    let _: TransportAddr = addr;
                }
                _ => {} // Other events don't have addresses
            }
        }
    }
}

/// Test PeerConnected event construction with UDP transport
#[test]
fn test_peer_connected_event_construction_udp() {
    let socket_addr: SocketAddr = "192.168.1.100:9000".parse().expect("valid addr");
    let test_public_key: Vec<u8> = vec![0x42; 32];

    // Construct event as would happen in P2pEndpoint
    let event = P2pEvent::PeerConnected {
        addr: TransportAddr::Udp(socket_addr),
        public_key: Some(test_public_key.clone()),
        side: saorsa_transport::Side::Client,
    };

    // Verify we can destructure it correctly
    if let P2pEvent::PeerConnected {
        addr,
        public_key,
        side,
    } = event
    {
        assert_eq!(public_key.unwrap(), test_public_key);
        assert_eq!(addr, TransportAddr::Udp(socket_addr));
        assert!(side.is_client());

        // Verify backward compatibility via as_socket_addr()
        let extracted = addr.as_socket_addr();
        assert_eq!(extracted, Some(socket_addr));
    } else {
        panic!("Expected PeerConnected event");
    }
}

/// Test ExternalAddressDiscovered event construction with UDP transport
#[test]
fn test_external_address_discovered_event_construction() {
    let socket_addr: SocketAddr = "203.0.113.50:12345".parse().expect("valid addr");

    // Construct event as would happen in P2pEndpoint
    let event = P2pEvent::ExternalAddressDiscovered {
        addr: TransportAddr::Udp(socket_addr),
    };

    // Verify we can destructure it correctly
    if let P2pEvent::ExternalAddressDiscovered { addr } = event {
        assert_eq!(addr, TransportAddr::Udp(socket_addr));

        // Verify backward compatibility
        let extracted = addr.as_socket_addr();
        assert_eq!(extracted, Some(socket_addr));
    } else {
        panic!("Expected ExternalAddressDiscovered event");
    }
}

/// Test that events can be cloned (required for broadcast channel)
#[test]
fn test_event_clone_for_broadcast() {
    let socket_addr: SocketAddr = "10.0.0.1:8080".parse().expect("valid addr");

    let original = P2pEvent::PeerConnected {
        addr: TransportAddr::Udp(socket_addr),
        public_key: Some(vec![0xaa; 32]),
        side: saorsa_transport::Side::Server,
    };

    // Clone is required for broadcast channel
    let cloned = original.clone();

    // Both should be identical
    match (&original, &cloned) {
        (
            P2pEvent::PeerConnected {
                addr: a1,
                public_key: pk1,
                side: s1,
            },
            P2pEvent::PeerConnected {
                addr: a2,
                public_key: pk2,
                side: s2,
            },
        ) => {
            assert_eq!(pk1, pk2);
            assert_eq!(a1, a2);
            assert_eq!(s1, s2);
        }
        _ => panic!("Events should both be PeerConnected"),
    }
}

/// Test events with different transport types can coexist
#[test]
fn test_multi_transport_events() {
    let udp_addr: SocketAddr = "192.168.1.1:9000".parse().expect("valid addr");
    let ble_device = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];

    // UDP event
    let udp_event = P2pEvent::PeerConnected {
        addr: TransportAddr::Udp(udp_addr),
        public_key: Some(vec![0x01; 32]),
        side: saorsa_transport::Side::Client,
    };

    // BLE event
    let ble_event = P2pEvent::PeerConnected {
        addr: TransportAddr::Ble {
            mac: ble_device,
            psm: DEFAULT_BLE_L2CAP_PSM,
        },
        public_key: Some(vec![0x02; 32]),
        side: saorsa_transport::Side::Server,
    };

    // Verify we can distinguish between them
    if let P2pEvent::PeerConnected { addr: udp, .. } = udp_event {
        assert!(
            udp.as_socket_addr().is_some(),
            "UDP should have socket addr"
        );
    }

    if let P2pEvent::PeerConnected { addr: ble, .. } = ble_event {
        assert!(
            ble.as_socket_addr().is_none(),
            "BLE should not have socket addr"
        );
    }
}

/// Test event pattern matching for transport-aware handlers
#[test]
fn test_transport_aware_event_handling() {
    let events = vec![
        P2pEvent::PeerConnected {
            addr: TransportAddr::Udp("10.0.0.1:8080".parse().expect("valid")),
            public_key: Some(vec![0x01; 32]),
            side: saorsa_transport::Side::Client,
        },
        P2pEvent::PeerConnected {
            addr: TransportAddr::Ble {
                mac: [0xaa; 6],
                psm: DEFAULT_BLE_L2CAP_PSM,
            },
            public_key: Some(vec![0x02; 32]),
            side: saorsa_transport::Side::Server,
        },
        P2pEvent::ExternalAddressDiscovered {
            addr: TransportAddr::Udp("203.0.113.1:9000".parse().expect("valid")),
        },
    ];

    let mut udp_connections = 0;
    let mut ble_connections = 0;
    let mut addresses_discovered = 0;

    for event in events {
        match event {
            P2pEvent::PeerConnected { addr, .. } => match addr {
                TransportAddr::Udp(_) => udp_connections += 1,
                TransportAddr::Ble { .. } => ble_connections += 1,
                _ => {}
            },
            P2pEvent::ExternalAddressDiscovered { .. } => {
                addresses_discovered += 1;
            }
            _ => {}
        }
    }

    assert_eq!(udp_connections, 1);
    assert_eq!(ble_connections, 1);
    assert_eq!(addresses_discovered, 1);
}

/// Test backward compatibility - code expecting SocketAddr can still work
#[test]
fn test_backward_compatibility_with_as_socket_addr() {
    let socket_addr: SocketAddr = "172.16.0.1:5000".parse().expect("valid addr");

    let event = P2pEvent::PeerConnected {
        addr: TransportAddr::Udp(socket_addr),
        public_key: Some(vec![0xff; 32]),
        side: saorsa_transport::Side::Client,
    };

    // Simulate legacy code that expects SocketAddr
    if let P2pEvent::PeerConnected { addr, .. } = event {
        // Legacy code path: extract SocketAddr
        if let Some(legacy_addr) = addr.as_socket_addr() {
            // Legacy code can work with SocketAddr as before
            assert_eq!(legacy_addr.ip().to_string(), "172.16.0.1");
            assert_eq!(legacy_addr.port(), 5000);
        } else {
            // Handle non-UDP transports gracefully
            panic!("Expected UDP transport in this test");
        }
    }
}

/// Test that TransportAddr::Udp wrapping is idempotent
#[test]
fn test_transport_addr_udp_wrapping() {
    let socket_addr1: SocketAddr = "1.2.3.4:5678".parse().expect("valid addr");
    let socket_addr2: SocketAddr = "1.2.3.4:5678".parse().expect("valid addr");

    let transport1 = TransportAddr::Udp(socket_addr1);
    let transport2 = TransportAddr::Udp(socket_addr2);

    // Same address should produce equal TransportAddr
    assert_eq!(transport1, transport2);

    // Should have same hash (for HashMap usage)
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    transport1.hash(&mut h1);
    transport2.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

/// Test event debug formatting includes transport info
#[test]
fn test_event_debug_formatting() {
    let event = P2pEvent::PeerConnected {
        addr: TransportAddr::Udp("192.168.0.100:9001".parse().expect("valid")),
        public_key: Some(vec![0x55; 32]),
        side: saorsa_transport::Side::Client,
    };

    let debug = format!("{:?}", event);

    // Should contain IP and port
    assert!(debug.contains("192.168.0.100"), "Debug should contain IP");
    assert!(debug.contains("9001"), "Debug should contain port");
    assert!(debug.contains("Client"), "Debug should contain side");
}
