// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Integration tests for multi-transport address advertisements
//!
//! This test module verifies the ADD_ADDRESS frame extensions for multi-transport support:
//! - Transport type indicators in wire format
//! - Capability flags encoding and decoding
//! - Transport-aware candidate selection
//! - Backward compatibility with UDP-only peers

use bytes::BytesMut;
use saorsa_transport::coding::Codec;
use saorsa_transport::nat_traversal::CapabilityFlags;
use saorsa_transport::nat_traversal::frames::{AddAddress, PunchMeNow, RemoveAddress};
use saorsa_transport::transport::{TransportAddr, TransportCapabilities, TransportType};
use std::net::SocketAddr;

const DEFAULT_BLE_L2CAP_PSM: u16 = 0x0080;
const DEFAULT_LORA_FREQ_HZ: u32 = 868_000_000;

// ============ Wire Format Tests ============

#[test]
fn test_add_address_udp_wire_format() {
    // Test that UDP addresses encode correctly with transport type
    let socket_addr: SocketAddr = "192.168.1.100:9000".parse().unwrap();
    let frame = AddAddress::udp(42, 100, socket_addr);

    // Encode
    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    // Decode
    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.sequence, 42);
    assert_eq!(decoded.priority, 100);
    assert_eq!(decoded.transport_type, TransportType::Udp);
    assert_eq!(decoded.socket_addr(), Some(socket_addr));
    assert!(!decoded.has_capabilities()); // UDP default has no caps
}

#[test]
fn test_add_address_ble_wire_format() {
    let mac = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    let frame = AddAddress::new(
        10,
        200,
        TransportAddr::Ble {
            mac,
            psm: DEFAULT_BLE_L2CAP_PSM,
        },
    );

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.sequence, 10);
    assert_eq!(decoded.priority, 200);
    assert_eq!(decoded.transport_type, TransportType::Ble);
    assert_eq!(decoded.socket_addr(), None); // BLE has no socket addr

    if let TransportAddr::Ble {
        mac: decoded_mac,
        psm,
    } = decoded.address
    {
        assert_eq!(decoded_mac, mac);
        assert_eq!(psm, DEFAULT_BLE_L2CAP_PSM);
    } else {
        panic!("Expected BLE address");
    }
}

#[test]
fn test_add_address_lora_wire_format() {
    let dev_addr = [0xDE, 0xAD, 0xBE, 0xEF];
    let frame = AddAddress::new(
        99,
        500,
        TransportAddr::LoRa {
            dev_addr,
            freq_hz: DEFAULT_LORA_FREQ_HZ,
        },
    );

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.sequence, 99);
    assert_eq!(decoded.transport_type, TransportType::LoRa);

    if let TransportAddr::LoRa {
        dev_addr: decoded_addr,
        freq_hz,
    } = decoded.address
    {
        assert_eq!(decoded_addr, dev_addr);
        assert_eq!(freq_hz, DEFAULT_LORA_FREQ_HZ);
    } else {
        panic!("Expected LoRa address");
    }
}

#[test]
fn test_add_address_serial_wire_format() {
    let frame = AddAddress::new(
        7,
        50,
        TransportAddr::Serial {
            port: "/dev/ttyUSB0".to_string(),
        },
    );

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.sequence, 7);
    assert_eq!(decoded.transport_type, TransportType::Serial);

    if let TransportAddr::Serial { port } = decoded.address {
        assert_eq!(port, "/dev/ttyUSB0");
    } else {
        panic!("Expected Serial address");
    }
}

// ============ Capability Flags Tests ============

#[test]
fn test_capability_flags_broadband() {
    let flags = CapabilityFlags::broadband();

    assert!(flags.supports_full_quic());
    assert!(flags.broadcast());
    assert!(!flags.half_duplex());
    assert!(!flags.metered());
    assert!(!flags.power_constrained());
    assert_eq!(flags.mtu_tier(), 2); // 1200-4096
    assert_eq!(flags.bandwidth_tier(), 3); // High
    assert_eq!(flags.latency_tier(), 3); // <100ms
}

#[test]
fn test_capability_flags_ble() {
    let flags = CapabilityFlags::ble();

    assert!(!flags.supports_full_quic());
    assert!(flags.broadcast());
    assert!(flags.power_constrained());
    assert!(flags.link_layer_acks());
    assert_eq!(flags.mtu_tier(), 0); // <500
    assert_eq!(flags.bandwidth_tier(), 2); // Medium
    assert_eq!(flags.latency_tier(), 2); // 100-500ms
}

#[test]
fn test_capability_flags_lora() {
    let flags = CapabilityFlags::lora_long_range();

    assert!(!flags.supports_full_quic());
    assert!(flags.half_duplex());
    assert!(flags.broadcast());
    assert!(flags.power_constrained());
    assert_eq!(flags.mtu_tier(), 0); // <500
    assert_eq!(flags.bandwidth_tier(), 0); // VeryLow
    assert_eq!(flags.latency_tier(), 0); // >2s
}

#[test]
fn test_capability_flags_from_transport_capabilities() {
    let caps = TransportCapabilities::broadband();
    let flags = CapabilityFlags::from_capabilities(&caps);

    assert!(flags.supports_full_quic());
    assert!(!flags.half_duplex());
    assert!(flags.broadcast());
    assert!(!flags.metered());
    assert!(!flags.power_constrained());
    assert_eq!(flags.bandwidth_tier(), 3); // High

    let caps = TransportCapabilities::ble();
    let flags = CapabilityFlags::from_capabilities(&caps);

    assert!(!flags.supports_full_quic()); // MTU too small
    assert!(flags.power_constrained());
    assert!(flags.link_layer_acks());
}

// ============ Frame with Capabilities Tests ============

#[test]
fn test_add_address_with_capabilities_roundtrip() {
    let socket_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
    let caps = CapabilityFlags::broadband();
    let frame = AddAddress::with_capabilities(42, 100, TransportAddr::Udp(socket_addr), caps);

    assert!(frame.has_capabilities());
    assert_eq!(frame.capability_flags(), Some(caps));
    assert_eq!(frame.supports_full_quic(), Some(true));

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.sequence, 42);
    assert!(decoded.has_capabilities());
    assert_eq!(decoded.capability_flags(), Some(caps));
    assert_eq!(decoded.supports_full_quic(), Some(true));
}

#[test]
fn test_add_address_ble_with_capabilities_roundtrip() {
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let caps = CapabilityFlags::ble();
    let frame = AddAddress::with_capabilities(
        5,
        300,
        TransportAddr::Ble {
            mac,
            psm: DEFAULT_BLE_L2CAP_PSM,
        },
        caps,
    );

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.transport_type, TransportType::Ble);
    assert!(decoded.has_capabilities());
    let flags = decoded.capability_flags().expect("expected flags");
    assert!(flags.power_constrained());
    assert_eq!(flags.mtu_tier(), 0);
}

#[test]
fn test_add_address_from_transport_capabilities() {
    let caps = TransportCapabilities::lora_long_range();
    let dev_addr = [0xDE, 0xAD, 0xBE, 0xEF];
    let frame = AddAddress::from_capabilities(
        10,
        200,
        TransportAddr::LoRa {
            dev_addr,
            freq_hz: DEFAULT_LORA_FREQ_HZ,
        },
        &caps,
    );

    assert!(frame.has_capabilities());
    // LoRa doesn't support full QUIC (MTU too small)
    assert_eq!(frame.supports_full_quic(), Some(false));

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert!(decoded.has_capabilities());
    let flags = decoded.capability_flags().expect("expected flags");
    assert!(!flags.supports_full_quic());
    assert!(flags.half_duplex());
    assert!(flags.power_constrained());
    assert_eq!(flags.latency_tier(), 0); // >2s RTT
}

// ============ Backward Compatibility Tests ============

#[test]
fn test_add_address_without_capabilities_backward_compat() {
    // Frames without capabilities should decode properly
    let socket_addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
    let frame = AddAddress::udp(1, 50, socket_addr);

    assert!(!frame.has_capabilities());
    assert_eq!(frame.capability_flags(), None);
    assert_eq!(frame.supports_full_quic(), None);

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert!(!decoded.has_capabilities());
}

// ============ Mixed Transport Tests ============

#[test]
fn test_multiple_transport_types_encoding() {
    // Test that we can encode multiple different transport types
    let transports = vec![
        AddAddress::udp(1, 100, "192.168.1.1:9000".parse().unwrap()),
        AddAddress::new(
            2,
            200,
            TransportAddr::Ble {
                mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                psm: DEFAULT_BLE_L2CAP_PSM,
            },
        ),
        AddAddress::new(
            3,
            150,
            TransportAddr::LoRa {
                dev_addr: [0xAB, 0xCD, 0xEF, 0x01],
                freq_hz: DEFAULT_LORA_FREQ_HZ,
            },
        ),
        AddAddress::new(
            4,
            50,
            TransportAddr::Serial {
                port: "/dev/ttyS0".to_string(),
            },
        ),
    ];

    for frame in transports {
        let mut buf = BytesMut::new();
        Codec::encode(&frame, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");
        assert_eq!(decoded.sequence, frame.sequence);
        assert_eq!(decoded.transport_type, frame.transport_type);
    }
}

// ============ PunchMeNow and RemoveAddress Tests ============

#[test]
fn test_punch_me_now_roundtrip() {
    let frame = PunchMeNow {
        round: 3,
        paired_with_sequence_number: 42,
        address: "192.168.1.100:9000".parse().unwrap(),
        target_peer_id: None,
    };

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = PunchMeNow::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.round, 3);
    assert_eq!(decoded.paired_with_sequence_number, 42);
    assert_eq!(decoded.address, frame.address);
    assert!(decoded.target_peer_id.is_none());
}

#[test]
fn test_punch_me_now_with_peer_id_roundtrip() {
    let peer_id = [0x42u8; 32];
    let frame = PunchMeNow {
        round: 5,
        paired_with_sequence_number: 10,
        address: "[::1]:9000".parse().unwrap(),
        target_peer_id: Some(peer_id),
    };

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = PunchMeNow::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.round, 5);
    assert_eq!(decoded.target_peer_id, Some(peer_id));
}

#[test]
fn test_remove_address_roundtrip() {
    let frame = RemoveAddress { sequence: 123 };

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = RemoveAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.sequence, 123);
}

// ============ Capability Score Tests ============

#[test]
fn test_capability_tiers() {
    // MTU tiers
    assert_eq!(
        CapabilityFlags::empty().with_mtu_tier(0).mtu_range(),
        (0, 499)
    );
    assert_eq!(
        CapabilityFlags::empty().with_mtu_tier(1).mtu_range(),
        (500, 1199)
    );
    assert_eq!(
        CapabilityFlags::empty().with_mtu_tier(2).mtu_range(),
        (1200, 4095)
    );
    assert_eq!(
        CapabilityFlags::empty().with_mtu_tier(3).mtu_range(),
        (4096, 65535)
    );

    // Latency tiers
    use std::time::Duration;
    let (min, max) = CapabilityFlags::empty()
        .with_latency_tier(3)
        .latency_range();
    assert_eq!(min, Duration::ZERO);
    assert_eq!(max, Duration::from_millis(100));

    let (min, _max) = CapabilityFlags::empty()
        .with_latency_tier(0)
        .latency_range();
    assert_eq!(min, Duration::from_secs(2));
}

#[test]
fn test_capability_builder() {
    let flags = CapabilityFlags::empty()
        .with_supports_full_quic(true)
        .with_broadcast(true)
        .with_mtu_tier(2)
        .with_bandwidth_tier(3)
        .with_latency_tier(3);

    assert!(flags.supports_full_quic());
    assert!(flags.broadcast());
    assert!(!flags.half_duplex());
    assert_eq!(flags.mtu_tier(), 2);
    assert_eq!(flags.bandwidth_tier(), 3);
    assert_eq!(flags.latency_tier(), 3);
}
