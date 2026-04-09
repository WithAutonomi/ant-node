// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Transport-specific addressing for multi-transport P2P networking
//!
//! This module defines [`TransportAddr`], a unified addressing type that supports
//! multiple physical transports including QUIC, TCP, Bluetooth, BLE, LoRa radio,
//! serial connections, and overlay networks.
//!
//! ## Canonical string format (multiaddr)
//!
//! ```text
//! /ip4/<ipv4>/udp/<port>/quic
//! /ip6/<ipv6>/udp/<port>/quic
//! /ip4/<ipv4>/tcp/<port>
//! /ip6/<ipv6>/tcp/<port>
//! /ip4/<ipv4>/udp/<port>
//! /ip6/<ipv6>/udp/<port>
//! /bt/<AA:BB:CC:DD:EE:FF>/rfcomm/<channel>
//! /ble/<AA:BB:CC:DD:EE:FF>/l2cap/<psm>
//! /lora/<hex-dev-addr>/<freq-hz>
//! /lorawan/<hex-dev-eui>
//! /serial/<port-name>
//! /ax25/<callsign>/<ssid>
//! /i2p/<hex-destination>
//! /yggdrasil/<hex-address>
//! /broadcast/<transport-type>
//! ```

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use anyhow::{Result, anyhow};

/// Transport type identifier for routing and capability matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// QUIC over UDP — primary Saorsa transport
    Quic,
    /// Plain TCP
    Tcp,
    /// Raw UDP (no QUIC)
    Udp,
    /// Classic Bluetooth RFCOMM
    Bluetooth,
    /// Bluetooth Low Energy — short-range, low-power wireless
    Ble,
    /// LoRa radio — long-range, low-bandwidth wireless
    LoRa,
    /// LoRaWAN (network-managed)
    LoRaWan,
    /// Serial port — direct wired connection
    Serial,
    /// AX.25 packet radio — amateur radio networks
    Ax25,
    /// I2P anonymous overlay network
    I2p,
    /// Yggdrasil mesh network
    Yggdrasil,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic => write!(f, "QUIC"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Bluetooth => write!(f, "Bluetooth"),
            Self::Ble => write!(f, "BLE"),
            Self::LoRa => write!(f, "LoRa"),
            Self::LoRaWan => write!(f, "LoRaWAN"),
            Self::Serial => write!(f, "Serial"),
            Self::Ax25 => write!(f, "AX.25"),
            Self::I2p => write!(f, "I2P"),
            Self::Yggdrasil => write!(f, "Yggdrasil"),
        }
    }
}

/// LoRa radio configuration parameters.
///
/// These are connection-time parameters, not part of the address. Use with
/// transport capability configuration when establishing LoRa links.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoRaParams {
    /// Spreading factor (7-12)
    pub spreading_factor: u8,
    /// Bandwidth in kHz (125, 250, or 500)
    pub bandwidth_khz: u16,
    /// Coding rate numerator (5-8 for 4/5 to 4/8)
    pub coding_rate: u8,
}

impl Default for LoRaParams {
    fn default() -> Self {
        Self {
            spreading_factor: 12, // Maximum range
            bandwidth_khz: 125,   // Standard narrow bandwidth
            coding_rate: 5,       // 4/5 coding (most efficient)
        }
    }
}

/// Transport-specific addressing.
///
/// A unified address type that can represent destinations on any supported
/// transport. Uses a canonical slash-delimited multiaddr string format.
///
/// # Example
///
/// ```rust
/// use saorsa_transport::transport::{TransportAddr, TransportType};
/// use std::net::SocketAddr;
///
/// // QUIC address (primary)
/// let quic_addr = TransportAddr::Quic("192.168.1.1:9000".parse().unwrap());
/// assert_eq!(quic_addr.transport_type(), TransportType::Quic);
/// assert_eq!(quic_addr.to_string(), "/ip4/192.168.1.1/udp/9000/quic");
///
/// // Parse from multiaddr string
/// let parsed: TransportAddr = "/ip4/10.0.0.1/tcp/8080".parse().unwrap();
/// assert_eq!(parsed.transport_type(), TransportType::Tcp);
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportAddr {
    /// QUIC over UDP (primary Saorsa transport).
    Quic(SocketAddr),

    /// Plain TCP.
    Tcp(SocketAddr),

    /// Raw UDP (no QUIC negotiation).
    Udp(SocketAddr),

    /// Classic Bluetooth RFCOMM.
    Bluetooth {
        /// 6-byte MAC address.
        mac: [u8; 6],
        /// RFCOMM channel number.
        channel: u8,
    },

    /// Bluetooth Low Energy L2CAP.
    Ble {
        /// 6-byte MAC address.
        mac: [u8; 6],
        /// Protocol/Service Multiplexer.
        psm: u16,
    },

    /// LoRa point-to-point.
    LoRa {
        /// 4-byte device address.
        dev_addr: [u8; 4],
        /// Frequency in Hz.
        freq_hz: u32,
    },

    /// LoRaWAN (network-managed).
    LoRaWan {
        /// 8-byte Device EUI.
        dev_eui: u64,
    },

    /// Serial port connection.
    Serial {
        /// Port name (e.g., "/dev/ttyUSB0", "COM3").
        port: String,
    },

    /// AX.25 packet radio (amateur radio).
    Ax25 {
        /// Amateur radio callsign.
        callsign: String,
        /// Secondary Station Identifier (0-15).
        ssid: u8,
    },

    /// I2P anonymous overlay network.
    I2p {
        /// I2P destination (387 bytes base64-decoded).
        destination: Box<[u8; 387]>,
    },

    /// Yggdrasil mesh network.
    Yggdrasil {
        /// 128-bit Yggdrasil address.
        address: [u8; 16],
    },

    /// Broadcast on a specific transport.
    Broadcast {
        /// Transport type to broadcast on.
        transport_type: TransportType,
    },
}

impl TransportAddr {
    /// Get the transport type for this address.
    pub fn transport_type(&self) -> TransportType {
        match self {
            Self::Quic(_) => TransportType::Quic,
            Self::Tcp(_) => TransportType::Tcp,
            Self::Udp(_) => TransportType::Udp,
            Self::Bluetooth { .. } => TransportType::Bluetooth,
            Self::Ble { .. } => TransportType::Ble,
            Self::LoRa { .. } => TransportType::LoRa,
            Self::LoRaWan { .. } => TransportType::LoRaWan,
            Self::Serial { .. } => TransportType::Serial,
            Self::Ax25 { .. } => TransportType::Ax25,
            Self::I2p { .. } => TransportType::I2p,
            Self::Yggdrasil { .. } => TransportType::Yggdrasil,
            Self::Broadcast { transport_type } => *transport_type,
        }
    }

    /// Create a BLE address.
    pub fn ble(mac: [u8; 6], psm: u16) -> Self {
        Self::Ble { mac, psm }
    }

    /// Create a LoRa address.
    pub fn lora(dev_addr: [u8; 4], freq_hz: u32) -> Self {
        Self::LoRa { dev_addr, freq_hz }
    }

    /// Create a serial port address.
    pub fn serial(port: impl Into<String>) -> Self {
        Self::Serial { port: port.into() }
    }

    /// Create an AX.25 address.
    pub fn ax25(callsign: impl Into<String>, ssid: u8) -> Self {
        Self::Ax25 {
            callsign: callsign.into(),
            ssid: ssid.min(15), // SSID is 0-15
        }
    }

    /// Create a Yggdrasil address.
    pub fn yggdrasil(address: [u8; 16]) -> Self {
        Self::Yggdrasil { address }
    }

    /// Create a broadcast address for a specific transport.
    pub fn broadcast(transport_type: TransportType) -> Self {
        Self::Broadcast { transport_type }
    }

    /// Check if this is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast { .. })
    }

    /// Returns the socket address for IP-based transports (`Quic`, `Tcp`, `Udp`),
    /// `None` for non-IP transports.
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Quic(a) | Self::Tcp(a) | Self::Udp(a) => Some(*a),
            _ => None,
        }
    }

    /// Human-readable transport kind for logging / metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Quic(_) => "quic",
            Self::Tcp(_) => "tcp",
            Self::Udp(_) => "udp",
            Self::Bluetooth { .. } => "bluetooth",
            Self::Ble { .. } => "ble",
            Self::LoRa { .. } => "lora",
            Self::LoRaWan { .. } => "lorawan",
            Self::Serial { .. } => "serial",
            Self::Ax25 { .. } => "ax25",
            Self::I2p { .. } => "i2p",
            Self::Yggdrasil { .. } => "yggdrasil",
            Self::Broadcast { .. } => "broadcast",
        }
    }

    /// Convert this transport address to a synthetic `SocketAddr` for internal
    /// tracking.
    ///
    /// For IP-based addresses (`Quic`, `Tcp`, `Udp`), returns the actual socket
    /// address. For non-IP addresses, creates a synthetic IPv6 address in the
    /// documentation range (`2001:db8::/32`) that uniquely identifies the
    /// transport endpoint.
    pub fn to_synthetic_socket_addr(&self) -> SocketAddr {
        match self {
            Self::Quic(addr) | Self::Tcp(addr) | Self::Udp(addr) => *addr,
            Self::Bluetooth { mac, channel } => {
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0007, // Transport type 7 = Bluetooth
                    ((mac[0] as u16) << 8) | (mac[1] as u16),
                    ((mac[2] as u16) << 8) | (mac[3] as u16),
                    ((mac[4] as u16) << 8) | (mac[5] as u16),
                    *channel as u16,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Ble { mac, psm } => {
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0001, // Transport type 1 = BLE
                    ((mac[0] as u16) << 8) | (mac[1] as u16),
                    ((mac[2] as u16) << 8) | (mac[3] as u16),
                    ((mac[4] as u16) << 8) | (mac[5] as u16),
                    *psm,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::LoRa { dev_addr, .. } => {
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0002, // Transport type 2 = LoRa
                    ((dev_addr[0] as u16) << 8) | (dev_addr[1] as u16),
                    ((dev_addr[2] as u16) << 8) | (dev_addr[3] as u16),
                    0,
                    0,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::LoRaWan { dev_eui } => {
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0008, // Transport type 8 = LoRaWAN
                    (*dev_eui >> 48) as u16,
                    (*dev_eui >> 32) as u16,
                    (*dev_eui >> 16) as u16,
                    *dev_eui as u16,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Serial { port } => {
                let mut hasher = DefaultHasher::new();
                port.hash(&mut hasher);
                let hash = hasher.finish();
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0003, // Transport type 3 = Serial
                    (hash >> 48) as u16,
                    (hash >> 32) as u16,
                    (hash >> 16) as u16,
                    hash as u16,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Ax25 { callsign, ssid } => {
                let mut hasher = DefaultHasher::new();
                callsign.hash(&mut hasher);
                ssid.hash(&mut hasher);
                let hash = hasher.finish();
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0004, // Transport type 4 = AX.25
                    (hash >> 48) as u16,
                    (hash >> 32) as u16,
                    (hash >> 16) as u16,
                    hash as u16,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::I2p { destination } => {
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0005, // Transport type 5 = I2P
                    ((destination[0] as u16) << 8) | (destination[1] as u16),
                    ((destination[2] as u16) << 8) | (destination[3] as u16),
                    ((destination[4] as u16) << 8) | (destination[5] as u16),
                    ((destination[6] as u16) << 8) | (destination[7] as u16),
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Yggdrasil { address } => {
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0006, // Transport type 6 = Yggdrasil
                    ((address[0] as u16) << 8) | (address[1] as u16),
                    ((address[2] as u16) << 8) | (address[3] as u16),
                    ((address[4] as u16) << 8) | (address[5] as u16),
                    ((address[6] as u16) << 8) | (address[7] as u16),
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Broadcast { transport_type } => {
                let type_code = match transport_type {
                    TransportType::Quic => 0x0000,
                    TransportType::Tcp => 0x0009,
                    TransportType::Udp => 0x000A,
                    TransportType::Bluetooth => 0x0007,
                    TransportType::Ble => 0x0001,
                    TransportType::LoRa => 0x0002,
                    TransportType::LoRaWan => 0x0008,
                    TransportType::Serial => 0x0003,
                    TransportType::Ax25 => 0x0004,
                    TransportType::I2p => 0x0005,
                    TransportType::Yggdrasil => 0x0006,
                };
                let addr = Ipv6Addr::new(
                    0x2001, 0x0db8, type_code, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Display — canonical multiaddr format
// ---------------------------------------------------------------------------

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic(addr) => match addr.ip() {
                IpAddr::V4(ip) => write!(f, "/ip4/{}/udp/{}/quic", ip, addr.port()),
                IpAddr::V6(ip) => write!(f, "/ip6/{}/udp/{}/quic", ip, addr.port()),
            },
            Self::Tcp(addr) => match addr.ip() {
                IpAddr::V4(ip) => write!(f, "/ip4/{}/tcp/{}", ip, addr.port()),
                IpAddr::V6(ip) => write!(f, "/ip6/{}/tcp/{}", ip, addr.port()),
            },
            Self::Udp(addr) => match addr.ip() {
                IpAddr::V4(ip) => write!(f, "/ip4/{}/udp/{}", ip, addr.port()),
                IpAddr::V6(ip) => write!(f, "/ip6/{}/udp/{}", ip, addr.port()),
            },
            Self::Bluetooth { mac, channel } => {
                write!(
                    f,
                    "/bt/{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}/rfcomm/{}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], channel
                )
            }
            Self::Ble { mac, psm } => {
                write!(
                    f,
                    "/ble/{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}/l2cap/{}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], psm
                )
            }
            Self::LoRa { dev_addr, freq_hz } => {
                write!(
                    f,
                    "/lora/{:02x}{:02x}{:02x}{:02x}/{}",
                    dev_addr[0], dev_addr[1], dev_addr[2], dev_addr[3], freq_hz
                )
            }
            Self::LoRaWan { dev_eui } => {
                write!(f, "/lorawan/{:016x}", dev_eui)
            }
            Self::Serial { port } => {
                // Percent-encode forward slashes in port names.
                let encoded = port.replace('/', "%2F");
                write!(f, "/serial/{}", encoded)
            }
            Self::Ax25 { callsign, ssid } => {
                write!(f, "/ax25/{}/{}", callsign, ssid)
            }
            Self::I2p { destination } => {
                let hex: String = destination.iter().map(|b| format!("{:02x}", b)).collect();
                write!(f, "/i2p/{}", hex)
            }
            Self::Yggdrasil { address } => {
                let hex: String = address.iter().map(|b| format!("{:02x}", b)).collect();
                write!(f, "/yggdrasil/{}", hex)
            }
            Self::Broadcast { transport_type } => {
                let kind = match transport_type {
                    TransportType::Quic => "quic",
                    TransportType::Tcp => "tcp",
                    TransportType::Udp => "udp",
                    TransportType::Bluetooth => "bluetooth",
                    TransportType::Ble => "ble",
                    TransportType::LoRa => "lora",
                    TransportType::LoRaWan => "lorawan",
                    TransportType::Serial => "serial",
                    TransportType::Ax25 => "ax25",
                    TransportType::I2p => "i2p",
                    TransportType::Yggdrasil => "yggdrasil",
                };
                write!(f, "/broadcast/{}", kind)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Debug — human-friendly format
// ---------------------------------------------------------------------------

impl fmt::Debug for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic(addr) => write!(f, "Quic({addr})"),
            Self::Tcp(addr) => write!(f, "Tcp({addr})"),
            Self::Udp(addr) => write!(f, "Udp({addr})"),
            Self::Bluetooth { mac, channel } => {
                write!(
                    f,
                    "Bluetooth({:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, ch{})",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], channel
                )
            }
            Self::Ble { mac, psm } => {
                write!(
                    f,
                    "Ble({:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, psm{})",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], psm
                )
            }
            Self::LoRa { dev_addr, freq_hz } => {
                write!(
                    f,
                    "LoRa(0x{:02X}{:02X}{:02X}{:02X}, {}Hz)",
                    dev_addr[0], dev_addr[1], dev_addr[2], dev_addr[3], freq_hz
                )
            }
            Self::LoRaWan { dev_eui } => write!(f, "LoRaWan(0x{:016X})", dev_eui),
            Self::Serial { port } => write!(f, "Serial({port})"),
            Self::Ax25 { callsign, ssid } => write!(f, "Ax25({callsign}-{ssid})"),
            Self::I2p { .. } => write!(f, "I2p([destination])"),
            Self::Yggdrasil { address } => {
                write!(f, "Yggdrasil({:02x}{:02x}:...)", address[0], address[1])
            }
            Self::Broadcast { transport_type } => write!(f, "Broadcast({transport_type})"),
        }
    }
}

// ---------------------------------------------------------------------------
// FromStr — canonical multiaddr format
// ---------------------------------------------------------------------------

impl FromStr for TransportAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Err(anyhow!("Invalid address format: {}", s));
        }

        match parts[0] {
            "ip4" | "ip6" => parse_ip_addr(&parts, s),
            "bt" => parse_bluetooth(&parts, s),
            "ble" => parse_ble(&parts, s),
            "lora" => parse_lora(&parts, s),
            "lorawan" => parse_lorawan(&parts, s),
            "serial" => parse_serial(&parts, s),
            "ax25" => parse_ax25(&parts, s),
            "i2p" => parse_i2p(&parts, s),
            "yggdrasil" => parse_yggdrasil(&parts, s),
            "broadcast" => parse_broadcast(&parts, s),
            _ => Err(anyhow!("Unknown address scheme '{}' in: {}", parts[0], s)),
        }
    }
}

/// Parse `/ip4/...` or `/ip6/...` addresses.
fn parse_ip_addr(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 4 {
        return Err(anyhow!("Invalid IP address format: {}", original));
    }

    let ip: IpAddr = parts[1]
        .parse()
        .map_err(|_| anyhow!("Invalid IP address: {}", parts[1]))?;

    // Validate ip4/ip6 matches actual address type.
    match (parts[0], &ip) {
        ("ip4", IpAddr::V4(_)) | ("ip6", IpAddr::V6(_)) => {}
        _ => return Err(anyhow!("IP version mismatch in: {}", original)),
    }

    let proto = parts[2];
    let port: u16 = parts[3]
        .parse()
        .map_err(|_| anyhow!("Invalid port: {}", parts[3]))?;
    let addr = SocketAddr::new(ip, port);

    match proto {
        "tcp" => {
            if parts.len() > 4 {
                return Err(anyhow!(
                    "Unexpected trailing components after TCP address: {}",
                    original
                ));
            }
            Ok(TransportAddr::Tcp(addr))
        }
        "udp" => {
            if parts.len() >= 5 && parts[4] == "quic" {
                if parts.len() > 5 {
                    return Err(anyhow!(
                        "Unexpected trailing components after QUIC address: {}",
                        original
                    ));
                }
                Ok(TransportAddr::Quic(addr))
            } else if parts.len() == 4 {
                Ok(TransportAddr::Udp(addr))
            } else {
                Err(anyhow!("Invalid UDP address suffix in: {}", original))
            }
        }
        _ => Err(anyhow!(
            "Unsupported IP protocol '{}' in: {}",
            proto,
            original
        )),
    }
}

/// Parse `/bt/<MAC>/rfcomm/<channel>`.
fn parse_bluetooth(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 4 || parts[2] != "rfcomm" {
        return Err(anyhow!("Invalid Bluetooth address: {}", original));
    }
    let mac = parse_mac(parts[1])?;
    let channel: u8 = parts[3]
        .parse()
        .map_err(|_| anyhow!("Invalid RFCOMM channel: {}", parts[3]))?;
    Ok(TransportAddr::Bluetooth { mac, channel })
}

/// Parse `/ble/<MAC>/l2cap/<psm>`.
fn parse_ble(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 4 || parts[2] != "l2cap" {
        return Err(anyhow!("Invalid BLE address: {}", original));
    }
    let mac = parse_mac(parts[1])?;
    let psm: u16 = parts[3]
        .parse()
        .map_err(|_| anyhow!("Invalid L2CAP PSM: {}", parts[3]))?;
    Ok(TransportAddr::Ble { mac, psm })
}

/// Parse `/lora/<hex-dev-addr>/<freq-hz>`.
fn parse_lora(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 3 {
        return Err(anyhow!("Invalid LoRa address: {}", original));
    }
    let hex = parts[1];
    if hex.len() != 8 {
        return Err(anyhow!(
            "Invalid LoRa dev_addr (expected 8 hex chars): {}",
            hex
        ));
    }
    let val =
        u32::from_str_radix(hex, 16).map_err(|_| anyhow!("Invalid LoRa dev_addr hex: {}", hex))?;
    let dev_addr = val.to_be_bytes();
    let freq_hz: u32 = parts[2]
        .parse()
        .map_err(|_| anyhow!("Invalid LoRa freq_hz: {}", parts[2]))?;
    Ok(TransportAddr::LoRa { dev_addr, freq_hz })
}

/// Parse `/lorawan/<hex-dev-eui>`.
fn parse_lorawan(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 2 {
        return Err(anyhow!("Invalid LoRaWAN address: {}", original));
    }
    let dev_eui = u64::from_str_radix(parts[1], 16)
        .map_err(|_| anyhow!("Invalid LoRaWAN dev_eui hex: {}", parts[1]))?;
    Ok(TransportAddr::LoRaWan { dev_eui })
}

/// Parse `/serial/<port-name>` (percent-encoded slashes).
fn parse_serial(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 2 {
        return Err(anyhow!("Invalid serial address: {}", original));
    }
    // Rejoin remaining parts (they were split on '/') and decode percent-encoding.
    let raw = parts[1..].join("/");
    let port = raw.replace("%2F", "/").replace("%2f", "/");
    Ok(TransportAddr::Serial { port })
}

/// Parse `/ax25/<callsign>/<ssid>`.
fn parse_ax25(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 3 {
        return Err(anyhow!("Invalid AX.25 address: {}", original));
    }
    let callsign = parts[1].to_string();
    let ssid: u8 = parts[2]
        .parse()
        .map_err(|_| anyhow!("Invalid AX.25 SSID: {}", parts[2]))?;
    Ok(TransportAddr::Ax25 {
        callsign,
        ssid: ssid.min(15),
    })
}

/// Parse `/i2p/<hex-destination>`.
fn parse_i2p(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 2 {
        return Err(anyhow!("Invalid I2P address: {}", original));
    }
    let hex = parts[1];
    let expected_hex_len = 387 * 2; // 774 hex chars
    if hex.len() != expected_hex_len {
        return Err(anyhow!(
            "Invalid I2P destination length: expected {} hex chars, got {}",
            expected_hex_len,
            hex.len()
        ));
    }
    let mut dest = [0u8; 387];
    for i in 0..387 {
        dest[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("Invalid I2P hex at position {}: {}", i * 2, hex))?;
    }
    Ok(TransportAddr::I2p {
        destination: Box::new(dest),
    })
}

/// Parse `/yggdrasil/<hex-address>`.
fn parse_yggdrasil(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 2 {
        return Err(anyhow!("Invalid Yggdrasil address: {}", original));
    }
    let hex = parts[1];
    if hex.len() != 32 {
        return Err(anyhow!(
            "Invalid Yggdrasil address (expected 32 hex chars): {}",
            hex
        ));
    }
    let mut address = [0u8; 16];
    for i in 0..16 {
        address[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("Invalid Yggdrasil hex at position {}: {}", i * 2, hex))?;
    }
    Ok(TransportAddr::Yggdrasil { address })
}

/// Parse `/broadcast/<transport-type>`.
fn parse_broadcast(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < 2 {
        return Err(anyhow!("Invalid broadcast address: {}", original));
    }
    let transport_type = match parts[1] {
        "quic" => TransportType::Quic,
        "tcp" => TransportType::Tcp,
        "udp" => TransportType::Udp,
        "bluetooth" => TransportType::Bluetooth,
        "ble" => TransportType::Ble,
        "lora" => TransportType::LoRa,
        "lorawan" => TransportType::LoRaWan,
        "serial" => TransportType::Serial,
        "ax25" => TransportType::Ax25,
        "i2p" => TransportType::I2p,
        "yggdrasil" => TransportType::Yggdrasil,
        _ => {
            return Err(anyhow!(
                "Unknown broadcast transport '{}' in: {}",
                parts[1],
                original
            ));
        }
    };
    Ok(TransportAddr::Broadcast { transport_type })
}

/// Parse a colon-separated MAC address string into 6 bytes.
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow!("Invalid MAC address (expected 6 octets): {}", s));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| anyhow!("Invalid MAC octet '{}' in: {}", part, s))?;
    }
    Ok(mac)
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

/// Convert a `SocketAddr` into a `TransportAddr::Quic` (the primary transport).
impl From<SocketAddr> for TransportAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Quic(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_quic_addr() {
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let transport_addr = TransportAddr::Quic(addr);

        assert_eq!(transport_addr.transport_type(), TransportType::Quic);
        assert_eq!(transport_addr.as_socket_addr(), Some(addr));
        assert!(!transport_addr.is_broadcast());
    }

    #[test]
    fn test_tcp_addr() {
        let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let transport_addr = TransportAddr::Tcp(addr);

        assert_eq!(transport_addr.transport_type(), TransportType::Tcp);
        assert_eq!(transport_addr.as_socket_addr(), Some(addr));
    }

    #[test]
    fn test_udp_addr() {
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let transport_addr = TransportAddr::Udp(addr);

        assert_eq!(transport_addr.transport_type(), TransportType::Udp);
        assert_eq!(transport_addr.as_socket_addr(), Some(addr));
    }

    #[test]
    fn test_bluetooth_addr() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let addr = TransportAddr::Bluetooth { mac, channel: 5 };

        assert_eq!(addr.transport_type(), TransportType::Bluetooth);
        assert!(addr.as_socket_addr().is_none());
    }

    #[test]
    fn test_ble_addr() {
        let mac = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let addr = TransportAddr::ble(mac, 128);

        assert_eq!(addr.transport_type(), TransportType::Ble);
        assert!(addr.as_socket_addr().is_none());

        let debug_str = format!("{addr:?}");
        assert!(debug_str.contains("12:34:56:78:9A:BC"));
        assert!(debug_str.contains("psm128"));
    }

    #[test]
    fn test_lora_addr() {
        let dev_addr = [0xDE, 0xAD, 0xBE, 0xEF];
        let addr = TransportAddr::lora(dev_addr, 868_000_000);

        assert_eq!(addr.transport_type(), TransportType::LoRa);

        if let TransportAddr::LoRa {
            dev_addr: da,
            freq_hz,
        } = &addr
        {
            assert_eq!(da, &[0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(*freq_hz, 868_000_000);
        } else {
            panic!("Expected LoRa variant");
        }
    }

    #[test]
    fn test_lorawan_addr() {
        let addr = TransportAddr::LoRaWan {
            dev_eui: 0x0011_2233_4455_6677,
        };
        assert_eq!(addr.transport_type(), TransportType::LoRaWan);
    }

    #[test]
    fn test_serial_addr() {
        let addr = TransportAddr::serial("/dev/ttyUSB0");
        assert_eq!(addr.transport_type(), TransportType::Serial);

        let display = format!("{addr}");
        assert_eq!(display, "/serial/%2Fdev%2FttyUSB0");
    }

    #[test]
    fn test_ax25_addr() {
        let addr = TransportAddr::ax25("N0CALL", 5);
        assert_eq!(addr.transport_type(), TransportType::Ax25);

        if let TransportAddr::Ax25 { callsign, ssid } = &addr {
            assert_eq!(callsign, "N0CALL");
            assert_eq!(*ssid, 5);
        }
    }

    #[test]
    fn test_ax25_ssid_clamp() {
        let addr = TransportAddr::ax25("N0CALL", 20);

        if let TransportAddr::Ax25 { ssid, .. } = &addr {
            assert_eq!(*ssid, 15);
        }
    }

    #[test]
    fn test_broadcast_addr() {
        let addr = TransportAddr::broadcast(TransportType::Ble);

        assert!(addr.is_broadcast());
        assert_eq!(addr.transport_type(), TransportType::Ble);
    }

    #[test]
    fn test_from_socket_addr() {
        let socket_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let transport_addr: TransportAddr = socket_addr.into();

        assert_eq!(transport_addr, TransportAddr::Quic(socket_addr));
    }

    #[test]
    fn test_from_socket_addr_ipv6() {
        let socket_addr: SocketAddr = "[::1]:9000".parse().unwrap();
        let transport_addr = TransportAddr::from(socket_addr);

        assert_eq!(transport_addr.transport_type(), TransportType::Quic);
        assert_eq!(transport_addr.as_socket_addr(), Some(socket_addr));
    }

    // -----------------------------------------------------------------------
    // Display roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_display_roundtrip_quic() {
        let addr = TransportAddr::Quic("192.168.1.1:9000".parse().unwrap());
        let s = addr.to_string();
        assert_eq!(s, "/ip4/192.168.1.1/udp/9000/quic");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_tcp() {
        let addr = TransportAddr::Tcp("10.0.0.1:8080".parse().unwrap());
        let s = addr.to_string();
        assert_eq!(s, "/ip4/10.0.0.1/tcp/8080");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_udp() {
        let addr = TransportAddr::Udp("10.0.0.1:5000".parse().unwrap());
        let s = addr.to_string();
        assert_eq!(s, "/ip4/10.0.0.1/udp/5000");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_ipv6_quic() {
        let addr = TransportAddr::Quic("[::1]:9000".parse().unwrap());
        let s = addr.to_string();
        assert_eq!(s, "/ip6/::1/udp/9000/quic");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_bluetooth() {
        let addr = TransportAddr::Bluetooth {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            channel: 5,
        };
        let s = addr.to_string();
        assert_eq!(s, "/bt/AA:BB:CC:DD:EE:FF/rfcomm/5");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_ble() {
        let addr = TransportAddr::ble([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], 128);
        let s = addr.to_string();
        assert_eq!(s, "/ble/01:02:03:04:05:06/l2cap/128");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_lora() {
        let addr = TransportAddr::lora([0xDE, 0xAD, 0xBE, 0xEF], 868_000_000);
        let s = addr.to_string();
        assert_eq!(s, "/lora/deadbeef/868000000");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_lorawan() {
        let addr = TransportAddr::LoRaWan {
            dev_eui: 0x0011_2233_4455_6677,
        };
        let s = addr.to_string();
        assert_eq!(s, "/lorawan/0011223344556677");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_serial() {
        let addr = TransportAddr::serial("/dev/ttyUSB0");
        let s = addr.to_string();
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_ax25() {
        let addr = TransportAddr::ax25("N0CALL", 5);
        let s = addr.to_string();
        assert_eq!(s, "/ax25/N0CALL/5");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_yggdrasil() {
        let addr = TransportAddr::yggdrasil([
            0x02, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ]);
        let s = addr.to_string();
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_display_roundtrip_broadcast() {
        let addr = TransportAddr::broadcast(TransportType::Ble);
        let s = addr.to_string();
        assert_eq!(s, "/broadcast/ble");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_transport_type_display() {
        assert_eq!(format!("{}", TransportType::Quic), "QUIC");
        assert_eq!(format!("{}", TransportType::Tcp), "TCP");
        assert_eq!(format!("{}", TransportType::Udp), "UDP");
        assert_eq!(format!("{}", TransportType::Bluetooth), "Bluetooth");
        assert_eq!(format!("{}", TransportType::Ble), "BLE");
        assert_eq!(format!("{}", TransportType::LoRa), "LoRa");
        assert_eq!(format!("{}", TransportType::LoRaWan), "LoRaWAN");
        assert_eq!(format!("{}", TransportType::Serial), "Serial");
        assert_eq!(format!("{}", TransportType::Ax25), "AX.25");
        assert_eq!(format!("{}", TransportType::I2p), "I2P");
        assert_eq!(format!("{}", TransportType::Yggdrasil), "Yggdrasil");
    }

    #[test]
    fn test_invalid_format_rejected() {
        assert!("garbage".parse::<TransportAddr>().is_err());
        assert!("/ip4/127.0.0.1/udp".parse::<TransportAddr>().is_err());
        assert!("/ip4/not-an-ip/tcp/80".parse::<TransportAddr>().is_err());
        assert!("/ip4/127.0.0.1/sctp/80".parse::<TransportAddr>().is_err());
        assert!("".parse::<TransportAddr>().is_err());
    }

    #[test]
    fn test_kind() {
        assert_eq!(
            TransportAddr::Quic(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).kind(),
            "quic"
        );
        assert_eq!(
            TransportAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).kind(),
            "tcp"
        );
        assert_eq!(
            TransportAddr::Bluetooth {
                mac: [0; 6],
                channel: 0
            }
            .kind(),
            "bluetooth"
        );
    }

    #[test]
    fn test_non_ip_transport_accessors() {
        let addr = TransportAddr::Bluetooth {
            mac: [0; 6],
            channel: 1,
        };
        assert_eq!(addr.as_socket_addr(), None);
        assert!(!addr.is_broadcast());
    }
}
