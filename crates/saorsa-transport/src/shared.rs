// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use bytes::{Buf, BufMut, BytesMut};

use crate::{Instant, MAX_CID_SIZE, ResetToken, coding::BufExt, packet::PartialDecode};

/// Events sent from an Endpoint to a Connection
#[derive(Debug)]
pub struct ConnectionEvent(pub(crate) ConnectionEventInner);

#[derive(Debug)]
pub(crate) enum ConnectionEventInner {
    /// A datagram has been received for the Connection
    Datagram(DatagramConnectionEvent),
    /// New connection identifiers have been issued for the Connection
    NewIdentifiers(Vec<IssuedCid>, Instant),
    /// Queue an ADD_ADDRESS frame for transmission
    QueueAddAddress(crate::frame::AddAddress),
    /// Queue a PUNCH_ME_NOW frame for transmission
    QueuePunchMeNow(crate::frame::PunchMeNow),
}

/// Variant of [`ConnectionEventInner`].
#[derive(Debug)]
pub(crate) struct DatagramConnectionEvent {
    pub(crate) now: Instant,
    pub(crate) remote: SocketAddr,
    pub(crate) ecn: Option<EcnCodepoint>,
    pub(crate) first_decode: PartialDecode,
    pub(crate) remaining: Option<BytesMut>,
}

/// Events sent from a Connection to an Endpoint
#[derive(Debug)]
pub struct EndpointEvent(pub(crate) EndpointEventInner);

impl EndpointEvent {
    /// Construct an event that indicating that a `Connection` will no longer emit events
    ///
    /// Useful for notifying an `Endpoint` that a `Connection` has been destroyed outside of the
    /// usual state machine flow, e.g. when being dropped by the user.
    pub fn drained() -> Self {
        Self(EndpointEventInner::Drained)
    }

    /// Determine whether this is the last event a `Connection` will emit
    ///
    /// Useful for determining when connection-related event loop state can be freed.
    pub fn is_drained(&self) -> bool {
        self.0 == EndpointEventInner::Drained
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]

pub(crate) enum EndpointEventInner {
    /// The connection has been drained
    Drained,
    /// The reset token and/or address eligible for generating resets has been updated
    ResetToken(SocketAddr, ResetToken),
    /// The connection needs connection identifiers
    NeedIdentifiers(Instant, u64),
    /// Stop routing connection ID for this sequence number to the connection
    /// When `bool == true`, a new connection ID will be issued to peer
    RetireConnectionId(Instant, u64, bool),
    /// Request to relay a PunchMeNow frame to a target peer
    /// Fields: (target_peer_id, coordination_frame, target_remote_address)
    RelayPunchMeNow([u8; 32], crate::frame::PunchMeNow, std::net::SocketAddr),
    /// Request to send an AddAddress frame to the peer
    #[allow(dead_code)]
    SendAddressFrame(crate::frame::AddAddress),
    /// NAT traversal candidate validation succeeded
    #[allow(dead_code)]
    NatCandidateValidated { address: SocketAddr, challenge: u64 },
    /// Initiate a hole-punch connection attempt to a peer's address.
    /// Emitted by the target node when it receives a relayed PUNCH_ME_NOW,
    /// triggering QUIC Initial packets to create a NAT binding.
    InitiateHolePunch {
        /// The peer's external address to connect to
        peer_address: SocketAddr,
    },
    /// A peer advertised a new reachable address via ADD_ADDRESS.
    /// The endpoint should propagate this so the DHT routing table is updated.
    PeerAddressAdvertised {
        /// The peer's current connection address
        peer_addr: SocketAddr,
        /// The new address the peer is advertising
        advertised_addr: SocketAddr,
    },
    /// Request to attempt connection to a target address (NAT callback mechanism)
    TryConnectTo {
        request_id: crate::VarInt,
        target_address: SocketAddr,
        timeout_ms: u16,
        requester_connection: SocketAddr,
        requested_at: crate::Instant,
    },
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    /// length of CID
    len: u8,
    /// CID in byte array
    bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    /// Construct cid from byte array
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    /// Constructs cid by reading `len` bytes from a `Buf`
    ///
    /// Callers need to assure that `buf.remaining() >= len`
    pub fn from_buf(buf: &mut (impl Buf + ?Sized), len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        buf.copy_to_slice(&mut res[..len]);
        res
    }

    /// Decode from long header format
    pub(crate) fn decode_long(buf: &mut impl Buf) -> Option<Self> {
        let len = buf.get::<u8>().ok()? as usize;
        match len > MAX_CID_SIZE || buf.remaining() < len {
            false => Some(Self::from_buf(buf, len)),
            true => None,
        }
    }

    /// Encode in long header format
    pub(crate) fn encode_long(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self);
    }
}

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes[0..self.len as usize].fmt(f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// The ECT(0) codepoint, indicating that an endpoint is ECN-capable
    Ect0 = 0b10,
    /// The ECT(1) codepoint, indicating that an endpoint is ECN-capable
    Ect1 = 0b01,
    /// The CE codepoint, signalling that congestion was experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }

    /// Returns whether the codepoint is a CE, signalling that congestion was experienced
    pub fn is_ce(self) -> bool {
        matches!(self, Self::Ce)
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct IssuedCid {
    pub(crate) sequence: u64,
    pub(crate) id: ConnectionId,
    pub(crate) reset_token: ResetToken,
}

/// Normalize a socket address by converting IPv4-mapped IPv6 addresses to pure IPv4.
///
/// This is critical for address comparison when connections may use either format.
/// For example, `[::ffff:192.168.1.1]:9000` normalizes to `192.168.1.1:9000`.
///
/// This normalization is essential for nodes bound to IPv4-only sockets (0.0.0.0:port)
/// that receive addresses in IPv4-mapped IPv6 format (::ffff:a.b.c.d). Without
/// normalization, attempting to connect to an IPv4-mapped address from an IPv4-only
/// socket fails with "Address family not supported by protocol" (EAFNOSUPPORT).
pub fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6_addr) => {
            // Check if this is an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
            if let Some(ipv4) = v6_addr.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(ipv4), v6_addr.port())
            } else {
                addr
            }
        }
        SocketAddr::V4(_) => addr,
    }
}

/// Return the alternate IPv4 / IPv4-mapped-IPv6 form of a socket address,
/// or `None` if the address is a pure IPv6 address (no alternate form).
///
/// On dual-stack sockets (`bindv6only=0`), the kernel represents IPv4 peers
/// as `[::ffff:x.x.x.x]` but callers may hold either representation.
/// This function produces the "other" form so both can be tried during lookups.
pub fn dual_stack_alternate(addr: &SocketAddr) -> Option<SocketAddr> {
    match addr {
        SocketAddr::V4(v4) => {
            let mapped = v4.ip().to_ipv6_mapped();
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                mapped,
                v4.port(),
                0,
                0,
            )))
        }
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ipv4| SocketAddr::new(IpAddr::V4(ipv4), v6.port())),
    }
}

/// Deterministic 32-byte wire identifier from a `SocketAddr`.
///
/// Used to correlate PUNCH_ME_NOW relay targets across connections.
/// The encoding is deterministic (no hashing): IP bytes are written directly
/// into a 32-byte array with a version-byte prefix.
///
/// Layout for IPv4 (`[4, ip0..ip3, port_hi, port_lo, 0..]`):
///   byte 0     = 4 (version tag)
///   bytes 1-4  = IPv4 octets
///   bytes 5-6  = port (big-endian)
///   bytes 7-31 = zero padding
///
/// Layout for IPv6 (`[6, ip0..ip15, port_hi, port_lo, 0..]`):
///   byte 0      = 6 (version tag)
///   bytes 1-16  = IPv6 octets
///   bytes 17-18 = port (big-endian)
///   bytes 19-31 = zero padding
pub fn wire_id_from_addr(addr: SocketAddr) -> [u8; 32] {
    // Normalise IPv4-mapped IPv6 to plain IPv4 so that the same peer
    // always produces the same wire ID regardless of whether the address
    // came from a dual-stack socket ([::ffff:x.x.x.x]) or a plain IPv4 socket.
    let addr = normalize_socket_addr(addr);
    let mut bytes = [0u8; 32];
    match addr {
        SocketAddr::V4(v4) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&v4.ip().octets());
            bytes[5..7].copy_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&v6.ip().octets());
            bytes[17..19].copy_from_slice(&v6.port().to_be_bytes());
        }
    }
    bytes
}
