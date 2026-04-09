// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Canonical peer identity type for the Saorsa P2P network.
//!
//! [`PeerId`] is a 256-bit identifier computed as the BLAKE3 hash of a node's
//! ML-DSA-65 public key. It is the single source of truth used across all
//! Saorsa crates (`saorsa-core`, `saorsa-transport`, etc.).

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Length of a PeerId in bytes (BLAKE3 output).
pub const PEER_ID_BYTE_LEN: usize = 32;

/// Number of bytes shown by [`PeerId::short_hex`].
const SHORT_HEX_BYTES: usize = 8;

/// Peer ID derived from public key (256-bit).
///
/// The canonical peer identity in the Saorsa network. Computed as the
/// BLAKE3 hash of the node's ML-DSA-65 public key.
///
/// Serializes as a hex string (64 characters) in all formats to maintain
/// wire compatibility with the existing postcard-based `WireMessage` protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub(crate) [u8; PEER_ID_BYTE_LEN]);

impl Serialize for PeerId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        PeerId::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Error returned when parsing a [`PeerId`] from a hex string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdParseError {
    /// The input string was not valid hexadecimal.
    InvalidHexEncoding(String),
    /// The decoded bytes had an unexpected length.
    InvalidLength {
        /// Expected number of bytes (always [`PEER_ID_BYTE_LEN`]).
        expected: usize,
        /// Actual number of decoded bytes.
        actual: usize,
    },
}

impl fmt::Display for PeerIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerIdParseError::InvalidHexEncoding(reason) => {
                write!(f, "Invalid hex encoding for PeerId: {reason}")
            }
            PeerIdParseError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid PeerId length: expected {expected} bytes, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for PeerIdParseError {}

impl PeerId {
    /// Convert to a byte-array reference.
    pub fn to_bytes(&self) -> &[u8; PEER_ID_BYTE_LEN] {
        &self.0
    }

    /// Backward-compatible byte accessor.
    pub fn as_bytes(&self) -> &[u8; PEER_ID_BYTE_LEN] {
        &self.0
    }

    /// XOR distance to another peer ID (for Kademlia).
    pub fn xor_distance(&self, other: &PeerId) -> [u8; PEER_ID_BYTE_LEN] {
        let mut distance = [0u8; PEER_ID_BYTE_LEN];
        for (i, out) in distance.iter_mut().enumerate() {
            *out = self.0[i] ^ other.0[i];
        }
        distance
    }

    /// XOR distance alias — provided so code using `DhtKey` can call
    /// `.distance()` unchanged.
    pub fn distance(&self, other: &PeerId) -> [u8; PEER_ID_BYTE_LEN] {
        self.xor_distance(other)
    }

    /// Create from a hex-encoded string (64 hex characters -> 32 bytes).
    pub fn from_hex(hex_str: &str) -> Result<Self, PeerIdParseError> {
        let bytes = hex::decode(hex_str).map_err(|e| {
            PeerIdParseError::InvalidHexEncoding(format!("Invalid hex for PeerId: {e}"))
        })?;
        if bytes.len() != PEER_ID_BYTE_LEN {
            return Err(PeerIdParseError::InvalidLength {
                expected: PEER_ID_BYTE_LEN,
                actual: bytes.len(),
            });
        }
        let mut id = [0u8; PEER_ID_BYTE_LEN];
        id.copy_from_slice(&bytes);
        Ok(Self(id))
    }

    /// Encode this PeerId as a lowercase hex string (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Return a short hex representation (first 8 bytes = 16 hex characters).
    ///
    /// Useful for compact log output.
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..SHORT_HEX_BYTES])
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; PEER_ID_BYTE_LEN]) -> Self {
        Self(bytes)
    }

    /// Create a deterministic PeerId by BLAKE3-hashing an arbitrary name.
    ///
    /// Use this for synthetic identifiers (e.g. CLI peer placeholders, test
    /// peers) where you don't have a real hex-encoded peer ID.
    pub fn from_name(name: &str) -> Self {
        let hash = blake3::hash(name.as_bytes());
        Self(*hash.as_bytes())
    }

    /// Create a random peer identifier (primarily for tests/simulation).
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// BLAKE3 hash constructor — produces a deterministic PeerId from
    /// arbitrary data.
    ///
    /// Equivalent to the former `DhtKey::new()`. Use this when you need a
    /// content-addressed identifier (e.g. hashing a test label into a key).
    pub fn new(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Ord for PeerId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for PeerId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<[u8; PEER_ID_BYTE_LEN]> for PeerId {
    fn from(bytes: [u8; PEER_ID_BYTE_LEN]) -> Self {
        Self(bytes)
    }
}

impl FromStr for PeerId {
    type Err = PeerIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let id = PeerId([0xAB; PEER_ID_BYTE_LEN]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "ab".repeat(32));

        let parsed = PeerId::from_hex(&hex).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_postcard_roundtrip() {
        let id = PeerId([0xAB; PEER_ID_BYTE_LEN]);
        let bytes = postcard::to_stdvec(&id).unwrap();
        let deserialized: PeerId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_json_roundtrip() {
        let id = PeerId([0xAB; PEER_ID_BYTE_LEN]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));

        let deserialized: PeerId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_xor_distance() {
        let id1 = PeerId([0u8; PEER_ID_BYTE_LEN]);
        let mut id2_bytes = [0u8; PEER_ID_BYTE_LEN];
        id2_bytes[0] = 0xFF;
        let id2 = PeerId(id2_bytes);

        let distance = id1.xor_distance(&id2);
        assert_eq!(distance[0], 0xFF);
        for byte in &distance[1..] {
            assert_eq!(*byte, 0);
        }
    }

    #[test]
    fn test_display_full_hex() {
        let id = PeerId([0xAB; PEER_ID_BYTE_LEN]);
        let display = format!("{id}");
        assert_eq!(display.len(), 64);
        assert_eq!(display, "ab".repeat(32));
    }

    #[test]
    fn test_short_hex() {
        let id = PeerId([0xAB; PEER_ID_BYTE_LEN]);
        let short = id.short_hex();
        assert_eq!(short.len(), 16);
        assert_eq!(short, "ab".repeat(8));
    }

    #[test]
    fn test_ord() {
        let a = PeerId([0x00; PEER_ID_BYTE_LEN]);
        let b = PeerId([0xFF; PEER_ID_BYTE_LEN]);
        assert!(a < b);
    }

    #[test]
    fn test_from_str() {
        let hex = "ab".repeat(32);
        let id: PeerId = hex.parse().unwrap();
        assert_eq!(id.0, [0xAB; PEER_ID_BYTE_LEN]);
    }

    #[test]
    fn test_from_str_invalid_hex() {
        let result = "not-hex".parse::<PeerId>();
        assert!(matches!(
            result,
            Err(PeerIdParseError::InvalidHexEncoding(_))
        ));
    }

    #[test]
    fn test_from_str_wrong_length() {
        let result = "aabb".parse::<PeerId>();
        assert!(matches!(
            result,
            Err(PeerIdParseError::InvalidLength {
                expected: 32,
                actual: 2,
            })
        ));
    }

    #[test]
    fn test_copy_semantics() {
        let a = PeerId([0x42; PEER_ID_BYTE_LEN]);
        let b = a; // Copy, not move
        assert_eq!(a, b); // `a` still usable
    }

    #[test]
    fn test_from_name_deterministic() {
        let a = PeerId::from_name("test-peer");
        let b = PeerId::from_name("test-peer");
        assert_eq!(a, b);

        let c = PeerId::from_name("other-peer");
        assert_ne!(a, c);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [0x42; PEER_ID_BYTE_LEN];
        let id = PeerId::from_bytes(bytes);
        assert_eq!(id.0, bytes);
    }

    #[test]
    fn test_from_array() {
        let bytes = [0x42; PEER_ID_BYTE_LEN];
        let id = PeerId::from(bytes);
        assert_eq!(id.0, bytes);
    }

    #[test]
    fn test_new_deterministic() {
        let a = PeerId::new(b"some data");
        let b = PeerId::new(b"some data");
        assert_eq!(a, b);

        let c = PeerId::new(b"other data");
        assert_ne!(a, c);
    }

    #[test]
    fn test_distance_alias() {
        let a = PeerId([0x00; PEER_ID_BYTE_LEN]);
        let b = PeerId([0xFF; PEER_ID_BYTE_LEN]);
        assert_eq!(a.distance(&b), a.xor_distance(&b));
    }
}
