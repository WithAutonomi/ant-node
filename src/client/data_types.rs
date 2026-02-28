//! Data type definitions for chunk storage.
//!
//! This module provides the core data types for content-addressed chunk storage
//! on the saorsa network. Chunks are immutable, content-addressed blobs where
//! the address is the BLAKE3 hash of the content.

use bytes::Bytes;
/// Compute the content address (BLAKE3 hash) for the given data.
#[must_use]
pub fn compute_address(content: &[u8]) -> XorName {
    *blake3::hash(content).as_bytes()
}

/// Compute the XOR distance between two 32-byte addresses.
///
/// Lexicographic comparison of the result gives correct Kademlia distance ordering.
#[must_use]
pub fn xor_distance(a: &XorName, b: &XorName) -> XorName {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Convert a hex-encoded peer ID string to an `XorName`.
///
/// Returns `None` if the string is not valid hex or is not exactly 32 bytes (64 hex chars).
#[must_use]
pub fn peer_id_to_xor_name(peer_id: &str) -> Option<XorName> {
    let bytes = hex::decode(peer_id).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&bytes);
    Some(name)
}

/// A content-addressed identifier (32 bytes).
///
/// The address is computed as BLAKE3(content) for chunks,
/// ensuring content-addressed storage.
pub type XorName = [u8; 32];

/// A chunk of data with its content-addressed identifier.
///
/// Chunks are the fundamental storage unit in saorsa. They are:
/// - **Immutable**: Content cannot be changed after storage
/// - **Content-addressed**: Address = BLAKE3(content)
/// - **Paid**: Storage requires EVM payment on Arbitrum
#[derive(Debug, Clone)]
pub struct DataChunk {
    /// The content-addressed identifier (BLAKE3 of content).
    pub address: XorName,
    /// The raw data content.
    pub content: Bytes,
}

impl DataChunk {
    /// Create a new data chunk.
    ///
    /// Note: This does NOT verify that address == BLAKE3(content).
    /// Use `from_content` for automatic address computation.
    #[must_use]
    pub fn new(address: XorName, content: Bytes) -> Self {
        Self { address, content }
    }

    /// Create a chunk from content, computing the address automatically.
    #[must_use]
    pub fn from_content(content: Bytes) -> Self {
        let address = compute_address(&content);
        Self { address, content }
    }

    /// Get the size of the chunk in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.content.len()
    }

    /// Verify that the address matches BLAKE3(content).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.address == compute_address(&self.content)
    }
}

/// Statistics about chunk operations.
#[derive(Debug, Default, Clone)]
pub struct ChunkStats {
    /// Number of chunks stored.
    pub chunks_stored: u64,
    /// Number of chunks retrieved.
    pub chunks_retrieved: u64,
    /// Number of cache hits.
    pub cache_hits: u64,
    /// Number of misses (not found).
    pub misses: u64,
    /// Total bytes stored.
    pub bytes_stored: u64,
    /// Total bytes retrieved.
    pub bytes_retrieved: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_data_chunk_creation() {
        let address = [0xAB; 32];
        let content = Bytes::from("test data");
        let chunk = DataChunk::new(address, content.clone());

        assert_eq!(chunk.address, address);
        assert_eq!(chunk.content, content);
        assert_eq!(chunk.size(), 9);
    }

    #[test]
    fn test_chunk_from_content() {
        let content = Bytes::from("hello world");
        let chunk = DataChunk::from_content(content.clone());

        // BLAKE3 of "hello world"
        let expected: [u8; 32] = [
            0xd7, 0x49, 0x81, 0xef, 0xa7, 0x0a, 0x0c, 0x88, 0x0b, 0x8d, 0x8c, 0x19, 0x85, 0xd0,
            0x75, 0xdb, 0xcb, 0xf6, 0x79, 0xb9, 0x9a, 0x5f, 0x99, 0x14, 0xe5, 0xaa, 0xf9, 0x6b,
            0x83, 0x1a, 0x9e, 0x24,
        ];

        assert_eq!(chunk.address, expected);
        assert_eq!(chunk.content, content);
        assert!(chunk.verify());
    }

    #[test]
    fn test_xor_distance_identity() {
        let a = [0xAB; 32];
        assert_eq!(xor_distance(&a, &a), [0u8; 32]);
    }

    #[test]
    fn test_xor_distance_symmetry() {
        let a = [0x01; 32];
        let b = [0xFF; 32];
        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    fn test_xor_distance_known_values() {
        let a = [0x00; 32];
        let b = [0xFF; 32];
        assert_eq!(xor_distance(&a, &b), [0xFF; 32]);

        let mut c = [0x00; 32];
        c[0] = 0x80;
        let mut expected = [0x00; 32];
        expected[0] = 0x80;
        assert_eq!(xor_distance(&a, &c), expected);
    }

    #[test]
    fn test_peer_id_to_xor_name_valid() {
        let hex_str = "ab".repeat(32);
        let result = peer_id_to_xor_name(&hex_str);
        assert_eq!(result, Some([0xAB; 32]));
    }

    #[test]
    fn test_peer_id_to_xor_name_invalid_hex() {
        assert_eq!(peer_id_to_xor_name("not_hex_at_all!"), None);
    }

    #[test]
    fn test_peer_id_to_xor_name_wrong_length() {
        // 16 bytes instead of 32
        let short = "ab".repeat(16);
        assert_eq!(peer_id_to_xor_name(&short), None);

        // 33 bytes
        let long = "ab".repeat(33);
        assert_eq!(peer_id_to_xor_name(&long), None);
    }

    #[test]
    fn test_chunk_verify() {
        // Valid chunk
        let content = Bytes::from("test");
        let valid = DataChunk::from_content(content);
        assert!(valid.verify());

        // Invalid chunk (wrong address)
        let invalid = DataChunk::new([0; 32], Bytes::from("test"));
        assert!(!invalid.verify());
    }
}
