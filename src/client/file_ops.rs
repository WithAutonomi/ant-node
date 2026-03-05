//! File chunking and reassembly operations.
//!
//! Files are split into chunks of up to `MAX_CHUNK_SIZE` (4 MB). A manifest
//! chunk stores the ordered list of chunk addresses and the original file
//! metadata so the file can be reconstructed from the network.

use super::data_types::compute_address;
use crate::ant_protocol::MAX_CHUNK_SIZE;
use crate::error::{Error, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// A file manifest that describes how to reassemble a file from its chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// Original file name (if known).
    pub filename: Option<String>,
    /// Total file size in bytes.
    pub total_size: u64,
    /// Ordered list of chunk addresses (SHA256 hashes).
    pub chunk_addresses: Vec<[u8; 32]>,
}

/// Split file content into chunks of at most `MAX_CHUNK_SIZE`.
///
/// Returns a list of `Bytes` chunks in order.
#[must_use]
pub fn split_file(content: &[u8]) -> Vec<Bytes> {
    if content.is_empty() {
        return vec![Bytes::from_static(b"")];
    }

    content
        .chunks(MAX_CHUNK_SIZE)
        .map(Bytes::copy_from_slice)
        .collect()
}

/// Create a `FileManifest` from the file content and chunk addresses.
#[must_use]
pub fn create_manifest(
    filename: Option<String>,
    total_size: u64,
    chunk_addresses: Vec<[u8; 32]>,
) -> FileManifest {
    FileManifest {
        filename,
        total_size,
        chunk_addresses,
    }
}

/// Serialize a manifest to bytes suitable for storing as a chunk.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_manifest(manifest: &FileManifest) -> Result<Bytes> {
    let bytes = rmp_serde::to_vec(manifest)
        .map_err(|e| Error::Serialization(format!("Failed to serialize manifest: {e}")))?;
    Ok(Bytes::from(bytes))
}

/// Deserialize a manifest from bytes.
///
/// # Errors
///
/// Returns an error if deserialization fails.
pub fn deserialize_manifest(bytes: &[u8]) -> Result<FileManifest> {
    rmp_serde::from_slice(bytes)
        .map_err(|e| Error::Serialization(format!("Failed to deserialize manifest: {e}")))
}

/// Reassemble file content from ordered chunks.
///
/// Validates that total reassembled size matches the manifest.
///
/// # Errors
///
/// Returns an error if the reassembled size doesn't match the manifest.
pub fn reassemble_file(manifest: &FileManifest, chunks: &[Bytes]) -> Result<Bytes> {
    let total: usize = chunks.iter().map(Bytes::len).sum();
    let expected = usize::try_from(manifest.total_size)
        .map_err(|e| Error::InvalidChunk(format!("File size too large for platform: {e}")))?;

    if total != expected {
        return Err(Error::InvalidChunk(format!(
            "Reassembled size {total} does not match manifest size {expected}"
        )));
    }

    let mut result = Vec::with_capacity(total);
    for chunk in chunks {
        result.extend_from_slice(chunk);
    }
    Ok(Bytes::from(result))
}

/// Compute the address for file content (for verification).
#[must_use]
pub fn compute_chunk_address(content: &[u8]) -> [u8; 32] {
    compute_address(content)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_split_empty_file() {
        let chunks = split_file(b"");
        assert_eq!(chunks.len(), 1);
        assert!(chunks.first().unwrap().is_empty());
    }

    #[test]
    fn test_split_small_file() {
        let data = b"hello world";
        let chunks = split_file(data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks.first().unwrap().as_ref(), data);
    }

    #[test]
    fn test_split_exact_chunk_size() {
        let data = vec![0xABu8; MAX_CHUNK_SIZE];
        let chunks = split_file(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks.first().unwrap().len(), MAX_CHUNK_SIZE);
    }

    #[test]
    fn test_split_multiple_chunks() {
        let data = vec![0xCDu8; MAX_CHUNK_SIZE * 2 + 100];
        let chunks = split_file(&data);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks.first().unwrap().len(), MAX_CHUNK_SIZE);
        assert_eq!(chunks.get(1).unwrap().len(), MAX_CHUNK_SIZE);
        assert_eq!(chunks.get(2).unwrap().len(), 100);
    }

    #[test]
    fn test_manifest_roundtrip() {
        let manifest = create_manifest(
            Some("test.txt".to_string()),
            1024,
            vec![[1u8; 32], [2u8; 32]],
        );

        let bytes = serialize_manifest(&manifest).unwrap();
        let deserialized = deserialize_manifest(&bytes).unwrap();

        assert_eq!(deserialized.filename.as_deref(), Some("test.txt"));
        assert_eq!(deserialized.total_size, 1024);
        assert_eq!(deserialized.chunk_addresses.len(), 2);
    }

    #[test]
    fn test_reassemble_file() {
        let original = b"hello world, this is a test file for reassembly";
        let chunks = split_file(original);
        let addresses: Vec<[u8; 32]> = chunks.iter().map(|c| compute_chunk_address(c)).collect();

        let manifest = create_manifest(None, original.len() as u64, addresses);
        let reassembled = reassemble_file(&manifest, &chunks).unwrap();
        assert_eq!(reassembled.as_ref(), original);
    }

    #[test]
    fn test_reassemble_size_mismatch() {
        let manifest = create_manifest(None, 9999, vec![[1u8; 32]]);
        let chunks = vec![Bytes::from_static(b"small")];
        let result = reassemble_file(&manifest, &chunks);
        assert!(result.is_err());
    }

    #[test]
    fn test_split_and_reassemble_large() {
        let data = vec![0xFFu8; MAX_CHUNK_SIZE * 3 + 500];
        let chunks = split_file(&data);
        assert_eq!(chunks.len(), 4);

        let addresses: Vec<[u8; 32]> = chunks.iter().map(|c| compute_chunk_address(c)).collect();
        let manifest = create_manifest(None, data.len() as u64, addresses);
        let reassembled = reassemble_file(&manifest, &chunks).unwrap();
        assert_eq!(reassembled.as_ref(), data.as_slice());
    }
}
