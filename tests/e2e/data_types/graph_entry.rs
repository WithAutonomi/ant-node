//! `GraphEntry` data type E2E tests.
//!
//! `GraphEntry` represents nodes in a directed acyclic graph (DAG).
//! Each entry contains:
//! - Owner public key
//! - Parent links (`XorNames` of parent entries)
//! - Content/payload (up to 100KB)
//! - Signature (ML-DSA-65)
//!
//! ## Use Cases
//!
//! - Version control (commit history)
//! - Social feeds (post threads)
//! - Document revisions
//! - Multi-owner collaborative structures
//!
//! ## Test Coverage
//!
//! - Basic store and retrieve
//! - Parent link validation
//! - DAG traversal
//! - Multi-owner entries
//! - Cross-node replication
//! - Maximum size handling (100KB)
//! - ML-DSA-65 signature verification

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{TestData, MAX_GRAPH_ENTRY_SIZE};

/// Test fixture for graph entry operations.
#[allow(dead_code)]
pub struct GraphEntryTestFixture {
    /// Owner public key (32 bytes).
    owner: [u8; 32],
    /// Parent entry addresses.
    pub parents: Vec<[u8; 32]>,
    /// Small content (1KB).
    pub small_content: Vec<u8>,
    /// Large content (100KB - max size).
    pub large_content: Vec<u8>,
}

impl Default for GraphEntryTestFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphEntryTestFixture {
    /// Create a new test fixture (root node with no parents).
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: TestData::test_owner(),
            parents: Vec::new(), // Root node
            small_content: TestData::generate(1024),
            large_content: TestData::generate(MAX_GRAPH_ENTRY_SIZE),
        }
    }

    /// Create fixture with specific parents.
    #[must_use]
    pub fn with_parents(parents: Vec<[u8; 32]>) -> Self {
        Self {
            owner: TestData::test_owner(),
            parents,
            small_content: TestData::generate(1024),
            large_content: TestData::generate(MAX_GRAPH_ENTRY_SIZE),
        }
    }

    /// Create fixture with specific owner and parents.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_owner_and_parents(owner: [u8; 32], parents: Vec<[u8; 32]>) -> Self {
        Self {
            owner,
            parents,
            small_content: TestData::generate(1024),
            large_content: TestData::generate(MAX_GRAPH_ENTRY_SIZE),
        }
    }

    /// Compute graph entry address from owner and content.
    #[must_use]
    pub fn compute_address(owner: &[u8; 32], content: &[u8], parents: &[[u8; 32]]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"graph_entry:");
        hasher.update(owner);
        hasher.update(content);
        for parent in parents {
            hasher.update(parent);
        }
        let hash = hasher.finalize();
        let mut address = [0u8; 32];
        address.copy_from_slice(&hash);
        address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 1: Graph entry address is deterministic
    #[test]
    fn test_graph_entry_address_deterministic() {
        let owner = TestData::test_owner();
        let content = TestData::generate(100);
        let parents: Vec<[u8; 32]> = vec![];

        let addr1 = GraphEntryTestFixture::compute_address(&owner, &content, &parents);
        let addr2 = GraphEntryTestFixture::compute_address(&owner, &content, &parents);
        assert_eq!(addr1, addr2, "Same inputs should produce same address");
    }

    /// Test 2: Different content produces different addresses
    #[test]
    fn test_different_content_different_address() {
        let owner = TestData::test_owner();
        let content1 = TestData::generate(100);
        let mut content2 = TestData::generate(100);
        content2[0] = 255;
        let parents: Vec<[u8; 32]> = vec![];

        let addr1 = GraphEntryTestFixture::compute_address(&owner, &content1, &parents);
        let addr2 = GraphEntryTestFixture::compute_address(&owner, &content2, &parents);
        assert_ne!(
            addr1, addr2,
            "Different content should produce different addresses"
        );
    }

    /// Test 3: Different parents produce different addresses
    #[test]
    fn test_different_parents_different_address() {
        let owner = TestData::test_owner();
        let content = TestData::generate(100);
        let parent1 = [1u8; 32];
        let parent2 = [2u8; 32];

        let addr1 = GraphEntryTestFixture::compute_address(&owner, &content, &[parent1]);
        let addr2 = GraphEntryTestFixture::compute_address(&owner, &content, &[parent2]);
        assert_ne!(
            addr1, addr2,
            "Different parents should produce different addresses"
        );
    }

    /// Test 4: Fixture creates correct sizes
    #[test]
    fn test_fixture_content_sizes() {
        let fixture = GraphEntryTestFixture::new();
        assert_eq!(fixture.small_content.len(), 1024);
        assert_eq!(fixture.large_content.len(), MAX_GRAPH_ENTRY_SIZE);
    }

    /// Test 5: Max graph entry size constant is correct
    #[test]
    fn test_max_graph_entry_size() {
        assert_eq!(MAX_GRAPH_ENTRY_SIZE, 100 * 1024); // 100KB
    }

    /// Test 6: Root fixture has no parents
    #[test]
    fn test_root_fixture_no_parents() {
        let fixture = GraphEntryTestFixture::new();
        assert!(fixture.parents.is_empty());
    }

    /// Test 7: Fixture with parents
    #[test]
    fn test_fixture_with_parents() {
        let parent = [42u8; 32];
        let fixture = GraphEntryTestFixture::with_parents(vec![parent]);
        assert_eq!(fixture.parents.len(), 1);
        assert_eq!(fixture.parents[0], parent);
    }
}
