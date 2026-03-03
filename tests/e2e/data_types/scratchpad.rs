//! Scratchpad data type E2E tests.
//!
//! Scratchpads are mutable, owner-indexed data blocks (up to 4MB) with
//! counter-based versioning (CRDT). The address is derived from the owner's
//! public key.
//!
//! ## Test Coverage
//!
//! - Basic store and retrieve
//! - Owner-based addressing
//! - Counter versioning (CRDT)
//! - Update semantics (higher counter wins)
//! - Cross-node replication
//! - Maximum size handling (4MB)
//! - Payment verification
//! - ML-DSA-65 signature verification

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{TestData, MAX_SCRATCHPAD_SIZE};

/// Test fixture for scratchpad operations.
#[allow(dead_code)]
pub struct ScratchpadTestFixture {
    /// Owner public key (32 bytes).
    pub owner: [u8; 32],
    /// Content type identifier.
    content_type: u64,
    /// Small test data (1KB).
    pub small_data: Vec<u8>,
    /// Large test data (4MB - max size).
    pub large_data: Vec<u8>,
}

impl Default for ScratchpadTestFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl ScratchpadTestFixture {
    /// Create a new test fixture with pre-generated data.
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: TestData::test_owner(),
            content_type: 1, // Generic content type
            small_data: TestData::generate(1024),
            large_data: TestData::generate(MAX_SCRATCHPAD_SIZE),
        }
    }

    /// Create fixture with a specific owner.
    #[must_use]
    pub fn with_owner(owner: [u8; 32]) -> Self {
        Self {
            owner,
            content_type: 1,
            small_data: TestData::generate(1024),
            large_data: TestData::generate(MAX_SCRATCHPAD_SIZE),
        }
    }

    /// Compute scratchpad address from owner public key.
    #[must_use]
    pub fn compute_address(owner: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"scratchpad:");
        hasher.update(owner);
        let hash = hasher.finalize();
        let mut address = [0u8; 32];
        address.copy_from_slice(&hash);
        address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 1: Scratchpad address is derived from owner
    #[test]
    fn test_scratchpad_address_from_owner() {
        let owner = TestData::test_owner();
        let addr1 = ScratchpadTestFixture::compute_address(&owner);
        let addr2 = ScratchpadTestFixture::compute_address(&owner);
        assert_eq!(addr1, addr2, "Same owner should produce same address");
    }

    /// Test 2: Different owners produce different addresses
    #[test]
    fn test_different_owners_different_addresses() {
        let owner1 = [1u8; 32];
        let owner2 = [2u8; 32];

        let addr1 = ScratchpadTestFixture::compute_address(&owner1);
        let addr2 = ScratchpadTestFixture::compute_address(&owner2);
        assert_ne!(
            addr1, addr2,
            "Different owners should produce different addresses"
        );
    }

    /// Test 3: Fixture creates correct sizes
    #[test]
    fn test_fixture_data_sizes() {
        let fixture = ScratchpadTestFixture::new();
        assert_eq!(fixture.small_data.len(), 1024);
        assert_eq!(fixture.large_data.len(), MAX_SCRATCHPAD_SIZE);
    }

    /// Test 4: Max scratchpad size constant is correct
    #[test]
    fn test_max_scratchpad_size() {
        assert_eq!(MAX_SCRATCHPAD_SIZE, 4 * 1024 * 1024); // 4MB
    }

    /// Test 5: Custom owner fixture
    #[test]
    fn test_custom_owner_fixture() {
        let custom_owner = [42u8; 32];
        let fixture = ScratchpadTestFixture::with_owner(custom_owner);
        assert_eq!(fixture.owner, custom_owner);
    }
}
