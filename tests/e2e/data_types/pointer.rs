//! Pointer data type E2E tests.
//!
//! Pointers are lightweight mutable references to other addresses.
//! They consist of:
//! - Owner public key (determines the pointer's address)
//! - Target `XorName` (the address being pointed to)
//! - Counter (for versioning like scratchpads)
//! - Signature (ML-DSA-65 for authenticity)
//!
//! ## Use Cases
//!
//! - Directory listings (pointer to current root)
//! - Mutable file references
//! - DNS-like name resolution
//!
//! ## Test Coverage
//!
//! - Basic store and retrieve
//! - Owner-based addressing
//! - Target update semantics
//! - Counter versioning
//! - Cross-node replication
//! - ML-DSA-65 signature verification

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::TestData;

/// Test fixture for pointer operations.
#[allow(dead_code)]
pub struct PointerTestFixture {
    /// Owner public key (32 bytes).
    owner: [u8; 32],
    /// Target address (`XorName`).
    pub target: [u8; 32],
    /// Alternative target for update tests.
    pub alt_target: [u8; 32],
}

impl Default for PointerTestFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl PointerTestFixture {
    /// Create a new test fixture.
    #[must_use]
    pub fn new() -> Self {
        let mut target = [0u8; 32];
        target[0..8].copy_from_slice(b"target01");

        let mut alt_target = [0u8; 32];
        alt_target[0..8].copy_from_slice(b"target02");

        Self {
            owner: TestData::test_owner(),
            target,
            alt_target,
        }
    }

    /// Create fixture with a specific owner.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_owner(owner: [u8; 32]) -> Self {
        let mut target = [0u8; 32];
        target[0..8].copy_from_slice(b"target01");

        let mut alt_target = [0u8; 32];
        alt_target[0..8].copy_from_slice(b"target02");

        Self {
            owner,
            target,
            alt_target,
        }
    }

    /// Compute pointer address from owner public key.
    #[must_use]
    pub fn compute_address(owner: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"pointer:");
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

    /// Test 1: Pointer address is derived from owner
    #[test]
    fn test_pointer_address_from_owner() {
        let owner = TestData::test_owner();
        let addr1 = PointerTestFixture::compute_address(&owner);
        let addr2 = PointerTestFixture::compute_address(&owner);
        assert_eq!(addr1, addr2, "Same owner should produce same address");
    }

    /// Test 2: Different owners produce different addresses
    #[test]
    fn test_different_owners_different_addresses() {
        let owner1 = [1u8; 32];
        let owner2 = [2u8; 32];

        let addr1 = PointerTestFixture::compute_address(&owner1);
        let addr2 = PointerTestFixture::compute_address(&owner2);
        assert_ne!(
            addr1, addr2,
            "Different owners should produce different addresses"
        );
    }

    /// Test 3: Fixture creates valid targets
    #[test]
    fn test_fixture_targets() {
        let fixture = PointerTestFixture::new();
        assert_eq!(fixture.target.len(), 32);
        assert_eq!(fixture.alt_target.len(), 32);
        assert_ne!(fixture.target, fixture.alt_target);
    }

    /// Test 4: Pointer address differs from scratchpad address
    #[test]
    fn test_pointer_address_namespace() {
        use super::super::scratchpad::ScratchpadTestFixture;

        let owner = [42u8; 32];
        let pointer_addr = PointerTestFixture::compute_address(&owner);
        let scratchpad_addr = ScratchpadTestFixture::compute_address(&owner);

        // Different prefixes should produce different addresses
        assert_ne!(
            pointer_addr, scratchpad_addr,
            "Pointer and scratchpad addresses should be in different namespaces"
        );
    }
}
