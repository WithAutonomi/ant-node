//! Payment verifier with LRU cache and EVM verification.
//!
//! This is the core payment verification logic for saorsa-node.
//! All new data requires EVM payment on Arbitrum (no free tier).

use crate::error::{Error, Result};
use crate::payment::cache::{CacheStats, VerifiedCache, XorName};
use ant_evm::ProofOfPayment;
use evmlib::Network as EvmNetwork;
use futures::future::try_join_all;
use tracing::{debug, info};

/// Configuration for EVM payment verification.
#[derive(Debug, Clone)]
pub struct EvmVerifierConfig {
    /// EVM network to use (Arbitrum One, Arbitrum Sepolia, etc.)
    pub network: EvmNetwork,
    /// Whether EVM verification is enabled.
    pub enabled: bool,
}

impl Default for EvmVerifierConfig {
    fn default() -> Self {
        Self {
            network: EvmNetwork::ArbitrumOne,
            enabled: true,
        }
    }
}

/// Configuration for the payment verifier.
///
/// All new data requires EVM payment on Arbitrum. The cache stores
/// previously verified payments to avoid redundant on-chain lookups.
#[derive(Debug, Clone)]
pub struct PaymentVerifierConfig {
    /// EVM verifier configuration.
    pub evm: EvmVerifierConfig,
    /// Cache capacity (number of `XorName` values to cache).
    pub cache_capacity: usize,
}

impl Default for PaymentVerifierConfig {
    fn default() -> Self {
        Self {
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100_000,
        }
    }
}

/// Status returned by payment verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    /// Data was found in local cache - previously paid.
    CachedAsVerified,
    /// New data - payment required.
    PaymentRequired,
    /// Payment was provided and verified.
    PaymentVerified,
}

impl PaymentStatus {
    /// Returns true if the data can be stored (cached or payment verified).
    #[must_use]
    pub fn can_store(&self) -> bool {
        matches!(self, Self::CachedAsVerified | Self::PaymentVerified)
    }

    /// Returns true if this status indicates the data was already paid for.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        matches!(self, Self::CachedAsVerified)
    }
}

/// Main payment verifier for saorsa-node.
///
/// Uses:
/// 1. LRU cache for fast lookups of previously verified `XorName` values
/// 2. EVM payment verification for new data (always required)
pub struct PaymentVerifier {
    /// LRU cache of verified `XorName` values.
    cache: VerifiedCache,
    /// Configuration.
    config: PaymentVerifierConfig,
}

impl PaymentVerifier {
    /// Create a new payment verifier.
    #[must_use]
    pub fn new(config: PaymentVerifierConfig) -> Self {
        let cache = VerifiedCache::with_capacity(config.cache_capacity);

        info!(
            "Payment verifier initialized (cache_capacity={}, evm_enabled={})",
            config.cache_capacity, config.evm.enabled
        );

        Self { cache, config }
    }

    /// Check if payment is required for the given `XorName`.
    ///
    /// This is the main entry point for payment verification:
    /// 1. Check LRU cache (fast path)
    /// 2. If not cached, payment is required
    ///
    /// # Arguments
    ///
    /// * `xorname` - The content-addressed name of the data
    ///
    /// # Returns
    ///
    /// * `PaymentStatus::CachedAsVerified` - Found in local cache (previously paid)
    /// * `PaymentStatus::PaymentRequired` - Not cached (payment required)
    pub fn check_payment_required(&self, xorname: &XorName) -> PaymentStatus {
        // Check LRU cache (fast path)
        if self.cache.contains(xorname) {
            if tracing::enabled!(tracing::Level::DEBUG) {
                debug!("Data {} found in verified cache", hex::encode(xorname));
            }
            return PaymentStatus::CachedAsVerified;
        }

        // Not in cache - payment required
        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Data {} not in cache - payment required",
                hex::encode(xorname)
            );
        }
        PaymentStatus::PaymentRequired
    }

    /// Verify that a PUT request has valid payment.
    ///
    /// This is the complete payment verification flow:
    /// 1. Check if data is in cache (previously paid)
    /// 2. If not, verify the provided payment proof
    ///
    /// # Arguments
    ///
    /// * `xorname` - The content-addressed name of the data
    /// * `payment_proof` - Optional payment proof (required if not in cache)
    ///
    /// # Returns
    ///
    /// * `Ok(PaymentStatus)` - Verification succeeded
    /// * `Err(Error::Payment)` - No payment and not cached, or payment invalid
    ///
    /// # Errors
    ///
    /// Returns an error if payment is required but not provided, or if payment is invalid.
    pub async fn verify_payment(
        &self,
        xorname: &XorName,
        payment_proof: Option<&[u8]>,
    ) -> Result<PaymentStatus> {
        // First check if payment is required
        let status = self.check_payment_required(xorname);

        match status {
            PaymentStatus::CachedAsVerified => {
                // No payment needed - already in cache
                Ok(status)
            }
            PaymentStatus::PaymentRequired => {
                // Test/devnet mode: EVM disabled - accept with or without proof
                if !self.config.evm.enabled {
                    if tracing::enabled!(tracing::Level::DEBUG) {
                        debug!(
                            "Test mode: Allowing storage without EVM verification (EVM disabled): {}",
                            hex::encode(xorname)
                        );
                    }
                    self.cache.insert(*xorname);
                    return Ok(PaymentStatus::PaymentVerified);
                }

                // Production mode: EVM enabled - verify the proof
                if let Some(proof) = payment_proof {
                    if proof.is_empty() {
                        return Err(Error::Payment("Empty payment proof".to_string()));
                    }
                    if proof.len() < 32 {
                        return Err(Error::Payment(format!(
                            "Payment proof too small: {} bytes (min 32)",
                            proof.len()
                        )));
                    }
                    if proof.len() > 10_240 {
                        return Err(Error::Payment(format!(
                            "Payment proof too large: {} bytes (max 10KB)",
                            proof.len()
                        )));
                    }

                    // Deserialize the ProofOfPayment
                    let payment: ProofOfPayment = rmp_serde::from_slice(proof).map_err(|e| {
                        Error::Payment(format!("Failed to deserialize payment proof: {e}"))
                    })?;

                    // Verify the payment using EVM
                    self.verify_evm_payment(xorname, &payment).await?;

                    // Cache the verified xorname
                    self.cache.insert(*xorname);

                    Ok(PaymentStatus::PaymentVerified)
                } else {
                    // No payment provided in production mode
                    Err(Error::Payment(format!(
                        "Payment required for new data {}",
                        hex::encode(xorname)
                    )))
                }
            }
            PaymentStatus::PaymentVerified => Err(Error::Payment(
                "Unexpected PaymentVerified status from check_payment_required".to_string(),
            )),
        }
    }

    /// Get cache statistics.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Get the number of cached entries.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Check if EVM verification is enabled.
    #[must_use]
    pub fn evm_enabled(&self) -> bool {
        self.config.evm.enabled
    }

    /// Verify an EVM payment proof.
    ///
    /// This is production-only verification that ALWAYS validates payment proofs.
    /// It verifies that:
    /// 1. All quote signatures are valid
    /// 2. The payment was made on-chain
    ///
    /// Test environments should disable EVM at the `verify_payment` level,
    /// not bypass verification here.
    async fn verify_evm_payment(&self, xorname: &XorName, payment: &ProofOfPayment) -> Result<()> {
        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Verifying EVM payment for {} with {} quotes",
                hex::encode(xorname),
                payment.peer_quotes.len()
            );
        }

        // Production-only verification - EVM must be enabled to call this function
        if !self.config.evm.enabled {
            return Err(Error::Payment(
                "EVM verification is disabled - cannot verify payment".to_string(),
            ));
        }

        // Verify quote signatures in parallel (doesn't require network).
        // Each signature verification is CPU-bound and independent, so we can parallelize.
        let verification_futures: Vec<_> = payment
            .peer_quotes
            .iter()
            .map(|(encoded_peer_id, quote)| {
                let encoded_peer_id = encoded_peer_id.clone();
                let quote = quote.clone();
                tokio::task::spawn_blocking(move || {
                    let peer_id = encoded_peer_id.to_peer_id().map_err(|e| {
                        Error::Payment(format!("Invalid peer ID in payment proof: {e}"))
                    })?;

                    if !quote.check_is_signed_by_claimed_peer(peer_id) {
                        return Err(Error::Payment(format!(
                            "Quote signature invalid for peer {peer_id}"
                        )));
                    }
                    Ok(())
                })
            })
            .collect();

        // Wait for all verifications to complete and propagate any errors
        for result in try_join_all(verification_futures)
            .await
            .map_err(|e| Error::Payment(format!("Signature verification task failed: {e}")))?
        {
            result?;
        }

        // Get the payment digest for on-chain verification
        let payment_digest = payment.digest();

        if payment_digest.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        // Verify on-chain payment
        // Note: We pass empty owned_quote_hashes because we're not a node claiming payment,
        // we just want to verify the payment is valid
        let owned_quote_hashes = vec![];
        match evmlib::contract::payment_vault::verify_data_payment(
            &self.config.evm.network,
            owned_quote_hashes,
            payment_digest,
        )
        .await
        {
            Ok(_amount) => {
                if tracing::enabled!(tracing::Level::INFO) {
                    info!("EVM payment verified for {}", hex::encode(xorname));
                }
                Ok(())
            }
            Err(evmlib::contract::payment_vault::error::Error::PaymentInvalid) => {
                Err(Error::Payment(format!(
                    "Payment verification failed on-chain for {}",
                    hex::encode(xorname)
                )))
            }
            Err(e) => Err(Error::Payment(format!(
                "EVM verification error for {}: {e}",
                hex::encode(xorname)
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn create_test_verifier() -> PaymentVerifier {
        let config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                enabled: false, // Disabled for tests
                ..Default::default()
            },
            cache_capacity: 100,
        };
        PaymentVerifier::new(config)
    }

    #[test]
    fn test_payment_required_for_new_data() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // All uncached data requires payment
        let status = verifier.check_payment_required(&xorname);
        assert_eq!(status, PaymentStatus::PaymentRequired);
    }

    #[test]
    fn test_cache_hit() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Manually add to cache
        verifier.cache.insert(xorname);

        // Should return CachedAsVerified
        let status = verifier.check_payment_required(&xorname);
        assert_eq!(status, PaymentStatus::CachedAsVerified);
    }

    #[tokio::test]
    async fn test_verify_payment_without_proof() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Test mode (EVM disabled): Should SUCCEED without payment proof
        // This allows tests to run without needing real EVM payments
        let result = verifier.verify_payment(&xorname, None).await;
        assert!(result.is_ok(), "Expected Ok in test mode, got: {result:?}");
        assert_eq!(
            result.expect("should succeed"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_verify_payment_with_proof() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Create a properly-sized proof
        let proof = ProofOfPayment {
            peer_quotes: vec![],
        };
        let mut proof_bytes = rmp_serde::to_vec(&proof).expect("should serialize");
        // Pad to at least 32 bytes to pass size validation
        proof_bytes.resize(32, 0);

        // EVM disabled (test/devnet mode): should SUCCEED even with a proof present.
        // When EVM is disabled, the verifier skips on-chain checks and accepts storage.
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;
        assert!(result.is_ok(), "Expected Ok in test mode, got: {result:?}");
        assert_eq!(
            result.expect("should succeed"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_verify_payment_cached() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Add to cache
        verifier.cache.insert(xorname);

        // Should succeed without payment (cached)
        let result = verifier.verify_payment(&xorname, None).await;
        assert!(result.is_ok());
        assert_eq!(result.expect("cached"), PaymentStatus::CachedAsVerified);
    }

    #[test]
    fn test_payment_status_can_store() {
        assert!(PaymentStatus::CachedAsVerified.can_store());
        assert!(PaymentStatus::PaymentVerified.can_store());
        assert!(!PaymentStatus::PaymentRequired.can_store());
    }

    #[test]
    fn test_payment_status_is_cached() {
        assert!(PaymentStatus::CachedAsVerified.is_cached());
        assert!(!PaymentStatus::PaymentVerified.is_cached());
        assert!(!PaymentStatus::PaymentRequired.is_cached());
    }
}
