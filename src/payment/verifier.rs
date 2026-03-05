//! Payment verifier with LRU cache and EVM verification.
//!
//! This is the core payment verification logic for saorsa-node.
//! All new data requires EVM payment on Arbitrum (no free tier).

use crate::error::{Error, Result};
use crate::payment::cache::{CacheStats, VerifiedCache, XorName};
use crate::payment::proof::deserialize_proof;
use crate::payment::quote::verify_quote_content;
use ant_evm::ProofOfPayment;
use evmlib::contract::payment_vault::error::Error as PaymentVaultError;
use evmlib::contract::payment_vault::verify_data_payment;
use evmlib::Network as EvmNetwork;
use tracing::{debug, info};

/// Minimum allowed size for a payment proof in bytes.
///
/// This minimum ensures the proof contains at least a basic cryptographic hash or identifier.
/// Proofs smaller than this are rejected as they cannot contain sufficient payment information.
const MIN_PAYMENT_PROOF_SIZE_BYTES: usize = 32;

/// Maximum allowed size for a payment proof in bytes (100 KB).
///
/// A `ProofOfPayment` with 5 ML-DSA-65 quotes can reach ~30 KB (each quote carries a
/// ~1,952-byte public key and a 3,309-byte signature plus metadata). 100 KB provides
/// headroom for future fields while still capping memory during verification.
const MAX_PAYMENT_PROOF_SIZE_BYTES: usize = 102_400;

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

        let cache_capacity = config.cache_capacity;
        let evm_enabled = config.evm.enabled;
        info!("Payment verifier initialized (cache_capacity={cache_capacity}, evm_enabled={evm_enabled})");

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
                    if proof.len() < MIN_PAYMENT_PROOF_SIZE_BYTES {
                        return Err(Error::Payment(format!(
                            "Payment proof too small: {} bytes (min {})",
                            proof.len(),
                            MIN_PAYMENT_PROOF_SIZE_BYTES
                        )));
                    }
                    if proof.len() > MAX_PAYMENT_PROOF_SIZE_BYTES {
                        return Err(Error::Payment(format!(
                            "Payment proof too large: {} bytes (max {} bytes)",
                            proof.len(),
                            MAX_PAYMENT_PROOF_SIZE_BYTES
                        )));
                    }

                    // Deserialize the proof (supports both new PaymentProof and legacy ProofOfPayment)
                    let (payment, tx_hashes) = deserialize_proof(proof).map_err(|e| {
                        Error::Payment(format!("Failed to deserialize payment proof: {e}"))
                    })?;

                    if !tx_hashes.is_empty() {
                        debug!("Proof includes {} transaction hash(es)", tx_hashes.len());
                    }

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
            let xorname_hex = hex::encode(xorname);
            let quote_count = payment.peer_quotes.len();
            debug!("Verifying EVM payment for {xorname_hex} with {quote_count} quotes");
        }

        // Invariant: this function is only called when EVM is enabled (checked by verify_payment)
        debug_assert!(self.config.evm.enabled);

        if payment.peer_quotes.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        // Verify that ALL quotes were issued for the correct content address.
        // This prevents an attacker from paying for chunk A and reusing
        // that proof to store chunks B, C, D, etc.
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            if !verify_quote_content(quote, xorname) {
                return Err(Error::Payment(format!(
                    "Quote content address mismatch for peer {encoded_peer_id:?}: expected {}, got {}",
                    hex::encode(xorname),
                    hex::encode(quote.content.0)
                )));
            }
        }

        // Verify quote signatures using ML-DSA-65 (post-quantum).
        // We use our own verification instead of ant-evm's check_is_signed_by_claimed_peer()
        // which only supports Ed25519/libp2p signatures.
        // TODO: Verify that quote.pub_key belongs to encoded_peer_id.
        // Currently we verify the signature is valid for the pub_key IN the quote,
        // but don't verify that pub_key actually belongs to the claimed peer.
        // Signature verification is CPU-bound, so we run it off the async runtime.
        let peer_quotes = payment.peer_quotes.clone();
        tokio::task::spawn_blocking(move || {
            for (encoded_peer_id, quote) in &peer_quotes {
                if !crate::payment::quote::verify_quote_signature(quote) {
                    return Err(Error::Payment(
                        format!("Quote ML-DSA-65 signature verification failed for peer {encoded_peer_id:?}"),
                    ));
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| Error::Payment(format!("Signature verification task failed: {e}")))??;

        // Get the payment digest for on-chain verification
        let payment_digest = payment.digest();

        if payment_digest.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        // Verify on-chain payment
        // Note: We pass empty owned_quote_hashes because we're not a node claiming payment,
        // we just want to verify the payment is valid
        let owned_quote_hashes = vec![];
        match verify_data_payment(&self.config.evm.network, owned_quote_hashes, payment_digest)
            .await
        {
            Ok(_amount) => {
                if tracing::enabled!(tracing::Level::INFO) {
                    info!("EVM payment verified for {}", hex::encode(xorname));
                }
                Ok(())
            }
            Err(PaymentVaultError::PaymentInvalid) => Err(Error::Payment(format!(
                "Payment verification failed on-chain for {}",
                hex::encode(xorname)
            ))),
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

    fn create_evm_enabled_verifier() -> PaymentVerifier {
        let config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                enabled: true,
                network: EvmNetwork::ArbitrumOne,
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
        // Pad to minimum required size to pass validation
        proof_bytes.resize(MIN_PAYMENT_PROOF_SIZE_BYTES, 0);

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

    #[tokio::test]
    async fn test_verifier_caches_after_successful_verification() {
        let verifier = create_test_verifier();
        let xorname = [42u8; 32];

        // Not yet cached — should require payment
        assert_eq!(
            verifier.check_payment_required(&xorname),
            PaymentStatus::PaymentRequired
        );

        // Verify payment (EVM disabled, so it succeeds and caches)
        let result = verifier.verify_payment(&xorname, None).await;
        assert!(result.is_ok());
        assert_eq!(result.expect("verified"), PaymentStatus::PaymentVerified);

        // Now the xorname should be cached
        assert_eq!(
            verifier.check_payment_required(&xorname),
            PaymentStatus::CachedAsVerified
        );
    }

    #[tokio::test]
    async fn test_verifier_rejects_without_proof_when_evm_enabled() {
        let verifier = create_evm_enabled_verifier();
        let xorname = [99u8; 32];

        // EVM enabled + no proof provided => should return an error
        let result = verifier.verify_payment(&xorname, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_proof_too_small() {
        let verifier = create_evm_enabled_verifier();
        let xorname = [1u8; 32];

        // Proof smaller than MIN_PAYMENT_PROOF_SIZE_BYTES
        let small_proof = vec![0u8; MIN_PAYMENT_PROOF_SIZE_BYTES - 1];
        let result = verifier.verify_payment(&xorname, Some(&small_proof)).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("too small"),
            "Error should mention 'too small': {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_proof_too_large() {
        let verifier = create_evm_enabled_verifier();
        let xorname = [2u8; 32];

        // Proof larger than MAX_PAYMENT_PROOF_SIZE_BYTES
        let large_proof = vec![0u8; MAX_PAYMENT_PROOF_SIZE_BYTES + 1];
        let result = verifier.verify_payment(&xorname, Some(&large_proof)).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("too large"),
            "Error should mention 'too large': {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_proof_at_min_boundary() {
        let verifier = create_evm_enabled_verifier();
        let xorname = [3u8; 32];

        // Exactly MIN_PAYMENT_PROOF_SIZE_BYTES — passes size check, but
        // will fail deserialization (not valid msgpack)
        let boundary_proof = vec![0xFFu8; MIN_PAYMENT_PROOF_SIZE_BYTES];
        let result = verifier
            .verify_payment(&xorname, Some(&boundary_proof))
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail deser"));
        assert!(
            err_msg.contains("deserialize"),
            "Error should mention deserialization: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_proof_at_max_boundary() {
        let verifier = create_evm_enabled_verifier();
        let xorname = [4u8; 32];

        // Exactly MAX_PAYMENT_PROOF_SIZE_BYTES — passes size check, but
        // will fail deserialization
        let boundary_proof = vec![0xFFu8; MAX_PAYMENT_PROOF_SIZE_BYTES];
        let result = verifier
            .verify_payment(&xorname, Some(&boundary_proof))
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail deser"));
        assert!(
            err_msg.contains("deserialize"),
            "Error should mention deserialization: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_malformed_msgpack_proof() {
        let verifier = create_evm_enabled_verifier();
        let xorname = [5u8; 32];

        // Valid size but garbage bytes — should fail deserialization
        let garbage = vec![0xAB; 64];
        let result = verifier.verify_payment(&xorname, Some(&garbage)).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(err_msg.contains("deserialize"));
    }

    #[test]
    fn test_evm_enabled_getter() {
        let verifier = create_test_verifier();
        assert!(!verifier.evm_enabled());

        let verifier = create_evm_enabled_verifier();
        assert!(verifier.evm_enabled());
    }

    #[test]
    fn test_cache_len_getter() {
        let verifier = create_test_verifier();
        assert_eq!(verifier.cache_len(), 0);

        verifier.cache.insert([10u8; 32]);
        assert_eq!(verifier.cache_len(), 1);

        verifier.cache.insert([20u8; 32]);
        assert_eq!(verifier.cache_len(), 2);
    }

    #[test]
    fn test_cache_stats_after_operations() {
        let verifier = create_test_verifier();
        let xorname = [7u8; 32];

        // Miss
        verifier.check_payment_required(&xorname);
        let stats = verifier.cache_stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Insert and hit
        verifier.cache.insert(xorname);
        verifier.check_payment_required(&xorname);
        let stats = verifier.cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.additions, 1);
    }

    #[tokio::test]
    async fn test_concurrent_verify_payment() {
        let verifier = std::sync::Arc::new(create_test_verifier());
        let mut handles = Vec::new();

        for i in 0..10u8 {
            let v = verifier.clone();
            handles.push(tokio::spawn(async move {
                let xorname = [i; 32];
                v.verify_payment(&xorname, None).await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task panicked");
            assert!(result.is_ok());
        }

        // All 10 should be cached
        assert_eq!(verifier.cache_len(), 10);
    }

    #[test]
    fn test_default_config() {
        let config = PaymentVerifierConfig::default();
        assert!(config.evm.enabled);
        assert_eq!(config.cache_capacity, 100_000);
    }

    #[test]
    fn test_default_evm_config() {
        let config = EvmVerifierConfig::default();
        assert!(config.enabled);
    }

    #[tokio::test]
    async fn test_content_address_mismatch_rejected() {
        use crate::payment::proof::PaymentProof;
        use ant_evm::{EncodedPeerId, PaymentQuote, QuotingMetrics, RewardsAddress};
        use libp2p::identity::Keypair;
        use libp2p::PeerId;
        use std::time::SystemTime;

        let verifier = create_evm_enabled_verifier();

        // The xorname we're trying to store
        let target_xorname = [0xAAu8; 32];

        // Create a quote for a DIFFERENT xorname
        let wrong_xorname = [0xBBu8; 32];
        let quote = PaymentQuote {
            content: xor_name::XorName(wrong_xorname),
            timestamp: SystemTime::now(),
            quoting_metrics: QuotingMetrics {
                data_size: 1024,
                data_type: 0,
                close_records_stored: 0,
                records_per_type: vec![],
                max_records: 1000,
                received_payment_count: 0,
                live_time: 0,
                network_density: None,
                network_size: None,
            },
            rewards_address: RewardsAddress::new([1u8; 20]),
            pub_key: vec![0u8; 64],
            signature: vec![0u8; 64],
        };

        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        let payment = ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::from(peer_id), quote)],
        };

        let proof = PaymentProof {
            proof_of_payment: payment,
            tx_hashes: vec![],
        };

        let proof_bytes = rmp_serde::to_vec(&proof).expect("serialize proof");

        let result = verifier
            .verify_payment(&target_xorname, Some(&proof_bytes))
            .await;

        assert!(result.is_err(), "Should reject mismatched content address");
        let err_msg = format!("{}", result.expect_err("should be error"));
        assert!(
            err_msg.contains("content address mismatch"),
            "Error should mention 'content address mismatch': {err_msg}"
        );
    }
}
