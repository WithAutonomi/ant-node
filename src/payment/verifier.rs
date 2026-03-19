//! Payment verifier with LRU cache and EVM verification.
//!
//! This is the core payment verification logic for saorsa-node.
//! All new data requires EVM payment on Arbitrum (no free tier).

use crate::error::{Error, Result};
use crate::payment::cache::{CacheStats, VerifiedCache, XorName};
use crate::payment::proof::deserialize_proof;
use crate::payment::quote::{verify_quote_content, verify_quote_signature};
use crate::payment::single_node::REQUIRED_QUOTES;
use ant_evm::{ProofOfPayment, RewardsAddress};
use evmlib::Network as EvmNetwork;
use saorsa_core::identity::node_identity::peer_id_from_public_key_bytes;
use std::time::SystemTime;
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

/// Maximum age of a payment quote before it's considered expired (24 hours).
/// Prevents replaying old cheap quotes against nearly-full nodes.
const QUOTE_MAX_AGE_SECS: u64 = 86_400;

/// Maximum allowed clock skew for quote timestamps (60 seconds).
/// Accounts for NTP synchronization differences between P2P nodes.
const QUOTE_CLOCK_SKEW_TOLERANCE_SECS: u64 = 60;

/// Configuration for EVM payment verification.
///
/// EVM verification is always on. All new data requires on-chain
/// payment verification. The network field selects which EVM chain to use.
#[derive(Debug, Clone)]
pub struct EvmVerifierConfig {
    /// EVM network to use (Arbitrum One, Arbitrum Sepolia, etc.)
    pub network: EvmNetwork,
}

impl Default for EvmVerifierConfig {
    fn default() -> Self {
        Self {
            network: EvmNetwork::ArbitrumOne,
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
    /// Local node's rewards address.
    /// The verifier rejects payments that don't include this node as a recipient.
    pub local_rewards_address: RewardsAddress,
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
        info!("Payment verifier initialized (cache_capacity={cache_capacity}, evm=always-on)");

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
                // EVM verification is always on — verify the proof
                if let Some(proof) = payment_proof {
                    let proof_len = proof.len();
                    if proof_len < MIN_PAYMENT_PROOF_SIZE_BYTES {
                        return Err(Error::Payment(format!(
                            "Payment proof too small: {proof_len} bytes (min {MIN_PAYMENT_PROOF_SIZE_BYTES})"
                        )));
                    }
                    if proof_len > MAX_PAYMENT_PROOF_SIZE_BYTES {
                        return Err(Error::Payment(format!(
                            "Payment proof too large: {proof_len} bytes (max {MAX_PAYMENT_PROOF_SIZE_BYTES} bytes)"
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

    /// Pre-populate the payment cache for a given address.
    ///
    /// This marks the address as already paid, so subsequent `verify_payment`
    /// calls will return `CachedAsVerified` without on-chain verification.
    /// Useful for test setups where real EVM payment is not needed.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn cache_insert(&self, xorname: XorName) {
        self.cache.insert(xorname);
    }

    /// Verify an EVM payment proof.
    ///
    /// This verification ALWAYS validates payment proofs on-chain.
    /// It verifies that:
    /// 1. All quotes target the correct content address (xorname binding)
    /// 2. All quote ML-DSA-65 signatures are valid (offloaded to a blocking
    ///    thread via `spawn_blocking` since post-quantum signature verification
    ///    is CPU-intensive)
    /// 3. The payment was made on-chain via the EVM payment vault contract
    ///
    /// For unit tests that don't need on-chain verification, pre-populate
    /// the cache so `verify_payment` returns `CachedAsVerified` before
    /// reaching this method.
    async fn verify_evm_payment(&self, xorname: &XorName, payment: &ProofOfPayment) -> Result<()> {
        if tracing::enabled!(tracing::Level::DEBUG) {
            let xorname_hex = hex::encode(xorname);
            let quote_count = payment.peer_quotes.len();
            debug!("Verifying EVM payment for {xorname_hex} with {quote_count} quotes");
        }

        Self::validate_quote_structure(payment)?;
        Self::validate_quote_content(payment, xorname)?;
        Self::validate_quote_timestamps(payment)?;
        Self::validate_peer_bindings(payment)?;
        self.validate_local_recipient(payment)?;

        // Verify quote signatures (CPU-bound, run off async runtime)
        let peer_quotes = payment.peer_quotes.clone();
        tokio::task::spawn_blocking(move || {
            for (encoded_peer_id, quote) in &peer_quotes {
                if !verify_quote_signature(quote) {
                    return Err(Error::Payment(
                        format!("Quote ML-DSA-65 signature verification failed for peer {encoded_peer_id:?}"),
                    ));
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| Error::Payment(format!("Signature verification task failed: {e}")))??;

        // Verify on-chain payment.
        //
        // The SingleNode payment model pays only the median-priced quote (at 3x)
        // and sends Amount::ZERO for the other 4. evmlib's pay_for_quotes()
        // filters out zero-amount payments, so only 1 quote has an on-chain
        // record. The contract's verifyPayment() returns amountPaid=0 and
        // isValid=false for unpaid quotes, which is expected.
        //
        // We use the amountPaid field to distinguish paid from unpaid results:
        // - At least one quote must have been paid (amountPaid > 0)
        // - ALL paid quotes must be valid (isValid=true)
        // - Unpaid quotes (amountPaid=0) are allowed to be invalid
        //
        // This matches autonomi's strict verification model (all paid must be
        // valid) while accommodating payment models that don't pay every quote.
        let payment_digest = payment.digest();
        if payment_digest.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        let payment_verifications: Vec<_> = payment_digest
            .into_iter()
            .map(
                evmlib::contract::payment_vault::interface::IPaymentVault::PaymentVerification::from,
            )
            .collect();

        let provider = evmlib::utils::http_provider(self.config.evm.network.rpc_url().clone());
        let handler = evmlib::contract::payment_vault::handler::PaymentVaultHandler::new(
            *self.config.evm.network.data_payments_address(),
            provider,
        );

        let results = handler
            .verify_payment(payment_verifications)
            .await
            .map_err(|e| {
                Error::Payment(format!(
                    "EVM verification error for {}: {e}",
                    hex::encode(xorname)
                ))
            })?;

        let paid_results: Vec<_> = results
            .iter()
            .filter(|r| r.amountPaid > evmlib::common::U256::ZERO)
            .collect();

        if paid_results.is_empty() {
            return Err(Error::Payment(format!(
                "Payment verification failed on-chain for {} (no paid quotes found)",
                hex::encode(xorname)
            )));
        }

        for result in &paid_results {
            if !result.isValid {
                return Err(Error::Payment(format!(
                    "Payment verification failed on-chain for {} (paid quote is invalid)",
                    hex::encode(xorname)
                )));
            }
        }

        if tracing::enabled!(tracing::Level::INFO) {
            let valid_count = paid_results.len();
            info!(
                "EVM payment verified for {} ({valid_count} paid and valid, {} total results)",
                hex::encode(xorname),
                results.len()
            );
        }
        Ok(())
    }

    /// Validate quote count, uniqueness, and basic structure.
    fn validate_quote_structure(payment: &ProofOfPayment) -> Result<()> {
        if payment.peer_quotes.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        let quote_count = payment.peer_quotes.len();
        if quote_count != REQUIRED_QUOTES {
            return Err(Error::Payment(format!(
                "Payment must have exactly {REQUIRED_QUOTES} quotes, got {quote_count}"
            )));
        }

        let mut seen: Vec<&ant_evm::EncodedPeerId> = Vec::with_capacity(quote_count);
        for (encoded_peer_id, _) in &payment.peer_quotes {
            if seen.contains(&encoded_peer_id) {
                return Err(Error::Payment(format!(
                    "Duplicate peer ID in payment quotes: {encoded_peer_id:?}"
                )));
            }
            seen.push(encoded_peer_id);
        }

        Ok(())
    }

    /// Verify all quotes target the correct content address.
    fn validate_quote_content(payment: &ProofOfPayment, xorname: &XorName) -> Result<()> {
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            if !verify_quote_content(quote, xorname) {
                return Err(Error::Payment(format!(
                    "Quote content address mismatch for peer {encoded_peer_id:?}: expected {}, got {}",
                    hex::encode(xorname),
                    hex::encode(quote.content.0)
                )));
            }
        }
        Ok(())
    }

    /// Verify quote freshness — reject stale or excessively future quotes.
    fn validate_quote_timestamps(payment: &ProofOfPayment) -> Result<()> {
        let now = SystemTime::now();
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            match now.duration_since(quote.timestamp) {
                Ok(age) => {
                    if age.as_secs() > QUOTE_MAX_AGE_SECS {
                        return Err(Error::Payment(format!(
                            "Quote from peer {encoded_peer_id:?} expired: age {}s exceeds max {QUOTE_MAX_AGE_SECS}s",
                            age.as_secs()
                        )));
                    }
                }
                Err(_) => {
                    if let Ok(skew) = quote.timestamp.duration_since(now) {
                        if skew.as_secs() > QUOTE_CLOCK_SKEW_TOLERANCE_SECS {
                            return Err(Error::Payment(format!(
                                "Quote from peer {encoded_peer_id:?} has timestamp {}s in the future \
                                 (exceeds {QUOTE_CLOCK_SKEW_TOLERANCE_SECS}s tolerance)",
                                skew.as_secs()
                            )));
                        }
                    } else {
                        return Err(Error::Payment(format!(
                            "Quote from peer {encoded_peer_id:?} has invalid timestamp"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Verify each quote's `pub_key` matches the claimed peer ID via BLAKE3.
    fn validate_peer_bindings(payment: &ProofOfPayment) -> Result<()> {
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            let expected_peer_id = peer_id_from_public_key_bytes(&quote.pub_key)
                .map_err(|e| Error::Payment(format!("Invalid ML-DSA public key in quote: {e}")))?;

            let libp2p_peer_id = encoded_peer_id
                .to_peer_id()
                .map_err(|e| Error::Payment(format!("Invalid encoded peer ID: {e}")))?;
            let peer_id_bytes = libp2p_peer_id.to_bytes();
            let raw_peer_bytes = if peer_id_bytes.len() > 2 {
                &peer_id_bytes[2..]
            } else {
                return Err(Error::Payment(format!(
                    "Invalid encoded peer ID: too short ({} bytes)",
                    peer_id_bytes.len()
                )));
            };

            if expected_peer_id.as_bytes() != raw_peer_bytes {
                return Err(Error::Payment(format!(
                    "Quote pub_key does not belong to claimed peer {encoded_peer_id:?}: \
                     BLAKE3(pub_key) = {}, peer_id = {}",
                    expected_peer_id.to_hex(),
                    hex::encode(raw_peer_bytes)
                )));
            }
        }
        Ok(())
    }

    /// Verify this node is among the paid recipients.
    fn validate_local_recipient(&self, payment: &ProofOfPayment) -> Result<()> {
        let local_addr = &self.config.local_rewards_address;
        let is_recipient = payment
            .peer_quotes
            .iter()
            .any(|(_, quote)| quote.rewards_address == *local_addr);
        if !is_recipient {
            return Err(Error::Payment(
                "Payment proof does not include this node as a recipient".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Create a verifier for unit tests. EVM is always on, but tests can
    /// pre-populate the cache to bypass on-chain verification.
    fn create_test_verifier() -> PaymentVerifier {
        let config = PaymentVerifierConfig {
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100,
            local_rewards_address: RewardsAddress::new([1u8; 20]),
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
    async fn test_verify_payment_without_proof_rejected() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // No proof provided => should return an error (EVM is always on)
        let result = verifier.verify_payment(&xorname, None).await;
        assert!(
            result.is_err(),
            "Expected Err without proof, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_verify_payment_cached() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Add to cache — simulates previously-paid data
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
    async fn test_cache_preload_bypasses_evm() {
        let verifier = create_test_verifier();
        let xorname = [42u8; 32];

        // Not yet cached — should require payment
        assert_eq!(
            verifier.check_payment_required(&xorname),
            PaymentStatus::PaymentRequired
        );

        // Pre-populate cache (simulates a previous successful payment)
        verifier.cache.insert(xorname);

        // Now the xorname should be cached
        assert_eq!(
            verifier.check_payment_required(&xorname),
            PaymentStatus::CachedAsVerified
        );
    }

    #[tokio::test]
    async fn test_proof_too_small() {
        let verifier = create_test_verifier();
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
        let verifier = create_test_verifier();
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
        let verifier = create_test_verifier();
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
        let verifier = create_test_verifier();
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
        let verifier = create_test_verifier();
        let xorname = [5u8; 32];

        // Valid size but garbage bytes — should fail deserialization
        let garbage = vec![0xAB; 64];
        let result = verifier.verify_payment(&xorname, Some(&garbage)).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(err_msg.contains("deserialize"));
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
    async fn test_concurrent_cache_lookups() {
        let verifier = std::sync::Arc::new(create_test_verifier());

        // Pre-populate cache for all 10 xornames
        for i in 0..10u8 {
            verifier.cache.insert([i; 32]);
        }

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
            assert_eq!(result.expect("cached"), PaymentStatus::CachedAsVerified);
        }

        assert_eq!(verifier.cache_len(), 10);
    }

    #[test]
    fn test_default_evm_config() {
        let _config = EvmVerifierConfig::default();
        // EVM is always on — default network is ArbitrumOne
    }

    #[test]
    fn test_real_ml_dsa_proof_size_within_limits() {
        use crate::payment::metrics::QuotingMetricsTracker;
        use crate::payment::proof::PaymentProof;
        use crate::payment::quote::{QuoteGenerator, XorName};
        use alloy::primitives::FixedBytes;
        use ant_evm::{EncodedPeerId, RewardsAddress};
        use saorsa_core::MlDsa65;
        use saorsa_pqc::pqc::types::MlDsaSecretKey;
        use saorsa_pqc::pqc::MlDsaOperations;

        let ml_dsa = MlDsa65::new();
        let mut peer_quotes = Vec::new();

        for i in 0..5u8 {
            let (public_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");

            let rewards_address = RewardsAddress::new([i; 20]);
            let metrics_tracker = QuotingMetricsTracker::new(1000, 0);
            let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

            let pub_key_bytes = public_key.as_bytes().to_vec();
            let sk_bytes = secret_key.as_bytes().to_vec();
            generator.set_signer(pub_key_bytes, move |msg| {
                let sk = MlDsaSecretKey::from_bytes(&sk_bytes).expect("sk parse");
                let ml_dsa = MlDsa65::new();
                ml_dsa.sign(&sk, msg).expect("sign").as_bytes().to_vec()
            });

            let content: XorName = [i; 32];
            let quote = generator.create_quote(content, 4096, 0).expect("quote");

            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer_id = libp2p::PeerId::from_public_key(&keypair.public());
            peer_quotes.push((EncodedPeerId::from(peer_id), quote));
        }

        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: vec![FixedBytes::from([0xABu8; 32])],
        };

        let proof_bytes = rmp_serde::to_vec(&proof).expect("serialize");

        // 5 ML-DSA-65 quotes with ~1952-byte pub keys and ~3309-byte signatures
        // should produce a proof in the 20-60 KB range
        assert!(
            proof_bytes.len() > 20_000,
            "Real 5-quote ML-DSA proof should be > 20 KB, got {} bytes",
            proof_bytes.len()
        );
        assert!(
            proof_bytes.len() < MAX_PAYMENT_PROOF_SIZE_BYTES,
            "Real 5-quote ML-DSA proof ({} bytes) should fit within {} byte limit",
            proof_bytes.len(),
            MAX_PAYMENT_PROOF_SIZE_BYTES
        );
    }

    #[tokio::test]
    async fn test_content_address_mismatch_rejected() {
        use crate::payment::proof::PaymentProof;
        use ant_evm::{EncodedPeerId, PaymentQuote, QuotingMetrics, RewardsAddress};
        use libp2p::identity::Keypair;
        use libp2p::PeerId;
        use std::time::SystemTime;

        let verifier = create_test_verifier();

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

        // Build 5 quotes with distinct peer IDs (required by REQUIRED_QUOTES enforcement)
        let mut peer_quotes = Vec::new();
        for _ in 0..5 {
            let keypair = Keypair::generate_ed25519();
            let peer_id = PeerId::from_public_key(&keypair.public());
            peer_quotes.push((EncodedPeerId::from(peer_id), quote.clone()));
        }
        let payment = ProofOfPayment { peer_quotes };

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

    /// Helper: create a fake quote with the given xorname and timestamp.
    fn make_fake_quote(
        xorname: [u8; 32],
        timestamp: SystemTime,
        rewards_address: RewardsAddress,
    ) -> ant_evm::PaymentQuote {
        use ant_evm::{PaymentQuote, QuotingMetrics};

        PaymentQuote {
            content: xor_name::XorName(xorname),
            timestamp,
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
            rewards_address,
            pub_key: vec![0u8; 64],
            signature: vec![0u8; 64],
        }
    }

    /// Helper: wrap quotes into a serialized `PaymentProof`.
    fn serialize_proof(
        peer_quotes: Vec<(ant_evm::EncodedPeerId, ant_evm::PaymentQuote)>,
    ) -> Vec<u8> {
        use crate::payment::proof::PaymentProof;

        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: vec![],
        };
        rmp_serde::to_vec(&proof).expect("serialize proof")
    }

    #[tokio::test]
    async fn test_expired_quote_rejected() {
        use ant_evm::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xCCu8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Create a quote that's 25 hours old (exceeds 24-hour max)
        let old_timestamp = SystemTime::now() - Duration::from_secs(25 * 3600);
        let quote = make_fake_quote(xorname, old_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..5 {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer_id = libp2p::PeerId::from_public_key(&keypair.public());
            peer_quotes.push((EncodedPeerId::from(peer_id), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;

        assert!(result.is_err(), "Should reject expired quote");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("expired"),
            "Error should mention 'expired': {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_future_timestamp_rejected() {
        use ant_evm::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xDDu8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Create a quote with a timestamp 1 hour in the future
        let future_timestamp = SystemTime::now() + Duration::from_secs(3600);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..5 {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer_id = libp2p::PeerId::from_public_key(&keypair.public());
            peer_quotes.push((EncodedPeerId::from(peer_id), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;

        assert!(result.is_err(), "Should reject future-timestamped quote");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("future"),
            "Error should mention 'future': {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quote_within_clock_skew_tolerance_accepted() {
        use ant_evm::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD1u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 30 seconds in the future — within 60s tolerance
        let future_timestamp = SystemTime::now() + Duration::from_secs(30);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..5 {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer_id = libp2p::PeerId::from_public_key(&keypair.public());
            peer_quotes.push((EncodedPeerId::from(peer_id), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;

        // Should NOT fail at timestamp check (will fail later at pub_key binding)
        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("future"),
            "Should pass timestamp check (within tolerance), but got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quote_just_beyond_clock_skew_tolerance_rejected() {
        use ant_evm::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD2u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 120 seconds in the future — exceeds 60s tolerance
        let future_timestamp = SystemTime::now() + Duration::from_secs(120);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..5 {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer_id = libp2p::PeerId::from_public_key(&keypair.public());
            peer_quotes.push((EncodedPeerId::from(peer_id), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;

        assert!(
            result.is_err(),
            "Should reject quote beyond clock skew tolerance"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("future"),
            "Error should mention 'future': {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quote_23h_old_still_accepted() {
        use ant_evm::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD3u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 23 hours old — within 24h max age
        let old_timestamp = SystemTime::now() - Duration::from_secs(23 * 3600);
        let quote = make_fake_quote(xorname, old_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..5 {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer_id = libp2p::PeerId::from_public_key(&keypair.public());
            peer_quotes.push((EncodedPeerId::from(peer_id), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;

        // Should NOT fail at timestamp check (will fail later at pub_key binding)
        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("expired"),
            "Should pass expiry check (23h < 24h), but got: {err_msg}"
        );
    }

    /// Helper: build an `EncodedPeerId` that matches the BLAKE3 hash of an ML-DSA public key.
    fn encoded_peer_id_for_pub_key(pub_key: &[u8]) -> ant_evm::EncodedPeerId {
        let saorsa_peer_id = peer_id_from_public_key_bytes(pub_key).expect("valid ML-DSA pub key");
        // Wrap raw 32-byte peer ID in identity multihash format: [0x00, length, ...bytes]
        let raw = saorsa_peer_id.as_bytes();
        let mut multihash_bytes = Vec::with_capacity(2 + raw.len());
        multihash_bytes.push(0x00); // identity multihash code
                                    // PeerId is always 32 bytes, safely fits in u8
        multihash_bytes.push(u8::try_from(raw.len()).unwrap_or(32));
        multihash_bytes.extend_from_slice(raw);
        let libp2p_peer_id =
            libp2p::PeerId::from_bytes(&multihash_bytes).expect("valid multihash peer ID");
        ant_evm::EncodedPeerId::from(libp2p_peer_id)
    }

    #[tokio::test]
    async fn test_local_not_in_paid_set_rejected() {
        use ant_evm::RewardsAddress;
        use saorsa_core::MlDsa65;
        use saorsa_pqc::pqc::MlDsaOperations;

        // Verifier with a local rewards address set
        let local_addr = RewardsAddress::new([0xAAu8; 20]);
        let config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                network: EvmNetwork::ArbitrumOne,
            },
            cache_capacity: 100,
            local_rewards_address: local_addr,
        };
        let verifier = PaymentVerifier::new(config);

        let xorname = [0xEEu8; 32];
        // Quotes pay a DIFFERENT rewards address
        let other_addr = RewardsAddress::new([0xBBu8; 20]);

        // Use real ML-DSA keys so the pub_key→peer_id binding check passes
        let ml_dsa = MlDsa65::new();
        let mut peer_quotes = Vec::new();
        for _ in 0..5 {
            let (public_key, _secret_key) = ml_dsa.generate_keypair().expect("keygen");
            let pub_key_bytes = public_key.as_bytes().to_vec();
            let encoded = encoded_peer_id_for_pub_key(&pub_key_bytes);

            let mut quote = make_fake_quote(xorname, SystemTime::now(), other_addr);
            quote.pub_key = pub_key_bytes;

            peer_quotes.push((encoded, quote));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;

        assert!(result.is_err(), "Should reject payment not addressed to us");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("does not include this node as a recipient"),
            "Error should mention recipient rejection: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_wrong_peer_binding_rejected() {
        use ant_evm::{EncodedPeerId, RewardsAddress};
        use saorsa_core::MlDsa65;
        use saorsa_pqc::pqc::MlDsaOperations;

        let verifier = create_test_verifier();
        let xorname = [0xFFu8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Generate a real ML-DSA keypair so pub_key is valid
        let ml_dsa = MlDsa65::new();
        let (public_key, _secret_key) = ml_dsa.generate_keypair().expect("keygen");
        let pub_key_bytes = public_key.as_bytes().to_vec();

        // Create a quote with a real pub_key but attach it to a random peer ID
        // whose identity multihash does NOT match BLAKE3(pub_key)
        let mut quote = make_fake_quote(xorname, SystemTime::now(), rewards_addr);
        quote.pub_key = pub_key_bytes;

        // Use random ed25519 peer IDs — they won't match BLAKE3(pub_key)
        let mut peer_quotes = Vec::new();
        for _ in 0..5 {
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer_id = libp2p::PeerId::from_public_key(&keypair.public());
            peer_quotes.push((EncodedPeerId::from(peer_id), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;

        assert!(result.is_err(), "Should reject wrong peer binding");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("pub_key does not belong to claimed peer"),
            "Error should mention binding mismatch: {err_msg}"
        );
    }
}
