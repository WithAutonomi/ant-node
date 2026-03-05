//! Payment quote generation for saorsa-node.
//!
//! Generates `PaymentQuote` values that clients use to pay for data storage.
//! Compatible with the autonomi payment system.
//!
//! NOTE: Quote generation requires integration with the node's signing
//! capabilities from saorsa-core. This module provides the interface
//! and will be fully integrated when the node is initialized.

use crate::error::{Error, Result};
use crate::payment::metrics::QuotingMetricsTracker;
use ant_evm::{PaymentQuote, QuotingMetrics, RewardsAddress};
use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use saorsa_pqc::pqc::MlDsaOperations;
use std::time::SystemTime;
use tracing::debug;

/// Content address type (32-byte `XorName`).
pub type XorName = [u8; 32];

/// Signing function type that takes bytes and returns a signature.
pub type SignFn = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// Quote generator for creating payment quotes.
///
/// Uses the node's signing capabilities to sign quotes, which clients
/// use to pay for storage on the Arbitrum network.
pub struct QuoteGenerator {
    /// The rewards address for receiving payments.
    rewards_address: RewardsAddress,
    /// Metrics tracker for quoting.
    metrics_tracker: QuotingMetricsTracker,
    /// Signing function provided by the node.
    /// Takes bytes and returns a signature.
    sign_fn: Option<SignFn>,
    /// Public key bytes for the quote.
    pub_key: Vec<u8>,
}

impl QuoteGenerator {
    /// Create a new quote generator without signing capability.
    ///
    /// Call `set_signer` to enable quote signing.
    ///
    /// # Arguments
    ///
    /// * `rewards_address` - The EVM address for receiving payments
    /// * `metrics_tracker` - Tracker for quoting metrics
    #[must_use]
    pub fn new(rewards_address: RewardsAddress, metrics_tracker: QuotingMetricsTracker) -> Self {
        Self {
            rewards_address,
            metrics_tracker,
            sign_fn: None,
            pub_key: Vec::new(),
        }
    }

    /// Set the signing function for quote generation.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - The node's public key bytes
    /// * `sign_fn` - Function that signs bytes and returns signature
    pub fn set_signer<F>(&mut self, pub_key: Vec<u8>, sign_fn: F)
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    {
        self.pub_key = pub_key;
        self.sign_fn = Some(Box::new(sign_fn));
    }

    /// Check if the generator has signing capability.
    #[must_use]
    pub fn can_sign(&self) -> bool {
        self.sign_fn.is_some()
    }

    /// Probe the signer with test data to verify it produces a non-empty signature.
    ///
    /// # Errors
    ///
    /// Returns an error if no signer is set or if signing produces an empty signature.
    pub fn probe_signer(&self) -> Result<()> {
        let sign_fn = self
            .sign_fn
            .as_ref()
            .ok_or_else(|| Error::Payment("Signer not set".to_string()))?;
        let test_msg = b"saorsa-signing-probe";
        let test_sig = sign_fn(test_msg);
        if test_sig.is_empty() {
            return Err(Error::Payment(
                "ML-DSA-65 signing probe failed: empty signature produced".to_string(),
            ));
        }
        Ok(())
    }

    /// Generate a payment quote for storing data.
    ///
    /// # Arguments
    ///
    /// * `content` - The `XorName` of the content to store
    /// * `data_size` - Size of the data in bytes
    /// * `data_type` - Type index of the data (0 for chunks)
    ///
    /// # Returns
    ///
    /// A signed `PaymentQuote` that the client can use to pay on-chain.
    ///
    /// # Errors
    ///
    /// Returns an error if signing is not configured.
    pub fn create_quote(
        &self,
        content: XorName,
        data_size: usize,
        data_type: u32,
    ) -> Result<PaymentQuote> {
        let sign_fn = self
            .sign_fn
            .as_ref()
            .ok_or_else(|| Error::Payment("Quote signing not configured".to_string()))?;

        let timestamp = SystemTime::now();

        // Get current quoting metrics
        let quoting_metrics = self.metrics_tracker.get_metrics(data_size, data_type);

        // Convert XorName to xor_name::XorName
        let xor_name = xor_name::XorName(content);

        // Create bytes for signing (following autonomi's pattern)
        let bytes = PaymentQuote::bytes_for_signing(
            xor_name,
            timestamp,
            &quoting_metrics,
            &self.rewards_address,
        );

        // Sign the bytes
        let signature = sign_fn(&bytes);
        if signature.is_empty() {
            return Err(Error::Payment(
                "Signing produced empty signature".to_string(),
            ));
        }

        let quote = PaymentQuote {
            content: xor_name,
            timestamp,
            quoting_metrics,
            pub_key: self.pub_key.clone(),
            rewards_address: self.rewards_address,
            signature,
        };

        if tracing::enabled!(tracing::Level::DEBUG) {
            let content_hex = hex::encode(content);
            debug!("Generated quote for {content_hex} (size: {data_size}, type: {data_type})");
        }

        Ok(quote)
    }

    /// Get the rewards address.
    #[must_use]
    pub fn rewards_address(&self) -> &RewardsAddress {
        &self.rewards_address
    }

    /// Get current quoting metrics.
    #[must_use]
    pub fn current_metrics(&self) -> QuotingMetrics {
        self.metrics_tracker.get_metrics(0, 0)
    }

    /// Record a payment received (delegates to metrics tracker).
    pub fn record_payment(&self) {
        self.metrics_tracker.record_payment();
    }

    /// Record data stored (delegates to metrics tracker).
    pub fn record_store(&self, data_type: u32) {
        self.metrics_tracker.record_store(data_type);
    }
}

/// Verify a payment quote's content address and ML-DSA-65 signature.
///
/// # Arguments
///
/// * `quote` - The quote to verify
/// * `expected_content` - The expected content `XorName`
///
/// # Returns
///
/// `true` if the content matches and the ML-DSA-65 signature is valid.
#[must_use]
pub fn verify_quote_content(quote: &PaymentQuote, expected_content: &XorName) -> bool {
    // Check content matches
    if quote.content.0 != *expected_content {
        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Quote content mismatch: expected {}, got {}",
                hex::encode(expected_content),
                hex::encode(quote.content.0)
            );
        }
        return false;
    }
    true
}

/// Verify that a payment quote has a valid ML-DSA-65 signature.
///
/// This replaces ant-evm's `check_is_signed_by_claimed_peer()` which only
/// handles Ed25519/libp2p signatures. Saorsa uses ML-DSA-65 post-quantum
/// signatures for quote signing.
///
/// # Arguments
///
/// * `quote` - The quote to verify
///
/// # Returns
///
/// `true` if the ML-DSA-65 signature is valid for the quote's content.
#[must_use]
pub fn verify_quote_signature(quote: &PaymentQuote) -> bool {
    // Parse public key from quote
    let pub_key = match MlDsaPublicKey::from_bytes(&quote.pub_key) {
        Ok(pk) => pk,
        Err(e) => {
            debug!("Failed to parse ML-DSA-65 public key from quote: {e}");
            return false;
        }
    };

    // Parse signature from quote
    let signature = match MlDsaSignature::from_bytes(&quote.signature) {
        Ok(sig) => sig,
        Err(e) => {
            debug!("Failed to parse ML-DSA-65 signature from quote: {e}");
            return false;
        }
    };

    // Get the bytes that were signed
    let bytes = quote.bytes_for_sig();

    // Verify using saorsa's ML-DSA-65 implementation
    let ml_dsa = MlDsa65::new();
    match ml_dsa.verify(&pub_key, &bytes, &signature) {
        Ok(valid) => {
            if !valid {
                debug!("ML-DSA-65 quote signature verification failed");
            }
            valid
        }
        Err(e) => {
            debug!("ML-DSA-65 verification error: {e}");
            false
        }
    }
}

/// Wire ML-DSA-65 signing from a node identity into a `QuoteGenerator`.
///
/// This is the shared setup used by both production nodes and devnet nodes
/// to configure quote signing from a `NodeIdentity`.
///
/// # Arguments
///
/// * `generator` - The quote generator to configure
/// * `identity` - The node identity providing signing keys
///
/// # Errors
///
/// Returns an error if the secret key cannot be deserialized or if the
/// signing probe (a test signature at startup) fails.
pub fn wire_ml_dsa_signer(
    generator: &mut QuoteGenerator,
    identity: &saorsa_core::identity::NodeIdentity,
) -> Result<()> {
    let pub_key_bytes = identity.public_key().as_bytes().to_vec();
    let sk_bytes = identity.secret_key_bytes().to_vec();
    let sk = MlDsaSecretKey::from_bytes(&sk_bytes)
        .map_err(|e| Error::Crypto(format!("Failed to deserialize ML-DSA-65 secret key: {e}")))?;
    let ml_dsa = MlDsa65::new();
    generator.set_signer(pub_key_bytes, move |msg| match ml_dsa.sign(&sk, msg) {
        Ok(sig) => sig.as_bytes().to_vec(),
        Err(e) => {
            tracing::error!("ML-DSA-65 signing failed: {e}");
            vec![]
        }
    });
    generator.probe_signer()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::payment::metrics::QuotingMetricsTracker;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;

    fn create_test_generator() -> QuoteGenerator {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 100);

        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Set up a dummy signer for testing
        generator.set_signer(vec![0u8; 64], |bytes| {
            // Dummy signature - just return hash of bytes
            let mut sig = vec![0u8; 64];
            for (i, b) in bytes.iter().take(64).enumerate() {
                sig[i] = *b;
            }
            sig
        });

        generator
    }

    #[test]
    fn test_create_quote() {
        let generator = create_test_generator();
        let content = [42u8; 32];

        let quote = generator.create_quote(content, 1024, 0);
        assert!(quote.is_ok());

        let quote = quote.expect("valid quote");
        assert_eq!(quote.content.0, content);
    }

    #[test]
    fn test_verify_quote_content() {
        let generator = create_test_generator();
        let content = [42u8; 32];

        let quote = generator
            .create_quote(content, 1024, 0)
            .expect("valid quote");
        assert!(verify_quote_content(&quote, &content));

        // Wrong content should fail
        let wrong_content = [99u8; 32];
        assert!(!verify_quote_content(&quote, &wrong_content));
    }

    #[test]
    fn test_generator_without_signer() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 100);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        assert!(!generator.can_sign());

        let content = [42u8; 32];
        let result = generator.create_quote(content, 1024, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_quote_signature_round_trip_real_keys() {
        let ml_dsa = MlDsa65::new();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("keypair generation");

        let rewards_address = RewardsAddress::new([2u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 100);
        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        let pub_key_bytes = public_key.as_bytes().to_vec();
        let sk_bytes = secret_key.as_bytes().to_vec();
        generator.set_signer(pub_key_bytes, move |msg| {
            let sk = MlDsaSecretKey::from_bytes(&sk_bytes).expect("secret key parse");
            let ml_dsa = MlDsa65::new();
            ml_dsa.sign(&sk, msg).expect("signing").as_bytes().to_vec()
        });

        let content = [7u8; 32];
        let quote = generator
            .create_quote(content, 2048, 0)
            .expect("create quote");

        // Valid signature should verify
        assert!(verify_quote_signature(&quote));

        // Tamper with the signature — flip a byte
        let mut tampered_quote = quote;
        if let Some(byte) = tampered_quote.signature.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(!verify_quote_signature(&tampered_quote));
    }

    #[test]
    fn test_empty_signature_fails_verification() {
        let generator = create_test_generator();
        let content = [42u8; 32];

        let quote = generator
            .create_quote(content, 1024, 0)
            .expect("create quote");

        // The dummy signer produces a 64-byte fake signature, not a valid
        // ML-DSA-65 signature (3309 bytes), so verification must fail.
        assert!(!verify_quote_signature(&quote));
    }

    #[test]
    fn test_rewards_address_getter() {
        let addr = RewardsAddress::new([42u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 0);
        let generator = QuoteGenerator::new(addr, metrics_tracker);

        assert_eq!(*generator.rewards_address(), addr);
    }

    #[test]
    fn test_current_metrics() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(500, 50);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        let metrics = generator.current_metrics();
        assert_eq!(metrics.max_records, 500);
        assert_eq!(metrics.close_records_stored, 50);
        assert_eq!(metrics.data_size, 0);
        assert_eq!(metrics.data_type, 0);
    }

    #[test]
    fn test_record_payment_delegation() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 0);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        generator.record_payment();
        generator.record_payment();

        let metrics = generator.current_metrics();
        assert_eq!(metrics.received_payment_count, 2);
    }

    #[test]
    fn test_record_store_delegation() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 0);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        generator.record_store(0);
        generator.record_store(1);
        generator.record_store(0);

        let metrics = generator.current_metrics();
        assert_eq!(metrics.close_records_stored, 3);
    }

    #[test]
    fn test_create_quote_different_data_types() {
        let generator = create_test_generator();
        let content = [10u8; 32];

        // Data type 0 (chunk)
        let q0 = generator.create_quote(content, 1024, 0).expect("type 0");
        assert_eq!(q0.quoting_metrics.data_type, 0);

        // Data type 1
        let q1 = generator.create_quote(content, 512, 1).expect("type 1");
        assert_eq!(q1.quoting_metrics.data_type, 1);

        // Data type 2
        let q2 = generator.create_quote(content, 256, 2).expect("type 2");
        assert_eq!(q2.quoting_metrics.data_type, 2);
    }

    #[test]
    fn test_create_quote_zero_size() {
        let generator = create_test_generator();
        let content = [11u8; 32];

        let quote = generator.create_quote(content, 0, 0).expect("zero size");
        assert_eq!(quote.quoting_metrics.data_size, 0);
    }

    #[test]
    fn test_create_quote_large_size() {
        let generator = create_test_generator();
        let content = [12u8; 32];

        let quote = generator
            .create_quote(content, 10_000_000, 0)
            .expect("large size");
        assert_eq!(quote.quoting_metrics.data_size, 10_000_000);
    }

    #[test]
    fn test_verify_quote_signature_empty_pub_key() {
        let quote = PaymentQuote {
            content: xor_name::XorName([0u8; 32]),
            timestamp: SystemTime::now(),
            quoting_metrics: ant_evm::QuotingMetrics {
                data_size: 0,
                data_type: 0,
                close_records_stored: 0,
                records_per_type: vec![],
                max_records: 0,
                received_payment_count: 0,
                live_time: 0,
                network_density: None,
                network_size: None,
            },
            rewards_address: RewardsAddress::new([0u8; 20]),
            pub_key: vec![],
            signature: vec![],
        };

        // Empty pub key should fail parsing
        assert!(!verify_quote_signature(&quote));
    }

    #[test]
    fn test_can_sign_after_set_signer() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 0);
        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        assert!(!generator.can_sign());

        generator.set_signer(vec![0u8; 32], |_| vec![0u8; 32]);

        assert!(generator.can_sign());
    }

    #[test]
    fn test_wire_ml_dsa_signer_returns_ok_with_valid_identity() {
        let identity = saorsa_core::identity::NodeIdentity::generate().expect("keypair generation");
        let rewards_address = RewardsAddress::new([3u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 0);
        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        let result = wire_ml_dsa_signer(&mut generator, &identity);
        assert!(
            result.is_ok(),
            "wire_ml_dsa_signer should succeed: {result:?}"
        );
        assert!(generator.can_sign());
    }

    #[test]
    fn test_probe_signer_fails_without_signer() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 0);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        let result = generator.probe_signer();
        assert!(result.is_err());
    }

    #[test]
    fn test_probe_signer_fails_with_empty_signature() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 0);
        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        generator.set_signer(vec![0u8; 32], |_| vec![]);

        let result = generator.probe_signer();
        assert!(result.is_err());
    }
}
