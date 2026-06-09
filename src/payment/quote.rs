//! Payment quote generation for ant-node.
//!
//! Generates `PaymentQuote` values that clients use to pay for data storage.
//! Compatible with the Autonomi payment system.
//!
//! NOTE: Quote generation requires integration with the node's signing
//! capabilities from saorsa-core. This module provides the interface
//! and will be fully integrated when the node is initialized.

use crate::error::{Error, Result};
use crate::logging::debug;
use crate::payment::metrics::QuotingMetricsTracker;
use crate::payment::pricing::calculate_price;
use crate::storage::lmdb::LmdbStorage;
use evmlib::merkle_payments::MerklePaymentCandidateNode;
use evmlib::PaymentQuote;
use evmlib::RewardsAddress;
use parking_lot::RwLock;
use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::MlDsaSecretKey;
use saorsa_pqc::pqc::MlDsaOperations;
use std::sync::Arc;
use std::time::SystemTime;

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
    /// Fallback in-memory record counter for pricing.
    ///
    /// Only consulted when no [`LmdbStorage`] is attached (unit tests, or a
    /// mis-configured startup). In production the price is derived from the
    /// attached store's `current_chunks()` instead — see [`Self::storage`].
    metrics_tracker: QuotingMetricsTracker,
    /// Authoritative on-disk record-count source for pricing.
    ///
    /// When attached, quote prices are computed from
    /// [`LmdbStorage::current_chunks()`] — the **same** count the
    /// [`PaymentVerifier`](crate::payment::PaymentVerifier) freshness gate
    /// compares the quote against. Keeping pricing and freshness on one source
    /// means a quote priced at record count `N` is later checked against a
    /// current count that differs only by genuine in-flight growth, instead of
    /// by the standing client-PUT-vs-replication gap that rejected every
    /// payment when pricing read the side counter and freshness read the store.
    /// `None` until [`Self::attach_storage`] is called.
    storage: RwLock<Option<Arc<LmdbStorage>>>,
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
            storage: RwLock::new(None),
            sign_fn: None,
            pub_key: Vec::new(),
        }
    }

    /// Attach the node's [`LmdbStorage`] so quote prices reflect the
    /// authoritative on-disk record count.
    ///
    /// This MUST be wired to the same `LmdbStorage` the
    /// [`PaymentVerifier`](crate::payment::PaymentVerifier) freshness gate reads
    /// via `current_chunks()`; otherwise pricing and freshness diverge and the
    /// gate rejects healthy payments. Idempotent: calling twice replaces the
    /// handle. Uses interior mutability so it can be called on an `Arc`.
    pub fn attach_storage(&self, storage: Arc<LmdbStorage>) {
        *self.storage.write() = Some(storage);
        debug!("QuoteGenerator: LmdbStorage attached for current-records pricing");
    }

    /// Record count used to price quotes.
    ///
    /// Prefers the attached `LmdbStorage` count (authoritative — counts client
    /// PUTs, replication stores, and repair fetches alike, exactly matching the
    /// verifier's freshness source). Falls back to the in-memory
    /// `metrics_tracker` when no storage is attached or the read fails, so
    /// pricing never panics or stalls.
    fn pricing_records_stored(&self) -> usize {
        if let Some(storage) = self.storage.read().as_ref() {
            match storage.current_chunks() {
                Ok(n) => return usize::try_from(n).unwrap_or(usize::MAX),
                Err(e) => {
                    debug!(
                        "QuoteGenerator: current_chunks() failed ({e}); \
                         falling back to metrics_tracker for pricing"
                    );
                }
            }
        }
        self.metrics_tracker.records_stored()
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
        let test_msg = b"ant-signing-probe";
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

        // Calculate price from the authoritative current record count (the same
        // count the verifier's freshness gate reads), falling back to the
        // in-memory counter only when no storage is attached.
        let price = calculate_price(self.pricing_records_stored());

        // Convert XorName to xor_name::XorName
        let xor_name = xor_name::XorName(content);

        // Create bytes for signing (following autonomi's pattern)
        let bytes =
            PaymentQuote::bytes_for_signing(xor_name, timestamp, &price, &self.rewards_address);

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
            price,
            pub_key: self.pub_key.clone(),
            rewards_address: self.rewards_address,
            signature,
        };

        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
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

    /// Get the current number of records stored.
    #[must_use]
    pub fn records_stored(&self) -> usize {
        self.metrics_tracker.records_stored()
    }

    /// Record data stored (delegates to metrics tracker).
    pub fn record_store(&self) {
        self.metrics_tracker.record_store();
    }

    /// Resync the quoting metric to an authoritative count of held records.
    ///
    /// The quote price is driven by `records_stored()`. A monotonic store
    /// counter would let a node delete chunks it was paid to hold yet keep
    /// quoting as if it still held everything. Callers pass the authoritative
    /// count of records the node ACTUALLY HOLDS (from the storage layer) so the
    /// price reflects current holdings, including deletions and pruning.
    pub fn resync_records(&self, count: usize) {
        self.metrics_tracker.set_records(count);
    }

    /// Create a merkle candidate quote for batch payment using ML-DSA-65.
    ///
    /// Returns a `MerklePaymentCandidateNode` constructed with the node's
    /// ML-DSA-65 public key and signature. This uses the same post-quantum
    /// signing stack as regular payment quotes, rather than the ed25519
    /// signing that the upstream `ant-evm` library assumes.
    ///
    /// The `pub_key` field stores the raw ML-DSA-65 public key bytes,
    /// and `signature` stores the ML-DSA-65 signature over `bytes_to_sign()`.
    /// Clients verify these using `verify_merkle_candidate_signature()`.
    ///
    /// # Errors
    ///
    /// Returns an error if signing is not configured.
    pub fn create_merkle_candidate_quote(
        &self,
        data_size: usize,
        data_type: u32,
        merkle_payment_timestamp: u64,
    ) -> Result<MerklePaymentCandidateNode> {
        let sign_fn = self
            .sign_fn
            .as_ref()
            .ok_or_else(|| Error::Payment("Quote signing not configured".to_string()))?;

        let price = calculate_price(self.pricing_records_stored());

        // Compute the same bytes_to_sign used by the upstream library
        let msg = MerklePaymentCandidateNode::bytes_to_sign(
            &price,
            &self.rewards_address,
            merkle_payment_timestamp,
        );

        // Sign with ML-DSA-65
        let signature = sign_fn(&msg);
        if signature.is_empty() {
            return Err(Error::Payment(
                "ML-DSA-65 signing produced empty signature for merkle candidate".to_string(),
            ));
        }

        let candidate = MerklePaymentCandidateNode {
            pub_key: self.pub_key.clone(),
            price,
            reward_address: self.rewards_address,
            merkle_payment_timestamp,
            signature,
        };

        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
            debug!(
                "Generated ML-DSA-65 merkle candidate quote (size: {data_size}, type: {data_type}, ts: {merkle_payment_timestamp})"
            );
        }

        Ok(candidate)
    }
}

// Wire-side signature verification (`verify_quote_content`,
// `verify_quote_signature`, `verify_merkle_candidate_signature`) lives
// in `ant_protocol::payment::verify`. Re-exported from
// `crate::payment` for backwards compatibility.

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
            crate::logging::error!("ML-DSA-65 signing failed: {e}");
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
    // Verification helpers live in ant-protocol; import them here so the
    // long-standing node-side negative tests (tampered keys, swapped
    // pub keys, wrong timestamp, etc.) keep running against the canonical
    // wire-side implementation.
    use ant_protocol::payment::verify::{
        verify_merkle_candidate_signature, verify_quote_content, verify_quote_signature,
    };
    use evmlib::common::Amount;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;

    fn create_test_generator() -> QuoteGenerator {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(100);

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

    /// Regression test for the STG-01 quote-freshness rejection: pricing must
    /// read the attached store's `current_chunks()`, NOT the side counter.
    ///
    /// Before the fix, the price came from `metrics_tracker` (client-PUT count
    /// only) while the verifier's freshness gate read `current_chunks()` (all
    /// records, including replicated ones). On a replicating network the store
    /// count ran far ahead of the side counter, so every quote looked "stale".
    /// Here we attach a store, write records WITHOUT touching the side counter
    /// (mimicking replication stores), and assert the quote prices off the
    /// store count — i.e. the two sources now agree.
    #[tokio::test]
    async fn test_pricing_tracks_attached_storage_not_side_counter() {
        use crate::payment::pricing::derive_records_stored_from_price;
        use crate::storage::{LmdbStorage, LmdbStorageConfig};
        use tempfile::TempDir;

        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(
            LmdbStorage::new(LmdbStorageConfig {
                root_dir: temp_dir.path().to_path_buf(),
                ..LmdbStorageConfig::test_default()
            })
            .await
            .expect("create storage"),
        );

        // Side counter deliberately starts well BELOW the store count to model
        // a node whose records arrived mostly via replication (which never
        // increments the side counter).
        let metrics_tracker = QuotingMetricsTracker::new(3);
        let mut generator = QuoteGenerator::new(RewardsAddress::new([1u8; 20]), metrics_tracker);
        generator.set_signer(vec![0u8; 64], |bytes| {
            let mut sig = vec![0u8; 64];
            for (i, b) in bytes.iter().take(64).enumerate() {
                sig[i] = *b;
            }
            sig
        });
        generator.attach_storage(Arc::clone(&storage));

        // Write 25 distinct records straight to the store, as a replication
        // store would — the side counter stays at 3.
        for i in 0..25u32 {
            let content = format!("replicated-record-{i}");
            let address = LmdbStorage::compute_address(content.as_bytes());
            storage
                .put(&address, content.as_bytes())
                .await
                .expect("put");
        }
        assert_eq!(
            generator.records_stored(),
            3,
            "side counter must be untouched"
        );
        assert_eq!(storage.current_chunks().expect("count"), 25);

        let quote = generator
            .create_quote([42u8; 32], 1024, 0)
            .expect("create quote");

        // Price must encode 25 (the store count), not 3 (the side counter).
        assert_eq!(
            quote.price,
            calculate_price(25),
            "price must be derived from current_chunks(), not metrics_tracker"
        );
        assert_eq!(
            derive_records_stored_from_price(quote.price),
            25,
            "verifier's price-inverse must recover the store count, keeping the \
             freshness delta at ~0 for a freshly issued quote"
        );
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
        let metrics_tracker = QuotingMetricsTracker::new(100);
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
        let metrics_tracker = QuotingMetricsTracker::new(100);
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
        let metrics_tracker = QuotingMetricsTracker::new(0);
        let generator = QuoteGenerator::new(addr, metrics_tracker);

        assert_eq!(*generator.rewards_address(), addr);
    }

    #[test]
    fn test_records_stored() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(50);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        assert_eq!(generator.records_stored(), 50);
    }

    #[test]
    fn test_record_store_delegation() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(0);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        generator.record_store();
        generator.record_store();
        generator.record_store();

        assert_eq!(generator.records_stored(), 3);
    }

    #[test]
    fn test_create_quote_different_data_types() {
        let generator = create_test_generator();
        let content = [10u8; 32];

        // All data types produce the same price (price depends on records_stored, not data_type)
        let q0 = generator.create_quote(content, 1024, 0).expect("type 0");
        let q1 = generator.create_quote(content, 512, 1).expect("type 1");
        let q2 = generator.create_quote(content, 256, 2).expect("type 2");

        // All quotes should have a valid price (minimum floor of 1)
        assert!(q0.price >= Amount::from(1u64));
        assert!(q1.price >= Amount::from(1u64));
        assert!(q2.price >= Amount::from(1u64));
    }

    #[test]
    fn test_create_quote_zero_size() {
        let generator = create_test_generator();
        let content = [11u8; 32];

        // Price depends on records_stored, not data size
        let quote = generator.create_quote(content, 0, 0).expect("zero size");
        assert!(quote.price >= Amount::from(1u64));
    }

    #[test]
    fn test_create_quote_large_size() {
        let generator = create_test_generator();
        let content = [12u8; 32];

        // Price depends on records_stored, not data size
        let quote = generator
            .create_quote(content, 10_000_000, 0)
            .expect("large size");
        assert!(quote.price >= Amount::from(1u64));
    }

    #[test]
    fn test_verify_quote_signature_empty_pub_key() {
        let quote = PaymentQuote {
            content: xor_name::XorName([0u8; 32]),
            timestamp: SystemTime::now(),
            price: Amount::from(1u64),
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
        let metrics_tracker = QuotingMetricsTracker::new(0);
        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        assert!(!generator.can_sign());

        generator.set_signer(vec![0u8; 32], |_| vec![0u8; 32]);

        assert!(generator.can_sign());
    }

    #[test]
    fn test_wire_ml_dsa_signer_returns_ok_with_valid_identity() {
        let identity = saorsa_core::identity::NodeIdentity::generate().expect("keypair generation");
        let rewards_address = RewardsAddress::new([3u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(0);
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
        let metrics_tracker = QuotingMetricsTracker::new(0);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        let result = generator.probe_signer();
        assert!(result.is_err());
    }

    #[test]
    fn test_probe_signer_fails_with_empty_signature() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(0);
        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        generator.set_signer(vec![0u8; 32], |_| vec![]);

        let result = generator.probe_signer();
        assert!(result.is_err());
    }

    #[test]
    fn test_create_merkle_candidate_quote_with_ml_dsa() {
        let ml_dsa = MlDsa65::new();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("keypair generation");

        let rewards_address = RewardsAddress::new([0x42u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(50);
        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing (same as production nodes)
        let pub_key_bytes = public_key.as_bytes().to_vec();
        let sk_bytes = secret_key.as_bytes().to_vec();
        generator.set_signer(pub_key_bytes.clone(), move |msg| {
            let sk = MlDsaSecretKey::from_bytes(&sk_bytes).expect("sk parse");
            let ml_dsa = MlDsa65::new();
            ml_dsa.sign(&sk, msg).expect("sign").as_bytes().to_vec()
        });

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let result = generator.create_merkle_candidate_quote(2048, 0, timestamp);

        assert!(
            result.is_ok(),
            "create_merkle_candidate_quote should succeed: {result:?}"
        );

        let candidate = result.expect("valid candidate");

        // Verify the returned node has the correct reward address
        assert_eq!(candidate.reward_address, rewards_address);

        // Verify the timestamp was set correctly
        assert_eq!(candidate.merkle_payment_timestamp, timestamp);

        // Verify price was calculated from records_stored using the pricing formula
        assert_eq!(candidate.price, calculate_price(50));

        // Verify the public key is the ML-DSA-65 public key (not ed25519)
        assert_eq!(
            candidate.pub_key, pub_key_bytes,
            "Public key should be raw ML-DSA-65 bytes"
        );

        // Verify ML-DSA-65 signature is valid using our verifier
        assert!(
            verify_merkle_candidate_signature(&candidate),
            "ML-DSA-65 merkle candidate signature must be valid"
        );

        // Verify tampered timestamp invalidates ML-DSA signature
        let mut tampered = candidate;
        tampered.merkle_payment_timestamp = timestamp + 1;
        assert!(
            !verify_merkle_candidate_signature(&tampered),
            "Tampered timestamp should invalidate the ML-DSA-65 signature"
        );
    }

    // =========================================================================
    // verify_merkle_candidate_signature — direct tests
    // =========================================================================

    /// Helper: create a validly-signed `MerklePaymentCandidateNode`.
    fn make_valid_merkle_candidate() -> MerklePaymentCandidateNode {
        let ml_dsa = MlDsa65::new();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");

        let rewards_address = RewardsAddress::new([0xABu8; 20]);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        let price = Amount::from(42u64);

        let msg = MerklePaymentCandidateNode::bytes_to_sign(&price, &rewards_address, timestamp);
        let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
        let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

        MerklePaymentCandidateNode {
            pub_key: public_key.as_bytes().to_vec(),
            price,
            reward_address: rewards_address,
            merkle_payment_timestamp: timestamp,
            signature,
        }
    }

    #[test]
    fn test_verify_merkle_candidate_valid_signature() {
        let candidate = make_valid_merkle_candidate();
        assert!(
            verify_merkle_candidate_signature(&candidate),
            "Freshly signed merkle candidate must verify"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_tampered_pub_key() {
        let mut candidate = make_valid_merkle_candidate();
        // Flip a byte in the public key
        if let Some(byte) = candidate.pub_key.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(
            !verify_merkle_candidate_signature(&candidate),
            "Tampered pub_key must invalidate the signature"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_tampered_reward_address() {
        let mut candidate = make_valid_merkle_candidate();
        candidate.reward_address = RewardsAddress::new([0xFFu8; 20]);
        assert!(
            !verify_merkle_candidate_signature(&candidate),
            "Tampered reward_address must invalidate the signature"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_tampered_price() {
        let mut candidate = make_valid_merkle_candidate();
        candidate.price = Amount::from(999_999u64);
        assert!(
            !verify_merkle_candidate_signature(&candidate),
            "Tampered price must invalidate the signature"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_tampered_signature_byte() {
        let mut candidate = make_valid_merkle_candidate();
        if let Some(byte) = candidate.signature.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(
            !verify_merkle_candidate_signature(&candidate),
            "Tampered signature byte must fail verification"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_empty_pub_key() {
        let mut candidate = make_valid_merkle_candidate();
        candidate.pub_key = vec![];
        assert!(
            !verify_merkle_candidate_signature(&candidate),
            "Empty pub_key must fail verification"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_empty_signature() {
        let mut candidate = make_valid_merkle_candidate();
        candidate.signature = vec![];
        assert!(
            !verify_merkle_candidate_signature(&candidate),
            "Empty signature must fail verification"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_wrong_length_signature() {
        let mut candidate = make_valid_merkle_candidate();
        // ML-DSA-65 signatures are 3309 bytes; use a truncated one
        candidate.signature = vec![0xAA; 100];
        assert!(
            !verify_merkle_candidate_signature(&candidate),
            "Wrong-length signature must fail verification"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_wrong_length_pub_key() {
        let mut candidate = make_valid_merkle_candidate();
        // ML-DSA-65 pub keys are 1952 bytes; use a truncated one
        candidate.pub_key = vec![0xBB; 100];
        assert!(
            !verify_merkle_candidate_signature(&candidate),
            "Wrong-length pub_key must fail verification"
        );
    }

    #[test]
    fn test_verify_merkle_candidate_cross_key_rejection() {
        // Sign with one key pair, then swap in a different valid public key
        let candidate = make_valid_merkle_candidate();
        let ml_dsa = MlDsa65::new();
        let (other_pk, _) = ml_dsa.generate_keypair().expect("keygen");

        let mut swapped = candidate;
        swapped.pub_key = other_pk.as_bytes().to_vec();
        assert!(
            !verify_merkle_candidate_signature(&swapped),
            "Signature from key A must not verify under key B"
        );
    }
}
