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

/// The commitment binding a quote prices against (ADR-0004).
///
/// `key_count` is the leaf count of the pinned commitment and the sole input to
/// the price formula; `pin` is that commitment's hash. A quote carries both,
/// signed, so any receiver can recompute the price and resolve the pin to the
/// signed commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteBinding {
    /// Number of keys in the pinned commitment (the price driver).
    pub key_count: u32,
    /// Hash of the pinned commitment.
    pub pin: [u8; 32],
}

/// Source of the live storage commitment a quote prices against (ADR-0004).
///
/// Implemented by the responder-side commitment state. Decouples
/// [`QuoteGenerator`] from replication internals: the generator only needs the
/// current commitment's `(key_count, pin)` and the guarantee that asking for it
/// refreshes its answerability ("quoting is advertising"). Returns `None` when
/// there is no live current commitment (never rotated, or retired), in which
/// case the node quotes the baseline with no pin.
pub trait CommitmentSource: Send + Sync {
    /// Snapshot the current commitment's binding AND refresh its answerability,
    /// atomically. `None` if there is no live current commitment.
    fn current_binding_for_quote(&self) -> Option<QuoteBinding>;

    /// ADR-0004: the serialized signed commitment for `pin`, if it is still
    /// retained, so the quote response can ship it as a sidecar ("the commitment
    /// arrived with the quote"). Returns the same canonical bytes a peer would
    /// receive via `GetCommitmentByPin`, so the client's pin match is identical
    /// across both resolution paths. `None` if the pin is no longer retained
    /// (in which case the response carries no commitment and the client falls
    /// back to gossip/fetch). Kept separate from [`Self::current_binding_for_quote`]
    /// so the ~5 KB blob is only materialised when a response is being built,
    /// never on the `Copy` pricing path.
    fn commitment_blob_for_pin(&self, pin: [u8; 32]) -> Option<Vec<u8>>;
}

/// Quote generator for creating payment quotes.
///
/// Uses the node's signing capabilities to sign quotes, which clients
/// use to pay for storage on the Arbitrum network.
pub struct QuoteGenerator {
    /// The rewards address for receiving payments.
    rewards_address: RewardsAddress,
    /// In-memory record counter, retained for the `records_stored` /
    /// `record_store` / `resync_records` accounting surface the storage handler
    /// drives.
    ///
    /// ADR-0004: this is NO LONGER a pricing input. A quote's price is bound to
    /// the live storage commitment via [`Self::commitment_source`] (or baseline
    /// when none); the on-disk/side record count no longer sets the price.
    metrics_tracker: QuotingMetricsTracker,
    /// ADR-0004 commitment source: the live storage commitment the price is
    /// bound to. When attached, a quote prices against the committed
    /// (responsible) key count and pins that commitment, refreshing its
    /// answerability on issuance. `None` until [`Self::attach_commitment_source`]
    /// is called — in which case the node falls back to baseline pricing with no
    /// pin (observe-only / pre-rotation / unit tests).
    commitment_source: RwLock<Option<Arc<dyn CommitmentSource>>>,
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
            commitment_source: RwLock::new(None),
            sign_fn: None,
            pub_key: Vec::new(),
        }
    }

    /// Attach the ADR-0004 commitment source so quotes bind their price to the
    /// node's live storage commitment.
    ///
    /// Idempotent: calling twice replaces the handle. Uses interior mutability
    /// so it can be called on an `Arc` after construction. When attached,
    /// [`Self::create_quote`] and [`Self::create_merkle_candidate_quote`] price
    /// against the committed responsible key count, pin the current commitment,
    /// and refresh its answerability. When absent, both fall back to baseline
    /// (no-pin) quotes.
    pub fn attach_commitment_source(&self, source: Arc<dyn CommitmentSource>) {
        *self.commitment_source.write() = Some(source);
        debug!("QuoteGenerator: ADR-0004 commitment source attached");
    }

    /// ADR-0004: the serialized signed commitment for `pin`, so the quote
    /// response can ship it as a sidecar. `None` when no commitment source is
    /// attached (baseline / pre-rotation / tests) or the pin is no longer
    /// retained — in which case the response carries no commitment and the
    /// client falls back to gossip/fetch. Lock is dropped before the (heavier)
    /// blob materialisation in the impl.
    #[must_use]
    pub fn commitment_blob_for_pin(&self, pin: [u8; 32]) -> Option<Vec<u8>> {
        let source = self.commitment_source.read().as_ref().map(Arc::clone);
        source.and_then(|src| src.commitment_blob_for_pin(pin))
    }

    /// Resolve the ADR-0004 pricing inputs a quote should carry, refreshing the
    /// pinned commitment's answerability as a side effect.
    ///
    /// Returns `(committed_key_count, commitment_pin, price_count)`:
    /// - with a live commitment, the price is driven by the committed key count
    ///   and the quote pins that commitment (the ADR-0004 forced price);
    /// - with no commitment source or no live current commitment, the node
    ///   emits a true **baseline** quote: `(0, None)` priced at
    ///   `calculate_price(0)`.
    ///
    /// Critically, the no-commitment branch prices at `0`, NOT at the on-disk
    /// record count. A `(committed_key_count = 0, commitment_pin = None)` quote
    /// is the canonical baseline shape, and ADR-0004's forced-price rule binds
    /// that shape to `calculate_price(0)`. Pricing the no-pin quote off the disk
    /// count would mint a `(0, None, price > baseline)` quote — a shape a
    /// modified node could forge to charge above baseline while carrying no
    /// auditable pin. A node that genuinely holds data prices through its
    /// commitment (the `Some` branch) once it has rotated one; until then it can
    /// only charge baseline, which is correct: it has nothing it can prove.
    ///
    /// Shared by both quote-generation paths so they stay byte-for-byte
    /// consistent in how they bind price to commitment.
    fn resolve_quote_pricing(&self) -> (u32, Option<[u8; 32]>, usize) {
        // Resolve (and drop) the lock guard before branching: the binding is a
        // plain `Copy` value, so the commitment-source lock is never held.
        let binding = self
            .commitment_source
            .read()
            .as_ref()
            .and_then(|src| src.current_binding_for_quote());
        binding.map_or((0u32, None, 0usize), |binding| {
            (
                binding.key_count,
                Some(binding.pin),
                usize::try_from(binding.key_count).unwrap_or(usize::MAX),
            )
        })
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

        // ADR-0004 forced price: when a live commitment exists, the price is a
        // deterministic function of its committed (responsible) key count, and
        // the quote pins that commitment (refreshing its answerability). Absent
        // a commitment source — observe-only, pre-first-rotation, or unit tests
        // — the node emits the canonical baseline quote `(0, None)` priced at
        // `calculate_price(0)`, NOT a price off the on-disk count (see
        // `resolve_quote_pricing`: an unpinned, above-baseline price would be a
        // forgeable shape).
        let (committed_key_count, commitment_pin, price_count) = self.resolve_quote_pricing();
        let price = calculate_price(price_count);

        // Convert XorName to xor_name::XorName
        let xor_name = xor_name::XorName(content);

        // Create bytes for signing (following autonomi's pattern)
        let bytes = PaymentQuote::bytes_for_signing(
            xor_name,
            timestamp,
            &price,
            &self.rewards_address,
            committed_key_count,
            &commitment_pin,
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
            price,
            rewards_address: self.rewards_address,
            committed_key_count,
            commitment_pin,
            pub_key: self.pub_key.clone(),
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

        // ADR-0004 forced price for the merkle-batch candidate, mirroring the
        // single-node path: bind to the live commitment when present, else
        // baseline with no pin.
        let (committed_key_count, commitment_pin, price_count) = self.resolve_quote_pricing();
        let price = calculate_price(price_count);

        // ADR-0004: sign the commitment binding into the merkle candidate
        // payload too (5-field `bytes_to_sign`), so a count/pin mismatch is
        // genuine same-key-signed evidence. ant-protocol verifies this same
        // 5-field message.
        let msg = MerklePaymentCandidateNode::bytes_to_sign(
            &price,
            &self.rewards_address,
            merkle_payment_timestamp,
            committed_key_count,
            &commitment_pin,
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
            committed_key_count,
            commitment_pin,
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

    /// Fixed-binding [`CommitmentSource`] for tests: always reports the same
    /// `(key_count, pin)` so we can assert the forced-price wiring exactly.
    struct FixedCommitmentSource {
        key_count: u32,
        pin: [u8; 32],
    }
    impl CommitmentSource for FixedCommitmentSource {
        fn current_binding_for_quote(&self) -> Option<QuoteBinding> {
            Some(QuoteBinding {
                key_count: self.key_count,
                pin: self.pin,
            })
        }

        fn commitment_blob_for_pin(&self, _pin: [u8; 32]) -> Option<Vec<u8>> {
            // The fixed source has no real commitment to serialize; the
            // forced-price tests assert on the binding, not the sidecar.
            None
        }
    }

    /// ADR-0004 forced price (single-node): with a commitment source attached,
    /// the quote price is exactly `calculate_price(committed_key_count)`, the
    /// quote carries that count, and it pins the commitment hash. This replaces
    /// the pre-ADR-0004 "price tracks on-disk count" behaviour — pricing is now
    /// bound to the signed commitment, not the raw store count.
    #[test]
    fn test_forced_price_binds_to_commitment() {
        let mut generator = QuoteGenerator::new(
            RewardsAddress::new([1u8; 20]),
            QuotingMetricsTracker::new(3),
        );
        generator.set_signer(vec![0u8; 64], |bytes| {
            let mut sig = vec![0u8; 64];
            for (i, b) in bytes.iter().take(64).enumerate() {
                sig[i] = *b;
            }
            sig
        });

        let pin = [7u8; 32];
        generator.attach_commitment_source(Arc::new(FixedCommitmentSource { key_count: 25, pin }));

        let quote = generator
            .create_quote([42u8; 32], 1024, 0)
            .expect("create quote");

        assert_eq!(
            quote.price,
            calculate_price(25),
            "price must be calculate_price(committed_key_count)"
        );
        assert_eq!(
            quote.committed_key_count, 25,
            "quote carries committed count"
        );
        assert_eq!(quote.commitment_pin, Some(pin), "quote pins the commitment");
    }

    /// ADR-0004 baseline: with NO commitment source (fresh node, pre first
    /// rotation), the quote is the canonical baseline shape — `(0, None)` priced
    /// at `calculate_price(0)` — NOT priced off the on-disk count. A node can
    /// only charge baseline until it has a commitment it can be audited against.
    #[test]
    fn test_no_commitment_source_prices_baseline() {
        let mut generator = QuoteGenerator::new(
            RewardsAddress::new([1u8; 20]),
            QuotingMetricsTracker::new(99),
        );
        generator.set_signer(vec![0u8; 64], |bytes| {
            let mut sig = vec![0u8; 64];
            for (i, b) in bytes.iter().take(64).enumerate() {
                sig[i] = *b;
            }
            sig
        });

        let quote = generator
            .create_quote([42u8; 32], 1024, 0)
            .expect("create quote");

        assert_eq!(
            quote.price,
            calculate_price(0),
            "no commitment source must price at baseline calculate_price(0)"
        );
        assert_eq!(quote.committed_key_count, 0);
        assert_eq!(quote.commitment_pin, None);
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
            committed_key_count: 0,
            commitment_pin: None,
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

        // ADR-0004: with no commitment source attached, the merkle candidate is
        // a baseline quote — price `calculate_price(0)`, count 0, no pin —
        // regardless of the side counter. Pricing is bound to the commitment,
        // not the metrics tracker.
        assert_eq!(candidate.price, calculate_price(0));
        assert_eq!(candidate.committed_key_count, 0);
        assert_eq!(candidate.commitment_pin, None);

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

        let msg = MerklePaymentCandidateNode::bytes_to_sign(
            &price,
            &rewards_address,
            timestamp,
            0,
            &None,
        );
        let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
        let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

        MerklePaymentCandidateNode {
            pub_key: public_key.as_bytes().to_vec(),
            price,
            reward_address: rewards_address,
            merkle_payment_timestamp: timestamp,
            committed_key_count: 0,
            commitment_pin: None,
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
