//! Payment verifier with LRU cache and EVM verification.
//!
//! This is the core payment verification logic for ant-node.
//! All new data requires EVM payment on Arbitrum (no free tier).

use crate::ant_protocol::CLOSE_GROUP_SIZE;
use crate::error::{Error, Result};
use crate::logging::{debug, info};
use crate::payment::cache::{CacheStats, VerifiedCache, XorName};
use crate::payment::proof::{
    deserialize_merkle_proof, deserialize_proof, detect_proof_type, ProofType,
};
use crate::payment::quote::{verify_quote_content, verify_quote_signature};
use crate::payment::single_node::SingleNodePayment;
use evmlib::common::Amount;
use evmlib::contract::payment_vault;
use evmlib::merkle_batch_payment::{OnChainPaymentInfo, PoolHash};
use evmlib::Network as EvmNetwork;
use evmlib::ProofOfPayment;
use evmlib::RewardsAddress;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use saorsa_core::identity::node_identity::peer_id_from_public_key_bytes;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::SystemTime;

/// Minimum allowed size for a payment proof in bytes.
///
/// This minimum ensures the proof contains at least a basic cryptographic hash or identifier.
/// Proofs smaller than this are rejected as they cannot contain sufficient payment information.
pub const MIN_PAYMENT_PROOF_SIZE_BYTES: usize = 32;

/// Maximum allowed size for a payment proof in bytes (256 KB).
///
/// Single-node proofs with 7 ML-DSA-65 quotes reach ~40 KB.
/// Merkle proofs include 16 candidate nodes (each with ~1,952-byte ML-DSA pub key
/// and ~3,309-byte signature) plus merkle branch hashes, totaling ~130 KB.
/// 256 KB provides headroom while still capping memory during verification.
pub const MAX_PAYMENT_PROOF_SIZE_BYTES: usize = 262_144;

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

/// Default capacity for the merkle pool cache (number of pool hashes to cache).
const DEFAULT_POOL_CACHE_CAPACITY: usize = 1_000;

/// Main payment verifier for ant-node.
///
/// Uses:
/// 1. LRU cache for fast lookups of previously verified `XorName` values
/// 2. EVM payment verification for new data (always required)
/// 3. Pool-level cache for merkle batch payments (avoids repeated on-chain queries)
pub struct PaymentVerifier {
    /// LRU cache of verified `XorName` values.
    cache: VerifiedCache,
    /// LRU cache of verified merkle pool hashes → on-chain payment info.
    pool_cache: Mutex<LruCache<PoolHash, OnChainPaymentInfo>>,
    /// LRU cache of pool hashes whose candidate closeness has already been
    /// verified by this node. Collapses the per-chunk Kademlia lookup cost
    /// within a batch (256 chunks × 1 pool = 1 lookup instead of 256).
    closeness_pass_cache: Mutex<LruCache<PoolHash, ()>>,
    /// In-flight closeness lookups, keyed by pool hash. Lets concurrent PUTs
    /// for the same pool coalesce onto a single Kademlia lookup AND share
    /// its result — on both success and failure — which bounds `DoS`
    /// amplification to one lookup per unique `pool_hash` regardless of
    /// concurrency.
    inflight_closeness: Mutex<LruCache<PoolHash, Arc<ClosenessSlot>>>,
    /// P2P node handle, attached post-construction so merkle verification can
    /// check that candidate `pub_keys` map to peers actually close to the pool
    /// midpoint in the live DHT. `None` in unit tests that don't exercise
    /// merkle verification; production startup MUST call [`attach_p2p_node`].
    p2p_node: RwLock<Option<Arc<P2PNode>>>,
    /// Configuration.
    config: PaymentVerifierConfig,
}

/// Shared state for an inflight closeness verification. The leader publishes
/// its result via the `OnceLock`; waiters read that result directly instead
/// of racing on a cache re-check. Wrapped in an `Arc` and held both by the
/// leader's drop guard and by each waiting task.
struct ClosenessSlot {
    notify: Arc<tokio::sync::Notify>,
    /// `Some(Ok(()))` on success, `Some(Err(msg))` on failure, `None` if the
    /// leader disappeared without publishing (panic, cancellation).
    result: std::sync::OnceLock<std::result::Result<(), String>>,
}

impl ClosenessSlot {
    fn new() -> Self {
        Self {
            notify: Arc::new(tokio::sync::Notify::new()),
            result: std::sync::OnceLock::new(),
        }
    }

    /// Build an owned `Notified` future that snapshots the `notify_waiters`
    /// counter at call time. Awaiting this future after dropping external
    /// locks is race-free: if `notify_waiters` fires between construction
    /// and the first poll, the snapshot mismatch resolves the future
    /// immediately.
    fn notified_owned(&self) -> tokio::sync::futures::OwnedNotified {
        Arc::clone(&self.notify).notified_owned()
    }
}

/// Drop guard that publishes the leader's result, clears the inflight slot,
/// and wakes all waiters. Fires on every exit path: success, failure, panic,
/// future-cancellation.
///
/// The guard owns its own `Arc<ClosenessSlot>` so `notify_waiters` still
/// fires even if LRU pressure evicted the slot before the leader finished.
/// Waiters see the published result via `result.get()`; the `Notify` is only
/// the wake-up signal.
struct InflightGuard<'a> {
    slot_cache: &'a Mutex<LruCache<PoolHash, Arc<ClosenessSlot>>>,
    pool_hash: PoolHash,
    slot: Arc<ClosenessSlot>,
}

impl InflightGuard<'_> {
    /// Publish the leader's result. Called exactly once by the leader on
    /// every successful or explicit-error exit. If dropped without calling
    /// (panic, cancellation) the guard still wakes waiters but leaves
    /// `result` empty, which waiters treat as a transient failure and retry.
    fn publish(&self, result: &Result<()>) {
        let stored: std::result::Result<(), String> = match result {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        };
        let _ = self.slot.result.set(stored);
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        // Remove the slot entry if it's still ours. A separate leader may
        // have inserted a new slot for the same pool_hash after LRU
        // eviction — don't pop someone else's entry.
        {
            let mut cache = self.slot_cache.lock();
            if let Some(existing) = cache.peek(&self.pool_hash) {
                if Arc::ptr_eq(existing, &self.slot) {
                    cache.pop(&self.pool_hash);
                }
            }
        }
        // Wake every waiter registered against OUR slot, regardless of
        // whether the cache entry is still ours.
        self.slot.notify.notify_waiters();
    }
}

impl PaymentVerifier {
    /// Create a new payment verifier.
    #[must_use]
    pub fn new(config: PaymentVerifierConfig) -> Self {
        const _: () = assert!(
            DEFAULT_POOL_CACHE_CAPACITY > 0,
            "pool cache capacity must be > 0"
        );
        let cache = VerifiedCache::with_capacity(config.cache_capacity);
        let pool_cache_size =
            NonZeroUsize::new(DEFAULT_POOL_CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        let pool_cache = Mutex::new(LruCache::new(pool_cache_size));
        let closeness_pass_cache = Mutex::new(LruCache::new(pool_cache_size));
        let inflight_closeness = Mutex::new(LruCache::new(pool_cache_size));

        let cache_capacity = config.cache_capacity;
        info!("Payment verifier initialized (cache_capacity={cache_capacity}, evm=always-on, pool_cache={DEFAULT_POOL_CACHE_CAPACITY})");

        // Loud warning if a production binary was accidentally built with
        // `test-utils`: that feature flips the closeness-check fail-open
        // switch, disabling the pay-yourself defence when P2PNode isn't
        // attached. Safe in tests, never intended for prod.
        #[cfg(feature = "test-utils")]
        crate::logging::error!(
            "PaymentVerifier: built with `test-utils` feature — merkle closeness \
             defence falls back to fail-open when no P2PNode is attached. This \
             feature is for test binaries only; production nodes must be built \
             without it."
        );

        Self {
            cache,
            pool_cache,
            closeness_pass_cache,
            inflight_closeness,
            p2p_node: RwLock::new(None),
            config,
        }
    }

    /// Attach the node's [`P2PNode`] handle so merkle-payment verification can
    /// check candidate `pub_keys` against the DHT's actual closest peers to the
    /// pool midpoint.
    ///
    /// Production startup MUST call this once the `P2PNode` exists. Without
    /// it, the closeness check fails CLOSED in release builds (rejects the
    /// PUT with a visible error) and fails open in test builds. Idempotent:
    /// calling twice replaces the handle.
    pub fn attach_p2p_node(&self, node: Arc<P2PNode>) {
        *self.p2p_node.write() = Some(node);
        debug!("PaymentVerifier: P2PNode attached for merkle closeness checks");
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
            if crate::logging::enabled!(crate::logging::Level::DEBUG) {
                debug!("Data {} found in verified cache", hex::encode(xorname));
            }
            return PaymentStatus::CachedAsVerified;
        }

        // Not in cache - payment required
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
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

                    // Detect proof type from version tag byte
                    match detect_proof_type(proof) {
                        Some(ProofType::Merkle) => {
                            self.verify_merkle_payment(xorname, proof).await?;
                        }
                        Some(ProofType::SingleNode) => {
                            let (payment, tx_hashes) = deserialize_proof(proof).map_err(|e| {
                                Error::Payment(format!("Failed to deserialize payment proof: {e}"))
                            })?;

                            if !tx_hashes.is_empty() {
                                debug!("Proof includes {} transaction hash(es)", tx_hashes.len());
                            }

                            self.verify_evm_payment(xorname, &payment).await?;
                        }
                        None => {
                            let tag = proof.first().copied().unwrap_or(0);
                            return Err(Error::Payment(format!(
                                "Unknown payment proof type tag: 0x{tag:02x}"
                            )));
                        }
                    }

                    // Cache the verified xorname
                    self.cache.insert(*xorname);

                    Ok(PaymentStatus::PaymentVerified)
                } else {
                    // No payment provided in production mode
                    let xorname_hex = hex::encode(xorname);
                    Err(Error::Payment(format!(
                        "Payment required for new data {xorname_hex}"
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

    /// Pre-populate the merkle pool cache. Testing helper that lets e2e tests
    /// bypass the on-chain `completedMerklePayments` lookup when the point of
    /// the test is to exercise merkle-verification logic BEFORE the on-chain
    /// call (e.g. the pay-yourself closeness check).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn pool_cache_insert(&self, pool_hash: PoolHash, info: OnChainPaymentInfo) {
        let mut cache = self.pool_cache.lock();
        cache.put(pool_hash, info);
    }

    /// Verify a single-node EVM payment proof.
    ///
    /// Verification steps:
    /// 1. Exactly `CLOSE_GROUP_SIZE` quotes are present
    /// 2. All quotes target the correct content address (xorname binding)
    /// 3. Quote timestamps are fresh (not expired or future-dated)
    /// 4. Peer ID bindings match the ML-DSA-65 public keys
    /// 5. This node is among the quoted recipients
    /// 6. All ML-DSA-65 signatures are valid (offloaded to `spawn_blocking`)
    /// 7. The median-priced quote was paid at least 3x its price on-chain
    ///    (looked up via `completedPayments(quoteHash)` on the payment vault)
    ///
    /// For unit tests that don't need on-chain verification, pre-populate
    /// the cache so `verify_payment` returns `CachedAsVerified` before
    /// reaching this method.
    async fn verify_evm_payment(&self, xorname: &XorName, payment: &ProofOfPayment) -> Result<()> {
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
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

        // Reconstruct the SingleNodePayment to identify the median quote.
        // from_quotes() sorts by price and marks the median for 3x payment.
        let quotes_with_prices: Vec<_> = payment
            .peer_quotes
            .iter()
            .map(|(_, quote)| (quote.clone(), quote.price))
            .collect();
        let single_payment = SingleNodePayment::from_quotes(quotes_with_prices).map_err(|e| {
            Error::Payment(format!(
                "Failed to reconstruct payment for verification: {e}"
            ))
        })?;

        // Verify the median quote was paid at least 3x its price on-chain
        // via completedPayments(quoteHash) on the payment vault contract.
        let verified_amount = single_payment
            .verify(&self.config.evm.network)
            .await
            .map_err(|e| {
                let xorname_hex = hex::encode(xorname);
                Error::Payment(format!(
                    "Median quote payment verification failed for {xorname_hex}: {e}"
                ))
            })?;

        if crate::logging::enabled!(crate::logging::Level::INFO) {
            let xorname_hex = hex::encode(xorname);
            info!("EVM payment verified for {xorname_hex} (median paid {verified_amount} atto)");
        }
        Ok(())
    }

    /// Validate quote count, uniqueness, and basic structure.
    fn validate_quote_structure(payment: &ProofOfPayment) -> Result<()> {
        if payment.peer_quotes.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        let quote_count = payment.peer_quotes.len();
        if quote_count != CLOSE_GROUP_SIZE {
            return Err(Error::Payment(format!(
                "Payment must have exactly {CLOSE_GROUP_SIZE} quotes, got {quote_count}"
            )));
        }

        let mut seen: Vec<&evmlib::EncodedPeerId> = Vec::with_capacity(quote_count);
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
                let expected_hex = hex::encode(xorname);
                let actual_hex = hex::encode(quote.content.0);
                return Err(Error::Payment(format!(
                    "Quote content address mismatch for peer {encoded_peer_id:?}: expected {expected_hex}, got {actual_hex}"
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

            if expected_peer_id.as_bytes() != encoded_peer_id.as_bytes() {
                let expected_hex = expected_peer_id.to_hex();
                let actual_hex = hex::encode(encoded_peer_id.as_bytes());
                return Err(Error::Payment(format!(
                    "Quote pub_key does not belong to claimed peer {encoded_peer_id:?}: \
                     BLAKE3(pub_key) = {expected_hex}, peer_id = {actual_hex}"
                )));
            }
        }
        Ok(())
    }

    /// Minimum number of candidate `pub_keys` (out of 16) whose derived `PeerId`
    /// must match the DHT's actual closest peers to the pool midpoint address.
    ///
    /// Set below 16/16 to absorb normal routing-table skew between the
    /// payer's view and this node's view — on a well-connected network the
    /// divergence between two nodes' closest-set views is typically 1-2
    /// peers, occasionally 3 during churn. 13/16 tolerates 3 divergent
    /// peers while still limiting how many candidates an attacker can
    /// fabricate before the check bites. A lower threshold (e.g. 9/16)
    /// would let an attacker who controls 7 real neighbourhood peers plant
    /// 7 fabricated candidates and still pass.
    ///
    /// This is the pure "fabricated key" defence; it does not stop an
    /// attacker who can grind the pool midpoint address to land near 13
    /// pre-chosen keys AND run those keys as Sybil DHT participants. That
    /// requires an orthogonal Sybil-resistance layer and is out of scope
    /// for this check.
    const CANDIDATE_CLOSENESS_REQUIRED: usize = 13;

    /// Timeout for the authoritative network lookup used by the closeness
    /// check.
    ///
    /// Iterative Kademlia lookups can cascade through up to 20 iterations,
    /// and a single unresponsive peer's dial can take 20-30s before timing
    /// out. 60s leaves room for the lookup to converge even under churn
    /// while still capping `DoS` amplification at roughly one bounded lookup
    /// per forged `pool_hash`.
    const CLOSENESS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    /// Maximum waiter → leader retries when the leader's future was cancelled
    /// or panicked before publishing a result. Beyond this the waiter returns
    /// a visible error rather than spinning indefinitely through a
    /// cancellation cascade.
    const MAX_LEADER_RETRIES: usize = 4;

    /// Verify that the candidate pool's `pub_keys` correspond to peers that
    /// are actually XOR-closest to the pool midpoint address, by querying
    /// the DHT for its closest peers to that address and requiring that a
    /// majority of the candidates match.
    ///
    /// **What this blocks**: the "pay yourself" attack. Candidate signatures
    /// only cover `(price, reward_address, timestamp)` and the `pub_key` bytes —
    /// nothing ties a candidate to a network-registered identity or to the
    /// pool neighbourhood. Without this check an attacker can generate 16
    /// ML-DSA keypairs locally, point all 16 `reward_address` fields at a
    /// single attacker-controlled wallet, submit the merkle payment, and drain
    /// their own payment back out.
    ///
    /// **How it blocks**: each candidate's `PeerId = BLAKE3(pub_key)`; the DHT
    /// is the authoritative source of "which peers exist at this XOR
    /// coordinate". If the attacker's 16 fabricated `PeerId`s are not among
    /// the peers the network actually lists as closest to the pool address,
    /// the pool is forged.
    ///
    /// **Scope**: a `MerklePaymentProof` carries exactly one `winner_pool`
    /// (the pool the smart contract selected for the batch). Every storing
    /// node that receives the proof independently re-runs this check against
    /// that same pool, so a forged pool is rejected at every node it
    /// reaches.
    ///
    /// **Known limitation — Sybil-grinding**: `midpoint_proof.address()` is a
    /// BLAKE3 hash of attacker-controllable inputs (leaf bytes, tree root,
    /// timestamp). A determined attacker who *also* runs Sybil DHT nodes can
    /// grind the midpoint until it lands in a region where 13 of their
    /// Sybil keys are the true network-closest — at which point this check
    /// passes for the attacker. Closing that gap requires binding the
    /// midpoint to an attacker-uncontrolled value (e.g. a block hash at
    /// payment time or an on-chain VRF) or a Sybil-resistant identity
    /// layer. This defence raises the attack cost from "free" to "run N
    /// Sybil nodes AND grind", which is a meaningful but not complete
    /// improvement.
    async fn verify_merkle_candidate_closeness(
        &self,
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
        pool_hash: PoolHash,
    ) -> Result<()> {
        // Fast path: this node already verified this pool successfully.
        // A batch of 256 chunks shares one winner_pool, so without this cache
        // we'd pay a Kademlia lookup per chunk.
        if self.closeness_pass_cache.lock().get(&pool_hash).is_some() {
            return Ok(());
        }

        // Single-flight: on each attempt, either claim leadership by
        // inserting a fresh `ClosenessSlot`, or wait on an existing leader
        // and read its published result. The leader holds an `Arc` to the
        // slot independent of the LruCache so waiters are still woken if
        // eviction pressure kicked the cache entry.
        //
        // The `notified_owned()` future snapshots the `notify_waiters`
        // counter at the moment of construction (while we hold the lock),
        // which makes the subsequent `.await` race-free: if the leader
        // calls `notify_waiters` between our construction and our poll, the
        // counter has advanced and the future resolves immediately on first
        // poll.
        //
        // Bounded retry: if we're a waiter and the leader gets cancelled or
        // panics (slot.result.get() == None after wake-up), we loop back to
        // claim leadership. `MAX_LEADER_RETRIES` bounds the attempts so
        // adversarial cancellation cascades cannot spin this indefinitely.
        for attempt in 0..=Self::MAX_LEADER_RETRIES {
            // Release the mutex guard explicitly before any await below.
            // Clippy wants `if let ... else` written as `map_or_else`, but
            // any such rewrite re-borrows the locked `inflight` inside the
            // closure and fails the borrow checker — so the lint is
            // silenced here.
            #[allow(clippy::option_if_let_else)]
            let (waiter_slot, leader_slot) = {
                let mut inflight = self.inflight_closeness.lock();
                let chosen = if let Some(existing) = inflight.get(&pool_hash) {
                    (Some(Arc::clone(existing)), None)
                } else {
                    let slot = Arc::new(ClosenessSlot::new());
                    inflight.put(pool_hash, Arc::clone(&slot));
                    (None, Some(slot))
                };
                drop(inflight);
                chosen
            };

            if let Some(slot) = waiter_slot {
                // Build the owned-notified future BEFORE awaiting, so it
                // snapshots the `notify_waiters` counter now. The slot
                // already existed when we locked, so the leader is either
                // running or finished; in both cases the snapshot + counter
                // check ensures we wake up correctly.
                let notified = slot.notified_owned();
                notified.await;

                // Leader published a result — use it directly.
                if let Some(result) = slot.result.get() {
                    return result.clone().map_err(Error::Payment);
                }
                // Leader disappeared without publishing (panic or
                // cancellation). Slot was cleared by the leader's drop
                // guard; loop to become the new leader — unless we've
                // hit the retry bound (see MAX_LEADER_RETRIES).
                if attempt == Self::MAX_LEADER_RETRIES {
                    return Err(Error::Payment(
                        "Merkle candidate pool rejected: closeness leader \
                         repeatedly failed to publish a result (likely \
                         repeated cancellation or panic)."
                            .into(),
                    ));
                }
                continue;
            }

            // Leader path. Drop guard clears the slot and wakes waiters on
            // every exit (success, failure, panic, cancellation).
            let Some(slot) = leader_slot else {
                // Unreachable by construction.
                return Err(Error::Payment(
                    "internal error: neither leader nor waiter in closeness check".into(),
                ));
            };
            let guard = InflightGuard {
                slot_cache: &self.inflight_closeness,
                pool_hash,
                slot,
            };

            let result = self.verify_merkle_candidate_closeness_inner(pool).await;
            guard.publish(&result);
            if result.is_ok() {
                self.closeness_pass_cache.lock().put(pool_hash, ());
            }
            return result;
        }
        // Unreachable: the for-loop body always either `return`s or `continue`s,
        // and the waiter branch's `continue` only runs when `attempt <
        // Self::MAX_LEADER_RETRIES`. The last iteration's waiter branch returns
        // via the retry-bound check; the leader branch always returns.
        Err(Error::Payment(
            "internal error: closeness retry loop exited without returning".into(),
        ))
    }

    /// Inner closeness check: the actual DHT lookup + set-membership test.
    /// Wrapped by [`verify_merkle_candidate_closeness`] with a pass-cache and
    /// single-flight guard so a batch of chunks and a storm of forged PUTs
    /// don't multiply the lookup cost.
    async fn verify_merkle_candidate_closeness_inner(
        &self,
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
    ) -> Result<()> {
        // Release the RwLock guard before any await to avoid holding it
        // across an iterative Kademlia lookup.
        let attached = self.p2p_node.read().as_ref().map(Arc::clone);
        let Some(p2p_node) = attached else {
            // Production must call attach_p2p_node at startup. Fail CLOSED
            // to avoid silently disabling the defence if a startup path
            // regresses and loses the attach call. Unit-test builds that
            // construct a PaymentVerifier directly without exercising merkle
            // verification are opted-in via `test-utils` to fall back to
            // fail-open.
            #[cfg(any(test, feature = "test-utils"))]
            {
                crate::logging::warn!(
                    "PaymentVerifier: no P2PNode attached; merkle pay-yourself \
                     defence SKIPPED (test build). Production startup MUST call \
                     PaymentVerifier::attach_p2p_node."
                );
                return Ok(());
            }
            #[cfg(not(any(test, feature = "test-utils")))]
            {
                crate::logging::error!(
                    "PaymentVerifier: no P2PNode attached; rejecting merkle \
                     payment. This is a node-startup bug — \
                     PaymentVerifier::attach_p2p_node must be called before \
                     any PUT handler runs."
                );
                return Err(Error::Payment(
                    "Merkle candidate pool rejected: verifier is not wired to \
                     the P2P layer; cannot verify candidate closeness."
                        .into(),
                ));
            }
        };

        let pool_address = pool.midpoint_proof.address();

        // Derive each candidate's would-be PeerId from its pub_key. Fail
        // closed on malformed keys — the candidate signature check ran
        // upstream so a valid-looking pool ought to parse cleanly here.
        let mut candidate_peer_ids = Vec::with_capacity(pool.candidate_nodes.len());
        for candidate in &pool.candidate_nodes {
            let pid = peer_id_from_public_key_bytes(&candidate.pub_key).map_err(|e| {
                Error::Payment(format!(
                    "Invalid ML-DSA public key in merkle candidate: {e}"
                ))
            })?;
            candidate_peer_ids.push(pid);
        }

        let lookup_count = pool.candidate_nodes.len();
        let network_lookup = p2p_node
            .dht_manager()
            .find_closest_nodes_network(&pool_address.0, lookup_count);
        let network_peers =
            match tokio::time::timeout(Self::CLOSENESS_LOOKUP_TIMEOUT, network_lookup).await {
                Ok(Ok(peers)) => peers,
                Ok(Err(e)) => {
                    debug!(
                        "Merkle closeness network-lookup failed for pool midpoint {}: {e}",
                        hex::encode(pool_address.0),
                    );
                    return Err(Error::Payment(
                        "Merkle candidate pool rejected: could not verify candidate \
                     closeness against the authoritative network view."
                            .into(),
                    ));
                }
                Err(_) => {
                    debug!(
                        "Merkle closeness network-lookup timeout ({:?}) for pool midpoint {}",
                        Self::CLOSENESS_LOOKUP_TIMEOUT,
                        hex::encode(pool_address.0),
                    );
                    return Err(Error::Payment(
                        "Merkle candidate pool rejected: authoritative network lookup \
                     timed out. Retry once the network lookup completes."
                            .into(),
                    ));
                }
            };

        // Set-membership check against the returned closest-peers list. The
        // lookup may return fewer than `lookup_count` on a sparse network,
        // which only tightens the bar — any candidate not in the returned
        // list counts as unmatched.
        let network_set: std::collections::HashSet<PeerId> =
            network_peers.iter().map(|n| n.peer_id).collect();
        let matched = candidate_peer_ids
            .iter()
            .filter(|pid| network_set.contains(pid))
            .count();

        if matched < Self::CANDIDATE_CLOSENESS_REQUIRED {
            debug!(
                "Merkle closeness rejected: {matched}/{} candidates match the DHT's closest peers \
                 for pool midpoint {} (required: {}, network returned {} peers)",
                pool.candidate_nodes.len(),
                hex::encode(pool_address.0),
                Self::CANDIDATE_CLOSENESS_REQUIRED,
                network_peers.len(),
            );
            return Err(Error::Payment(
                "Merkle candidate pool rejected: candidate pub_keys do not match the \
                 network's closest peers to the pool midpoint address. Pools must be \
                 collected from the pool-address close group, not fabricated off-network."
                    .into(),
            ));
        }

        debug!(
            "Merkle closeness passed: {matched}/{} candidates matched the DHT's closest peers \
             for pool midpoint {}",
            pool.candidate_nodes.len(),
            hex::encode(pool_address.0),
        );
        Ok(())
    }

    /// Verify a merkle batch payment proof.
    ///
    /// This verification flow:
    /// 1. Deserialize the `MerklePaymentProof`
    /// 2. Check pool cache for previously verified pool hash
    /// 3. If not cached, query on-chain for payment info
    /// 4. Validate the proof against on-chain data
    /// 5. Cache the pool hash for subsequent chunk verifications in the same batch
    #[allow(clippy::too_many_lines)]
    async fn verify_merkle_payment(&self, xorname: &XorName, proof_bytes: &[u8]) -> Result<()> {
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
            debug!("Verifying merkle payment for {}", hex::encode(xorname));
        }

        // Deserialize the merkle proof
        let merkle_proof = deserialize_merkle_proof(proof_bytes)
            .map_err(|e| Error::Payment(format!("Failed to deserialize merkle proof: {e}")))?;

        // Verify the address in the proof matches the xorname being stored
        if merkle_proof.address.0 != *xorname {
            let proof_hex = hex::encode(merkle_proof.address.0);
            let store_hex = hex::encode(xorname);
            return Err(Error::Payment(format!(
                "Merkle proof address mismatch: proof is for {proof_hex}, but storing {store_hex}"
            )));
        }

        let pool_hash = merkle_proof.winner_pool_hash();

        // Run cheap local checks BEFORE expensive on-chain queries.
        // This prevents DoS via garbage proofs that trigger RPC lookups.
        for candidate in &merkle_proof.winner_pool.candidate_nodes {
            if !crate::payment::verify_merkle_candidate_signature(candidate) {
                return Err(Error::Payment(format!(
                    "Invalid ML-DSA-65 signature on merkle candidate node (reward: {})",
                    candidate.reward_address
                )));
            }
        }

        // Pay-yourself defence: the candidate pub_keys must map to peers the
        // live DHT actually considers closest to the pool midpoint. Without
        // this, an attacker can point all 16 reward_address fields at a
        // self-owned wallet and drain their own payment. Every storing node
        // runs this check against the single `winner_pool` in the proof, so a
        // forged pool is rejected everywhere it lands. The pass cache and
        // single-flight keyed on pool_hash collapse the Kademlia lookup cost
        // within a batch and across concurrent PUTs for the same pool.
        self.verify_merkle_candidate_closeness(&merkle_proof.winner_pool, pool_hash)
            .await?;

        // Check pool cache first
        let cached_info = {
            let mut pool_cache = self.pool_cache.lock();
            pool_cache.get(&pool_hash).cloned()
        };

        let payment_info = if let Some(info) = cached_info {
            debug!("Pool cache hit for hash {}", hex::encode(pool_hash));
            info
        } else {
            // Query on-chain for completed merkle payment
            let info =
                payment_vault::get_completed_merkle_payment(&self.config.evm.network, pool_hash)
                    .await
                    .map_err(|e| {
                        let pool_hex = hex::encode(pool_hash);
                        Error::Payment(format!(
                            "Failed to query merkle payment info for pool {pool_hex}: {e}"
                        ))
                    })?;

            let paid_node_addresses: Vec<_> = info
                .paidNodeAddresses
                .iter()
                .map(|pna| (pna.rewardsAddress, usize::from(pna.poolIndex), pna.amount))
                .collect();

            let on_chain_info = OnChainPaymentInfo {
                depth: info.depth,
                merkle_payment_timestamp: info.merklePaymentTimestamp,
                paid_node_addresses,
            };

            // Cache the pool info for subsequent chunks in the same batch
            {
                let mut pool_cache = self.pool_cache.lock();
                pool_cache.put(pool_hash, on_chain_info.clone());
            }

            debug!(
                "Queried on-chain merkle payment info for pool {}: depth={}, timestamp={}, paid_nodes={}",
                hex::encode(pool_hash),
                on_chain_info.depth,
                on_chain_info.merkle_payment_timestamp,
                on_chain_info.paid_node_addresses.len()
            );

            on_chain_info
        };

        // Verify timestamp consistency (signatures already checked above before RPC).
        for candidate in &merkle_proof.winner_pool.candidate_nodes {
            if candidate.merkle_payment_timestamp != payment_info.merkle_payment_timestamp {
                return Err(Error::Payment(format!(
                    "Candidate timestamp mismatch: expected {}, got {} (reward: {})",
                    payment_info.merkle_payment_timestamp,
                    candidate.merkle_payment_timestamp,
                    candidate.reward_address
                )));
            }
        }

        // Get the root from the winner pool's midpoint proof
        let smart_contract_root = merkle_proof.winner_pool.midpoint_proof.root();

        // Verify the cryptographic merkle proofs (address belongs to tree,
        // midpoint belongs to tree, roots match, timestamps valid).
        evmlib::merkle_payments::verify_merkle_proof(
            &merkle_proof.address,
            &merkle_proof.data_proof,
            &merkle_proof.winner_pool.midpoint_proof,
            payment_info.depth,
            smart_contract_root,
            payment_info.merkle_payment_timestamp,
        )
        .map_err(|e| {
            let xorname_hex = hex::encode(xorname);
            Error::Payment(format!(
                "Merkle proof verification failed for {xorname_hex}: {e}"
            ))
        })?;

        // Verify paid node count matches depth
        let expected_depth = payment_info.depth as usize;
        let actual_paid = payment_info.paid_node_addresses.len();
        if actual_paid != expected_depth {
            return Err(Error::Payment(format!(
                "Wrong number of paid nodes: expected {expected_depth}, got {actual_paid}"
            )));
        }

        // Compute expected per-node payment using the contract formula:
        // totalAmount = median16(candidate_prices) * (1 << depth)
        // amountPerNode = totalAmount / depth
        let expected_per_node = if payment_info.depth > 0 {
            let mut candidate_prices: Vec<Amount> = merkle_proof
                .winner_pool
                .candidate_nodes
                .iter()
                .map(|c| c.price)
                .collect();
            candidate_prices.sort_unstable(); // ascending
                                              // Upper median (index 8 of 16) — matches Solidity's median16 (k = 8)
            let median_price = *candidate_prices
                .get(candidate_prices.len() / 2)
                .ok_or_else(|| Error::Payment("empty candidate pool in merkle proof".into()))?;
            let shift = u32::from(payment_info.depth);
            let multiplier = 1u64
                .checked_shl(shift)
                .ok_or_else(|| Error::Payment("merkle proof depth too large".into()))?;
            let total_amount = median_price * Amount::from(multiplier);
            total_amount / Amount::from(u64::from(payment_info.depth))
        } else {
            Amount::ZERO
        };

        // Verify paid node indices, addresses, and amounts against the candidate pool.
        //
        // Each paid node must:
        // 1. Have a valid index within the candidate pool
        // 2. Match the expected reward address at that index
        // 3. Have been paid at least the expected per-node amount from the
        //    contract formula: median16(prices) * 2^depth / depth
        //
        // Note: unlike single-node payments, merkle proofs are NOT bound to a
        // specific storing node. The contract pays `depth` random nodes from the
        // winner pool; the storing node is whichever close-group peer the client
        // routes the chunk to. There is no local-recipient check here because
        // any node that can verify the merkle proof is allowed to store the chunk.
        // Replay protection comes from the per-address proof binding (each proof
        // is for a specific XorName in the paid tree).
        for (addr, idx, paid_amount) in &payment_info.paid_node_addresses {
            let node = merkle_proof
                .winner_pool
                .candidate_nodes
                .get(*idx)
                .ok_or_else(|| {
                    Error::Payment(format!(
                        "Paid node index {idx} out of bounds for pool size {}",
                        merkle_proof.winner_pool.candidate_nodes.len()
                    ))
                })?;
            if node.reward_address != *addr {
                return Err(Error::Payment(format!(
                    "Paid node address mismatch at index {idx}: expected {addr}, got {}",
                    node.reward_address
                )));
            }
            if *paid_amount < expected_per_node {
                return Err(Error::Payment(format!(
                    "Underpayment for node at index {idx}: paid {paid_amount}, \
                     expected at least {expected_per_node} \
                     (median16 formula, depth={})",
                    payment_info.depth
                )));
            }
        }

        if crate::logging::enabled!(crate::logging::Level::INFO) {
            info!(
                "Merkle payment verified for {} (pool: {})",
                hex::encode(xorname),
                hex::encode(pool_hash)
            );
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
    use evmlib::merkle_payments::MerklePaymentCandidatePool;

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
    async fn test_proof_at_min_boundary_unknown_tag() {
        let verifier = create_test_verifier();
        let xorname = [3u8; 32];

        // Exactly MIN_PAYMENT_PROOF_SIZE_BYTES with unknown tag — rejected
        let boundary_proof = vec![0xFFu8; MIN_PAYMENT_PROOF_SIZE_BYTES];
        let result = verifier
            .verify_payment(&xorname, Some(&boundary_proof))
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Unknown payment proof type tag"),
            "Error should mention unknown tag: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_proof_at_max_boundary_unknown_tag() {
        let verifier = create_test_verifier();
        let xorname = [4u8; 32];

        // Exactly MAX_PAYMENT_PROOF_SIZE_BYTES with unknown tag — rejected
        let boundary_proof = vec![0xFFu8; MAX_PAYMENT_PROOF_SIZE_BYTES];
        let result = verifier
            .verify_payment(&xorname, Some(&boundary_proof))
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Unknown payment proof type tag"),
            "Error should mention unknown tag: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_malformed_single_node_proof() {
        let verifier = create_test_verifier();
        let xorname = [5u8; 32];

        // Valid tag (0x01) but garbage payload — should fail deserialization
        let mut garbage = vec![crate::ant_protocol::PROOF_TAG_SINGLE_NODE];
        garbage.extend_from_slice(&[0xAB; 63]);
        let result = verifier.verify_payment(&xorname, Some(&garbage)).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("deserialize") || err_msg.contains("Failed"),
            "Error should mention deserialization failure: {err_msg}"
        );
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
        use evmlib::{EncodedPeerId, RewardsAddress};
        use saorsa_core::MlDsa65;
        use saorsa_pqc::pqc::types::MlDsaSecretKey;
        use saorsa_pqc::pqc::MlDsaOperations;

        let ml_dsa = MlDsa65::new();
        let mut peer_quotes = Vec::new();

        for i in 0..5u8 {
            let (public_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");

            let rewards_address = RewardsAddress::new([i; 20]);
            let metrics_tracker = QuotingMetricsTracker::new(0);
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

            peer_quotes.push((EncodedPeerId::new(rand::random()), quote));
        }

        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: vec![FixedBytes::from([0xABu8; 32])],
        };

        let proof_bytes =
            crate::payment::proof::serialize_single_node_proof(&proof).expect("serialize");

        // 7 ML-DSA-65 quotes with ~1952-byte pub keys and ~3309-byte signatures
        // should produce a proof in the 30-80 KB range
        assert!(
            proof_bytes.len() > 20_000,
            "Real 7-quote ML-DSA proof should be > 20 KB, got {} bytes",
            proof_bytes.len()
        );
        assert!(
            proof_bytes.len() < MAX_PAYMENT_PROOF_SIZE_BYTES,
            "Real 7-quote ML-DSA proof ({} bytes) should fit within {} byte limit",
            proof_bytes.len(),
            MAX_PAYMENT_PROOF_SIZE_BYTES
        );
    }

    #[tokio::test]
    async fn test_content_address_mismatch_rejected() {
        use crate::payment::proof::{serialize_single_node_proof, PaymentProof};
        use evmlib::{EncodedPeerId, PaymentQuote, RewardsAddress};
        use std::time::SystemTime;

        let verifier = create_test_verifier();

        // The xorname we're trying to store
        let target_xorname = [0xAAu8; 32];

        // Create a quote for a DIFFERENT xorname
        let wrong_xorname = [0xBBu8; 32];
        let quote = PaymentQuote {
            content: xor_name::XorName(wrong_xorname),
            timestamp: SystemTime::now(),
            price: Amount::from(1u64),
            rewards_address: RewardsAddress::new([1u8; 20]),
            pub_key: vec![0u8; 64],
            signature: vec![0u8; 64],
        };

        // Build CLOSE_GROUP_SIZE quotes with distinct peer IDs
        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: vec![],
        };

        let proof_bytes = serialize_single_node_proof(&proof).expect("serialize proof");

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
    ) -> evmlib::PaymentQuote {
        use evmlib::PaymentQuote;

        PaymentQuote {
            content: xor_name::XorName(xorname),
            timestamp,
            price: Amount::from(1u64),
            rewards_address,
            pub_key: vec![0u8; 64],
            signature: vec![0u8; 64],
        }
    }

    /// Helper: wrap quotes into a tagged serialized `PaymentProof`.
    fn serialize_proof(peer_quotes: Vec<(evmlib::EncodedPeerId, evmlib::PaymentQuote)>) -> Vec<u8> {
        use crate::payment::proof::{serialize_single_node_proof, PaymentProof};

        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: vec![],
        };
        serialize_single_node_proof(&proof).expect("serialize proof")
    }

    #[tokio::test]
    async fn test_expired_quote_rejected() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xCCu8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Create a quote that's 25 hours old (exceeds 24-hour max)
        let old_timestamp = SystemTime::now() - Duration::from_secs(25 * 3600);
        let quote = make_fake_quote(xorname, old_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
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
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xDDu8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Create a quote with a timestamp 1 hour in the future
        let future_timestamp = SystemTime::now() + Duration::from_secs(3600);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
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
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD1u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 30 seconds in the future — within 60s tolerance
        let future_timestamp = SystemTime::now() + Duration::from_secs(30);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
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
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD2u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 120 seconds in the future — exceeds 60s tolerance
        let future_timestamp = SystemTime::now() + Duration::from_secs(120);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
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
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD3u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 23 hours old — within 24h max age
        let old_timestamp = SystemTime::now() - Duration::from_secs(23 * 3600);
        let quote = make_fake_quote(xorname, old_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
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
    fn encoded_peer_id_for_pub_key(pub_key: &[u8]) -> evmlib::EncodedPeerId {
        let ant_peer_id = peer_id_from_public_key_bytes(pub_key).expect("valid ML-DSA pub key");
        evmlib::EncodedPeerId::new(*ant_peer_id.as_bytes())
    }

    #[tokio::test]
    async fn test_local_not_in_paid_set_rejected() {
        use evmlib::RewardsAddress;
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
        for _ in 0..CLOSE_GROUP_SIZE {
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
        use evmlib::{EncodedPeerId, RewardsAddress};
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
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
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

    // =========================================================================
    // Merkle-tagged proof tests
    // =========================================================================

    #[tokio::test]
    async fn test_merkle_tagged_proof_invalid_data_rejected() {
        use crate::ant_protocol::PROOF_TAG_MERKLE;

        let verifier = create_test_verifier();
        let xorname = [0xA1u8; 32];

        // Build a merkle-tagged proof with garbage body.
        // The tag byte is correct but the body is not valid msgpack.
        let mut merkle_garbage = Vec::with_capacity(64);
        merkle_garbage.push(PROOF_TAG_MERKLE);
        merkle_garbage.extend_from_slice(&[0xAB; 63]);

        let result = verifier
            .verify_payment(&xorname, Some(&merkle_garbage))
            .await;

        assert!(
            result.is_err(),
            "Should reject merkle proof with invalid body"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("deserialize") || err_msg.contains("merkle proof"),
            "Error should mention deserialization failure: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_single_node_tagged_proof_deserialization() {
        use crate::payment::proof::serialize_single_node_proof;
        use evmlib::{EncodedPeerId, RewardsAddress};

        let verifier = create_test_verifier();
        let xorname = [0xA2u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Build a valid tagged single-node proof
        let quote = make_fake_quote(xorname, SystemTime::now(), rewards_addr);
        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof = crate::payment::proof::PaymentProof {
            proof_of_payment: ProofOfPayment {
                peer_quotes: peer_quotes.clone(),
            },
            tx_hashes: vec![],
        };

        let tagged_bytes = serialize_single_node_proof(&proof).expect("serialize tagged proof");

        // detect_proof_type should identify it as SingleNode
        assert_eq!(
            crate::payment::proof::detect_proof_type(&tagged_bytes),
            Some(crate::payment::proof::ProofType::SingleNode)
        );

        // verify_payment should process it through the single-node path.
        // It will fail at quote validation (fake pub_key), but we verify
        // it passes the deserialization stage by checking the error type.
        let result = verifier.verify_payment(&xorname, Some(&tagged_bytes)).await;

        assert!(result.is_err(), "Should fail at quote validation stage");
        let err_msg = format!("{}", result.expect_err("should fail"));
        // It should NOT be a deserialization error — it should get further
        assert!(
            !err_msg.contains("deserialize"),
            "Should pass deserialization but fail later: {err_msg}"
        );
    }

    #[test]
    fn test_pool_cache_insert_and_lookup() {
        use evmlib::merkle_batch_payment::PoolHash;

        // Verify the pool_cache field exists and works correctly.
        // Insert a pool hash, then verify it's present on lookup.
        let verifier = create_test_verifier();

        let pool_hash: PoolHash = [0xBBu8; 32];
        let payment_info = evmlib::merkle_payments::OnChainPaymentInfo {
            depth: 4,
            merkle_payment_timestamp: 1_700_000_000,
            paid_node_addresses: vec![],
        };

        // Insert into pool cache
        {
            let mut cache = verifier.pool_cache.lock();
            cache.put(pool_hash, payment_info);
        }

        // First lookup — should find it
        {
            let found = verifier.pool_cache.lock().get(&pool_hash).cloned();
            assert!(found.is_some(), "Pool hash should be in cache after insert");
            let info = found.expect("cached info");
            assert_eq!(info.depth, 4);
            assert_eq!(info.merkle_payment_timestamp, 1_700_000_000);
        }

        // Second lookup — same result (no double-query needed)
        {
            let found = verifier.pool_cache.lock().get(&pool_hash).cloned();
            assert!(
                found.is_some(),
                "Pool hash should still be in cache on second lookup"
            );
        }

        // Different pool hash — should NOT be found
        let other_hash: PoolHash = [0xCCu8; 32];
        {
            let found = verifier.pool_cache.lock().get(&other_hash).cloned();
            assert!(found.is_none(), "Unknown pool hash should not be in cache");
        }
    }

    #[tokio::test]
    async fn closeness_pass_cache_short_circuits_second_call() {
        // When a pool_hash is in the closeness_pass_cache, the outer
        // verify_merkle_candidate_closeness must return Ok(()) without
        // running the inner lookup — even if no P2PNode is attached.
        // That second half (no-p2p → would normally fail-closed in release)
        // is the proof the cache short-circuit ran first.
        let verifier = create_test_verifier();
        let pool_hash = [0xAAu8; 32];
        verifier.closeness_pass_cache.lock().put(pool_hash, ());

        // Construct a dummy pool — contents don't matter because the cache
        // hit means we never look at them.
        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: make_candidate_nodes(1_700_000_000),
        };

        let result = verifier
            .verify_merkle_candidate_closeness(&pool, pool_hash)
            .await;
        assert!(
            result.is_ok(),
            "cached pool hash must bypass the inner check and return Ok(()), got: {result:?}"
        );
    }

    #[tokio::test]
    async fn closeness_single_flight_concurrent_readers_share_one_verification() {
        // Two concurrent callers for the same pool_hash should produce the
        // same outcome, and the cache should end up populated exactly once.
        // We use the test-utils fail-open path to short-circuit the inner
        // DHT lookup; the purpose of this test is the single-flight
        // plumbing, not the lookup itself.
        let verifier = Arc::new(create_test_verifier());
        let pool_hash = [0x77u8; 32];
        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: make_candidate_nodes(1_700_000_000),
        };

        let v1 = Arc::clone(&verifier);
        let p1 = pool.clone();
        let v2 = Arc::clone(&verifier);
        let p2 = pool.clone();

        let (r1, r2) = tokio::join!(
            async move { v1.verify_merkle_candidate_closeness(&p1, pool_hash).await },
            async move { v2.verify_merkle_candidate_closeness(&p2, pool_hash).await },
        );

        assert_eq!(r1.is_ok(), r2.is_ok(), "concurrent callers must agree");
        assert!(
            r1.is_ok(),
            "both callers must succeed on the test-utils path"
        );
        assert!(
            verifier
                .closeness_pass_cache
                .lock()
                .get(&pool_hash)
                .is_some(),
            "success path must populate the pass cache"
        );
        assert!(
            verifier.inflight_closeness.lock().get(&pool_hash).is_none(),
            "inflight slot must be cleared after the leader finishes"
        );
    }

    #[tokio::test]
    async fn closeness_waiter_reads_leaders_published_failure() {
        // Prove the waiter path actually surfaces a failure published by a
        // concurrent leader, without running its own inner check. Insert a
        // slot, spawn a waiter (which will park on notified_owned), then
        // publish failure + notify from the outside — simulating what the
        // leader's `publish` + drop-guard pair does.
        let verifier = Arc::new(create_test_verifier());
        let pool_hash = [0x55u8; 32];
        let slot = Arc::new(ClosenessSlot::new());
        verifier
            .inflight_closeness
            .lock()
            .put(pool_hash, Arc::clone(&slot));

        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: make_candidate_nodes(1_700_000_000),
        };

        let verifier_c = Arc::clone(&verifier);
        let pool_c = pool.clone();
        let waiter = tokio::spawn(async move {
            verifier_c
                .verify_merkle_candidate_closeness(&pool_c, pool_hash)
                .await
        });

        // Yield so the waiter can run up to its `notified_owned().await`.
        // A few yields cover both single-threaded and multi-threaded tokio
        // runtimes regardless of scheduling.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }

        // Simulate the leader's `publish` + drop-guard: publish the result,
        // clear the slot, wake waiters.
        slot.result
            .set(Err("forged pool: not close enough".to_string()))
            .expect("set once");
        verifier.inflight_closeness.lock().pop(&pool_hash);
        slot.notify.notify_waiters();

        let result = waiter.await.expect("task panicked");
        let err = result.expect_err("waiter must return the leader's published failure");
        assert!(
            err.to_string().contains("forged pool"),
            "waiter must surface the leader's error message, got: {err}"
        );
    }

    /// Build a deterministic but otherwise-unused `MidpointProof` so unit
    /// tests can construct a `MerklePaymentCandidatePool` without spinning
    /// up a real merkle tree. The closeness path only calls `.address()`
    /// on it, which is a pure BLAKE3 of the branch's leaf/root/timestamp —
    /// the values don't need to be tree-valid for these tests.
    fn fake_midpoint_proof() -> evmlib::merkle_payments::MidpointProof {
        // Build a minimal tree of two leaves so we get a real branch.
        let leaves = vec![xor_name::XorName([1u8; 32]), xor_name::XorName([2u8; 32])];
        let tree = evmlib::merkle_payments::MerkleTree::from_xornames(leaves).expect("tree");
        let candidates = tree.reward_candidates(1_700_000_000).expect("candidates");
        candidates.first().expect("at least one").clone()
    }

    // =========================================================================
    // Merkle verification unit tests
    // =========================================================================

    /// Helper: build 16 validly-signed ML-DSA-65 candidate nodes.
    fn make_candidate_nodes(
        timestamp: u64,
    ) -> [evmlib::merkle_payments::MerklePaymentCandidateNode;
           evmlib::merkle_payments::CANDIDATES_PER_POOL] {
        use evmlib::merkle_payments::{MerklePaymentCandidateNode, CANDIDATES_PER_POOL};
        use saorsa_core::MlDsa65;
        use saorsa_pqc::pqc::types::MlDsaSecretKey;
        use saorsa_pqc::pqc::MlDsaOperations;

        std::array::from_fn::<_, CANDIDATES_PER_POOL, _>(|i| {
            let ml_dsa = MlDsa65::new();
            let (pub_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");
            let price = evmlib::common::Amount::from(1024u64);
            #[allow(clippy::cast_possible_truncation)]
            let reward_address = RewardsAddress::new([i as u8; 20]);
            let msg = MerklePaymentCandidateNode::bytes_to_sign(&price, &reward_address, timestamp);
            let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
            let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

            MerklePaymentCandidateNode {
                pub_key: pub_key.as_bytes().to_vec(),
                price,
                reward_address,
                merkle_payment_timestamp: timestamp,
                signature,
            }
        })
    }

    /// Helper: build a valid `MerklePaymentProof` with real ML-DSA-65
    /// signatures. Returns the raw proof, pool hash, xorname, and timestamp.
    fn make_valid_merkle_proof() -> (
        evmlib::merkle_payments::MerklePaymentProof,
        evmlib::merkle_batch_payment::PoolHash,
        [u8; 32],
        u64,
    ) {
        use evmlib::merkle_payments::{MerklePaymentCandidatePool, MerklePaymentProof, MerkleTree};

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let addresses: Vec<xor_name::XorName> = (0..4u8)
            .map(|i| xor_name::XorName::from_content(&[i]))
            .collect();
        let tree = MerkleTree::from_xornames(addresses.clone()).expect("tree");

        let candidate_nodes = make_candidate_nodes(timestamp);

        let reward_candidates = tree
            .reward_candidates(timestamp)
            .expect("reward candidates");
        let midpoint_proof = reward_candidates
            .first()
            .expect("at least one candidate")
            .clone();

        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        };

        let first_address = *addresses.first().expect("first address");
        let address_proof = tree
            .generate_address_proof(0, first_address)
            .expect("proof");

        let merkle_proof = MerklePaymentProof::new(first_address, address_proof, pool);
        let pool_hash = merkle_proof.winner_pool_hash();
        let xorname = first_address.0;

        (merkle_proof, pool_hash, xorname, timestamp)
    }

    /// Helper: build a minimal valid `MerklePaymentProof` with real ML-DSA-65
    /// signatures. Returns `(xorname, serialized_tagged_proof, pool_hash, timestamp)`.
    fn make_valid_merkle_proof_bytes() -> (
        [u8; 32],
        Vec<u8>,
        evmlib::merkle_batch_payment::PoolHash,
        u64,
    ) {
        let (merkle_proof, pool_hash, xorname, timestamp) = make_valid_merkle_proof();
        let tagged = crate::payment::proof::serialize_merkle_proof(&merkle_proof)
            .expect("serialize merkle proof");
        (xorname, tagged, pool_hash, timestamp)
    }

    #[tokio::test]
    async fn test_merkle_address_mismatch_rejected() {
        let verifier = create_test_verifier();
        let (_correct_xorname, tagged_proof, _pool_hash, _ts) = make_valid_merkle_proof_bytes();

        // Use a DIFFERENT xorname than what the proof was built for
        let wrong_xorname = [0xFFu8; 32];

        let result = verifier
            .verify_payment(&wrong_xorname, Some(&tagged_proof))
            .await;

        assert!(
            result.is_err(),
            "Should reject merkle proof address mismatch"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("address mismatch") || err_msg.contains("Merkle proof address"),
            "Error should mention address mismatch: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_malformed_body_rejected() {
        let verifier = create_test_verifier();
        let xorname = [0xA3u8; 32];

        // Valid merkle tag but truncated/corrupted msgpack body
        let mut bad_proof = vec![crate::ant_protocol::PROOF_TAG_MERKLE];
        bad_proof.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        bad_proof.extend_from_slice(&[0x00; 10]);
        // pad to minimum size
        while bad_proof.len() < MIN_PAYMENT_PROOF_SIZE_BYTES {
            bad_proof.push(0x00);
        }

        let result = verifier.verify_payment(&xorname, Some(&bad_proof)).await;

        assert!(result.is_err(), "Should reject malformed merkle body");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("deserialize") || err_msg.contains("Failed"),
            "Error should mention deserialization: {err_msg}"
        );
    }

    #[test]
    fn test_merkle_proof_serialized_size_within_limits() {
        let (_xorname, tagged_proof, _pool_hash, _ts) = make_valid_merkle_proof_bytes();

        // 16 ML-DSA-65 candidates (~1952 pub key + ~3309 sig each) ≈ 84 KB + tree data
        assert!(
            tagged_proof.len() >= MIN_PAYMENT_PROOF_SIZE_BYTES,
            "Merkle proof ({} bytes) should be >= min {} bytes",
            tagged_proof.len(),
            MIN_PAYMENT_PROOF_SIZE_BYTES
        );
        assert!(
            tagged_proof.len() <= MAX_PAYMENT_PROOF_SIZE_BYTES,
            "Merkle proof ({} bytes) should be <= max {} bytes",
            tagged_proof.len(),
            MAX_PAYMENT_PROOF_SIZE_BYTES
        );
    }

    #[test]
    fn test_merkle_proof_tag_is_correct() {
        let (_xorname, tagged_proof, _pool_hash, _ts) = make_valid_merkle_proof_bytes();

        assert_eq!(
            tagged_proof.first().copied(),
            Some(crate::ant_protocol::PROOF_TAG_MERKLE),
            "First byte must be the merkle tag"
        );
        assert_eq!(
            crate::payment::proof::detect_proof_type(&tagged_proof),
            Some(crate::payment::proof::ProofType::Merkle)
        );
    }

    #[test]
    fn test_pool_cache_eviction() {
        use evmlib::merkle_batch_payment::PoolHash;

        let config = PaymentVerifierConfig {
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100,
            local_rewards_address: RewardsAddress::new([1u8; 20]),
        };
        let verifier = PaymentVerifier::new(config);

        // Fill the pool cache to capacity (DEFAULT_POOL_CACHE_CAPACITY = 1000)
        for i in 0..DEFAULT_POOL_CACHE_CAPACITY {
            let mut hash: PoolHash = [0u8; 32];
            // Write index bytes into the hash
            let idx_bytes = i.to_le_bytes();
            for (j, b) in idx_bytes.iter().enumerate() {
                if j < 32 {
                    hash[j] = *b;
                }
            }
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 4,
                merkle_payment_timestamp: 1_700_000_000,
                paid_node_addresses: vec![],
            };
            verifier.pool_cache.lock().put(hash, info);
        }

        assert_eq!(
            verifier.pool_cache.lock().len(),
            DEFAULT_POOL_CACHE_CAPACITY
        );

        // Insert one more — should evict the oldest
        let overflow_hash: PoolHash = [0xFFu8; 32];
        let info = evmlib::merkle_payments::OnChainPaymentInfo {
            depth: 8,
            merkle_payment_timestamp: 1_800_000_000,
            paid_node_addresses: vec![],
        };
        verifier.pool_cache.lock().put(overflow_hash, info);

        // Size should still be at capacity (not capacity + 1)
        assert_eq!(
            verifier.pool_cache.lock().len(),
            DEFAULT_POOL_CACHE_CAPACITY
        );

        // The new entry should be present
        let found = verifier.pool_cache.lock().get(&overflow_hash).cloned();
        assert!(
            found.is_some(),
            "Newly inserted pool hash should be present"
        );
        assert_eq!(found.expect("info").depth, 8);
    }

    #[test]
    fn test_pool_cache_concurrent_access() {
        use evmlib::merkle_batch_payment::PoolHash;
        use std::sync::Arc;

        let verifier = Arc::new(create_test_verifier());

        let mut handles = Vec::new();
        for i in 0..20u8 {
            let v = verifier.clone();
            handles.push(std::thread::spawn(move || {
                let hash: PoolHash = [i; 32];
                let info = evmlib::merkle_payments::OnChainPaymentInfo {
                    depth: i,
                    merkle_payment_timestamp: u64::from(i) * 1000,
                    paid_node_addresses: vec![],
                };
                v.pool_cache.lock().put(hash, info);

                // Read back
                let found = v.pool_cache.lock().get(&hash).cloned();
                assert!(found.is_some(), "Entry {i} should be readable after insert");
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // All 20 entries should be present (well under 1000 capacity)
        assert_eq!(verifier.pool_cache.lock().len(), 20);
    }

    #[tokio::test]
    async fn test_merkle_tampered_candidate_signature_rejected() {
        let verifier = create_test_verifier();

        let (mut merkle_proof, _pool_hash, xorname, timestamp) = make_valid_merkle_proof();

        // Tamper the first candidate's signature
        if let Some(byte) = merkle_proof
            .winner_pool
            .candidate_nodes
            .first_mut()
            .and_then(|c| c.signature.first_mut())
        {
            *byte ^= 0xFF;
        }

        // Recompute pool hash after tampering (signature change alters the hash)
        let tampered_pool_hash = merkle_proof.winner_pool_hash();

        // Pre-populate pool cache so we skip the on-chain query
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 4,
                merkle_payment_timestamp: timestamp,
                paid_node_addresses: vec![],
            };
            verifier.pool_cache.lock().put(tampered_pool_hash, info);
        }

        let tagged =
            crate::payment::proof::serialize_merkle_proof(&merkle_proof).expect("serialize");

        let result = verifier.verify_payment(&xorname, Some(&tagged)).await;

        assert!(
            result.is_err(),
            "Should reject merkle proof with tampered candidate signature"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Invalid ML-DSA-65 signature"),
            "Error should mention invalid signature: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_timestamp_mismatch_rejected() {
        let verifier = create_test_verifier();

        let (xorname, tagged, pool_hash, timestamp) = make_valid_merkle_proof_bytes();

        // Pre-populate pool cache with a DIFFERENT timestamp than the candidates
        {
            let mismatched_ts = timestamp + 9999;
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 4,
                merkle_payment_timestamp: mismatched_ts,
                paid_node_addresses: vec![],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier.verify_payment(&xorname, Some(&tagged)).await;

        assert!(
            result.is_err(),
            "Should reject merkle proof with timestamp mismatch"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("timestamp mismatch"),
            "Error should mention timestamp mismatch: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_paid_node_index_out_of_bounds_rejected() {
        let verifier = create_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        // The test tree has 4 addresses → depth 2. We must match the tree depth
        // so verify_merkle_proof passes the depth check, then the paid node
        // index out-of-bounds check fires.
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    // First paid node: valid (matches candidate 0, amount matches formula)
                    // Expected per-node: median(1024) * 2^2 / 2 = 2048
                    (RewardsAddress::new([0u8; 20]), 0, Amount::from(2048u64)),
                    // Second paid node: index 999 is way beyond CANDIDATES_PER_POOL (16)
                    (RewardsAddress::new([1u8; 20]), 999, Amount::from(2048u64)),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier.verify_payment(&xorname, Some(&tagged_proof)).await;

        assert!(
            result.is_err(),
            "Should reject paid node index out of bounds"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("out of bounds"),
            "Error should mention out of bounds: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_paid_node_address_mismatch_rejected() {
        let verifier = create_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        // Tree has depth 2, so provide 2 paid node entries.
        // Both use valid indices but the second has a wrong reward address.
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    // Index 0 with matching address [0x00; 20]
                    // Expected per-node: median(1024) * 2^2 / 2 = 2048
                    (RewardsAddress::new([0u8; 20]), 0, Amount::from(2048u64)),
                    // Index 1 with WRONG address — candidate 1's address is [0x01; 20]
                    (RewardsAddress::new([0xFF; 20]), 1, Amount::from(2048u64)),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier.verify_payment(&xorname, Some(&tagged_proof)).await;

        assert!(result.is_err(), "Should reject paid node address mismatch");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("address mismatch"),
            "Error should mention address mismatch: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_wrong_depth_rejected() {
        let verifier = create_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        // Pre-populate pool cache with depth=3 but only 1 paid node address
        // (depth must equal paid_node_addresses.len())
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 3,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![(
                    RewardsAddress::new([0u8; 20]),
                    0,
                    Amount::from(1024u64),
                )],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier.verify_payment(&xorname, Some(&tagged_proof)).await;

        assert!(
            result.is_err(),
            "Should reject mismatched depth vs paid node count"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Wrong number of paid nodes")
                || err_msg.contains("verification failed"),
            "Error should mention depth/count mismatch: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_underpayment_rejected() {
        let verifier = create_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        // Tree depth=2, so 2 paid nodes required. Candidates all quote price=1024.
        // Expected per-node: median(1024) * 2^2 / 2 = 2048.
        // Pay only 1 wei per node — far below the expected amount.
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    (RewardsAddress::new([0u8; 20]), 0, Amount::from(1u64)),
                    (RewardsAddress::new([1u8; 20]), 1, Amount::from(1u64)),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier.verify_payment(&xorname, Some(&tagged_proof)).await;

        assert!(
            result.is_err(),
            "Should reject merkle payment where paid amount < expected per-node amount"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Underpayment"),
            "Error should mention underpayment: {err_msg}"
        );
    }
}
