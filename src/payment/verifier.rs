//! Payment verifier with LRU cache and EVM verification.
//!
//! This is the core payment verification logic for ant-node.
//! All new data requires EVM payment on Arbitrum (no free tier).

use crate::ant_protocol::CLOSE_GROUP_SIZE;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::payment::cache::{CacheStats, VerifiedCache, XorName};
use crate::payment::pricing::{calculate_price, derive_records_stored_from_price};
use crate::payment::proof::{
    deserialize_merkle_proof, deserialize_single_node_proof, detect_proof_type, ProofType,
};
use crate::replication::config::K_BUCKET_SIZE;
use crate::storage::lmdb::LmdbStorage;
use ant_protocol::payment::verify::{verify_quote_content, verify_quote_signature};
use evmlib::common::{Amount, QuoteHash};
use evmlib::contract::payment_vault;
use evmlib::merkle_batch_payment::{OnChainPaymentInfo, PoolHash};
use evmlib::Network as EvmNetwork;
use evmlib::PaymentQuote;
use evmlib::ProofOfPayment;
use evmlib::RewardsAddress;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use saorsa_core::identity::node_identity::peer_id_from_public_key_bytes;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

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

/// Maximum percentage by which the median-paid quote may fall below this
/// verifier's current local price before a client PUT is rejected.
///
/// A 20% floor means a paid quote must be at least `0.8 * P_v`, so an
/// attacker who controls a real K-close issuer still pays at least
/// `0.8 * P_v * 3` for an honest verifier. Honest median-paid bundles have
/// a structural majority guarantee: the four nodes at or below the median
/// accept unless their own price grows more than `1 / 0.8 = 1.25x` between
/// quote and PUT. Above-median nodes may reject when `P_v > 1.25 * median`;
/// those records are backfilled by replication, which deliberately skips
/// this present-tense floor.
const PAID_QUOTE_PRICE_FLOOR_TOLERANCE_PCT: u64 = 20;

const PERCENT_DENOMINATOR: u64 = 100;
const PAID_QUOTE_PAYMENT_MULTIPLIER: u64 = 3;
const PAYMENT_VERIFY_SLOW_LOG_MS: u128 = 500;

/// Number of nearest DHT peers accepted for paid-quote issuer locality.
///
/// This is the Kademlia K width, intentionally wider than `CLOSE_GROUP_SIZE`.
const PAID_QUOTE_ISSUER_CLOSENESS_WIDTH: usize = K_BUCKET_SIZE;

#[derive(Clone, Copy)]
struct LegacyMedianCandidate<'a> {
    encoded_peer_id: &'a evmlib::EncodedPeerId,
    quote: &'a PaymentQuote,
    expected_amount: Amount,
}

fn price_floor(current_price: Amount, tolerance_pct: u64) -> Amount {
    current_price.saturating_mul(Amount::from(
        PERCENT_DENOMINATOR.saturating_sub(tolerance_pct),
    )) / Amount::from(PERCENT_DENOMINATOR)
}

fn median_quote_index(quote_count: usize) -> usize {
    quote_count / 2
}

fn payment_proof_type_label(payment_proof: Option<&[u8]>) -> &'static str {
    match payment_proof.and_then(detect_proof_type) {
        Some(ProofType::Merkle) => "merkle",
        Some(ProofType::SingleNode) => "single_node",
        Some(_) => "unsupported",
        None if payment_proof.is_some() => "unknown",
        None => "none",
    }
}

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
    /// Close-group width exposed to storage and replication admission callers.
    pub close_group_size: usize,
    /// Local node's rewards address.
    ///
    /// Kept in the verifier config for payment policies that bind receipts to
    /// this node's payout address.
    pub local_rewards_address: RewardsAddress,
}

/// The fresh admission path a payment proof is being verified for.
///
/// - **`ClientPut`** — the node is admitting a chunk store. The verifier
///   applies store-strength cache semantics and live payment checks.
/// - **`PaidListAdmission`** — the node is admitting fresh paid-list metadata.
///   It runs the same live payment checks as `ClientPut`, but writes a weaker
///   cache entry that does not authorize future chunk stores.
///
/// The caller must check local receiver/admission membership before invoking
/// the verifier for replication admission: fresh chunk replication requires
/// local close-group responsibility, and fresh paid-list replication requires
/// local paid-list close-group membership. Direct client PUT deliberately does
/// not perform a receiver-responsibility gate. The verifier itself only checks
/// payment proof validity and that the paid quote's issuer is in the K closest
/// peers for the quoted chunk address.
///
/// Immediate fresh chunk replication is different: the receiver is about to
/// store the newly written chunk as if the client PUT it there directly, so
/// that call site deliberately uses `ClientPut`.
///
/// Later neighbour-sync repair does not include proof-of-payment bytes and
/// does not call this verifier. It authorizes repair from network evidence:
/// majority storage among the configured close group, or majority paid-list
/// membership among the closest K.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationContext {
    /// The node is admitting a chunk store with store-strength cache semantics.
    ClientPut,
    /// The node is admitting fresh paid-list metadata with paid-list-strength
    /// cache semantics.
    PaidListAdmission,
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

/// Outcome of the ADR-0003 quote-vs-commitment cross-check (see
/// [`PaymentVerifier::cross_check_binding`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCheck {
    /// Pin resolves to the commitment and the counts agree: nothing to report.
    Match,
    /// Pin resolves to the commitment but the claimed and committed counts
    /// disagree: deterministic, first-occurrence contradiction (evidence).
    Mismatch {
        /// The key count the quote claimed.
        quoted_key_count: u32,
        /// The key count the pinned commitment actually attests.
        committed_key_count: u32,
    },
    /// The supplied commitment does not hash to the quote's pin: the pin is
    /// unresolved (treat as fetch/skip), never evidence.
    PinDoesNotResolve,
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

/// ADR-0003: max commitment sidecars processed per bundle. A legitimate bundle
/// carries at most one commitment per quote/candidate — `CANDIDATES_PER_POOL`
/// (16) is the larger of the single-node (`CLOSE_GROUP_SIZE` = 7) and merkle
/// cases, so it covers both. Excess sidecars from a malicious client are
/// ignored before any deserialize/verify work (bounds the hot-path cost).
const MAX_SIDECARS_PER_BUNDLE: usize = evmlib::merkle_batch_payment::CANDIDATES_PER_POOL;

/// Shared handle to the replication engine's gossip commitment cache
/// (`last_commitment_by_peer`), used by the ADR-0003 cross-check to resolve a
/// quote's pin against a neighbour's recently gossiped commitment. A `tokio`
/// `RwLock` to match the engine's; read with `.await` on the async path.
type CommitmentCache = Arc<
    tokio::sync::RwLock<
        HashMap<PeerId, crate::replication::commitment_state::PeerCommitmentRecord>,
    >,
>;

/// Per-`(peer, pin)` negative cache for unresolved ADR-0003 pin fetches: a pin a
/// peer answered `NotRetained` (or that timed out) is remembered so repeated
/// bundles don't re-fetch it. Behind an `Arc` so the detached fetch task owns a
/// handle without borrowing the verifier.
type PinFetchNegativeCache = Arc<Mutex<LruCache<(PeerId, [u8; 32]), ()>>>;

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
    /// P2P node handle, attached post-construction so paid-quote verification
    /// can check paid-quote issuer K-closeness, and merkle verification can
    /// check that candidate `pub_keys` map to peers actually close to the pool
    /// midpoint in the live DHT. `None` in unit tests that don't exercise
    /// live-DHT checks; production startup MUST call [`attach_p2p_node`].
    p2p_node: RwLock<Option<Arc<P2PNode>>>,
    /// LMDB storage handle, attached post-construction so the paid-quote
    /// price-floor check can read the authoritative on-disk record count without
    /// depending on a side counter that may drift from replication/repair/prune
    /// paths. `None` in unit tests that pre-set [`Self::test_records_override`];
    /// production startup MUST call [`attach_storage`].
    storage: RwLock<Option<Arc<LmdbStorage>>>,
    /// Test-only override for the paid-quote local price floor.
    ///
    /// When `Some(n)`, `validate_paid_quote_price_floor` uses `n` as the
    /// current record count instead of querying `storage.current_chunks()`. Set via
    /// [`Self::set_records_stored_for_tests`] so unit tests that don't wire a
    /// real `LmdbStorage` can still drive the price-floor logic.
    test_records_override: RwLock<Option<u64>>,
    /// Test-only override for the paid-quote issuer K-closest check.
    ///
    /// Production code derives closest peers from the attached [`P2PNode`].
    #[cfg(any(test, feature = "test-utils"))]
    test_paid_quote_k_closest_override: RwLock<Option<Vec<[u8; 32]>>>,
    /// Test-only override for `completedPayments(quote_hash)`.
    ///
    /// Production always queries the payment vault; unit tests use this to
    /// exercise the full verifier path without starting an EVM chain.
    #[cfg(any(test, feature = "test-utils"))]
    test_completed_payments_override: RwLock<HashMap<QuoteHash, Amount>>,
    /// Test-only override for this node's own peer ID, used by
    /// `validate_quote_freshness` to pick out the node's own quote from the
    /// payment bundle. Production code derives it from the attached
    /// [`P2PNode`]; set via [`Self::set_peer_id_for_tests`] so unit tests can
    /// drive the freshness logic without wiring a real `P2PNode`.
    test_peer_id_override: RwLock<Option<[u8; 32]>>,
    /// ADR-0003 gossip commitment cache, shared with the replication engine
    /// (`last_commitment_by_peer`). The cross-check resolves a quote's
    /// `commitment_pin` against the neighbour's most recently gossiped
    /// commitment held here, *only if seen within the answerability TTL*;
    /// otherwise the pin is treated as unknown (fetch/skip), never a penalty.
    /// A `tokio` `RwLock` to match the engine's; read with `.await` on the
    /// async verification path. `None` until [`Self::attach_commitment_cache`]
    /// (unit tests, or pre-replication startup).
    commitment_cache: RwLock<Option<CommitmentCache>>,
    /// ADR-0003 negative cache for unresolved pin fetches: a `(peer, pin)` that
    /// resolved to `NotRetained` or timed out is remembered here so repeated
    /// bundles citing the same unknown pin don't re-fetch (bounding the
    /// amplification an attacker can drive). Keyed by `(PeerId, pin)`. Behind an
    /// `Arc` so the detached background fetch task (which runs off the payment
    /// hot path) can read and update it without borrowing the verifier.
    pin_fetch_negative_cache: PinFetchNegativeCache,
    /// ADR-0003: sender to surface monetized pins (commitments that backed a
    /// payment) to the replication engine's deterministic first-audit drainer.
    /// `None` until [`Self::attach_monetized_pin_sender`] (unit tests, or
    /// pre-replication startup), in which case no first audit is scheduled.
    monetized_pin_tx:
        RwLock<Option<tokio::sync::mpsc::UnboundedSender<crate::replication::MonetizedPinEvent>>>,
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
        // `test-utils`: that feature flips the live-DHT payment-check
        // fail-open switches when P2PNode isn't attached. Safe in tests, never
        // intended for prod.
        #[cfg(feature = "test-utils")]
        crate::logging::error!(
            "PaymentVerifier: built with `test-utils` feature — payment live-DHT \
             checks fall back to fail-open when no P2PNode is attached. This \
             feature is for test binaries only; production nodes must be built \
             without it."
        );

        Self {
            cache,
            pool_cache,
            closeness_pass_cache,
            inflight_closeness,
            p2p_node: RwLock::new(None),
            storage: RwLock::new(None),
            test_records_override: RwLock::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            test_paid_quote_k_closest_override: RwLock::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            test_completed_payments_override: RwLock::new(HashMap::new()),
            test_peer_id_override: RwLock::new(None),
            commitment_cache: RwLock::new(None),
            pin_fetch_negative_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(crate::replication::config::PIN_FETCH_NEGATIVE_CACHE_CAPACITY)
                    .unwrap_or(NonZeroUsize::MIN),
            ))),
            monetized_pin_tx: RwLock::new(None),
            config,
        }
    }

    /// Attach the ADR-0003 monetized-pin sender (the replication engine's
    /// first-audit drainer channel) so the cross-check can route commitments
    /// that backed a payment into a deterministic first audit. Idempotent;
    /// absent (unit tests / pre-replication) no first audit is scheduled.
    pub fn attach_monetized_pin_sender(
        &self,
        tx: tokio::sync::mpsc::UnboundedSender<crate::replication::MonetizedPinEvent>,
    ) {
        *self.monetized_pin_tx.write() = Some(tx);
        debug!("PaymentVerifier: ADR-0003 monetized-pin sender attached");
    }

    /// Attach the ADR-0003 gossip commitment cache (the replication engine's
    /// `last_commitment_by_peer`) so the cross-check can resolve a quote's
    /// `commitment_pin` against the neighbour's recently gossiped commitment.
    ///
    /// Wired by the node once the replication engine exists, alongside the
    /// quote generator's commitment source. Idempotent. Absent (unit tests,
    /// pre-replication startup), the cross-check resolves no pins from gossip
    /// and falls back to fetch/skip — never a penalty.
    pub fn attach_commitment_cache(&self, cache: CommitmentCache) {
        *self.commitment_cache.write() = Some(cache);
        debug!("PaymentVerifier: ADR-0003 commitment cache attached");
    }

    /// Attach the node's [`P2PNode`] handle so paid-quote verification can
    /// check issuer closeness, and merkle-payment verification can check
    /// candidate `pub_keys` against the DHT's actual closest peers to the pool
    /// midpoint.
    ///
    /// Production startup MUST call this once the `P2PNode` exists. Without
    /// it, live-DHT payment checks fail CLOSED in release builds with a visible
    /// error and fail open in test builds. Idempotent: calling twice replaces
    /// the handle.
    pub fn attach_p2p_node(&self, node: Arc<P2PNode>) {
        *self.p2p_node.write() = Some(node);
        debug!("PaymentVerifier: P2PNode attached for payment live-DHT checks");
    }

    /// Configured close-group width used by storage admission callers.
    #[must_use]
    pub fn close_group_size(&self) -> usize {
        self.config.close_group_size
    }

    /// Attach the node's [`LmdbStorage`] handle so paid-quote price-floor
    /// checks can query the authoritative on-disk record count.
    ///
    /// Production startup MUST call this once the storage exists; otherwise
    /// client PUTs using paid-quote verification are rejected because
    /// the local economic floor cannot be checked. Idempotent: calling twice
    /// replaces the handle.
    pub fn attach_storage(&self, storage: Arc<LmdbStorage>) {
        *self.storage.write() = Some(storage);
        debug!("PaymentVerifier: LmdbStorage attached for paid-quote price-floor checks");
    }

    /// Test-only setter for the current record count used by paid-quote
    /// price-floor checks. Lets unit tests drive the floor logic without
    /// wiring a real `LmdbStorage`. Has no effect in production code because
    /// production code is expected to call [`Self::attach_storage`] instead.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_records_stored_for_tests(&self, count: u64) {
        *self.test_records_override.write() = Some(count);
    }

    /// Test-only setter for local closest peers used by the paid-quote
    /// issuer K-closest check.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_paid_quote_k_closest_for_tests(&self, peer_ids: Vec<[u8; 32]>) {
        *self.test_paid_quote_k_closest_override.write() = Some(peer_ids);
    }

    /// Compatibility alias for older tests that called this the close group.
    /// The check now accepts the K closest peers for the quoted chunk address.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_paid_quote_close_group_for_tests(&self, peer_ids: Vec<[u8; 32]>) {
        self.set_paid_quote_k_closest_for_tests(peer_ids);
    }

    /// Compatibility alias for older tests that called this the known-peer
    /// set. The check now accepts the K closest peers for the quoted chunk
    /// address.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_paid_quote_known_peers_for_tests(&self, peer_ids: Vec<[u8; 32]>) {
        self.set_paid_quote_k_closest_for_tests(peer_ids);
    }

    /// Test-only setter for an on-chain completed payment amount.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_completed_payment_for_tests(&self, quote_hash: QuoteHash, amount: Amount) {
        self.test_completed_payments_override
            .write()
            .insert(quote_hash, amount);
    }

    /// Snapshot the current record count for paid-quote price-floor checks.
    ///
    /// Prefers the attached `LmdbStorage` (authoritative — covers client PUTs,
    /// replication stores, repair fetches, and prune deletes by definition).
    /// Falls back to a test override if one was set. Returns `None` only when
    /// no source is available (mis-configured production startup). The
    /// paid-quote floor rejects client PUTs because the local floor is
    /// the economic security gate for this proof policy.
    fn current_records_stored(&self) -> Option<u64> {
        // Clone the Arc out and drop the guard before the storage read, so the
        // `RwLock<Option<Arc<LmdbStorage>>>` is never held across `current_chunks()`.
        let storage = self.storage.read().as_ref().map(Arc::clone);
        if let Some(storage) = storage {
            match storage.current_chunks() {
                Ok(n) => return Some(n),
                Err(e) => {
                    warn!(
                        "PaymentVerifier: failed to read current_chunks() for price-floor check: {e}"
                    );
                    return None;
                }
            }
        }
        *self.test_records_override.read()
    }

    /// Check if payment is required for the given `XorName`.
    ///
    /// This is the main entry point for payment verification:
    /// 1. Check LRU cache (fast path)
    /// 2. If not cached, payment is required
    ///
    /// The fast path is context-aware. A `ClientPut` lookup is satisfied only
    /// by a close-group store verification. A `PaidListAdmission` lookup is
    /// satisfied by either a paid-list or client-PUT verification.
    ///
    /// # Arguments
    ///
    /// * `xorname` - The content-addressed name of the data
    /// * `context` - The verification context of the caller
    ///
    /// # Returns
    ///
    /// * `PaymentStatus::CachedAsVerified` - Found in local cache (previously paid)
    /// * `PaymentStatus::PaymentRequired` - Not cached (payment required)
    pub fn check_payment_required(
        &self,
        xorname: &XorName,
        context: VerificationContext,
    ) -> PaymentStatus {
        // Check LRU cache (fast path)
        let cached = match context {
            VerificationContext::ClientPut => self.cache.contains_client_put_verified(xorname),
            VerificationContext::PaidListAdmission => {
                self.cache.contains_paid_list_verified(xorname)
            }
        };
        if cached {
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
    /// * `context` - Which fresh admission path is verifying the proof — see
    ///   [`VerificationContext`] for cache-strength semantics
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
        context: VerificationContext,
    ) -> Result<PaymentStatus> {
        let started = Instant::now();
        let proof_type = payment_proof_type_label(payment_proof);
        let proof_bytes = payment_proof.map_or(0, <[u8]>::len);
        let result = self
            .verify_payment_inner(xorname, payment_proof, context)
            .await;
        let elapsed_ms = started.elapsed().as_millis();

        match &result {
            Ok(status) if elapsed_ms >= PAYMENT_VERIFY_SLOW_LOG_MS => {
                info!(
                    target: "ant_node::payment::verify",
                    "Slow payment verification: context={context:?}, proof_type={proof_type}, proof_bytes={proof_bytes}, status={status:?}, elapsed_ms={elapsed_ms}",
                );
            }
            Ok(status) => {
                debug!(
                    target: "ant_node::payment::verify",
                    "Payment verification: context={context:?}, proof_type={proof_type}, proof_bytes={proof_bytes}, status={status:?}, elapsed_ms={elapsed_ms}",
                );
            }
            Err(e) if elapsed_ms >= PAYMENT_VERIFY_SLOW_LOG_MS => {
                warn!(
                    target: "ant_node::payment::verify",
                    "Slow payment verification failed: context={context:?}, proof_type={proof_type}, proof_bytes={proof_bytes}, elapsed_ms={elapsed_ms}: {e}",
                );
            }
            Err(e) => {
                debug!(
                    target: "ant_node::payment::verify",
                    "Payment verification failed: context={context:?}, proof_type={proof_type}, proof_bytes={proof_bytes}, elapsed_ms={elapsed_ms}: {e}",
                );
            }
        }

        result
    }

    async fn verify_payment_inner(
        &self,
        xorname: &XorName,
        payment_proof: Option<&[u8]>,
        context: VerificationContext,
    ) -> Result<PaymentStatus> {
        // First check if payment is required
        let status = self.check_payment_required(xorname, context);

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
                            self.verify_merkle_payment(xorname, proof, context).await?;
                        }
                        Some(ProofType::SingleNode) => {
                            let parsed = deserialize_single_node_proof(proof).map_err(|e| {
                                Error::Payment(format!("Failed to deserialize payment proof: {e}"))
                            })?;

                            if !parsed.tx_hashes.is_empty() {
                                debug!(
                                    "Proof includes {} transaction hash(es)",
                                    parsed.tx_hashes.len()
                                );
                            }

                            self.verify_evm_payment(
                                xorname,
                                &parsed.proof_of_payment,
                                &parsed.commitment_sidecars,
                                context,
                            )
                            .await?;
                        }
                        None => {
                            let tag = proof.first().copied().unwrap_or(0);
                            return Err(Error::Payment(format!(
                                "Unknown payment proof type tag: 0x{tag:02x}"
                            )));
                        }
                        // ant-protocol marks `ProofType` as `#[non_exhaustive]`.
                        // A future proof variant that this node does not yet
                        // understand must be rejected, not silently accepted.
                        Some(_) => {
                            let tag = proof.first().copied().unwrap_or(0);
                            return Err(Error::Payment(format!(
                                "Unsupported payment proof type tag: 0x{tag:02x} (this node's protocol version does not handle it — upgrade ant-node)"
                            )));
                        }
                    }

                    // Cache the verified xorname at the context's verification
                    // strength. Stronger entries satisfy weaker future lookups,
                    // but not the reverse.
                    match context {
                        VerificationContext::ClientPut => self.cache.insert(*xorname),
                        VerificationContext::PaidListAdmission => {
                            self.cache.insert_paid_list_verified(*xorname);
                        }
                    }

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
    /// 1. Between 1 and `CLOSE_GROUP_SIZE` quotes are present
    /// 2. Median-priced candidate quotes are derived from the supplied bundle
    /// 3. Each candidate is checked for content binding, peer binding, and a
    ///    valid ML-DSA-65 signature
    /// 4. Each candidate must also come from a local K-close peer and
    ///    satisfy the paid-quote price floor
    /// 5. A candidate is accepted only if `completedPayments(quoteHash)` is at
    ///    least 3x the median price
    ///
    /// Non-median quotes are parsed only to locate the median. Their content,
    /// peer bindings, and signatures are deliberately ignored: the paid
    /// quote's content hash, quote hash, signature, local floor, issuer
    /// K-closeness check, and on-chain settlement are the authority. A
    /// one-quote proof is valid when that single quote passes these checks and
    /// was paid 3x.
    async fn verify_evm_payment(
        &self,
        xorname: &XorName,
        payment: &ProofOfPayment,
        commitment_sidecars: &[Vec<u8>],
        context: VerificationContext,
    ) -> Result<()> {
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
            let xorname_hex = hex::encode(xorname);
            let quote_count = payment.peer_quotes.len();
            debug!(
                "Verifying EVM payment for {xorname_hex} with {quote_count} quotes ({context:?})"
            );
        }

        Self::validate_quote_structure(payment)?;
        // ADR-0003: re-run the `price == calculate_price(committed_key_count)`
        // arithmetic/binding check on EVERY quote in the bundle (all single-node
        // quotes), per the ADR's "every storer re-runs the
        // price-equals-formula-of-count check on every quote in the bundle"
        // rule — bundle-level, before median selection (the candidate loop below
        // only sees median-priced quotes). This hard cutover also RETIRES the
        // percentage-based own-quote price-staleness gate: a quote's price is
        // now exactly bound to its committed count here (both the `(n>0, Some)`
        // and baseline `(0, None)` shapes), and the committed responsible count
        // legitimately differs from the on-disk count, so the old gate would
        // FALSE-REJECT healthy ADR quotes. The binding gate supersedes it.
        Self::validate_quote_arithmetic(payment)?;
        let candidates = Self::legacy_median_candidates(payment)?;
        let mut failures = Vec::with_capacity(candidates.len());
        let mut verified_paid_quote = false;

        for candidate in candidates {
            match self
                .verify_legacy_median_candidate(xorname, candidate)
                .await
            {
                Ok(()) => {
                    verified_paid_quote = true;
                    break;
                }
                Err(err) => failures.push(err.to_string()),
            }
        }

        if !verified_paid_quote {
            let xorname_hex = hex::encode(xorname);
            let details = if failures.is_empty() {
                "no median-priced candidates were available".to_string()
            } else {
                failures.join("; ")
            };
            return Err(Error::Payment(format!(
                "Median quote payment verification failed for {xorname_hex}: {details}"
            )));
        }

        // ADR-0003 observe-only telemetry: log off-curve quotes only AFTER the
        // paid (median) quote's ML-DSA-65 signature has verified above, so
        // unauthenticated senders cannot poison rollout logs. In enforce mode
        // `validate_quote_arithmetic` already rejected; this is a no-op there.
        Self::log_off_curve_single_node(payment);

        // ADR-0003 cross-check + first-audit enqueue (ClientPut only) runs ONLY
        // after on-chain payment verification has SUCCEEDED above, so an unpaid
        // (but signed) bundle can never enqueue audits or drive pin fetches —
        // closing the free-amplification path. Fresh client-put bundles only.
        if context == VerificationContext::ClientPut {
            self.cross_check_quotes(payment, commitment_sidecars).await;
        }

        if crate::logging::enabled!(crate::logging::Level::INFO) {
            let xorname_hex = hex::encode(xorname);
            info!("EVM payment verified for {xorname_hex}");
        }
        Ok(())
    }

    fn legacy_median_candidates(
        payment: &ProofOfPayment,
    ) -> Result<Vec<LegacyMedianCandidate<'_>>> {
        let mut sorted_quotes: Vec<(&evmlib::EncodedPeerId, &PaymentQuote)> = payment
            .peer_quotes
            .iter()
            .map(|(encoded_peer_id, quote)| (encoded_peer_id, quote))
            .collect();
        sorted_quotes.sort_by_key(|(_, quote)| quote.price);
        let quote_count = sorted_quotes.len();
        let median_index = median_quote_index(quote_count);
        let median_price = sorted_quotes
            .get(median_index)
            .ok_or_else(|| {
                Error::Payment(format!("Missing paid quote at median index {median_index}"))
            })?
            .1
            .price;
        let expected_amount = median_price
            .checked_mul(Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER))
            .ok_or_else(|| {
                Error::Payment(format!(
                    "Median quote payment amount overflow for price {median_price}"
                ))
            })?;

        if expected_amount == Amount::ZERO || median_price == Amount::ZERO {
            return Err(Error::Payment(format!(
                "Median quote has zero price/amount (price={median_price}, amount={expected_amount}); refusing to verify as paid"
            )));
        }

        Ok(sorted_quotes
            .into_iter()
            .filter(|(_, quote)| quote.price == median_price)
            .map(|(encoded_peer_id, quote)| LegacyMedianCandidate {
                encoded_peer_id,
                quote,
                expected_amount,
            })
            .collect())
    }

    async fn verify_legacy_median_candidate(
        &self,
        xorname: &XorName,
        candidate: LegacyMedianCandidate<'_>,
    ) -> Result<()> {
        Self::validate_paid_quote_content(xorname, candidate)?;
        let issuer_peer_id =
            Self::validate_paid_quote_peer_binding(candidate.encoded_peer_id, candidate.quote)?;

        self.validate_paid_quote_issuer_k_closest(xorname, &issuer_peer_id)
            .await?;
        self.validate_paid_quote_price_floor(candidate.quote)?;

        Self::validate_paid_quote_signature(candidate).await?;

        let on_chain_amount = self
            .completed_payment_amount(candidate.quote.hash())
            .await?;
        if on_chain_amount >= candidate.expected_amount {
            return Ok(());
        }

        Err(Error::Payment(format!(
            "Median-priced quote for peer {:?} was not paid enough: expected at least {}, got {on_chain_amount}",
            candidate.encoded_peer_id, candidate.expected_amount
        )))
    }

    fn validate_paid_quote_content(
        xorname: &XorName,
        candidate: LegacyMedianCandidate<'_>,
    ) -> Result<()> {
        if verify_quote_content(candidate.quote, xorname) {
            return Ok(());
        }

        let expected_hex = hex::encode(xorname);
        let actual_hex = hex::encode(candidate.quote.content.0);
        Err(Error::Payment(format!(
            "Paid quote content address mismatch for peer {:?}: expected {expected_hex}, got {actual_hex}",
            candidate.encoded_peer_id
        )))
    }

    async fn validate_paid_quote_signature(candidate: LegacyMedianCandidate<'_>) -> Result<()> {
        let quote_for_signature = candidate.quote.clone();
        let peer_id_for_error = candidate.encoded_peer_id.clone();
        tokio::task::spawn_blocking(move || {
            if !verify_quote_signature(&quote_for_signature) {
                return Err(Error::Payment(format!(
                    "Paid quote ML-DSA-65 signature verification failed for peer {peer_id_for_error:?}"
                )));
            }
            Ok(())
        })
        .await
        .map_err(|e| Error::Payment(format!("Signature verification task failed: {e}")))?
    }

    async fn completed_payment_amount(&self, quote_hash: QuoteHash) -> Result<Amount> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            let completed_payment_override = {
                self.test_completed_payments_override
                    .read()
                    .get(&quote_hash)
                    .copied()
            };
            if let Some(amount) = completed_payment_override {
                return Ok(amount);
            }
        }

        let provider = evmlib::utils::http_provider(self.config.evm.network.rpc_url().clone());
        let vault_address = *self.config.evm.network.payment_vault_address();
        let contract = payment_vault::interface::IPaymentVault::new(vault_address, provider);

        let result = contract
            .completedPayments(quote_hash)
            .call()
            .await
            .map_err(|e| Error::Payment(format!("completedPayments lookup failed: {e}")))?;

        Ok(Amount::from(result.amount))
    }

    fn validate_paid_quote_peer_binding(
        encoded_peer_id: &evmlib::EncodedPeerId,
        quote: &PaymentQuote,
    ) -> Result<PeerId> {
        let expected_peer_id = peer_id_from_public_key_bytes(&quote.pub_key)
            .map_err(|e| Error::Payment(format!("Invalid ML-DSA public key in quote: {e}")))?;

        if expected_peer_id.as_bytes() != encoded_peer_id.as_bytes() {
            let expected_hex = expected_peer_id.to_hex();
            let actual_hex = hex::encode(encoded_peer_id.as_bytes());
            return Err(Error::Payment(format!(
                "Paid quote pub_key does not belong to claimed peer {encoded_peer_id:?}: \
                 BLAKE3(pub_key) = {expected_hex}, peer_id = {actual_hex}"
            )));
        }

        Ok(expected_peer_id)
    }

    fn validate_paid_quote_price_floor(&self, quote: &PaymentQuote) -> Result<()> {
        let Some(current_records) = self.current_records_stored() else {
            return Err(Error::Payment(
                "PaymentVerifier: no record-count source attached; cannot verify \
                 paid-quote local price floor"
                    .to_string(),
            ));
        };

        let current_price = calculate_price(usize::try_from(current_records).unwrap_or(usize::MAX));
        let min_acceptable_price = price_floor(current_price, PAID_QUOTE_PRICE_FLOOR_TOLERANCE_PCT);

        if quote.price < min_acceptable_price {
            let quoted_records = derive_records_stored_from_price(quote.price);
            return Err(Error::Payment(format!(
                "Paid quote price below local floor: quoted price encodes \
                 {quoted_records} records but node currently holds {current_records} \
                 (quoted {}, minimum acceptable {min_acceptable_price} at \
                 {PAID_QUOTE_PRICE_FLOOR_TOLERANCE_PCT}% under-payment tolerance)",
                quote.price
            )));
        }

        Ok(())
    }

    async fn validate_paid_quote_issuer_k_closest(
        &self,
        xorname: &XorName,
        issuer_peer_id: &PeerId,
    ) -> Result<()> {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(k_closest_peer_ids) = self.test_paid_quote_k_closest_override.read().as_ref() {
            if k_closest_peer_ids
                .iter()
                .any(|peer_id| peer_id == issuer_peer_id.as_bytes())
            {
                return Ok(());
            }
            let issuer_closeness_width = PAID_QUOTE_ISSUER_CLOSENESS_WIDTH;
            return Err(Error::Payment(format!(
                "Paid quote issuer {} is not among this node's local K={issuer_closeness_width} closest peers for {}",
                issuer_peer_id.to_hex(),
                hex::encode(xorname)
            )));
        }

        let attached = self.p2p_node.read().as_ref().map(Arc::clone);
        let Some(p2p_node) = attached else {
            #[cfg(any(test, feature = "test-utils"))]
            {
                crate::logging::warn!(
                    "PaymentVerifier: no P2PNode attached; paid-quote issuer \
                     K-closest check SKIPPED (test build). Production startup MUST call \
                     PaymentVerifier::attach_p2p_node."
                );
                return Ok(());
            }
            #[cfg(not(any(test, feature = "test-utils")))]
            {
                crate::logging::error!(
                    "PaymentVerifier: no P2PNode attached; rejecting paid-quote \
                     payment. This is a node-startup bug — \
                     PaymentVerifier::attach_p2p_node must be called before \
                     any PUT handler runs."
                );
                return Err(Error::Payment(
                    "Paid quote rejected: verifier is not wired to the P2P \
                     layer; cannot verify issuer closeness."
                        .into(),
                ));
            }
        };

        // Closeness *verification* must mirror the uploader's pure XOR-distance
        // peer selection. `find_closest_nodes_local_with_self` reranks the local
        // routing table by reachability (preferring directly-reachable peers,
        // XOR only as a tiebreaker), which demotes an XOR-close relay-only /
        // NAT'd peer out of the compared window and falsely rejects an honest
        // payment that legitimately quoted that peer. Use the XOR-only sibling
        // so this check matches how the client chose the quoted K-closest set.
        let issuer_closeness_width = PAID_QUOTE_ISSUER_CLOSENESS_WIDTH;
        let closest = p2p_node
            .dht_manager()
            .find_closest_nodes_local_by_distance_with_self(xorname, issuer_closeness_width)
            .await;
        if closest.iter().any(|node| node.peer_id == *issuer_peer_id) {
            return Ok(());
        }

        Err(Error::Payment(format!(
            "Paid quote issuer {} is not among this node's local K={issuer_closeness_width} closest peers for {}",
            issuer_peer_id.to_hex(),
            hex::encode(xorname)
        )))
    }

    /// Validate quote count, uniqueness, and basic structure.
    fn validate_quote_structure(payment: &ProofOfPayment) -> Result<()> {
        if payment.peer_quotes.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        let quote_count = payment.peer_quotes.len();
        if quote_count > CLOSE_GROUP_SIZE {
            return Err(Error::Payment(format!(
                "Payment must have at most {CLOSE_GROUP_SIZE} quotes, got {quote_count}"
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

    /// ADR-0003: enforce that every quoted price lies exactly on the public
    /// pricing curve.
    ///
    /// **Scope** (this slice): canonicality only. The gate proves the price is
    /// some `calculate_price(n)` for a non-negative integer `n`; it does NOT
    /// yet prove `n` matches a signed commitment, because `PaymentQuote` lives
    /// in evmlib (crates.io) and has no `claimed_key_count` / `commitment_pin`
    /// fields yet. A future slice will bind `n` to a signed commitment once
    /// the evmlib quote payload is extended. Until then, an attacker can still
    /// quote `calculate_price(fake_n)` for any fake count and pass this gate;
    /// what dies here is the strictly weaker attack of picking a price *off*
    /// the curve altogether.
    ///
    /// **Check**: exact recomputation, never price-inversion. We derive the
    /// candidate `n` for which `quote.price` would be the curve value (using
    /// the existing inverse `derive_records_stored_from_price`, which floors),
    /// then recompute `calculate_price(n)` and require strict equality.
    /// On-curve prices round-trip exactly; off-curve prices floor to a smaller
    /// `n` whose recomputed value is strictly less than `quote.price` and so
    /// are rejected. Floor-then-equality is the canonicality test the ADR
    /// specifies; price inversion alone would silently accept any value
    /// between two curve points.
    ///
    /// **Where it runs**: in every [`VerificationContext`] over **every**
    /// quote in **both** quote types — all 7 single-node quotes
    /// ([`Self::validate_quote_arithmetic`]) and all 16 merkle candidates
    /// ([`Self::validate_merkle_candidate_arithmetic`]) — because the rule
    /// "every storer re-runs the price-equals-formula-of-count check on every
    /// quote in the bundle" (ADR-0003) needs no peer-specific state and depends
    /// only on the bundle itself, so every honest storer reaches the same
    /// verdict with no split-brain risk.
    ///
    /// **Reject-only**, per ADR-0003: no trust evidence is emitted, no audit
    /// is scheduled. The rejection is the consequence. The gate is
    /// rollout-gated by
    /// [`crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED`]; when
    /// `false`, off-curve quotes are accepted and only telemetered
    /// ([`Self::log_off_curve_single_node`] /
    /// [`Self::log_off_curve_merkle`]), matching ADR-0003's observe-only
    /// rollout. Telemetry is invoked **after** ML-DSA-65 signature
    /// verification so unauthenticated senders cannot poison the rollout
    /// logs.
    fn validate_quote_arithmetic(payment: &ProofOfPayment) -> Result<()> {
        if !crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            return Ok(());
        }
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            if let Some(detail) = Self::quote_arithmetic_violation(quote) {
                return Err(Error::Payment(format!(
                    "ADR-0003 off-curve quote rejected for peer {encoded_peer_id:?}: {detail}"
                )));
            }
        }
        Ok(())
    }

    /// The ADR-0003 forced-price rule for a single quote, returning a human
    /// diagnostic iff the quote violates it. Shared by single-node quotes and
    /// merkle candidates via [`Self::binding_violation`].
    ///
    /// The rule is the ADR's exact one — `price == calculate_price(
    /// committed_key_count)`, recomputed, never inverted from the price (which
    /// rounds) — PLUS a binding-shape check. There is no "legacy degradation"
    /// that infers an old quote from its field values: a `(0, None)` quote is
    /// rejected unless its price is exactly `calculate_price(0)`, closing the
    /// bypass where a modified node strips the pin yet prices above baseline.
    /// Old-format quotes (which never carried these fields) are tolerated only
    /// at the *wire-decode* layer, where they decode as `(0, None)` and are then
    /// held to the same baseline rule; an explicit version negotiation, not
    /// field inference, is the sanctioned path if non-baseline legacy quotes
    /// must ever be accepted.
    fn quote_arithmetic_violation(quote: &evmlib::PaymentQuote) -> Option<String> {
        Self::binding_violation(
            quote.committed_key_count,
            quote.commitment_pin,
            &quote.price,
        )
    }

    /// The shared ADR-0003 binding rule over a `(committed_key_count,
    /// commitment_pin, price)` triple, used for both quote types.
    ///
    /// Enforces, in order:
    /// 1. **Shape.** `(0, None)` baseline or `(n>0, Some(pin))` bound; the mixed
    ///    shapes `(n>0, None)` and `(0, Some(_))` are always rejected — a count
    ///    without a pin is unauditable, and a pin without a count is incoherent.
    /// 2. **Cap.** `committed_key_count <= MAX_COMMITMENT_KEY_COUNT`; a count a
    ///    commitment could never legitimately attest is rejected before pricing.
    /// 3. **Forced price.** `price == calculate_price(committed_key_count)`, by
    ///    exact recomputation.
    fn binding_violation(
        committed_key_count: u32,
        commitment_pin: Option<[u8; 32]>,
        price: &Amount,
    ) -> Option<String> {
        match (committed_key_count, commitment_pin.is_some()) {
            (0, false) | (1.., true) => {}
            (1.., false) => {
                return Some(format!(
                    "binding shape invalid: committed_key_count={committed_key_count} > 0 \
                     but commitment_pin is None (unauditable count)"
                ));
            }
            (0, true) => {
                return Some(
                    "binding shape invalid: committed_key_count=0 with a commitment_pin \
                     (incoherent baseline)"
                        .to_string(),
                );
            }
        }
        if committed_key_count > crate::replication::commitment::MAX_COMMITMENT_KEY_COUNT {
            return Some(format!(
                "committed_key_count={committed_key_count} exceeds MAX_COMMITMENT_KEY_COUNT={}",
                crate::replication::commitment::MAX_COMMITMENT_KEY_COUNT
            ));
        }
        let expected = calculate_price(Self::candidate_count_to_usize(u64::from(
            committed_key_count,
        )));
        if &expected == price {
            None
        } else {
            Some(format!(
                "price {price} does not equal calculate_price(committed_key_count={committed_key_count}) = {expected}"
            ))
        }
    }

    /// Pure ADR-0003 cross-check: compare a quote's claimed `(key_count, pin)`
    /// against a resolved signed commitment.
    ///
    /// This is the decision core of "peers cross-check the original": given a
    /// quote's binding and the actual `StorageCommitment` the pin was resolved
    /// to (from the sidecar, the gossip cache, or a fetch), decide whether the
    /// quote contradicts the commitment. It is deliberately a pure function over
    /// the two artifacts so it is exhaustively unit-testable without any cache,
    /// network, or trust wiring; the caller owns resolution and emission.
    ///
    /// Outcomes:
    /// - [`CrossCheck::Match`] — the pin matches the commitment's hash and the
    ///   counts agree: nothing to report.
    /// - [`CrossCheck::Mismatch`] — the pin matches the commitment's hash but
    ///   the quote's `committed_key_count` differs from the commitment's
    ///   `key_count`. Two artifacts signed by the same key contradict each
    ///   other: this is the deterministic, first-occurrence evidence.
    /// - [`CrossCheck::PinDoesNotResolve`] — the supplied commitment's hash does
    ///   not equal the quote's pin (wrong/garbled resolution). NOT evidence: the
    ///   caller must treat it as an unresolved pin (fetch/skip), never a
    ///   penalty, exactly like an unanswerable pin.
    ///
    /// A baseline quote `(0, None)` is never cross-checked (it pins nothing);
    /// callers skip it before reaching here.
    fn cross_check_binding(
        quoted_key_count: u32,
        quoted_pin: [u8; 32],
        commitment: &crate::replication::commitment::StorageCommitment,
    ) -> CrossCheck {
        // The pin IS the commitment hash; if the resolved commitment hashes to
        // something else, this is not the artifact the quote pinned.
        match crate::replication::commitment::commitment_hash(commitment) {
            Some(h) if h == quoted_pin => {
                if commitment.key_count == quoted_key_count {
                    CrossCheck::Match
                } else {
                    CrossCheck::Mismatch {
                        quoted_key_count,
                        committed_key_count: commitment.key_count,
                    }
                }
            }
            _ => CrossCheck::PinDoesNotResolve,
        }
    }

    /// ADR-0003 "peers cross-check the original": for each non-baseline quote in
    /// a client-put bundle, resolve its `commitment_pin` against the gossip
    /// commitment cache and report a count/pin contradiction.
    ///
    /// Resolution today is the gossip cache only, and only if the neighbour's
    /// commitment was seen within `GOSSIP_ANSWERABILITY_TTL` — a staler cache
    /// entry is treated as unknown (the ADR's "cached commitment older than the
    /// answerability TTL is treated as unknown"). An unresolved pin is never a
    /// penalty: it is skipped here (the sidecar and `GetCommitmentByPin` fetch
    /// fallbacks resolve more pins and are layered on next, but a pin that
    /// resolves nowhere stays graced, exactly like an unanswerable audit pin).
    ///
    /// A genuine [`CrossCheck::Mismatch`] is a deterministic, first-occurrence
    /// contradiction between two same-key-signed artifacts: when enforcing, it
    /// emits [`FailureEvidence::QuoteCommitmentMismatch`] to the trust engine
    /// (same lane as a confirmed deterministic audit failure — NOT the timeout
    /// silence lane); when observe-only, it only logs. Always best-effort: a
    /// missing cache or absent `P2PNode` degrades to "resolve nothing", never an
    /// error on the payment path — the synchronous arithmetic gate and the
    /// later audit remain the load-bearing checks.
    /// Resolve a cached peer commitment record to its commitment *only if* it
    /// was seen within the answerability TTL; a staler entry is treated as
    /// unknown (ADR-0003: "a cached commitment older than the answerability TTL
    /// is treated as unknown"). Pure over `(record, now, ttl)` so the TTL
    /// boundary is unit-testable without the async cache/network path.
    fn fresh_cached_commitment(
        rec: &crate::replication::commitment_state::PeerCommitmentRecord,
        pin: [u8; 32],
        now: std::time::Instant,
        ttl: std::time::Duration,
    ) -> Option<crate::replication::commitment::StorageCommitment> {
        if now.saturating_duration_since(rec.received_at) >= ttl {
            return None; // stale cache entry -> treat as unknown
        }
        // Only resolve when the cached commitment is actually the one the quote
        // pinned. The auditor cache holds a peer's LATEST gossiped commitment,
        // which may be a DIFFERENT pin than this quote's; returning it would make
        // `cross_check_binding` yield `PinDoesNotResolve` and wrongly suppress
        // the fetch fallback for the quoted pin. A pin mismatch here means "not
        // cached" -> fall through to fetch.
        if rec.commitment_hash() != Some(pin) {
            return None;
        }
        rec.last_commitment().cloned()
    }

    /// Resolve a `(peer, pin)` from the gossip commitment cache, if the cache is
    /// wired and holds a fresh entry whose hash matches the pin. Shared by the
    /// single-node and merkle cross-check paths.
    async fn cache_resolve(
        cache: Option<&CommitmentCache>,
        peer_id: PeerId,
        pin: [u8; 32],
        now: std::time::Instant,
        ttl: std::time::Duration,
    ) -> Option<crate::replication::commitment::StorageCommitment> {
        let cache = cache?;
        let guard = cache.read().await;
        guard
            .get(&peer_id)
            .and_then(|rec| Self::fresh_cached_commitment(rec, pin, now, ttl))
    }

    /// Parse and validate ADR-0003 commitment sidecars into a `(peer, pin) ->
    /// commitment` map. Each blob is deserialized and held to the SAME gates as
    /// a gossip-ingested or fetched commitment (peer id derived from its own
    /// `sender_peer_id`, `BLAKE3(pubkey) == sender_peer_id`, valid signature),
    /// keyed by `(its own peer, its own hash)`. Resolution then matches a quote
    /// only when both the quote's peer AND pin equal the sidecar's, so a sidecar
    /// can never satisfy a different peer's or a different pin's quote. An
    /// unparseable or invalid sidecar is silently skipped (resolution falls back
    /// to gossip/fetch), never a hard error on the payment path.
    fn index_valid_sidecars(
        sidecars: &[Vec<u8>],
    ) -> HashMap<(PeerId, [u8; 32]), crate::replication::commitment::StorageCommitment> {
        use crate::replication::commitment::MAX_COMMITMENT_SIDECAR_BYTES;
        let mut map = HashMap::new();
        // Bound the number of sidecars we even look at: a legitimate bundle has
        // at most one commitment per quote/candidate. `MAX_SIDECARS_PER_BUNDLE`
        // (= CANDIDATES_PER_POOL, the larger of the two) caps the deserialize/
        // verify work a malicious client can force on the hot path.
        for blob in sidecars.iter().take(MAX_SIDECARS_PER_BUNDLE) {
            // Cap blob size before parsing: never attempt to deserialize an
            // oversized commitment.
            if blob.len() > MAX_COMMITMENT_SIDECAR_BYTES {
                continue;
            }
            let Ok(commitment) =
                rmp_serde::from_slice::<crate::replication::commitment::StorageCommitment>(blob)
            else {
                continue; // unparseable -> skip
            };
            let peer_id = PeerId::from_bytes(commitment.sender_peer_id);
            let Some(pin) = crate::replication::commitment::commitment_hash(&commitment) else {
                continue;
            };
            // Validate against its own (peer, pin): peer binding + pubkey
            // derivation + signature + hash==pin.
            if Self::fetched_commitment_is_valid(&commitment, &peer_id, pin) {
                map.insert((peer_id, pin), commitment);
            }
        }
        map
    }

    async fn cross_check_quotes(&self, payment: &ProofOfPayment, commitment_sidecars: &[Vec<u8>]) {
        let now = std::time::Instant::now();
        let ttl = crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
        let p2p = self.p2p_node.read().as_ref().map(Arc::clone);
        let monetized_pin_tx = self.monetized_pin_tx.read().as_ref().cloned();
        let cache = self.commitment_cache.read().as_ref().map(Arc::clone);

        // ADR-0003 "the commitment arrived with the quote": parse and FULLY
        // validate the sidecars (peer/pubkey/signature/hash gates, keyed by
        // `(peer, pin)`), so the cross-check resolves synchronously without a
        // gossip-cache hit or a post-payment fetch. An invalid sidecar is simply
        // dropped (resolution falls back to gossip/fetch), never a hard error.
        let sidecar_map = Self::index_valid_sidecars(commitment_sidecars);

        // Inline pass: resolve from the sidecar first, then the gossip cache
        // (cheap, no network). Pins that don't resolve here are collected for
        // the off-hot-path fetch.
        let mut unresolved: Vec<(PeerId, [u8; 32], u32, Vec<u8>)> = Vec::new();
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            let Some(pin) = quote.commitment_pin else {
                continue; // baseline quote pins nothing
            };
            let peer_id = PeerId::from_bytes(*encoded_peer_id.as_bytes());

            // ADR-0003: this commitment backed a payment — route it for a
            // deterministic first audit (the drainer dedups by pin and respects
            // the cooldown). Best-effort: a closed channel just means no first
            // audit is scheduled, never an error on the payment path.
            if let Some(ref tx) = monetized_pin_tx {
                let _ = tx.send(crate::replication::MonetizedPinEvent {
                    peer: peer_id,
                    pin,
                    key_count: quote.committed_key_count,
                });
            }
            // Resolution order: sidecar (synchronous, no state) -> gossip cache
            // (fresh within TTL) -> fetch fallback (collected as unresolved).
            let resolved = match sidecar_map.get(&(peer_id, pin)) {
                Some(c) => Some(c.clone()),
                None => Self::cache_resolve(cache.as_ref(), peer_id, pin, now, ttl).await,
            };
            match resolved {
                Some(commitment) => {
                    let artifact = rmp_serde::to_vec(quote).unwrap_or_default();
                    Self::handle_cross_check(
                        &peer_id,
                        pin,
                        quote.committed_key_count,
                        artifact,
                        &commitment,
                        p2p.as_ref(),
                    )
                    .await;
                }
                None => unresolved.push((
                    peer_id,
                    pin,
                    quote.committed_key_count,
                    rmp_serde::to_vec(quote).unwrap_or_default(),
                )),
            }
        }

        // Off-hot-path fallback: fetch the unresolved pins via
        // `GetCommitmentByPin` and cross-check the results in a detached task,
        // so `verify_payment` does not block on the network.
        if unresolved.is_empty() {
            return;
        }
        let Some(p2p) = p2p else {
            return; // no P2P handle: cannot fetch, leave graced
        };
        let neg_cache = Arc::clone(&self.pin_fetch_negative_cache);
        tokio::spawn(async move {
            Self::drain_unresolved_pin_fetches(&p2p, &neg_cache, unresolved).await;
        });
    }

    /// Fetch each unresolved pin via `GetCommitmentByPin` and cross-check the
    /// result. Bounded at [`MAX_PIN_FETCHES_PER_BUNDLE`] per call, negatively
    /// cached per `(peer, pin)`, and graced on any miss/timeout. Shared by the
    /// single-node and merkle cross-check paths; meant to run in a detached task
    /// off the payment hot path.
    async fn drain_unresolved_pin_fetches(
        p2p: &Arc<P2PNode>,
        neg_cache: &PinFetchNegativeCache,
        unresolved: Vec<(PeerId, [u8; 32], u32, Vec<u8>)>,
    ) {
        let mut fetched = 0usize;
        for (peer_id, pin, quoted_key_count, artifact) in unresolved {
            if fetched >= crate::replication::config::MAX_PIN_FETCHES_PER_BUNDLE {
                debug!("ADR-0003 pin-fetch cap reached for this bundle; leaving rest graced");
                break;
            }
            // Skip pins already known-unresolvable for this peer.
            if neg_cache.lock().get(&(peer_id, pin)).is_some() {
                continue;
            }
            fetched += 1;
            match Self::fetch_commitment_by_pin(p2p, &peer_id, pin).await {
                Some(commitment) => {
                    Self::handle_cross_check(
                        &peer_id,
                        pin,
                        quoted_key_count,
                        artifact,
                        &commitment,
                        Some(p2p),
                    )
                    .await;
                }
                None => {
                    // NotRetained / timeout / malformed: graced (never a
                    // penalty), but remembered so we don't re-fetch.
                    neg_cache.lock().put((peer_id, pin), ());
                }
            }
        }
    }

    /// Apply the ADR-0003 cross-check verdict for one resolved `(peer, pin,
    /// quoted_count)` against `commitment`, emitting a trust failure on a
    /// genuine mismatch (when enforcing) or logging it (observe-only). Shared by
    /// the inline cache pass and the background fetch path so both reach the
    /// same verdict and emission.
    async fn handle_cross_check(
        peer_id: &PeerId,
        pin: [u8; 32],
        quoted_key_count: u32,
        quote_artifact: Vec<u8>,
        commitment: &crate::replication::commitment::StorageCommitment,
        p2p: Option<&Arc<P2PNode>>,
    ) {
        let CrossCheck::Mismatch {
            quoted_key_count,
            committed_key_count,
        } = Self::cross_check_binding(quoted_key_count, pin, commitment)
        else {
            return; // Match or PinDoesNotResolve: nothing to report
        };
        // The evidence is only meaningful if it carries the signed quote
        // artifact (one of the two contradicting same-key signatures). An empty
        // artifact — a re-serialization failure upstream — would produce
        // non-portable, unverifiable evidence, so grace it (log) instead of
        // emitting it: the deterministic first audit still convicts a genuine
        // inflater on the disk bytes.
        if quote_artifact.is_empty() {
            warn!(
                "ADR-0003 quote/commitment mismatch for {peer_id}: dropping evidence, \
                 quote artifact failed to serialize (graced; the audit still runs)"
            );
            return;
        }
        // Build the portable evidence variant — the two same-key-signed
        // artifacts that contradict each other, carried in full so any third
        // party can re-verify both signatures and recompute the contradiction.
        // This value IS the record; `emit_mismatch_evidence` turns it into the
        // trust action (or an observe-only log).
        let evidence = crate::replication::types::FailureEvidence::QuoteCommitmentMismatch {
            peer: *peer_id,
            pinned_commitment: pin,
            quoted_key_count,
            committed_key_count,
            quote_artifact,
            commitment: Box::new(commitment.clone()),
        };
        Self::emit_mismatch_evidence(&evidence, p2p).await;
    }

    /// Route a `QuoteCommitmentMismatch` evidence record: when enforcing, report
    /// it to the trust engine as a confirmed deterministic failure (an
    /// `ApplicationFailure` — same lane as a confirmed audit failure, NOT the
    /// timeout silence lane); when observe-only, only log it. Separated so the
    /// evidence→action mapping is unit-testable independent of resolution.
    async fn emit_mismatch_evidence(
        evidence: &crate::replication::types::FailureEvidence,
        p2p: Option<&Arc<P2PNode>>,
    ) {
        let crate::replication::types::FailureEvidence::QuoteCommitmentMismatch {
            peer,
            quoted_key_count,
            committed_key_count,
            ..
        } = evidence
        else {
            return; // only this variant is handled here
        };
        let enforce = crate::replication::config::QUOTE_COMMITMENT_MISMATCH_TRUST_ENABLED;
        if enforce {
            warn!(
                "ADR-0003 quote/commitment mismatch (enforcing) for {peer}: quote claims \
                 {quoted_key_count} keys but pinned commitment attests {committed_key_count}"
            );
            if let Some(p2p) = p2p {
                p2p.report_trust_event(
                    peer,
                    saorsa_core::TrustEvent::ApplicationFailure(
                        crate::replication::config::AUDIT_FAILURE_TRUST_WEIGHT,
                    ),
                )
                .await;
            }
        } else {
            warn!(
                "ADR-0003 quote/commitment mismatch observed (not enforcing) for {peer}: quote \
                 claims {quoted_key_count} keys but pinned commitment attests {committed_key_count}"
            );
        }
    }

    /// Fetch a peer's commitment by pin via `GetCommitmentByPin`, returning it
    /// only if the peer answered `Found` with a commitment that (a) is validly
    /// signed and peer-bound and (b) actually hashes to the requested pin.
    /// `None` on `NotRetained`, timeout, malformed, or any verification failure
    /// — all graced (the caller never penalises an unresolved pin).
    async fn fetch_commitment_by_pin(
        p2p: &Arc<P2PNode>,
        peer_id: &PeerId,
        pin: [u8; 32],
    ) -> Option<crate::replication::commitment::StorageCommitment> {
        use crate::replication::config::{PIN_FETCH_TIMEOUT, REPLICATION_PROTOCOL_ID};
        use crate::replication::protocol::{
            GetCommitmentByPin, GetCommitmentByPinResponse, ReplicationMessage,
            ReplicationMessageBody,
        };
        let msg = ReplicationMessage {
            request_id: 0,
            body: ReplicationMessageBody::GetCommitmentByPin(GetCommitmentByPin { pin }),
        };
        let encoded = msg.encode().ok()?;
        let resp = p2p
            .send_request(peer_id, REPLICATION_PROTOCOL_ID, encoded, PIN_FETCH_TIMEOUT)
            .await
            .ok()?;
        let decoded = ReplicationMessage::decode(&resp.data).ok()?;
        let ReplicationMessageBody::GetCommitmentByPinResponse(GetCommitmentByPinResponse::Found {
            commitment,
        }) = decoded.body
        else {
            return None; // NotRetained / unexpected -> graced
        };
        Self::fetched_commitment_is_valid(&commitment, peer_id, pin).then_some(commitment)
    }

    /// The untrusted-fetched-commitment validation gates, pure over
    /// `(commitment, peer_id, pin)` so they are unit-testable. A fetched
    /// commitment is accepted only if it passes the SAME gates as a gossip
    /// ingest, so a peer cannot answer with another peer's (validly signed)
    /// commitment and have it pass as its own:
    ///   (a) it is bound to THIS peer (`sender_peer_id == peer_id`),
    ///   (b) the embedded pubkey derives that peer id (`BLAKE3(pk) == id`),
    ///   (c) its signature is valid (binds the pubkey),
    ///   (d) it actually hashes to the pin we asked for.
    fn fetched_commitment_is_valid(
        commitment: &crate::replication::commitment::StorageCommitment,
        peer_id: &PeerId,
        pin: [u8; 32],
    ) -> bool {
        commitment.sender_peer_id == *peer_id.as_bytes()
            && *blake3::hash(&commitment.sender_public_key).as_bytes() == commitment.sender_peer_id
            && crate::replication::commitment::verify_commitment_signature(commitment)
            && crate::replication::commitment::commitment_hash(commitment) == Some(pin)
    }

    /// Single-node telemetry for off-curve quotes. Always returns; never
    /// errors. MUST be called only after ML-DSA-65 signature verification has
    /// passed, so unauthenticated peers cannot drive log volume.
    fn log_off_curve_single_node(payment: &ProofOfPayment) {
        if crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            return; // enforce mode already rejected; no separate telemetry.
        }
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            if let Some(detail) = Self::quote_arithmetic_violation(quote) {
                warn!(
                    "ADR-0003 off-curve single-node quote observed (not enforcing): \
                     peer {encoded_peer_id:?} {detail}"
                );
            }
        }
    }

    /// ADR-0003 sister gate for the merkle batch path: every candidate's
    /// `price` field must lie on the pricing curve, by exact recomputation.
    /// See [`Self::validate_quote_arithmetic`] for the rationale; semantics
    /// (reject-only, rollout-gated, no trust evidence) are identical.
    fn validate_merkle_candidate_arithmetic(
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
    ) -> Result<()> {
        if !crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            return Ok(());
        }
        for candidate in &pool.candidate_nodes {
            if let Some(detail) = Self::binding_violation(
                candidate.committed_key_count,
                candidate.commitment_pin,
                &candidate.price,
            ) {
                return Err(Error::Payment(format!(
                    "ADR-0003 merkle candidate rejected (reward {}): {detail}",
                    candidate.reward_address
                )));
            }
        }
        Ok(())
    }

    /// Merkle batch telemetry for off-curve candidates. Always returns; never
    /// errors. MUST be called only after ML-DSA-65 signature verification has
    /// passed.
    fn log_off_curve_merkle(pool: &evmlib::merkle_payments::MerklePaymentCandidatePool) {
        if crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            return; // enforce mode already rejected; no separate telemetry.
        }
        for candidate in &pool.candidate_nodes {
            if let Some(detail) = Self::binding_violation(
                candidate.committed_key_count,
                candidate.commitment_pin,
                &candidate.price,
            ) {
                warn!(
                    "ADR-0003 merkle candidate violation observed (not enforcing): \
                     reward {} {detail}",
                    candidate.reward_address
                );
            }
        }
    }

    /// Pure curve-canonicality predicate: does `price` lie exactly on the
    /// pricing curve? Equivalent to "there exists some non-negative integer
    /// `n` such that `calculate_price(n) == price`".
    ///
    /// Separated from the rollout-gated outer gates so the canonicality rule
    /// itself is unit-testable independent of the gate. Callers MUST use this
    /// and not `derive_records_stored_from_price` directly: the latter floors
    /// and is not a canonicality test.
    ///
    /// Saturation: `derive_records_stored_from_price` saturates to `u64::MAX`
    /// for prices beyond `calculate_price(u64::MAX)`, and
    /// [`Self::candidate_count_to_usize`] saturates to `usize::MAX` on 32-bit
    /// targets. Both saturation regimes converge on `calculate_price`'s own
    /// saturation ceiling; an honest in-range price (which can never approach
    /// these regions — `MAX_COMMITMENT_KEY_COUNT` is `1_000_000`) round-trips
    /// exactly.
    #[allow(dead_code)] // boolean convenience for tests + follow-up slices
    fn quote_price_is_on_curve(price: &Amount) -> bool {
        Self::price_off_curve_diagnostics(price).is_none()
    }

    /// Returns `Some((candidate_count, recomputed))` iff `price` is off-curve;
    /// `None` iff `price` is on-curve. The tuple is the diagnostic detail used
    /// by both the rejection error message and the telemetry warning.
    fn price_off_curve_diagnostics(price: &Amount) -> Option<(u64, Amount)> {
        let candidate_count = derive_records_stored_from_price(*price);
        let recomputed = calculate_price(Self::candidate_count_to_usize(candidate_count));
        if recomputed == *price {
            None
        } else {
            Some((candidate_count, recomputed))
        }
    }

    /// Narrow the canonicality predicate's `u64` candidate into `usize` for
    /// [`calculate_price`]. On every 64-bit target (the only supported
    /// production target) this is the identity; on 32-bit targets we saturate
    /// to `usize::MAX`, which matches `calculate_price`'s own
    /// `Amount::saturating_mul` behaviour so the round-trip still terminates
    /// in the same saturation regime rather than panicking.
    fn candidate_count_to_usize(candidate_count: u64) -> usize {
        usize::try_from(candidate_count).unwrap_or(usize::MAX)
    }

    /// Verify quote freshness by price staleness, not wall-clock time and not a
    /// symmetric record-count delta.
    ///
    /// The quote price encodes the quoting node's record count via the quadratic
    /// pricing formula. We compute the price the node would charge *now* for its
    /// current fullness and reject the quote only if the client under-paid that
    /// current price by more than [`QUOTE_PRICE_STALENESS_PCT_TOLERANCE`]. This:
    ///
    /// - removes the platform clock dependency that caused Windows/UTC false
    ///   rejections (timestamps are deliberately unused);
    /// - never rejects an over-payment (the previous symmetric `abs_diff` check
    ///   rejected quotes where the node had *fewer* records than when it quoted,
    ///   i.e. the client paid for a fuller, pricier node — nonsensical to
    ///   reject); and
    /// - self-scales with the pricing curve, so benign in-flight churn (a node
    ///   storing a few replicated records between quoting and verifying) — a
    ///   negligible price move where the curve is flat — no longer rejects an
    ///   otherwise-valid payment. On a fresh, rapidly-filling testnet that churn
    ///   routinely exceeded the old fixed 5-record tolerance and rejected ~100%
    ///   of uploads via the multiplicative per-chunk effect.
    ///
    /// The current record count comes from the attached [`LmdbStorage`] via
    /// `current_chunks()` — an O(1) B-tree page-header read, authoritative
    /// regardless of which path stored the record (client PUT, replication
    /// store, repair fetch) or removed it (prune delete). If no storage source
    /// is available (mis-configured production startup, or a unit test that
    /// didn't set a test override), the gate is skipped entirely rather than
    /// rejecting every quote — see [`Self::current_records_stored`].
    ///
    /// **Only this node's own quote is gated.** A bundle contains one quote
    /// per close-group peer, and fullness across a close group is wildly
    /// heterogeneous on a real network (a freshly joined node holds tens of
    /// records while an established neighbour holds thousands). Comparing a
    /// *neighbour's* quote price against *this node's* record count therefore
    /// rejects honest payments whenever the group spans more than the
    /// tolerance — on ant-prod-01 a close group spanning 47..=1788 records
    /// made the three fullest nodes reject every bundle containing the
    /// emptiest node's (perfectly fresh, 10-second-old) quote, failing the
    /// PUT after the client had already paid on-chain. The node can only
    /// re-derive *its own* price from its own record count, so its own quote
    /// is the only one it can legitimately call stale. Replay of another
    /// node's old cheap quote is that node's gate to enforce when the PUT
    /// reaches it; the on-chain median payment binding is unaffected either
    /// way.
    ///
    /// A bundle holds at most one quote per peer — [`Self::validate_quote_structure`]
    /// rejects duplicate peer IDs and runs before this gate on every path —
    /// so the loop below matches at most one own quote.
    ///
    /// RETIRED (ADR-0003 hard cutover): no longer called on the verification
    /// path. Forced pricing binds a quote's price exactly to its committed count
    /// via `validate_quote_arithmetic`, so a valid quote can never be "stale";
    /// and the committed *responsible* count legitimately differs from the live
    /// on-disk `current_chunks()` this gate reads, so running it would
    /// false-reject healthy ADR quotes (notably baseline quotes from a node that
    /// holds records but has no live commitment yet). Kept, with its unit tests,
    /// only to document the legacy gate's exact semantics.
    #[allow(dead_code)]
    fn validate_quote_freshness(&self, payment: &ProofOfPayment) -> Result<()> {
        let Some(current_records) = self.current_records_stored() else {
            debug!(
                "PaymentVerifier: no record-count source attached; skipping \
                 quote price-staleness check"
            );
            return Ok(());
        };

        let Some(self_peer_id) = self.self_peer_id_bytes() else {
            debug!(
                "PaymentVerifier: no self peer-id source attached; skipping \
                 quote price-staleness check"
            );
            return Ok(());
        };

        // The price the node would charge right now for its current fullness,
        // and the floor a quote may not drop below (one-directional: paying at
        // or above `current_price` is always accepted).
        let current_price = calculate_price(usize::try_from(current_records).unwrap_or(usize::MAX));
        let min_acceptable_price = current_price.saturating_mul(Amount::from(
            100u64.saturating_sub(QUOTE_PRICE_STALENESS_PCT_TOLERANCE),
        )) / Amount::from(100u64);

        let mut own_quote_seen = false;
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            if encoded_peer_id.as_bytes() != &self_peer_id {
                // A neighbour's quote prices the *neighbour's* fullness; this
                // node has no basis to judge it against its own record count.
                continue;
            }
            own_quote_seen = true;
            if quote.price < min_acceptable_price {
                let quoted_records = derive_records_stored_from_price(quote.price);
                return Err(Error::Payment(format!(
                    "Own quote {encoded_peer_id:?} stale: quoted price encodes \
                     {quoted_records} records but node currently holds {current_records} \
                     (quoted {}, minimum acceptable {min_acceptable_price} at \
                     {QUOTE_PRICE_STALENESS_PCT_TOLERANCE}% under-payment tolerance)",
                    quote.price
                )));
            }
        }

        // Two self-identity notions coexist in this verifier and are expected
        // to refer to the same node: `validate_local_recipient` matches "us"
        // by rewards address, this gate by peer ID. They legitimately diverge
        // when a PUT reaches a node whose own quote isn't in the bundle but
        // whose rewards address is shared with a quoted sibling (common in
        // fleet deployments). The gate fail-opens in that case — leave a
        // breadcrumb, because a silent no-op is exactly what makes a
        // production incident hard to reconstruct from node logs.
        if !own_quote_seen {
            let our_rewards_address_quoted = payment
                .peer_quotes
                .iter()
                .any(|(_, quote)| quote.rewards_address == self.config.local_rewards_address);
            if our_rewards_address_quoted {
                debug!(
                    "PaymentVerifier: bundle contains our rewards address but no quote \
                     under our peer ID; skipping quote price-staleness check"
                );
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

    /// Minimum number of candidate `pub_keys` (out of 16) whose derived
    /// `PeerId` must be among the DHT's actual closest peers to the pool
    /// midpoint address for the pool to be accepted.
    ///
    /// Set to a simple majority (9/16). Two nodes' views of the closest set
    /// to a midpoint diverge on a young, high-churn, NAT-heavy network — by
    /// more than a near-unanimous threshold tolerates — so a stricter bar
    /// rejected honest pools whose candidates are genuinely drawn from the
    /// midpoint's close group but don't all reappear in this storer's own
    /// lookup. A majority absorbs that divergence while still requiring most
    /// candidates to be real peers the live DHT lists as closest.
    ///
    /// Security cost: a lower threshold widens the room for the "pay-yourself"
    /// attack — an attacker running real neighbourhood peers needs fewer of
    /// them to clear a majority than to clear a near-unanimous bar. No theft
    /// of funds is possible regardless (payment binds on-chain to the rewards
    /// address); the cost is that grinding storage payments back to your own
    /// nodes gets cheaper. Each counted candidate must still be a peer the
    /// live DHT actually returns as closest — a fabricated off-network key
    /// cannot satisfy this — so the floor is "run N real top-K Sybil nodes
    /// AND grind the midpoint", just with a smaller N. Pairs with the planned
    /// pool-midpoint consensus-anchor work, which removes the midpoint
    /// grinding freedom that makes a low threshold dangerous.
    const CANDIDATE_CLOSENESS_REQUIRED: usize = 9;

    /// Timeout for the authoritative network lookup used by the closeness
    /// check.
    ///
    /// Iterative Kademlia lookups can cascade through `MAX_ITERATIONS = 20`
    /// rounds in saorsa-core's `find_closest_nodes_network`, and a single
    /// unresponsive peer's dial can take 20–30s before timing out. On a
    /// young network (e.g. fresh testnet, NAT-simulated peers in 30% of
    /// the swarm) iterations average ~10s each — captured trace from
    /// STG-01 EWR-3 ant-node-1 just before a pre-fix timeout:
    ///
    /// ```text
    /// Iter 0: +0.0s | Iter 1: +0.2s | Iter 2: +6.6s | Iter 3: +13.1s
    /// Iter 4: +20.9s | Iter 5: +39.8s | Iter 6: +50.8s | [60s wall]
    /// ```
    ///
    /// 60s caps the lookup at ~7 iterations and rejects honest pools whose
    /// candidates only emerge after iteration 7. 240s gives ~1.2× headroom
    /// over the ~200s natural worst-case runtime on a 1k-node testnet.
    ///
    /// `DoS` amplification stays bounded at roughly one in-flight lookup
    /// per unique `pool_hash` under typical load, via
    /// [`closeness_pass_cache`] + [`inflight_closeness`]. The bound is
    /// "typical" because `inflight_closeness` is an LRU and a sustained
    /// flood of unique `pool_hash` entries can evict an in-flight slot,
    /// at which point a second leader can race for the same pool (see
    /// [`InflightGuard::drop`]). At steady state the pool cache and pool
    /// signature verification gate keep this rare in practice.
    const CLOSENESS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);

    /// Width of the storer's authoritative network lookup, in peers.
    ///
    /// The client over-queries `2 * CANDIDATES_PER_POOL = 32` peers via
    /// `find_closest_peers(addr, 32)` (see
    /// `ant-client/ant-core/src/data/client/merkle.rs::get_merkle_candidate_pool`)
    /// and selects 16 valid responders by XOR distance — so truly-close
    /// peers that are slow, NAT'd, or briefly unreachable get filtered
    /// out and replaced by peers from positions 17–32 of the network's
    /// actual ranking. The storer must therefore verify against the same
    /// wider window: a pool containing peers from positions 17–32 is
    /// honest (those peers really exist in the network's closest-32 set),
    /// it's just that the client's quote-collection step couldn't reach
    /// the peers at positions <17 in time.
    ///
    /// Empirical effect on STG-01 (1k-node testnet, 30% NAT-simulated):
    /// widening from K=16 to K=32 dropped client-side closeness
    /// mismatches from ~115 to ~31 per 5 min, a 73% reduction.
    ///
    /// Performance note: `count` does not just truncate the lookup —
    /// `find_closest_nodes_network` keeps iterating until either
    /// `MAX_ITERATIONS` is reached or `best_nodes.len() >= count`. K=32
    /// can therefore extend lookups by a few iterations on sparse
    /// networks vs K=16, which reinforces (rather than undermines) the
    /// timeout bump above.
    ///
    /// Security: the pay-yourself attack still requires the attacker's
    /// fabricated `PeerId`s to land in the storer's authoritative top-K, so
    /// the dominant cost is Sybil-grinding midpoint addresses or running real
    /// nodes near the target. The leniency for honest divergence comes from
    /// the `CANDIDATE_CLOSENESS_REQUIRED` majority threshold, not from this
    /// window; widening the window further was measured as too heavy on the
    /// lookup path.
    const CLOSENESS_LOOKUP_WIDTH: usize = 2 * evmlib::merkle_payments::CANDIDATES_PER_POOL;

    /// Maximum waiter → leader retries when the leader's future was cancelled
    /// or panicked before publishing a result. Beyond this the waiter returns
    /// a visible error rather than spinning indefinitely through a
    /// cancellation cascade.
    ///
    /// Worst-case waiter wall-clock is `(MAX_LEADER_RETRIES + 1) *
    /// CLOSENESS_LOOKUP_TIMEOUT` (one wait per attempt). Kept low (1)
    /// because the only realistic trigger is leader future-cancellation,
    /// which should be extraordinarily rare; under sustained adversarial
    /// cancellation a higher cap doesn't add resilience, it just hides
    /// the symptom. With `CLOSENESS_LOOKUP_TIMEOUT = 240s` this caps a
    /// single user-visible verification at ~8 min worst case (vs ~20 min
    /// at the previous value of 4).
    const MAX_LEADER_RETRIES: usize = 1;

    /// Compute the storer's authoritative-lookup width for a candidate pool.
    ///
    /// Returns `max(CLOSENESS_LOOKUP_WIDTH, pool_len)`: matches the client's
    /// over-query width today, and scales with the pool if a future protocol
    /// bump grows pool size beyond `CLOSENESS_LOOKUP_WIDTH`. Truncating to
    /// `CLOSENESS_LOOKUP_WIDTH` in that future case would re-open the
    /// K-too-small failure mode (the storer would reject honest pools whose
    /// candidates legitimately span a wider XOR range than the storer
    /// fetched). Pinned by `closeness_lookup_count_uses_max_of_width_and_pool_len`.
    const fn closeness_lookup_count(pool_len: usize) -> usize {
        if Self::CLOSENESS_LOOKUP_WIDTH > pool_len {
            Self::CLOSENESS_LOOKUP_WIDTH
        } else {
            pool_len
        }
    }

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
    /// grind the midpoint until it lands in a region where a majority of
    /// their Sybil keys are the true network-closest — at which point this check
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
    /// Derive each candidate's `PeerId` from its `pub_key` and reject the
    /// pool if any `PeerId` appears more than once.
    ///
    /// This is a pure-validation pre-check, runnable without a `P2PNode`:
    /// catches the case where one real peer's `pub_key` is repeated to
    /// inflate the closeness match count, without paying for a Kademlia
    /// lookup. An honest pool has [`evmlib::merkle_payments::CANDIDATES_PER_POOL`]
    /// distinct candidate `pub_keys` by construction.
    fn derive_distinct_candidate_peer_ids(
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
    ) -> Result<Vec<PeerId>> {
        let mut candidate_peer_ids = Vec::with_capacity(pool.candidate_nodes.len());
        let mut seen = std::collections::HashSet::with_capacity(pool.candidate_nodes.len());
        for candidate in &pool.candidate_nodes {
            let pid = peer_id_from_public_key_bytes(&candidate.pub_key).map_err(|e| {
                Error::Payment(format!(
                    "Invalid ML-DSA public key in merkle candidate: {e}"
                ))
            })?;
            if !seen.insert(pid) {
                return Err(Error::Payment(
                    "Merkle candidate pool rejected: duplicate candidate PeerId. An \
                     honest pool has 16 distinct candidate pub_keys; duplicates would \
                     let a single real peer satisfy the closeness threshold by being \
                     counted multiple times."
                        .into(),
                ));
            }
            candidate_peer_ids.push(pid);
        }
        Ok(candidate_peer_ids)
    }

    /// Pure-logic closeness check: given the pool's candidate peer IDs and
    /// the storer's authoritative network view (closest peers to the pool
    /// midpoint), decide whether the pool passes the
    /// `CANDIDATE_CLOSENESS_REQUIRED`-of-N threshold.
    ///
    /// A candidate counts only if its `PeerId` is one of the peers the
    /// storer's own network lookup returned (exact set membership). This is
    /// the property that makes the gate meaningful: a passing candidate must
    /// be a real, reachable peer the live DHT actually routes to and lists
    /// among the closest — it cannot be a key fabricated off-network. The
    /// leniency in this check is purely the lowered threshold (a majority
    /// rather than near-unanimity), which tolerates the closest-set
    /// divergence between two nodes' views without admitting fabricated keys.
    ///
    /// Extracted from `verify_merkle_candidate_closeness_inner` so tests
    /// can exercise the matching logic without standing up a real DHT.
    /// Mirrors the runtime path exactly: same sparse-network short-circuit,
    /// same set-membership check, same error strings.
    fn check_closeness_match(
        candidate_peer_ids: &[PeerId],
        network_peer_ids: &[PeerId],
        pool_address: &[u8; 32],
    ) -> Result<()> {
        // Sparse-network short-circuit: if the DHT itself returned fewer
        // peers than the closeness threshold, the proof can never pass —
        // not because the candidates are forged, but because we don't
        // have an authoritative view to compare against. Surface this
        // distinct cause so operators can tell "retry once the network
        // settles" apart from "this peer sent a forged pool".
        if network_peer_ids.len() < Self::CANDIDATE_CLOSENESS_REQUIRED {
            debug!(
                "Merkle closeness deferred: network lookup returned {} peers \
                 for pool midpoint {} (need at least {} to verify)",
                network_peer_ids.len(),
                hex::encode(pool_address),
                Self::CANDIDATE_CLOSENESS_REQUIRED,
            );
            return Err(Error::Payment(format!(
                "Merkle candidate pool rejected: authoritative DHT lookup returned \
                 only {} peers, less than the {} required to verify candidate \
                 closeness. Retry once the routing table populates further.",
                network_peer_ids.len(),
                Self::CANDIDATE_CLOSENESS_REQUIRED,
            )));
        }

        // Exact-match membership against the returned closest peers.
        // Candidate `PeerId`s are deduplicated upstream, so each match
        // corresponds to a distinct peer.
        let network_set: std::collections::HashSet<PeerId> =
            network_peer_ids.iter().copied().collect();
        let matched = candidate_peer_ids
            .iter()
            .filter(|pid| network_set.contains(pid))
            .count();

        if matched < Self::CANDIDATE_CLOSENESS_REQUIRED {
            debug!(
                "Merkle closeness rejected: {matched}/{} candidates match the DHT's closest peers \
                 for pool midpoint {} (required: {}, network returned {} peers)",
                candidate_peer_ids.len(),
                hex::encode(pool_address),
                Self::CANDIDATE_CLOSENESS_REQUIRED,
                network_peer_ids.len(),
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
            candidate_peer_ids.len(),
            hex::encode(pool_address),
        );
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn verify_merkle_candidate_closeness_inner(
        &self,
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
    ) -> Result<()> {
        // Pre-check: catch malformed/hostile pools (duplicate candidate
        // PeerIds) before paying for the Kademlia lookup. Runs in unit
        // tests without a P2PNode too.
        let candidate_peer_ids = Self::derive_distinct_candidate_peer_ids(pool)?;

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
        // Match the client's over-query width. The client's
        // `get_merkle_candidate_pool` queries 2 × `CANDIDATES_PER_POOL` peers
        // and picks the 16 closest *valid responders* — so legitimate pools
        // routinely include peers from positions 17–32 of the network's true
        // ranking when the closer peers are slow or NAT-stuck. The storer
        // must look at the same window or it will reject honest pools with
        // no security benefit.
        //
        // `pool.candidate_nodes` is currently a fixed-size array of length
        // `CANDIDATES_PER_POOL` (= 16), so `.max(...)` always evaluates to
        // `CLOSENESS_LOOKUP_WIDTH` today. The compile-time
        // `const _: () = assert!(WIDTH >= CANDIDATES_PER_POOL)` in the test
        // module pins that invariant. The `.max(...)` form is belt-and-braces
        // for a hypothetical future protocol that grows pool size to a
        // `Vec`-typed candidate set: the storer would scale its lookup with
        // the pool rather than truncating, which would otherwise re-open the
        // K-too-small failure mode.
        let lookup_count = Self::closeness_lookup_count(pool.candidate_nodes.len());
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

        let network_peer_ids: Vec<PeerId> = network_peers.iter().map(|n| n.peer_id).collect();
        Self::check_closeness_match(&candidate_peer_ids, &network_peer_ids, &pool_address.0)
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
    async fn verify_merkle_payment(
        &self,
        xorname: &XorName,
        proof_bytes: &[u8],
        context: VerificationContext,
    ) -> Result<()> {
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
            debug!(
                "Verifying merkle payment for {} ({context:?})",
                hex::encode(xorname)
            );
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

        // ADR-0003: every storer re-runs the price-equals-formula-of-count
        // check on every merkle candidate, in every context, before median
        // reconstruction. Runs AFTER signature verification so observe-only
        // telemetry cannot be spoofed by unauthenticated senders. Reject-only
        // when enforcement is enabled; no trust evidence emitted in either
        // mode.
        Self::validate_merkle_candidate_arithmetic(&merkle_proof.winner_pool)?;
        Self::log_off_curve_merkle(&merkle_proof.winner_pool);

        // Pay-yourself defence: the candidate pub_keys must map to peers the
        // live DHT actually considers closest to the pool midpoint. Without
        // this, an attacker can point all 16 reward_address fields at a
        // self-owned wallet and drain their own payment. Every storing node
        // runs this check against the single `winner_pool` in the proof, so a
        // forged pool is rejected everywhere it lands. The pass cache and
        // single-flight keyed on pool_hash collapse the Kademlia lookup cost
        // within a batch and across concurrent PUTs for the same pool.
        //
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

        // ADR-0003: route the merkle-batch candidates through the SAME
        // cross-check + first-audit funnel as single-node quotes, AFTER on-chain
        // verification has succeeded (so an unpaid pool cannot drive audits or
        // fetches). ClientPut only — a replication receipt's pins have aged out.
        if context == VerificationContext::ClientPut {
            self.cross_check_merkle_candidates(
                &merkle_proof.winner_pool,
                &merkle_proof.commitment_sidecars,
            )
            .await;
        }

        Ok(())
    }

    /// ADR-0003 cross-check for the merkle-batch path: every candidate carries
    /// the same signed `(committed_key_count, commitment_pin)` binding as a
    /// single-node quote, so each non-baseline candidate is resolved against the
    /// gossip cache (or fetched) and routed into the deterministic first audit,
    /// exactly like [`Self::cross_check_quotes`]. The candidate's peer id is
    /// derived from its `pub_key` (`PeerId = BLAKE3(pub_key)`), matching how the
    /// network binds identities.
    async fn cross_check_merkle_candidates(
        &self,
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
        commitment_sidecars: &[Vec<u8>],
    ) {
        let now = std::time::Instant::now();
        let ttl = crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
        let p2p = self.p2p_node.read().as_ref().map(Arc::clone);
        let monetized_pin_tx = self.monetized_pin_tx.read().as_ref().cloned();
        let cache = self.commitment_cache.read().as_ref().map(Arc::clone);
        // ADR-0003 "the commitment arrived with the quote" for the merkle path:
        // validate sidecars exactly as the single-node path does.
        let sidecar_map = Self::index_valid_sidecars(commitment_sidecars);

        let mut unresolved: Vec<(PeerId, [u8; 32], u32, Vec<u8>)> = Vec::new();
        for candidate in &pool.candidate_nodes {
            let Some(pin) = candidate.commitment_pin else {
                continue; // baseline candidate pins nothing
            };
            let peer_id = PeerId::from_bytes(*blake3::hash(&candidate.pub_key).as_bytes());

            if let Some(ref tx) = monetized_pin_tx {
                let _ = tx.send(crate::replication::MonetizedPinEvent {
                    peer: peer_id,
                    pin,
                    key_count: candidate.committed_key_count,
                });
            }

            let resolved = match sidecar_map.get(&(peer_id, pin)) {
                Some(c) => Some(c.clone()),
                None => Self::cache_resolve(cache.as_ref(), peer_id, pin, now, ttl).await,
            };
            match resolved {
                Some(commitment) => {
                    let artifact = rmp_serde::to_vec(candidate).unwrap_or_default();
                    Self::handle_cross_check(
                        &peer_id,
                        pin,
                        candidate.committed_key_count,
                        artifact,
                        &commitment,
                        p2p.as_ref(),
                    )
                    .await;
                }
                None => unresolved.push((
                    peer_id,
                    pin,
                    candidate.committed_key_count,
                    rmp_serde::to_vec(candidate).unwrap_or_default(),
                )),
            }
        }

        if unresolved.is_empty() {
            return;
        }
        let Some(p2p) = p2p else {
            return;
        };
        let neg_cache = Arc::clone(&self.pin_fetch_negative_cache);
        tokio::spawn(async move {
            Self::drain_unresolved_pin_fetches(&p2p, &neg_cache, unresolved).await;
        });
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
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use evmlib::merkle_payments::MerklePaymentCandidatePool;
    use evmlib::PaymentQuote;
    use saorsa_core::MlDsa65;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;
    use saorsa_pqc::pqc::MlDsaOperations;
    use std::time::SystemTime;

    /// Create a verifier for unit tests. EVM is always on, but tests can
    /// pre-populate the cache to bypass on-chain verification.
    fn create_test_verifier() -> PaymentVerifier {
        let config = PaymentVerifierConfig {
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100,
            close_group_size: CLOSE_GROUP_SIZE,
            local_rewards_address: RewardsAddress::new([1u8; 20]),
        };
        PaymentVerifier::new(config)
    }

    #[test]
    fn paid_quote_issuer_closeness_width_uses_k() {
        let issuer_closeness_width = PAID_QUOTE_ISSUER_CLOSENESS_WIDTH;
        let k_bucket_size = K_BUCKET_SIZE;
        let close_group_size = CLOSE_GROUP_SIZE;

        assert_eq!(issuer_closeness_width, k_bucket_size);
        assert!(issuer_closeness_width > close_group_size);
    }

    fn make_signed_quote(
        xorname: XorName,
        price: Amount,
        rewards_seed: u8,
    ) -> (evmlib::EncodedPeerId, PaymentQuote) {
        let ml_dsa = MlDsa65::new();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");
        let pub_key_bytes = public_key.as_bytes().to_vec();
        let peer_id = encoded_peer_id_for_pub_key(&pub_key_bytes);
        let mut quote = PaymentQuote {
            content: xor_name::XorName(xorname),
            timestamp: SystemTime::now(),
            price,
            rewards_address: RewardsAddress::new([rewards_seed; 20]),
            pub_key: pub_key_bytes,
            signature: Vec::new(),
        };
        let secret_key = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("secret key");
        quote.signature = ml_dsa
            .sign(&secret_key, &quote.bytes_for_sig())
            .expect("sign quote")
            .as_bytes()
            .to_vec();
        (peer_id, quote)
    }

    fn make_signed_legacy_bundle(
        xorname: XorName,
        prices: [Amount; CLOSE_GROUP_SIZE],
    ) -> Vec<(evmlib::EncodedPeerId, PaymentQuote)> {
        prices
            .into_iter()
            .enumerate()
            .map(|(index, price)| {
                let rewards_seed = u8::try_from(index + 1).expect("small test index");
                make_signed_quote(xorname, price, rewards_seed)
            })
            .collect()
    }

    fn price_at_records(records: usize) -> Amount {
        crate::payment::pricing::calculate_price(records)
    }

    fn unique_test_prices() -> [Amount; CLOSE_GROUP_SIZE] {
        [
            price_at_records(0),
            price_at_records(1),
            price_at_records(2),
            price_at_records(3),
            price_at_records(4),
            price_at_records(5),
            price_at_records(6),
        ]
    }

    fn tied_median_test_prices() -> [Amount; CLOSE_GROUP_SIZE] {
        [
            price_at_records(0),
            price_at_records(1),
            price_at_records(2),
            price_at_records(3),
            price_at_records(3),
            price_at_records(4),
            price_at_records(5),
        ]
    }

    fn median_test_candidates(
        peer_quotes: &[(evmlib::EncodedPeerId, PaymentQuote)],
    ) -> Vec<(evmlib::EncodedPeerId, PaymentQuote)> {
        let mut sorted_quotes: Vec<_> = peer_quotes.iter().collect();
        sorted_quotes.sort_by_key(|(_, quote)| quote.price);
        let median_index = median_quote_index(sorted_quotes.len());
        let median_price = sorted_quotes
            .get(median_index)
            .expect("median quote")
            .1
            .price;

        sorted_quotes
            .into_iter()
            .filter(|(_, quote)| quote.price == median_price)
            .map(|(peer_id, quote)| (peer_id.clone(), quote.clone()))
            .collect()
    }

    fn expected_median_payment(peer_quotes: &[(evmlib::EncodedPeerId, PaymentQuote)]) -> Amount {
        let median_price = median_test_candidates(peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .price;
        median_price * Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER)
    }

    fn mark_k_closest_paid_candidates(
        verifier: &PaymentVerifier,
        peer_quotes: &[(evmlib::EncodedPeerId, PaymentQuote)],
    ) {
        let k_closest_peers = median_test_candidates(peer_quotes)
            .iter()
            .map(|(peer_id, _)| *peer_id.as_bytes())
            .collect();
        verifier.set_paid_quote_k_closest_for_tests(k_closest_peers);
    }

    fn mark_candidate_paid(verifier: &PaymentVerifier, quote: &PaymentQuote, amount: Amount) {
        verifier.set_completed_payment_for_tests(quote.hash(), amount);
    }

    fn mark_all_median_candidates_unpaid(
        verifier: &PaymentVerifier,
        peer_quotes: &[(evmlib::EncodedPeerId, PaymentQuote)],
    ) {
        for (_, quote) in median_test_candidates(peer_quotes) {
            mark_candidate_paid(verifier, &quote, Amount::ZERO);
        }
    }

    #[test]
    fn test_payment_required_for_new_data() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // All uncached data requires payment
        let status = verifier.check_payment_required(&xorname, VerificationContext::ClientPut);
        assert_eq!(status, PaymentStatus::PaymentRequired);
    }

    #[test]
    fn test_cache_hit() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Manually add to cache
        verifier.cache.insert(xorname);

        // Should return CachedAsVerified
        let status = verifier.check_payment_required(&xorname, VerificationContext::ClientPut);
        assert_eq!(status, PaymentStatus::CachedAsVerified);
    }

    #[tokio::test]
    async fn test_verify_payment_without_proof_rejected() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // No proof provided => should return an error (EVM is always on)
        let result = verifier
            .verify_payment(&xorname, None, VerificationContext::ClientPut)
            .await;
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
        let result = verifier
            .verify_payment(&xorname, None, VerificationContext::ClientPut)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.expect("cached"), PaymentStatus::CachedAsVerified);
    }

    #[tokio::test]
    async fn test_paid_list_cache_entry_does_not_satisfy_client_put() {
        let verifier = create_test_verifier();
        let xorname = [0xB8u8; 32];
        verifier.cache.insert_paid_list_verified(xorname);

        assert_eq!(
            verifier.check_payment_required(&xorname, VerificationContext::PaidListAdmission),
            PaymentStatus::CachedAsVerified,
            "paid-list lookups must hit a paid-list-verified entry"
        );
        assert_eq!(
            verifier.check_payment_required(&xorname, VerificationContext::ClientPut),
            PaymentStatus::PaymentRequired,
            "client PUT must not fast-path on a paid-list-verified entry"
        );

        let err = verifier
            .verify_payment(&xorname, None, VerificationContext::ClientPut)
            .await
            .expect_err("proof-less client PUT must not ride the paid-list entry");
        assert!(
            format!("{err}").contains("Payment required"),
            "client PUT must still demand payment: {err}"
        );
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
            verifier.check_payment_required(&xorname, VerificationContext::ClientPut),
            PaymentStatus::PaymentRequired
        );

        // Pre-populate cache (simulates a previous successful payment)
        verifier.cache.insert(xorname);

        // Now the xorname should be cached
        assert_eq!(
            verifier.check_payment_required(&xorname, VerificationContext::ClientPut),
            PaymentStatus::CachedAsVerified
        );
    }

    #[tokio::test]
    async fn test_proof_too_small() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Proof smaller than MIN_PAYMENT_PROOF_SIZE_BYTES
        let small_proof = vec![0u8; MIN_PAYMENT_PROOF_SIZE_BYTES - 1];
        let result = verifier
            .verify_payment(&xorname, Some(&small_proof), VerificationContext::ClientPut)
            .await;
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
        let result = verifier
            .verify_payment(&xorname, Some(&large_proof), VerificationContext::ClientPut)
            .await;
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
            .verify_payment(
                &xorname,
                Some(&boundary_proof),
                VerificationContext::ClientPut,
            )
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
            .verify_payment(
                &xorname,
                Some(&boundary_proof),
                VerificationContext::ClientPut,
            )
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
        let result = verifier
            .verify_payment(&xorname, Some(&garbage), VerificationContext::ClientPut)
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("deserialize") || err_msg.contains("Failed"),
            "Error should mention deserialization failure: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_median_full_path_accepted() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xA1u8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("paid median should verify"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_single_quote_proof_accepted() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xB1u8; 32];
        let (peer_id, quote) = make_signed_quote(xorname, price_at_records(0), 1);
        let peer_quotes = vec![(peer_id, quote.clone())];
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        mark_candidate_paid(&verifier, &quote, expected_median_payment(&peer_quotes));

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("single paid quote should verify"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_single_quote_proof_requires_three_x_payment() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xB2u8; 32];
        let (peer_id, quote) = make_signed_quote(xorname, price_at_records(0), 1);
        let peer_quotes = vec![(peer_id, quote.clone())];
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        mark_candidate_paid(&verifier, &quote, quote.price);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("single quote paid less than 3x should be rejected");

        assert!(
            format!("{err}").contains("not paid enough"),
            "Error should mention underpayment: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_too_many_quotes_rejected() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xB3u8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        peer_quotes.push(make_signed_quote(xorname, price_at_records(7), 8));

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("proof with more than close-group quotes should be rejected");

        assert!(
            format!("{err}").contains("at most"),
            "Error should mention max quote count: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_structural_majority_price_at_median_accepted() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(1000);
        let xorname = [0xA2u8; 32];
        let peer_quotes = make_signed_legacy_bundle(
            xorname,
            [
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(100),
                crate::payment::pricing::calculate_price(500),
                crate::payment::pricing::calculate_price(1000),
                crate::payment::pricing::calculate_price(2000),
                crate::payment::pricing::calculate_price(4000),
                crate::payment::pricing::calculate_price(6000),
            ],
        );
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("median-priced verifier should accept"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_above_median_verifier_rejected_by_floor() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(2000);
        let xorname = [0xA3u8; 32];
        let peer_quotes = make_signed_legacy_bundle(
            xorname,
            [
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(100),
                crate::payment::pricing::calculate_price(500),
                crate::payment::pricing::calculate_price(1000),
                crate::payment::pricing::calculate_price(2000),
                crate::payment::pricing::calculate_price(4000),
                crate::payment::pricing::calculate_price(6000),
            ],
        );
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("above-median verifier should reject the client PUT");

        assert!(
            format!("{err}").contains("below local floor"),
            "Error should mention paid-quote floor: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_median_issuer_k_closest_rejection() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        verifier.set_paid_quote_k_closest_for_tests(vec![rand::random()]);
        let xorname = [0xA4u8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("out-of-K paid issuer should be rejected");

        assert!(
            format!("{err}").contains("not among this node's local"),
            "Error should mention local K-closest peers: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_median_floor_rejection() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(6000);
        let xorname = [0xA5u8; 32];
        let peer_quotes = make_signed_legacy_bundle(
            xorname,
            [
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
            ],
        );
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("cheap paid median should be rejected");

        assert!(
            format!("{err}").contains("below local floor"),
            "Error should mention local floor: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_zero_price_median_rejected() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xA6u8; 32];
        let peer_quotes = make_signed_legacy_bundle(
            xorname,
            [
                Amount::ZERO,
                Amount::ZERO,
                Amount::ZERO,
                Amount::ZERO,
                Amount::from(1u64),
                Amount::from(2u64),
                Amount::from(3u64),
            ],
        );

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("zero median must be rejected");

        assert!(
            format!("{err}").contains("zero price"),
            "Error should mention zero price: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_quote_content_mismatch_rejected() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xA7u8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        let median_index = median_quote_index(peer_quotes.len());
        peer_quotes[median_index].1.content = xor_name::XorName([0xE7u8; 32]);
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("paid quote content mismatch should be rejected");

        assert!(
            format!("{err}").contains("content address mismatch"),
            "Error should mention content mismatch: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_unpaid_quote_content_mismatch_accepted() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xA8u8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        peer_quotes[0].1.content = xor_name::XorName([0xE8u8; 32]);
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("unpaid content mismatch should be ignored"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_quote_bad_signature_rejected() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xA9u8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        let median_index = median_quote_index(peer_quotes.len());
        peer_quotes[median_index].1.signature.push(0xFF);
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("paid bad signature should be rejected");

        assert!(
            format!("{err}").contains("signature verification failed"),
            "Error should mention signature failure: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_unpaid_quote_bad_signature_accepted() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xAAu8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        peer_quotes[0].1.signature.push(0xFF);
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("unpaid bad signature should be ignored"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_unpaid_peer_binding_mismatch_accepted() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xABu8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        peer_quotes[0].0 = evmlib::EncodedPeerId::new(rand::random());
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("unpaid peer binding mismatch should be ignored"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_median_tie_accepts_paid_candidate() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        let xorname = [0xACu8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, tied_median_test_prices());
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        mark_all_median_candidates_unpaid(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .get(1)
            .expect("second tied median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("one paid tied median candidate should verify"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_list_admission_enforces_issuer_k_closest() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(0);
        verifier.set_paid_quote_k_closest_for_tests(Vec::new());
        let xorname = [0xB5u8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(
                &xorname,
                Some(&proof_bytes),
                VerificationContext::PaidListAdmission,
            )
            .await
            .expect_err("paid-list admission must enforce the paid issuer K-closest check");

        assert!(
            format!("{err}").contains("not among this node's local"),
            "Error should mention local K-closest peers: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_list_admission_enforces_full_bundle_floor() {
        let verifier = create_test_verifier();
        verifier.set_records_stored_for_tests(6000);
        let xorname = [0xB6u8; 32];
        let peer_quotes = make_signed_legacy_bundle(
            xorname,
            [
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(0),
            ],
        );
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(
                &xorname,
                Some(&proof_bytes),
                VerificationContext::PaidListAdmission,
            )
            .await
            .expect_err("paid-list admission must enforce the floor for full bundles");

        assert!(
            format!("{err}").contains("below local floor"),
            "Error should mention the local price floor: {err}"
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
        verifier.check_payment_required(&xorname, VerificationContext::ClientPut);
        let stats = verifier.cache_stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Insert and hit
        verifier.cache.insert(xorname);
        verifier.check_payment_required(&xorname, VerificationContext::ClientPut);
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
                v.verify_payment(&xorname, None, VerificationContext::ClientPut)
                    .await
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
            commitment_sidecars: vec![],
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
            committed_key_count: 0,
            commitment_pin: None,
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
            commitment_sidecars: vec![],
        };

        let proof_bytes = serialize_single_node_proof(&proof).expect("serialize proof");

        let result = verifier
            .verify_payment(
                &target_xorname,
                Some(&proof_bytes),
                VerificationContext::ClientPut,
            )
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
            committed_key_count: 0,
            commitment_pin: None,
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
            commitment_sidecars: vec![],
        };
        serialize_single_node_proof(&proof).expect("serialize proof")
    }

    #[tokio::test]
    async fn test_old_quote_uses_storage_delta_not_timestamp() {
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
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("expired"),
            "Should not reject by timestamp age: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_future_quote_uses_storage_delta_not_timestamp() {
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
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("future"),
            "Should not reject by future timestamp: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quote_within_clock_skew_tolerance_accepted() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD1u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 30 seconds in the future — well within 300s tolerance
        let future_timestamp = SystemTime::now() + Duration::from_secs(30);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        // Should NOT fail at timestamp check (will fail later at pub_key binding)
        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("future"),
            "Should pass timestamp check (within tolerance), but got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quote_beyond_clock_skew_still_uses_storage_delta() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD2u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 360 seconds in the future — exceeds 300s tolerance
        let future_timestamp = SystemTime::now() + Duration::from_secs(360);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("future"),
            "Should not reject by future timestamp: {err_msg}"
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
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

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
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert!(result.is_err(), "Should reject wrong peer binding");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("pub_key does not belong to claimed peer"),
            "Error should mention binding mismatch: {err_msg}"
        );
    }

    // =========================================================================
    // VerificationContext tests — both contexts verify fresh proof admissions.
    // Later neighbour-sync repair has no proof-of-payment and is authorized by
    // closest-7 storage quorum or closest-K paid-list quorum instead.
    // =========================================================================

    /// Content binding is required for every fresh proof context. A receipt for
    /// chunk A cannot admit chunk B as either a direct/fresh store or a fresh
    /// paid-list update.
    #[tokio::test]
    async fn test_fresh_contexts_reject_content_mismatch() {
        let verifier = create_test_verifier();
        let stored_xorname = [0xD2u8; 32];
        let quoted_xorname = [0xD3u8; 32];
        let rewards = RewardsAddress::new([1u8; 20]);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            let quote = make_fake_quote(quoted_xorname, SystemTime::now(), rewards);
            peer_quotes.push((evmlib::EncodedPeerId::new(rand::random()), quote));
        }
        let proof_bytes = serialize_proof(peer_quotes);

        for context in [
            VerificationContext::ClientPut,
            VerificationContext::PaidListAdmission,
        ] {
            let err = verifier
                .verify_payment(&stored_xorname, Some(&proof_bytes), context)
                .await
                .expect_err("content binding must hold in every context");
            assert!(
                format!("{err}").contains("content address mismatch"),
                "{context:?} must reject a receipt for a different address: {err}"
            );
        }
    }

    /// The merkle pay-yourself closeness defence (including its duplicate-
    /// candidate pre-check, which runs without a `P2PNode`) applies to every
    /// proof verification context because every context is a fresh admission.
    #[tokio::test]
    async fn test_fresh_contexts_enforce_merkle_closeness() {
        let verifier = create_test_verifier();

        let (mut merkle_proof, _pool_hash, xorname, _timestamp) = make_valid_merkle_proof();

        // 16 copies of one real candidate: every self-signature is valid, but
        // the candidate PeerIds are duplicates — the closeness pre-check
        // rejects this pool on a client PUT.
        let shared = merkle_proof
            .winner_pool
            .candidate_nodes
            .first()
            .expect("candidates")
            .clone();
        for c in &mut merkle_proof.winner_pool.candidate_nodes {
            *c = shared.clone();
        }
        let tagged =
            crate::payment::proof::serialize_merkle_proof(&merkle_proof).expect("serialize");

        for context in [
            VerificationContext::ClientPut,
            VerificationContext::PaidListAdmission,
        ] {
            let err = verifier
                .verify_payment(&xorname, Some(&tagged), context)
                .await
                .expect_err("duplicate candidate PeerIds must fail fresh admission closeness");
            assert!(
                format!("{err}").contains("duplicate candidate PeerId"),
                "{context:?} must fail at the closeness pre-check: {err}"
            );
        }
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
            .verify_payment(
                &xorname,
                Some(&merkle_garbage),
                VerificationContext::ClientPut,
            )
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
            commitment_sidecars: vec![],
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
        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_bytes),
                VerificationContext::ClientPut,
            )
            .await;

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

    #[tokio::test]
    async fn closeness_rejects_pool_with_duplicate_candidate_pub_keys() {
        // An attacker who submits 16 copies of the same real peer's pub_key
        // would otherwise satisfy the closeness threshold trivially:
        // that one peer's membership in the DHT-returned set would count
        // 16 times. The dedupe check in verify_merkle_candidate_closeness_inner
        // must reject the pool BEFORE the network lookup runs (so this test
        // works even with no P2PNode attached).
        let verifier = create_test_verifier();
        let pool_hash = [0xDDu8; 32];

        // Build a normal pool, then overwrite every candidate's pub_key
        // with a single shared key so all 16 derive to the same PeerId.
        let mut candidates = make_candidate_nodes(1_700_000_000);
        let shared_pub_key = candidates
            .first()
            .expect("make_candidate_nodes returns CANDIDATES_PER_POOL entries")
            .pub_key
            .clone();
        for c in &mut candidates {
            c.pub_key = shared_pub_key.clone();
        }
        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: candidates,
        };

        let result = verifier
            .verify_merkle_candidate_closeness(&pool, pool_hash)
            .await;
        let err = result.expect_err("duplicate candidate PeerIds must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate candidate PeerId"),
            "rejection must be the duplicate-PeerId branch, got: {msg}"
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
            let msg = MerklePaymentCandidateNode::bytes_to_sign(
                &price,
                &reward_address,
                timestamp,
                0,
                &None,
            );
            let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
            let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

            MerklePaymentCandidateNode {
                pub_key: pub_key.as_bytes().to_vec(),
                price,
                reward_address,
                merkle_payment_timestamp: timestamp,
                committed_key_count: 0,
                commitment_pin: None,
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
            .verify_payment(
                &wrong_xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
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

        let result = verifier
            .verify_payment(&xorname, Some(&bad_proof), VerificationContext::ClientPut)
            .await;

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
            close_group_size: CLOSE_GROUP_SIZE,
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

        let result = verifier
            .verify_payment(&xorname, Some(&tagged), VerificationContext::ClientPut)
            .await;

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

        let result = verifier
            .verify_payment(&xorname, Some(&tagged), VerificationContext::ClientPut)
            .await;

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

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

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

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

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

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

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

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

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

    // =========================================================================
    // Closeness-window constants regression tests
    //
    // These constants are load-bearing for both correctness (the storer
    // must look at the same window the client picks from, otherwise honest
    // pools are rejected) and DoS resistance (the timeout caps lookup
    // amplification per forged pool_hash). Pinning them with tests gives
    // future patches a one-line failure if either is silently changed
    // without updating the security argument in the doc comments.
    //
    // Empirical justification, captured during STG-01 investigation on
    // 2026-05-01:
    //
    //   - 60s timeout cut iterative lookups off after ~7 of 20 iterations
    //     (trace from EWR-3 ant-node-1 in CLOSENESS_LOOKUP_TIMEOUT doc).
    //   - K=16 storer window vs K=32 client over-query produced 73%
    //     false-positive mismatch rejections under realistic load
    //     (115 → 31 client mismatches per 5min after K=32 deploy).
    // =========================================================================

    #[test]
    fn closeness_lookup_timeout_is_240s() {
        // Pin the timeout. If a future change drops it back to 60s the
        // failure mode from the trace in the doc comment will return.
        assert_eq!(
            PaymentVerifier::CLOSENESS_LOOKUP_TIMEOUT,
            std::time::Duration::from_secs(240),
            "CLOSENESS_LOOKUP_TIMEOUT must be 240s; if changing this, update \
             the iteration trace in the doc comment and re-validate on a \
             fresh testnet"
        );
    }

    #[test]
    fn closeness_lookup_width_is_32() {
        // Pin the storer's lookup width. Must equal the client's
        // over-query factor (CANDIDATES_PER_POOL * 2 = 32) so the storer
        // sees the same peers the client legitimately picks from.
        assert_eq!(
            PaymentVerifier::CLOSENESS_LOOKUP_WIDTH,
            2 * evmlib::merkle_payments::CANDIDATES_PER_POOL,
            "CLOSENESS_LOOKUP_WIDTH must equal 2 * CANDIDATES_PER_POOL to \
             match the client's over-query in get_merkle_candidate_pool"
        );
    }

    #[test]
    fn closeness_required_threshold_is_majority() {
        // Pin the threshold so a future change can't silently move it. This
        // is the security knob: a 9/16 majority tolerates closest-set
        // divergence between two nodes' views while still requiring most
        // candidates to be real peers the live DHT lists as closest.
        assert_eq!(
            PaymentVerifier::CANDIDATE_CLOSENESS_REQUIRED,
            9,
            "closeness threshold is a 9/16 majority"
        );
    }

    #[test]
    fn closeness_lookup_count_uses_max_of_width_and_pool_len() {
        // The honest case: a 16-candidate pool must trigger a 32-peer
        // network lookup. This is the K=16-rejects-honest-pool fix from
        // the STG-01 investigation — without it, the storer never
        // observes the peers at network-true positions 17–32 that the
        // client legitimately picks from.
        let standard =
            PaymentVerifier::closeness_lookup_count(evmlib::merkle_payments::CANDIDATES_PER_POOL);
        assert_eq!(
            standard, 32,
            "honest 16-candidate pool must trigger a 32-peer DHT lookup"
        );

        // Future-proof: if a protocol bump ever produces a pool larger
        // than CLOSENESS_LOOKUP_WIDTH, lookup_count must scale with the
        // pool — not truncate to WIDTH. Truncating would let an attacker
        // hide candidates by padding the pool past the storer's window.
        assert_eq!(
            PaymentVerifier::closeness_lookup_count(64),
            64,
            "lookup_count must scale up if pool exceeds CLOSENESS_LOOKUP_WIDTH"
        );

        // Lower bound (also covered by the const-assert below; pin the
        // runtime path too in case the const-assert is ever removed).
        assert_eq!(
            PaymentVerifier::closeness_lookup_count(1),
            PaymentVerifier::CLOSENESS_LOOKUP_WIDTH,
            "lookup_count must never drop below CLOSENESS_LOOKUP_WIDTH"
        );
    }

    // Compile-time invariant: the `closeness_lookup_count` formula relies
    // on WIDTH being ≥ CANDIDATES_PER_POOL so we never request fewer peers
    // than the pool itself contains.
    const _: () = assert!(
        PaymentVerifier::CLOSENESS_LOOKUP_WIDTH >= evmlib::merkle_payments::CANDIDATES_PER_POOL,
        "CLOSENESS_LOOKUP_WIDTH must be ≥ CANDIDATES_PER_POOL",
    );

    // =========================================================================
    // Closeness-match logic tests
    //
    // These tests use the extracted `check_closeness_match` helper to
    // exercise the matching logic directly with synthetic peer-ID sets,
    // without standing up a real DHT. They cover:
    //
    //   - the 9/16 majority threshold (accept at exactly 9, reject below);
    //   - that a candidate counts only via exact membership in the storer's
    //     returned closest peers, so off-network fabrications are rejected;
    //   - the sparse-network short-circuit.
    //
    // Synthetic PeerIds put the tag in `bytes[0]`, so a candidate is in or
    // out of the network's returned set purely by tag value.
    // =========================================================================

    /// Build a deterministic `PeerId` from a single byte tag.
    fn synthetic_peer_id(tag: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        PeerId::from_bytes(bytes)
    }

    /// Build a vector of synthetic `PeerId`s tagged with bytes 1..=n.
    fn synthetic_peer_ids(n: u8) -> Vec<PeerId> {
        (1..=n).map(synthetic_peer_id).collect()
    }

    #[test]
    fn closeness_match_passes_when_all_16_candidates_in_top_16() {
        // Trivial case: every candidate is in the network's top-16.
        // Asserts the happy path still works after the refactor.
        let candidates = synthetic_peer_ids(16);
        let network = synthetic_peer_ids(16);
        let pool_address = [0u8; 32];
        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(result.is_ok(), "all-in-top-16 pool must pass: {result:?}");
    }

    #[test]
    fn closeness_match_passes_when_candidates_span_positions_1_to_15_and_17() {
        // The client's pool contains 16 candidates, 15 at network-true
        // positions 1..=15 plus one at position 17 (the position-16 peer was
        // unresponsive when the client over-queried). Under K=32 all 16 are
        // exact matches, comfortably ≥ the 9/16 majority.
        let candidates = synthetic_peer_ids(15)
            .into_iter()
            .chain(std::iter::once(synthetic_peer_id(17)))
            .collect::<Vec<_>>();
        // Lookup window = 32, includes position 17.
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();
        let pool_address = [0u8; 32];
        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(
            result.is_ok(),
            "pool with one candidate at position 17 must pass: {result:?}"
        );
    }

    #[test]
    fn closeness_match_accepts_honest_skew_via_exact_matches() {
        // Honest skew: the client's 16 candidates span network-true positions
        // {1..=12, 17, 19, 21, 23}. The lookup window of 32 covers all of
        // them, so all 16 are exact matches — trivially ≥ the 9/16 majority.
        let candidates: Vec<PeerId> = (1..=12u8)
            .chain([17u8, 19, 21, 23])
            .map(synthetic_peer_id)
            .collect();
        let pool_address = [0u8; 32];
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();

        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(
            result.is_ok(),
            "honest pool fully inside the lookup window must pass: {result:?}"
        );
    }

    #[test]
    fn closeness_match_rejects_forged_pool() {
        // Security floor: a fully-forged pool whose candidate PeerIds are
        // disjoint from the network's returned closest peers must be
        // rejected. The lowered majority threshold must NOT let off-network
        // fabrications pass — every counted candidate has to be a peer the
        // live DHT actually returned.
        let forged_candidates: Vec<PeerId> = (100..=115).map(synthetic_peer_id).collect();
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();
        let pool_address = [0u8; 32];

        let result =
            PaymentVerifier::check_closeness_match(&forged_candidates, &network, &pool_address);
        match result {
            Err(Error::Payment(msg)) => {
                assert!(
                    msg.contains("candidate pub_keys do not match"),
                    "expected forged-pool rejection message, got: {msg}"
                );
            }
            other => {
                panic!("forged pool disjoint from the network set must be rejected: {other:?}")
            }
        }
    }

    #[test]
    fn closeness_match_rejects_pool_below_majority() {
        // Threshold sanity: 8 candidates are exact matches (tags 1..=8) and
        // the other 8 are off-network fabrications (tags 100..=107). 8 < 9
        // → reject.
        let mut candidates = synthetic_peer_ids(8);
        candidates.extend((100..=107).map(synthetic_peer_id)); // 8 fabrications
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();
        let pool_address = [0u8; 32];

        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(
            result.is_err(),
            "8 matches < majority of 9/16 must reject: {result:?}"
        );
    }

    #[test]
    fn closeness_match_accepts_at_exactly_majority() {
        // Threshold sanity: exactly 9 candidates are exact matches (tags
        // 1..=9), the other 7 are off-network fabrications (tags 100..=106).
        // 9 ≥ 9 → accept.
        let mut candidates = synthetic_peer_ids(9);
        candidates.extend((100..=106).map(synthetic_peer_id)); // 7 fabrications
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();
        let pool_address = [0u8; 32];

        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(
            result.is_ok(),
            "9/16 ≥ majority threshold must accept: {result:?}"
        );
    }

    #[test]
    fn closeness_match_returns_sparse_dht_error_when_lookup_too_small() {
        // The sparse-DHT short-circuit fires when the lookup returned
        // fewer peers than the threshold itself — even an all-matching
        // candidate set can't pass because the storer doesn't have an
        // authoritative view to compare against.
        let candidates = synthetic_peer_ids(16);
        let network = synthetic_peer_ids(8); // < CANDIDATE_CLOSENESS_REQUIRED (9)
        let pool_address = [0u8; 32];

        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        match result {
            Err(Error::Payment(msg)) => {
                assert!(
                    msg.contains("authoritative DHT lookup returned only 8"),
                    "expected sparse-DHT error message, got: {msg}"
                );
            }
            other => panic!("expected sparse-DHT rejection, got: {other:?}"),
        }
    }

    // ---------- ADR-0003: quote arithmetic re-check ----------

    /// Curve canonicality: any price produced by `calculate_price(n)` is
    /// on-curve by construction. We exercise a spread of `n` covering the
    /// baseline floor (n=0), small counts, the pricing-curve knee
    /// (`n=PRICING_DIVISOR=6000`), and a saturating-arithmetic regime.
    #[test]
    fn adr0003_on_curve_prices_round_trip() {
        for &n in &[0usize, 1, 2, 100, 5999, 6000, 6001, 50_000, 1_000_000] {
            let price = crate::payment::pricing::calculate_price(n);
            assert!(
                PaymentVerifier::quote_price_is_on_curve(&price),
                "calculate_price({n}) = {price} must be on-curve"
            );
        }
    }

    /// Off-curve canonicality: a price one wei above or below an on-curve
    /// point is between two adjacent curve values and must fail the
    /// canonicality predicate. The check IS exact equality, not a tolerance.
    #[test]
    fn adr0003_off_curve_prices_rejected_by_predicate() {
        // n=100 is well above baseline so price ± 1 is non-saturating.
        let on = crate::payment::pricing::calculate_price(100);
        let just_above = on + Amount::from(1u64);
        let just_below = on - Amount::from(1u64);
        assert!(
            !PaymentVerifier::quote_price_is_on_curve(&just_above),
            "price one wei above an on-curve point must be off-curve"
        );
        assert!(
            !PaymentVerifier::quote_price_is_on_curve(&just_below),
            "price one wei below an on-curve point must be off-curve"
        );
    }

    /// A price strictly below the baseline floor is off-curve: the formula's
    /// minimum value is `calculate_price(0) = BASELINE`, so any smaller value
    /// has no corresponding `n`.
    #[test]
    fn adr0003_sub_baseline_price_is_off_curve() {
        let baseline = crate::payment::pricing::calculate_price(0);
        let sub_baseline = baseline - Amount::from(1u64);
        assert!(
            !PaymentVerifier::quote_price_is_on_curve(&sub_baseline),
            "price strictly below baseline must be off-curve"
        );
    }

    /// ADR-0003 storer-side gate: a bundle in which every quote is on-curve
    /// passes the gate **and** the per-quote canonicality predicate. Runs in
    /// every context (no `ClientPut` split): the rule depends only on the
    /// bundle, not on per-peer state. The outer `validate_quote_arithmetic`
    /// short-circuits to `Ok` under the observe-only rollout const, so the
    /// per-quote diagnostics assertion is what proves the bundle is genuinely
    /// on-curve regardless of how the const ships.
    #[test]
    fn adr0003_validate_quote_arithmetic_passes_for_honest_bundle() {
        use evmlib::{EncodedPeerId, RewardsAddress};

        let payment = ProofOfPayment {
            peer_quotes: (0..crate::ant_protocol::CLOSE_GROUP_SIZE)
                .map(|i| {
                    let id: [u8; 32] = rand::random();
                    let byte = u8::try_from(i & 0xFF).unwrap_or(0);
                    let quote = make_fake_quote_at_records(
                        [0xC0u8; 32],
                        SystemTime::now(),
                        RewardsAddress::new([byte; 20]),
                        100 * (i + 1),
                    );
                    (EncodedPeerId::new(id), quote)
                })
                .collect(),
        };
        PaymentVerifier::validate_quote_arithmetic(&payment)
            .expect("honest on-curve bundle must pass the gate (any const value)");
        for (_, quote) in &payment.peer_quotes {
            assert!(
                PaymentVerifier::price_off_curve_diagnostics(&quote.price).is_none(),
                "every quote in honest bundle must be canonically on-curve"
            );
        }
    }

    /// Off-curve quote behaviour follows the rollout gate
    /// [`QUOTE_ARITHMETIC_RECHECK_ENABLED`]. We assert the gate's current
    /// observe-only stance: an off-curve quote is accepted with no error.
    /// The enforcement-branch behaviour is exercised separately by
    /// `adr0003_off_curve_diagnostics_yields_reject_payload` so both branches
    /// of the const-gated split are covered in CI.
    #[test]
    fn adr0003_observe_only_does_not_reject_off_curve_quote() {
        use evmlib::{EncodedPeerId, RewardsAddress};

        let mut quote = make_fake_quote_at_records(
            [0xC1u8; 32],
            SystemTime::now(),
            RewardsAddress::new([1u8; 20]),
            100,
        );
        // Bump one wei off the curve.
        quote.price += Amount::from(1u64);

        let id: [u8; 32] = rand::random();
        let payment = ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::new(id), quote)],
        };

        // This test is only meaningful in the observe-only configuration
        // (which is the default at slice ship). If a future change flips the
        // const, the assertion documents the regression instead of silently
        // changing semantics.
        if !crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            assert!(
                PaymentVerifier::validate_quote_arithmetic(&payment).is_ok(),
                "observe-only rollout must not reject off-curve quotes"
            );
        }
    }

    /// Enforcement-branch coverage: the rejection payload (peer id, candidate
    /// `n`, recomputed price) is produced for off-curve prices independently
    /// of the rollout const, so CI exercises the rejection code path even
    /// while [`QUOTE_ARITHMETIC_RECHECK_ENABLED`] ships as `false`. Flipping
    /// the const to `true` then merely wires this diagnostic into the outer
    /// `Err` return, which is what `validate_quote_arithmetic` does.
    #[test]
    fn adr0003_off_curve_diagnostics_yields_reject_payload() {
        let on = crate::payment::pricing::calculate_price(100);
        let off = on + Amount::from(1u64);

        let diag = PaymentVerifier::price_off_curve_diagnostics(&off)
            .expect("off-curve price must produce diagnostics");
        let (candidate_count, recomputed) = diag;
        assert_eq!(candidate_count, 100, "floor candidate must be n=100");
        assert_eq!(
            recomputed, on,
            "recomputed price must equal the floor curve point"
        );
        assert!(
            recomputed < off,
            "off-curve diagnostics' recomputed price must be strictly below the off-curve input"
        );

        // And an on-curve price must produce no diagnostics.
        assert!(
            PaymentVerifier::price_off_curve_diagnostics(&on).is_none(),
            "on-curve price must yield no off-curve diagnostics"
        );
    }

    /// Saturation regime: a price strictly above
    /// `calculate_price(u64::MAX-equivalent saturating ceiling)` is rejected.
    /// We do not have direct access to that ceiling, but `Amount::MAX` is
    /// guaranteed above it (since `calculate_price(usize::MAX)` saturates to
    /// some value strictly less than `Amount::MAX` due to the additive
    /// baseline). The gate must reject it.
    #[test]
    fn adr0003_amount_max_price_is_off_curve() {
        let price = Amount::MAX;
        assert!(
            !PaymentVerifier::quote_price_is_on_curve(&price),
            "Amount::MAX must not be a valid on-curve price"
        );
    }

    /// Merkle gate, predicate-level: the same canonicality rule applies to
    /// `MerklePaymentCandidateNode.price`. We don't construct a full merkle
    /// proof here (the test fixtures for that live elsewhere); we prove the
    /// underlying decision matches the single-node side, so the Merkle gate
    /// inherits the same correctness as `validate_quote_arithmetic`.
    #[test]
    fn adr0003_merkle_candidate_canonicality_matches_single_node() {
        // Every on-curve `n` produces a price the predicate accepts; one wei
        // off produces a price the predicate rejects. This is the entire
        // contract; the Merkle gate's outer wrapper enforces the same const
        // as the single-node gate, so the wrappers are mechanically
        // equivalent.
        for &n in &[0usize, 1, 100, 6000, 1_000_000] {
            let on = crate::payment::pricing::calculate_price(n);
            assert!(
                PaymentVerifier::quote_price_is_on_curve(&on),
                "merkle candidate price for n={n} must be on-curve"
            );
            if n > 0 {
                let off = on + Amount::from(1u64);
                assert!(
                    !PaymentVerifier::quote_price_is_on_curve(&off),
                    "merkle candidate price one wei above n={n} must be off-curve"
                );
            }
        }
    }

    /// Merkle gate, pool-level: build a real signed candidate pool, set every
    /// candidate's price to the same on-curve value, and assert the gate
    /// passes. Then bump one candidate's price one wei off-curve and assert
    /// the per-candidate diagnostics correctly identify it. We use the
    /// diagnostics predicate rather than the outer `validate_merkle_candidate_arithmetic`
    /// because the outer wrapper short-circuits to `Ok` under the observe-only
    /// rollout const; the diagnostics path is what carries the rejection
    /// information when enforcement flips on.
    #[test]
    fn adr0003_merkle_pool_off_curve_candidate_caught_by_diagnostics() {
        use evmlib::merkle_payments::MerklePaymentCandidatePool;

        let timestamp = 1_700_000_000u64;
        let mut candidates = make_candidate_nodes(timestamp);

        // Set every candidate price to calculate_price(500) so the pool is
        // honestly on-curve to start.
        let on_curve = crate::payment::pricing::calculate_price(500);
        for c in &mut candidates {
            c.price = on_curve;
        }
        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: candidates,
        };
        // The outer wrapper is rollout-gated, but a fully on-curve pool must
        // pass it under any const value because the loop finds no off-curve
        // candidate to reject.
        PaymentVerifier::validate_merkle_candidate_arithmetic(&pool)
            .expect("honest on-curve pool must pass merkle gate (any const value)");
        for c in &pool.candidate_nodes {
            assert!(
                PaymentVerifier::price_off_curve_diagnostics(&c.price).is_none(),
                "every honest candidate must be canonically on-curve"
            );
        }

        // Now bump exactly one candidate off-curve and check that the
        // diagnostics path catches it. (The outer wrapper still short-circuits
        // under observe-only; this proves the underlying detection works
        // independently of the rollout const, exercising the rejection-payload
        // path in CI.)
        let mut tampered = pool;
        tampered.candidate_nodes[3].price += Amount::from(1u64);
        let mut off_curve_seen = 0;
        for c in &tampered.candidate_nodes {
            if PaymentVerifier::price_off_curve_diagnostics(&c.price).is_some() {
                off_curve_seen += 1;
            }
        }
        assert_eq!(
            off_curve_seen, 1,
            "exactly one tampered candidate must register as off-curve"
        );
    }

    // === ADR-0003 binding-shape + cross-check unit tests ===

    use crate::payment::pricing::calculate_price as cp;

    /// Build a real signed commitment over `n` synthetic keys for tests.
    fn test_built_commitment(n: u32) -> crate::replication::commitment_state::BuiltCommitment {
        use saorsa_pqc::api::sig::ml_dsa_65;
        let (pk, sk) = ml_dsa_65().generate_keypair().expect("keypair");
        let pk_bytes = pk.to_bytes();
        let peer_id = blake3::hash(&pk_bytes);
        let entries: Vec<([u8; 32], [u8; 32])> = (0..n)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&i.to_le_bytes());
                let mut b = [1u8; 32];
                b[..4].copy_from_slice(&i.to_le_bytes());
                (k, b)
            })
            .collect();
        crate::replication::commitment_state::BuiltCommitment::build(
            entries,
            peer_id.as_bytes(),
            &sk,
            &pk_bytes,
        )
        .expect("build commitment")
    }

    #[test]
    fn binding_baseline_ok_only_at_baseline_price() {
        // (0, None) with calculate_price(0) is the valid baseline.
        assert!(PaymentVerifier::binding_violation(0, None, &cp(0)).is_none());
        // (0, None) with a non-baseline price is REJECTED — this is the BLOCKER
        // bypass the round-1 review found (unpinned quote priced above baseline).
        assert!(PaymentVerifier::binding_violation(0, None, &cp(500)).is_some());
    }

    #[test]
    fn binding_bound_ok_only_with_pin_and_exact_price() {
        let pin = [9u8; 32];
        // (n>0, Some(pin)) priced exactly is valid.
        assert!(PaymentVerifier::binding_violation(500, Some(pin), &cp(500)).is_none());
        // (n>0, Some(pin)) priced for a DIFFERENT count is rejected (on-curve
        // but wrong count — stronger than canonicality).
        assert!(PaymentVerifier::binding_violation(500, Some(pin), &cp(499)).is_some());
    }

    #[test]
    fn binding_rejects_incoherent_shapes() {
        let pin = [9u8; 32];
        // count > 0 but no pin: unauditable.
        assert!(PaymentVerifier::binding_violation(500, None, &cp(500)).is_some());
        // count 0 but a pin: incoherent baseline.
        assert!(PaymentVerifier::binding_violation(0, Some(pin), &cp(0)).is_some());
    }

    #[test]
    fn binding_rejects_count_above_cap() {
        let pin = [9u8; 32];
        let over = crate::replication::commitment::MAX_COMMITMENT_KEY_COUNT + 1;
        assert!(PaymentVerifier::binding_violation(over, Some(pin), &cp(over as usize)).is_some());
    }

    #[test]
    fn cross_check_match_when_pin_and_count_agree() {
        let built = test_built_commitment(12);
        let outcome = PaymentVerifier::cross_check_binding(12, built.hash(), built.commitment());
        assert_eq!(outcome, CrossCheck::Match);
    }

    #[test]
    fn cross_check_mismatch_when_count_inflated() {
        let built = test_built_commitment(12);
        // Quote claims 999 but the pinned commitment attests 12.
        let outcome = PaymentVerifier::cross_check_binding(999, built.hash(), built.commitment());
        assert_eq!(
            outcome,
            CrossCheck::Mismatch {
                quoted_key_count: 999,
                committed_key_count: 12,
            }
        );
    }

    #[test]
    fn cross_check_unresolved_when_pin_wrong() {
        let built = test_built_commitment(12);
        // Pin does not match the supplied commitment's hash: not evidence.
        let outcome = PaymentVerifier::cross_check_binding(12, [0xFFu8; 32], built.commitment());
        assert_eq!(outcome, CrossCheck::PinDoesNotResolve);
    }

    #[test]
    fn fresh_cached_commitment_honours_ttl_boundary() {
        use crate::replication::commitment_state::PeerCommitmentRecord;
        let built = test_built_commitment(5);
        let commitment = built.commitment().clone();
        let pin = built.hash();
        let ttl = std::time::Duration::from_secs(3 * 3600);
        let now = std::time::Instant::now();

        // Fresh AND matching pin -> resolves to the commitment.
        let fresh = PeerCommitmentRecord::from_verified(commitment.clone(), now);
        assert!(
            PaymentVerifier::fresh_cached_commitment(&fresh, pin, now, ttl).is_some(),
            "a fresh cache entry whose hash matches the pin must resolve"
        );

        // Fresh but a DIFFERENT pin -> treated as not-cached (None), so the
        // caller falls through to fetch the actually-quoted pin instead of
        // mis-resolving against the peer's latest (different) commitment.
        assert!(
            PaymentVerifier::fresh_cached_commitment(&fresh, [0xEEu8; 32], now, ttl).is_none(),
            "a fresh cache entry for a DIFFERENT pin must not resolve (fetch fallback runs)"
        );

        // Stale: received older than the TTL -> treated as unknown (None), the
        // ADR-0003 false-positive guard against an aged cache entry.
        let stale_at = now
            .checked_sub(ttl + std::time::Duration::from_secs(1))
            .expect("instant in range");
        let stale = PeerCommitmentRecord::from_verified(commitment, stale_at);
        assert!(
            PaymentVerifier::fresh_cached_commitment(&stale, pin, now, ttl).is_none(),
            "a cache entry older than the answerability TTL must be treated as unknown"
        );
    }

    #[test]
    fn fetched_commitment_must_be_bound_to_the_queried_peer() {
        // A fetched commitment is accepted only when it is bound to the peer we
        // asked (sender_peer_id == peer_id) and hashes to the requested pin.
        let built = test_built_commitment(8);
        let commitment = built.commitment().clone();
        let pin = built.hash();
        let owner = PeerId::from_bytes(commitment.sender_peer_id);

        // Correct owner + correct pin -> accepted.
        assert!(
            PaymentVerifier::fetched_commitment_is_valid(&commitment, &owner, pin),
            "a peer's own validly-signed commitment, hashing to the pin, must be accepted"
        );

        // Same (validly signed) commitment but attributed to a DIFFERENT peer ->
        // rejected. This is the MAJOR fix: a peer must not be able to answer with
        // someone else's commitment and have it pass as its own.
        let other = PeerId::from_bytes([0xABu8; 32]);
        assert!(
            !PaymentVerifier::fetched_commitment_is_valid(&commitment, &other, pin),
            "another peer's commitment must be rejected for the queried peer"
        );

        // Correct owner but wrong pin -> rejected.
        assert!(
            !PaymentVerifier::fetched_commitment_is_valid(&commitment, &owner, [0u8; 32]),
            "a commitment that does not hash to the requested pin must be rejected"
        );
    }

    #[tokio::test]
    async fn emit_mismatch_evidence_is_observe_only_safe_without_p2p() {
        // The evidence variant is constructed and routed; in observe-only mode
        // (and with no P2P handle) it must log without panicking and take no
        // trust action. This exercises the evidence->action mapping directly.
        let built = test_built_commitment(12);
        let evidence = crate::replication::types::FailureEvidence::QuoteCommitmentMismatch {
            peer: PeerId::from_bytes([1u8; 32]),
            pinned_commitment: [2u8; 32],
            quoted_key_count: 999,
            committed_key_count: 12,
            quote_artifact: vec![0xAA; 16],
            commitment: Box::new(built.commitment().clone()),
        };
        // No P2P -> no trust event even if enforce were on; must not panic.
        PaymentVerifier::emit_mismatch_evidence(&evidence, None).await;
    }

    #[test]
    fn valid_sidecar_is_indexed_and_resolves_synchronously() {
        // A valid sidecar blob is indexed under its own (peer, pin) so the
        // cross-check resolves it synchronously — "the commitment arrived with
        // the quote", no gossip-cache hit or fetch needed.
        let built = test_built_commitment(9);
        let commitment = built.commitment().clone();
        let pin = built.hash();
        let owner = PeerId::from_bytes(commitment.sender_peer_id);
        let blob = rmp_serde::to_vec(&commitment).expect("serialize sidecar");

        let map = PaymentVerifier::index_valid_sidecars(std::slice::from_ref(&blob));
        assert!(
            map.contains_key(&(owner, pin)),
            "a valid sidecar must be indexed under its own (peer, pin)"
        );

        // A garbage blob is silently skipped (resolution falls back), never a
        // hard error.
        let map2 = PaymentVerifier::index_valid_sidecars(&[vec![0xFF; 8]]);
        assert!(map2.is_empty(), "an unparseable sidecar must be skipped");
    }
}
