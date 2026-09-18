//! LRU cache for verified `XorName` values.
//!
//! Caches `XorName` values that have been verified to exist on the autonomi network,
//! reducing the number of network queries needed for repeated/popular data.

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub use super::quote::XorName;

/// Default cache capacity (100,000 entries = 3.2MB memory).
const DEFAULT_CACHE_CAPACITY: usize = 100_000;

/// What a cache entry is about.
///
/// A typed key, not a hashed one. Hashing a pointer's two addresses back into
/// 32 bytes would not create a separate namespace: a chunk's address is
/// `BLAKE3(content)`, so a client could store a chunk whose *content* is
/// exactly that preimage and land on the same key — paying chunk price for a
/// pointer update, and skipping issuer proximity, the price floor and the
/// proof-shape rule with it. Distinct variants cannot collide at all.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PaidKey {
    /// A chunk, paid for and stored at one address.
    Chunk(XorName),
    /// A pointer state: routed at the pointer's address, paid at its `state_id`.
    PointerState {
        /// The pointer's address, stable for its life.
        routing: XorName,
        /// The state paid for, which changes with every update.
        state_id: XorName,
    },
}

/// LRU cache for verified `XorName` values.
///
/// This cache stores `XorName` values that have been verified to exist on the
/// autonomi network, avoiding repeated network queries for the same data.
///
/// Each entry records which fresh proof verification level inserted it. A
/// paid-list entry must not satisfy a later client-PUT fast-path because
/// paid-list admission does not authorize storing the actual chunk. Stronger
/// entries satisfy weaker lookups.
#[derive(Clone)]
pub struct VerifiedCache {
    inner: Arc<Mutex<LruCache<PaidKey, VerificationLevel>>>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    additions: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationLevel {
    PaidList,
    ClientPut,
}

impl VerificationLevel {
    fn satisfies(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::PaidList, Self::PaidList) | (Self::ClientPut, Self::PaidList | Self::ClientPut)
        )
    }
}

/// Cache statistics for monitoring.
#[derive(Debug, Default, Clone, Copy)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of entries added.
    pub additions: u64,
}

impl CacheStats {
    /// Calculate hit rate as a percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

impl VerifiedCache {
    /// Create a new cache with default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    /// Create a new cache with the specified capacity.
    ///
    /// If capacity is 0, defaults to 1.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        // Use max(1, capacity) to ensure non-zero, avoiding unsafe or expect
        let effective_capacity = capacity.max(1);
        // This is guaranteed to succeed since effective_capacity >= 1
        // Using if-let pattern since we know it will always be Some
        let cap = NonZeroUsize::new(effective_capacity).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(cap))),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            additions: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Check if a `XorName` is in the cache (verified under any fresh check set).
    ///
    /// Returns `true` if the `XorName` is cached (verified to exist on autonomi).
    /// Paid-list and client-PUT lookups must use their stricter helpers.
    #[must_use]
    pub fn contains_key(&self, key: &PaidKey) -> bool {
        let found = self.inner.lock().get(key).is_some();

        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }

        found
    }

    /// Check if a `XorName` is cached AND its verification ran at least the
    /// paid-list admission check set.
    ///
    /// A client-PUT entry returns `true` here because it passed the stricter
    /// store-admission path at the caller.
    #[must_use]
    pub fn contains_paid_list_verified_key(&self, key: &PaidKey) -> bool {
        let found = self
            .inner
            .lock()
            .get(key)
            .copied()
            .is_some_and(|level| level.satisfies(VerificationLevel::PaidList));

        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }

        found
    }

    /// Check if a `XorName` is cached AND its verification ran the full
    /// client-PUT store-admission check set.
    ///
    /// Paid-list entries return `false` here because they did not pass the
    /// client-PUT store-admission path.
    #[must_use]
    pub fn contains_client_put_verified_key(&self, key: &PaidKey) -> bool {
        let found = self
            .inner
            .lock()
            .get(key)
            .copied()
            .is_some_and(|level| level.satisfies(VerificationLevel::ClientPut));

        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }

        found
    }

    /// Add a `XorName` verified under the full client-PUT check set.
    ///
    /// This should be called after verifying that data exists on the autonomi network.
    /// Also upgrades an existing paid-list-verified entry.
    pub fn insert_key(&self, key: PaidKey) {
        self.insert_with_level(key, VerificationLevel::ClientPut);
    }

    /// Add a `XorName` verified under paid-list admission checks.
    ///
    /// Never downgrades an existing client-PUT-verified entry.
    pub fn insert_paid_list_verified_key(&self, key: PaidKey) {
        self.insert_with_level(key, VerificationLevel::PaidList);
    }

    fn insert_with_level(&self, key: PaidKey, level: VerificationLevel) {
        let added = {
            let mut inner = self.inner.lock();
            // `get_mut` refreshes LRU recency for existing entries of either kind.
            if inner.get(&key).is_some() {
                if let Some(existing) = inner.get_mut(&key) {
                    if !existing.satisfies(level) {
                        *existing = level;
                    }
                }
                false
            } else {
                inner.put(key, level);
                true
            }
        };
        if added {
            self.additions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// As [`Self::contains_key`], for a chunk at `address`.
    #[must_use]
    pub fn contains(&self, address: &XorName) -> bool {
        self.contains_key(&PaidKey::Chunk(*address))
    }

    /// As [`Self::contains_paid_list_verified_key`], for a chunk at `address`.
    #[must_use]
    pub fn contains_paid_list_verified(&self, address: &XorName) -> bool {
        self.contains_paid_list_verified_key(&PaidKey::Chunk(*address))
    }

    /// As [`Self::contains_client_put_verified_key`], for a chunk at `address`.
    #[must_use]
    pub fn contains_client_put_verified(&self, address: &XorName) -> bool {
        self.contains_client_put_verified_key(&PaidKey::Chunk(*address))
    }

    /// As [`Self::insert_key`], for a chunk at `address`.
    pub fn insert(&self, address: XorName) {
        self.insert_key(PaidKey::Chunk(address));
    }

    /// As [`Self::insert_paid_list_verified_key`], for a chunk at `address`.
    pub fn insert_paid_list_verified(&self, address: XorName) {
        self.insert_paid_list_verified_key(PaidKey::Chunk(address));
    }

    /// Get current cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            additions: self.additions.load(Ordering::Relaxed),
        }
    }

    /// Get the current number of entries in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Check if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Clear all entries from the cache.
    pub fn clear(&self) {
        self.inner.lock().clear();
    }
}

impl Default for VerifiedCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic_operations() {
        let cache = VerifiedCache::new();

        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        // Initially empty
        assert!(cache.is_empty());
        assert!(!cache.contains(&key1));

        // Insert and check
        cache.insert(key1);
        assert!(cache.contains(&key1));
        assert!(!cache.contains(&key2));
        assert_eq!(cache.len(), 1);

        // Insert another
        cache.insert(key2);
        assert!(cache.contains(&key1));
        assert!(cache.contains(&key2));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_verification_levels_do_not_downgrade_or_over_authorize() {
        let cache = VerifiedCache::new();
        let paid_list = [2u8; 32];
        let client_put = [3u8; 32];

        cache.insert_paid_list_verified(paid_list);
        assert!(cache.contains(&paid_list));
        assert!(cache.contains_paid_list_verified(&paid_list));
        assert!(!cache.contains_client_put_verified(&paid_list));

        cache.insert(paid_list);
        assert!(cache.contains_client_put_verified(&paid_list));

        cache.insert(client_put);
        assert!(cache.contains(&client_put));
        assert!(cache.contains_paid_list_verified(&client_put));
        assert!(cache.contains_client_put_verified(&client_put));

        cache.insert_paid_list_verified(client_put);
        assert!(cache.contains_client_put_verified(&client_put));
    }

    #[test]
    fn test_cache_stats() {
        let cache = VerifiedCache::new();
        let key = [1u8; 32];

        // Miss
        assert!(!cache.contains(&key));
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Add
        cache.insert(key);
        let stats = cache.stats();
        assert_eq!(stats.additions, 1);

        // Hit
        assert!(cache.contains(&key));
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);

        // Hit rate should be 50%
        assert!((stats.hit_rate() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_cache_lru_eviction() {
        // Small cache for testing eviction
        let cache = VerifiedCache::with_capacity(2);

        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let key3 = [3u8; 32];

        cache.insert(key1);
        cache.insert(key2);
        assert_eq!(cache.len(), 2);

        // Insert third, should evict key1 (least recently used)
        cache.insert(key3);
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&key1)); // evicted
                                         // Note: after contains call on evicted item, stats will show a miss
    }

    #[test]
    fn test_cache_clear() {
        let cache = VerifiedCache::new();

        cache.insert([1u8; 32]);
        cache.insert([2u8; 32]);
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_with_capacity_zero_defaults_to_one() {
        let cache = VerifiedCache::with_capacity(0);
        // Should be able to store at least 1 element
        cache.insert([1u8; 32]);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_default_impl() {
        let cache = VerifiedCache::default();
        assert!(cache.is_empty());
        cache.insert([1u8; 32]);
        assert!(cache.contains(&[1u8; 32]));
    }

    #[test]
    fn test_hit_rate_zero_total() {
        let stats = CacheStats::default();
        assert!(stats.hit_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn test_hit_rate_all_hits() {
        let stats = CacheStats {
            hits: 10,
            misses: 0,
            additions: 0,
        };
        assert!((stats.hit_rate() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_hit_rate_all_misses() {
        let stats = CacheStats {
            hits: 0,
            misses: 10,
            additions: 0,
        };
        assert!(stats.hit_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn test_clear_does_not_reset_stats() {
        let cache = VerifiedCache::new();
        cache.insert([1u8; 32]);
        let _ = cache.contains(&[1u8; 32]); // hit
        let _ = cache.contains(&[2u8; 32]); // miss

        cache.clear();

        // Stats should persist after clear
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.additions, 1);
    }

    #[test]
    fn test_concurrent_insert_and_contains() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(VerifiedCache::with_capacity(1000));
        let mut handles = Vec::new();

        // 10 threads inserting
        for i in 0..10u8 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                let key = [i; 32];
                c.insert(key);
            }));
        }

        // 10 threads checking
        for i in 0..10u8 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                let key = [i; 32];
                let _ = c.contains(&key);
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // All 10 should have been inserted
        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn test_cache_stats_copy() {
        let stats = CacheStats {
            hits: 5,
            misses: 3,
            additions: 8,
        };
        let stats2 = stats; // Copy
        assert_eq!(stats.hits, stats2.hits);
        assert_eq!(stats.misses, stats2.misses);
        assert_eq!(stats.additions, stats2.additions);
    }
}
