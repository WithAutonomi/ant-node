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

/// LRU cache for verified `XorName` values.
///
/// This cache stores `XorName` values that have been verified to exist on the
/// autonomi network, avoiding repeated network queries for the same data.
#[derive(Clone)]
pub struct VerifiedCache {
    inner: Arc<Mutex<LruCache<XorName, ()>>>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    additions: Arc<AtomicU64>,
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

    /// Check if a `XorName` is in the cache.
    ///
    /// Returns `true` if the `XorName` is cached (verified to exist on autonomi).
    #[must_use]
    pub fn contains(&self, xorname: &XorName) -> bool {
        let found = self.inner.lock().get(xorname).is_some();

        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }

        found
    }

    /// Add a `XorName` to the cache.
    ///
    /// This should be called after verifying that data exists on the autonomi network.
    pub fn insert(&self, xorname: XorName) {
        self.inner.lock().put(xorname, ());
        self.additions.fetch_add(1, Ordering::Relaxed);
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

        let xorname1 = [1u8; 32];
        let xorname2 = [2u8; 32];

        // Initially empty
        assert!(cache.is_empty());
        assert!(!cache.contains(&xorname1));

        // Insert and check
        cache.insert(xorname1);
        assert!(cache.contains(&xorname1));
        assert!(!cache.contains(&xorname2));
        assert_eq!(cache.len(), 1);

        // Insert another
        cache.insert(xorname2);
        assert!(cache.contains(&xorname1));
        assert!(cache.contains(&xorname2));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_stats() {
        let cache = VerifiedCache::new();
        let xorname = [1u8; 32];

        // Miss
        assert!(!cache.contains(&xorname));
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Add
        cache.insert(xorname);
        let stats = cache.stats();
        assert_eq!(stats.additions, 1);

        // Hit
        assert!(cache.contains(&xorname));
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

        let xorname1 = [1u8; 32];
        let xorname2 = [2u8; 32];
        let xorname3 = [3u8; 32];

        cache.insert(xorname1);
        cache.insert(xorname2);
        assert_eq!(cache.len(), 2);

        // Insert third, should evict xorname1 (least recently used)
        cache.insert(xorname3);
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&xorname1)); // evicted
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
                let xorname = [i; 32];
                c.insert(xorname);
            }));
        }

        // 10 threads checking
        for i in 0..10u8 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                let xorname = [i; 32];
                let _ = c.contains(&xorname);
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
