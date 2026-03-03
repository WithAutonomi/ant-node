//! Periodic self-lookup scheduling (Section 13.1).
//!
//! Nodes periodically perform DHT self-lookups to keep `CloseNeighbors(self)`
//! current. This module provides the interval computation with jitter;
//! the actual network lookup is performed by the caller.

use crate::replication::params::{SELF_LOOKUP_INTERVAL_MAX_SECS, SELF_LOOKUP_INTERVAL_MIN_SECS};
use std::time::Duration;

/// Compute a randomized self-lookup interval within the configured range.
///
/// Returns a `Duration` uniformly sampled from
/// `[SELF_LOOKUP_INTERVAL_MIN_SECS, SELF_LOOKUP_INTERVAL_MAX_SECS]`.
#[must_use]
pub fn jittered_self_lookup_interval(rng_u64: u64) -> Duration {
    let range = SELF_LOOKUP_INTERVAL_MAX_SECS - SELF_LOOKUP_INTERVAL_MIN_SECS;
    let jitter = if range == 0 { 0 } else { rng_u64 % (range + 1) };
    Duration::from_secs(SELF_LOOKUP_INTERVAL_MIN_SECS + jitter)
}

/// Minimum self-lookup interval.
#[must_use]
pub fn min_interval() -> Duration {
    Duration::from_secs(SELF_LOOKUP_INTERVAL_MIN_SECS)
}

/// Maximum self-lookup interval.
#[must_use]
pub fn max_interval() -> Duration {
    Duration::from_secs(SELF_LOOKUP_INTERVAL_MAX_SECS)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_within_bounds() {
        for seed in 0..100 {
            let interval = jittered_self_lookup_interval(seed);
            assert!(interval >= min_interval());
            assert!(interval <= max_interval());
        }
    }

    #[test]
    fn test_interval_min_boundary() {
        // When rng produces 0, should get minimum
        let interval = jittered_self_lookup_interval(0);
        assert_eq!(interval, min_interval());
    }

    #[test]
    fn test_interval_max_boundary() {
        // When rng produces exactly range, should get maximum
        let range = SELF_LOOKUP_INTERVAL_MAX_SECS - SELF_LOOKUP_INTERVAL_MIN_SECS;
        let interval = jittered_self_lookup_interval(range);
        assert_eq!(interval, max_interval());
    }

    #[test]
    fn test_different_seeds_produce_variation() {
        let i1 = jittered_self_lookup_interval(0);
        let i2 = jittered_self_lookup_interval(42);
        let i3 = jittered_self_lookup_interval(999);
        // At least some variation (not all identical)
        assert!(i1 != i2 || i2 != i3 || i1 != i3);
    }
}
