// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Observed-address cache for transport-level reflexive address fallback.
//!
//! ## Why this exists
//!
//! `saorsa-transport` exposes the node's externally-observed address (from
//! QUIC `OBSERVED_ADDRESS` frames) only via *active* connections — when every
//! connection drops, the live read returns `None` and the node has no way to
//! tell the DHT how to be reached. The result is a temporary "invisible
//! window" between the connection drop and the next reconnection.
//!
//! This cache fills that gap. It records every `ExternalAddressDiscovered`
//! event the transport emits and serves as a fallback when no live connection
//! has an observation.
//!
//! ## Per-local-bind partitioning (multi-homed safety)
//!
//! On a multi-homed host, different local interfaces (LAN, cellular, WAN
//! uplink, dual-stack v4/v6 binds) can receive different observations from
//! different sets of peers. An observation seen on the cellular interface is
//! not necessarily reachable from peers that connect via the LAN, and vice
//! versa. Mixing them in one keyspace would let a stale observation from
//! one interface be served as the self-entry advertisement when only a
//! different interface is currently usable.
//!
//! The cache therefore keys observations by **`(local_bind, observed)`**.
//! Selection within a local bind is independent of every other local bind:
//! [`Self::most_frequent_recent_per_local_bind`] returns one best address
//! per bind that has any data, so the caller can publish all of them. The
//! single-address [`Self::most_frequent_recent`] accessor remains for
//! callers that only want one (it picks the global best across binds with
//! the same recency-and-frequency rule).
//!
//! ## Frequency-based selection
//!
//! Different peers can legitimately observe a node at different addresses
//! (symmetric NAT, multi-homed hosts, dual-stack divergence). The cache
//! tracks how many distinct events have been received for each address and
//! returns the one with the highest count, breaking ties by recency. The
//! intuition: "the address most peers agree on" is the most likely to be
//! reachable from any new peer.
//!
//! ## Recency window for NAT-rebinding handling
//!
//! Pure frequency would let a long-lived stale address (count: 10000, last
//! seen 24h ago) win over a fresh new address (count: 5, last seen now).
//! That is the wrong answer when a NAT mapping has rebinded.
//!
//! Selection is therefore split into two passes:
//!
//! 1. Among entries observed within [`OBSERVATION_RECENCY_WINDOW`], return
//!    the highest-count one (with `last_seen` as the tiebreaker).
//! 2. If nothing is recent, fall back to the global highest-count entry —
//!    handles the case where the node has been quiet for longer than the
//!    recency window.
//!
//! Eviction is also recency-based: when the cache is full, the entry with
//! the *oldest* `last_seen` is removed. This ensures stale high-count
//! entries get pushed out as fresh observations arrive.
//!
//! ## Bounded
//!
//! The cache is bounded at [`MAX_CACHED_OBSERVATIONS`] entries to keep
//! memory predictable. The bound is chosen to comfortably handle:
//!
//! - Dual-stack (IPv4 + IPv6) observations of the same node
//! - Symmetric-NAT divergence (different external port per peer)
//! - A handful of recent NAT rebindings during the recency window
//!
//! ## Persistence
//!
//! The cache is in-memory only. A node restart resets it. This is
//! intentional: a freshly-started node should re-discover its current
//! address from live connections rather than trusting potentially-stale
//! state from a previous run.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Maximum number of distinct observed addresses retained in the cache.
///
/// Bounds memory and protects against pathological cases (a buggy peer
/// reporting random addresses). Sized to fit normal operating conditions:
/// dual-stack + symmetric-NAT divergence + a couple of recent rebindings.
pub(crate) const MAX_CACHED_OBSERVATIONS: usize = 16;

/// Time window during which an observation counts as "recent".
///
/// Within this window, selection prefers the highest-count entry. Beyond
/// it, the cache treats observations as stale candidates that only matter
/// if nothing recent exists.
///
/// 10 minutes is long enough to absorb a normal disconnect+reconnect cycle
/// (typically seconds to a minute) and short enough that a NAT rebinding
/// is reflected in the selection within ~10 min, even if the stale address
/// still wins on raw count.
pub(crate) const OBSERVATION_RECENCY_WINDOW: Duration = Duration::from_secs(600);

/// Per-address bookkeeping inside [`ObservedAddressCache`].
#[derive(Debug, Clone, Copy)]
struct ObservedEntry {
    /// Cumulative count of `ExternalAddressDiscovered` events received for
    /// this address. Each (peer, address) pair contributes at most once,
    /// per saorsa-transport's own dedup, so this is effectively a count of
    /// distinct peers that have agreed on this address.
    count: u64,
    /// The most recent instant we received an event for this address.
    /// Used both for recency-based selection and for LRU eviction.
    last_seen: Instant,
}

/// Composite cache key: an observed external address is always associated
/// with the **local bind** that received it. Two different local interfaces
/// (e.g. v4 and v6 stacks, or LAN and WAN) recording the same observed
/// address get separate entries so their counts and recencies do not
/// cross-contaminate.
type CacheKey = (SocketAddr, SocketAddr);

/// Bounded cache of observed external addresses with frequency- and
/// recency-aware selection. See module-level docs for the rationale.
#[derive(Debug, Default)]
pub(crate) struct ObservedAddressCache {
    entries: HashMap<CacheKey, ObservedEntry>,
}

impl ObservedAddressCache {
    /// Create an empty cache.
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record an observation of `observed` received via `local_bind`.
    /// Increments the count for an existing entry or inserts a new one,
    /// evicting the oldest entry by `last_seen` if the cache is full.
    pub(crate) fn record(&mut self, local_bind: SocketAddr, observed: SocketAddr) {
        self.record_at(local_bind, observed, Instant::now());
    }

    /// Record an observation at a caller-provided instant. Exposed for
    /// deterministic unit tests; production callers should use [`record`].
    pub(crate) fn record_at(&mut self, local_bind: SocketAddr, observed: SocketAddr, now: Instant) {
        let key = (local_bind, observed);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.count = entry.count.saturating_add(1);
            entry.last_seen = now;
            return;
        }

        if self.entries.len() >= MAX_CACHED_OBSERVATIONS {
            self.evict_oldest();
        }

        self.entries.insert(
            key,
            ObservedEntry {
                count: 1,
                last_seen: now,
            },
        );
    }

    /// Return one observed address per **local bind** that has at least
    /// one cached entry, picking the highest-count recent observation for
    /// each bind. Multi-homed callers should publish all addresses
    /// returned here so peers reaching the node via *any* interface can
    /// dial it.
    ///
    /// Within a local bind, selection follows the same recency-and-
    /// frequency algorithm as [`Self::most_frequent_recent`]: prefer
    /// entries inside [`OBSERVATION_RECENCY_WINDOW`], fall back to the
    /// highest-count overall if nothing is recent.
    pub(crate) fn most_frequent_recent_per_local_bind(&self) -> Vec<SocketAddr> {
        self.most_frequent_recent_per_local_bind_at(Instant::now())
    }

    /// Selection at a caller-provided "now". Exposed for deterministic
    /// unit tests; production callers should use the non-`_at` variant.
    pub(crate) fn most_frequent_recent_per_local_bind_at(&self, now: Instant) -> Vec<SocketAddr> {
        // Collect distinct local binds, preserving deterministic order
        // for callers that may iterate the result. We sort by the local
        // bind so the output is reproducible across runs.
        let mut binds: Vec<SocketAddr> = self.entries.keys().map(|(bind, _)| *bind).collect();
        binds.sort();
        binds.dedup();

        let mut result = Vec::with_capacity(binds.len());
        for bind in binds {
            if let Some(addr) = self.best_observed_for_bind_at(bind, now) {
                result.push(addr);
            }
        }
        result
    }

    /// Best observed address for a single local bind, applying the
    /// recent-then-fallback selection rule.
    fn best_observed_for_bind_at(
        &self,
        local_bind: SocketAddr,
        now: Instant,
    ) -> Option<SocketAddr> {
        let recent = self
            .entries
            .iter()
            .filter(|((bind, _), _)| *bind == local_bind)
            .filter(|(_, e)| now.duration_since(e.last_seen) <= OBSERVATION_RECENCY_WINDOW)
            .max_by_key(|(_, e)| (e.count, e.last_seen))
            .map(|((_, observed), _)| *observed);

        if recent.is_some() {
            return recent;
        }

        self.entries
            .iter()
            .filter(|((bind, _), _)| *bind == local_bind)
            .max_by_key(|(_, e)| (e.count, e.last_seen))
            .map(|((_, observed), _)| *observed)
    }

    /// Return the **single** address with the highest observation count
    /// among entries seen within [`OBSERVATION_RECENCY_WINDOW`], breaking
    /// ties by most recent `last_seen`. If no entry is recent, fall back
    /// to the highest count overall.
    ///
    /// This crosses local-bind boundaries — it is the right answer for
    /// callers that only want a single address (single-interface hosts,
    /// legacy callers). Multi-homed callers should prefer
    /// [`Self::most_frequent_recent_per_local_bind`] instead.
    pub(crate) fn most_frequent_recent(&self) -> Option<SocketAddr> {
        self.most_frequent_recent_at(Instant::now())
    }

    /// Selection at a caller-provided "now". Exposed for deterministic
    /// unit tests; production callers should use [`most_frequent_recent`].
    pub(crate) fn most_frequent_recent_at(&self, now: Instant) -> Option<SocketAddr> {
        let recent = self
            .entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_seen) <= OBSERVATION_RECENCY_WINDOW)
            .max_by_key(|(_, e)| (e.count, e.last_seen))
            .map(|((_, observed), _)| *observed);

        if recent.is_some() {
            return recent;
        }

        self.entries
            .iter()
            .max_by_key(|(_, e)| (e.count, e.last_seen))
            .map(|((_, observed), _)| *observed)
    }

    /// Evict the entry with the oldest `last_seen`. No-op on an empty cache.
    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.entries.remove(&key);
        }
    }

    /// Number of distinct addresses currently cached. Exposed for tests
    /// and diagnostics.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Default local bind used by tests that only care about a single
    /// interface (the most common case).
    const DEFAULT_LOCAL_BIND_PORT: u16 = 7000;
    /// Alternate local bind for multi-homed partitioning tests.
    const ALT_LOCAL_BIND_PORT: u16 = 7001;

    /// Construct a unique IPv4 socket address for tests.
    fn addr(last_octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)), port)
    }

    /// Default local-bind socket used by single-interface tests.
    fn default_bind() -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            DEFAULT_LOCAL_BIND_PORT,
        )
    }

    /// Alternate local-bind socket used by multi-homed partitioning tests.
    fn alt_bind() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ALT_LOCAL_BIND_PORT)
    }

    #[test]
    fn empty_cache_returns_none() {
        let cache = ObservedAddressCache::new();
        assert_eq!(cache.most_frequent_recent(), None);
        assert!(cache.most_frequent_recent_per_local_bind().is_empty());
    }

    #[test]
    fn single_observation_returns_that_address() {
        let mut cache = ObservedAddressCache::new();
        let a = addr(1, 9000);
        cache.record(default_bind(), a);
        assert_eq!(cache.most_frequent_recent(), Some(a));
        assert_eq!(cache.most_frequent_recent_per_local_bind(), vec![a]);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn repeated_observation_increments_count_without_growing() {
        let mut cache = ObservedAddressCache::new();
        let a = addr(1, 9000);
        cache.record(default_bind(), a);
        cache.record(default_bind(), a);
        cache.record(default_bind(), a);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.most_frequent_recent(), Some(a));
    }

    #[test]
    fn higher_count_wins_among_recent_entries() {
        let mut cache = ObservedAddressCache::new();
        let popular = addr(1, 9000);
        let unpopular = addr(2, 9000);

        // popular: 5 observations, unpopular: 1 observation, all recent.
        for _ in 0..5 {
            cache.record(default_bind(), popular);
        }
        cache.record(default_bind(), unpopular);

        assert_eq!(cache.most_frequent_recent(), Some(popular));
    }

    #[test]
    fn equal_counts_break_tie_by_recency() {
        let mut cache = ObservedAddressCache::new();
        let older = addr(1, 9000);
        let newer = addr(2, 9000);

        let base = Instant::now();
        cache.record_at(default_bind(), older, base);
        cache.record_at(default_bind(), newer, base + Duration::from_secs(1));

        assert_eq!(
            cache.most_frequent_recent_at(base + Duration::from_secs(2)),
            Some(newer)
        );
    }

    #[test]
    fn stale_high_count_loses_to_recent_low_count() {
        // The NAT-rebinding scenario: an old address has a huge count from
        // a long session, but a new address has just started accumulating
        // observations after the rebind. The cache should prefer the new one
        // because the old one is outside the recency window.
        let mut cache = ObservedAddressCache::new();
        let stale = addr(1, 9000);
        let fresh = addr(2, 9000);

        let base = Instant::now();

        // 1000 observations of `stale`, all well outside the recency window.
        let stale_time = base;
        for _ in 0..1000 {
            cache.record_at(default_bind(), stale, stale_time);
        }

        // 3 observations of `fresh`, all just now.
        let fresh_time = base + OBSERVATION_RECENCY_WINDOW + Duration::from_secs(60);
        for _ in 0..3 {
            cache.record_at(default_bind(), fresh, fresh_time);
        }

        let now = fresh_time + Duration::from_secs(1);
        assert_eq!(cache.most_frequent_recent_at(now), Some(fresh));
    }

    #[test]
    fn falls_back_to_global_highest_count_when_nothing_is_recent() {
        // Long-quiet network case: the node has been silent for longer than
        // the recency window, so the recent-pass returns nothing. The
        // fallback returns the highest-count address overall so the node
        // can still publish *something*.
        let mut cache = ObservedAddressCache::new();
        let popular = addr(1, 9000);
        let unpopular = addr(2, 9000);

        let base = Instant::now();
        for _ in 0..5 {
            cache.record_at(default_bind(), popular, base);
        }
        cache.record_at(default_bind(), unpopular, base);

        // Far in the future — every entry is stale, fallback path engages.
        let far_future = base + OBSERVATION_RECENCY_WINDOW * 10;
        assert_eq!(cache.most_frequent_recent_at(far_future), Some(popular));
    }

    #[test]
    fn eviction_removes_oldest_by_last_seen_when_full() {
        let mut cache = ObservedAddressCache::new();
        let base = Instant::now();

        // Fill the cache with MAX entries, each at a distinct time.
        for i in 0..(MAX_CACHED_OBSERVATIONS as u8) {
            cache.record_at(
                default_bind(),
                addr(i + 1, 9000),
                base + Duration::from_secs(u64::from(i)),
            );
        }
        assert_eq!(cache.len(), MAX_CACHED_OBSERVATIONS);

        // The oldest entry is the one inserted at `base` (i = 0, addr=1).
        let oldest_key = (default_bind(), addr(1, 9000));
        assert!(cache.entries.contains_key(&oldest_key));

        // Insert one more — should evict the oldest.
        let newcomer_key = (default_bind(), addr(99, 9000));
        cache.record_at(
            newcomer_key.0,
            newcomer_key.1,
            base + Duration::from_secs(MAX_CACHED_OBSERVATIONS as u64),
        );

        assert_eq!(cache.len(), MAX_CACHED_OBSERVATIONS);
        assert!(
            !cache.entries.contains_key(&oldest_key),
            "oldest entry should have been evicted"
        );
        assert!(
            cache.entries.contains_key(&newcomer_key),
            "newcomer should be present"
        );
    }

    #[test]
    fn re_observing_an_existing_entry_does_not_trigger_eviction() {
        // If we record an address that's already in the cache, we just
        // bump its count and last_seen — no eviction needed even when the
        // cache is full.
        let mut cache = ObservedAddressCache::new();
        let base = Instant::now();

        for i in 0..(MAX_CACHED_OBSERVATIONS as u8) {
            cache.record_at(
                default_bind(),
                addr(i + 1, 9000),
                base + Duration::from_secs(u64::from(i)),
            );
        }
        assert_eq!(cache.len(), MAX_CACHED_OBSERVATIONS);

        // Re-observe the oldest entry, refreshing its last_seen.
        let oldest_key = (default_bind(), addr(1, 9000));
        let refresh_time = base + Duration::from_secs(1000);
        cache.record_at(oldest_key.0, oldest_key.1, refresh_time);

        // Cache size unchanged; the entry is now the youngest.
        assert_eq!(cache.len(), MAX_CACHED_OBSERVATIONS);
        let entry = cache.entries.get(&oldest_key).copied().unwrap();
        assert_eq!(entry.count, 2);
        assert_eq!(entry.last_seen, refresh_time);
    }

    #[test]
    fn observations_for_different_local_binds_do_not_collide() {
        // Two different local interfaces independently observe the SAME
        // external address. They must remain as separate entries so the
        // counts and recencies of one cannot leak into the other.
        let mut cache = ObservedAddressCache::new();
        let observed = addr(1, 9000);

        cache.record(default_bind(), observed);
        cache.record(alt_bind(), observed);
        cache.record(alt_bind(), observed);

        assert_eq!(cache.len(), 2);

        // Each bind tracks its own count.
        let default_entry = cache.entries.get(&(default_bind(), observed)).unwrap();
        let alt_entry = cache.entries.get(&(alt_bind(), observed)).unwrap();
        assert_eq!(default_entry.count, 1);
        assert_eq!(alt_entry.count, 2);
    }

    #[test]
    fn per_local_bind_returns_one_address_per_distinct_bind() {
        // A multi-homed host with two interfaces observing two distinct
        // external addresses (one per interface). The plural API must
        // return both so the caller can publish all of them.
        let mut cache = ObservedAddressCache::new();
        let observed_default = addr(1, 9000);
        let observed_alt = addr(2, 9000);

        cache.record(default_bind(), observed_default);
        cache.record(alt_bind(), observed_alt);

        let mut result = cache.most_frequent_recent_per_local_bind();
        result.sort();
        let mut expected = vec![observed_default, observed_alt];
        expected.sort();
        assert_eq!(result, expected);
    }

    #[test]
    fn per_local_bind_picks_best_within_each_bind_independently() {
        // For each local bind, the picked address must be the best
        // observation for THAT bind, not the global best.
        let mut cache = ObservedAddressCache::new();
        let default_winner = addr(1, 9000);
        let default_loser = addr(2, 9000);
        let alt_winner = addr(3, 9000);
        let alt_loser = addr(4, 9000);

        // default_bind: default_winner has 5 observations, default_loser has 1.
        for _ in 0..5 {
            cache.record(default_bind(), default_winner);
        }
        cache.record(default_bind(), default_loser);

        // alt_bind: alt_winner has 3 observations, alt_loser has 1.
        for _ in 0..3 {
            cache.record(alt_bind(), alt_winner);
        }
        cache.record(alt_bind(), alt_loser);

        let mut result = cache.most_frequent_recent_per_local_bind();
        result.sort();
        let mut expected = vec![default_winner, alt_winner];
        expected.sort();
        assert_eq!(result, expected);
    }

    #[test]
    fn stale_observation_on_one_bind_does_not_affect_recency_on_another() {
        // The multi-homed correctness scenario: bind A has only stale data
        // (outside the recency window) while bind B has fresh data. The
        // partitioning means each bind's selection runs independently —
        // bind A correctly falls back to its global pick, bind B uses
        // its recent pick.
        let mut cache = ObservedAddressCache::new();
        let stale_for_default = addr(1, 9000);
        let fresh_for_alt = addr(2, 9000);

        let base = Instant::now();
        cache.record_at(default_bind(), stale_for_default, base);
        let fresh_time = base + OBSERVATION_RECENCY_WINDOW + Duration::from_secs(60);
        cache.record_at(alt_bind(), fresh_for_alt, fresh_time);

        let now = fresh_time + Duration::from_secs(1);
        let mut result = cache.most_frequent_recent_per_local_bind_at(now);
        result.sort();
        let mut expected = vec![stale_for_default, fresh_for_alt];
        expected.sort();
        assert_eq!(result, expected);
    }
}
