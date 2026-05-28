//! Tunable parameters for the replication subsystem.
//!
//! All values below are a reference profile used for logic validation.
//! Parameter safety constraints (Section 4):
//! 1. `1 <= QUORUM_THRESHOLD <= CLOSE_GROUP_SIZE`
//! 2. Effective paid-list threshold is per-key dynamic:
//!    `ConfirmNeeded(K) = floor(PaidGroupSize(K)/2)+1`
//! 3. If constraints are violated at runtime reconfiguration, node MUST reject
//!    the config.

#![allow(clippy::module_name_repetitions)]

use std::time::Duration;

use rand::Rng;

use crate::ant_protocol::CLOSE_GROUP_SIZE;

// ---------------------------------------------------------------------------
// Static constants (compile-time reference profile)
// ---------------------------------------------------------------------------

/// Maximum number of peers per k-bucket in the Kademlia routing table.
pub const K_BUCKET_SIZE: usize = 20;

/// Full-network target for required positive presence votes.
///
/// Effective per-key threshold is
/// `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
pub const QUORUM_THRESHOLD: usize = 4; // floor(CLOSE_GROUP_SIZE / 2) + 1

/// Maximum number of closest nodes tracking paid status for a key.
pub const PAID_LIST_CLOSE_GROUP_SIZE: usize = 20;

/// Number of closest peers to self eligible for neighbor sync.
pub const NEIGHBOR_SYNC_SCOPE: usize = 20;

/// Number of close-neighbor peers synced concurrently per round-robin repair
/// round.
pub const NEIGHBOR_SYNC_PEER_COUNT: usize = 4;

/// Minimum neighbor-sync cadence. Actual interval is randomized within
/// `[min, max]`.
const NEIGHBOR_SYNC_INTERVAL_MIN_SECS: u64 = 10 * 60;
/// Maximum neighbor-sync cadence.
const NEIGHBOR_SYNC_INTERVAL_MAX_SECS: u64 = 20 * 60;

/// Neighbor sync cadence range (min).
pub const NEIGHBOR_SYNC_INTERVAL_MIN: Duration =
    Duration::from_secs(NEIGHBOR_SYNC_INTERVAL_MIN_SECS);

/// Neighbor sync cadence range (max).
pub const NEIGHBOR_SYNC_INTERVAL_MAX: Duration =
    Duration::from_secs(NEIGHBOR_SYNC_INTERVAL_MAX_SECS);

/// Per-peer minimum spacing between successive syncs with the same peer.
const NEIGHBOR_SYNC_COOLDOWN_SECS: u64 = 60 * 60; // 1 hour
/// Per-peer minimum spacing between successive syncs with the same peer.
pub const NEIGHBOR_SYNC_COOLDOWN: Duration = Duration::from_secs(NEIGHBOR_SYNC_COOLDOWN_SECS);

/// Minimum self-lookup cadence.
const SELF_LOOKUP_INTERVAL_MIN_SECS: u64 = 5 * 60;
/// Maximum self-lookup cadence.
const SELF_LOOKUP_INTERVAL_MAX_SECS: u64 = 10 * 60;

/// Periodic self-lookup cadence range (min) to keep close neighborhood
/// current.
pub const SELF_LOOKUP_INTERVAL_MIN: Duration = Duration::from_secs(SELF_LOOKUP_INTERVAL_MIN_SECS);

/// Periodic self-lookup cadence range (max).
pub const SELF_LOOKUP_INTERVAL_MAX: Duration = Duration::from_secs(SELF_LOOKUP_INTERVAL_MAX_SECS);

/// Maximum number of concurrent outbound replication sends.
///
/// Caps how many fresh-replication chunk transfers can be in-flight at once
/// across the entire replication engine. Prevents bandwidth saturation on
/// home broadband connections when multiple chunks arrive simultaneously.
/// Each send transfers up to 4 MB (`MAX_CHUNK_SIZE`), so a limit of 3 means
/// at most ~12 MB queued for the upload link at any instant.
pub const MAX_CONCURRENT_REPLICATION_SENDS: usize = 3;

/// Concurrent fetches cap, derived from hardware thread count.
///
/// Uses `std::thread::available_parallelism()` so the node scales to the
/// machine it runs on.  Falls back to 4 if the OS query fails.
const AVAILABLE_PARALLELISM_FALLBACK: usize = 4;

/// Returns the number of hardware threads available, used as the fetch
/// concurrency limit.
#[allow(clippy::incompatible_msrv)] // NonZero::get is stable since 1.79; MSRV lint conflicts with redundant_closure
pub fn max_parallel_fetch() -> usize {
    std::thread::available_parallelism()
        .map_or(AVAILABLE_PARALLELISM_FALLBACK, std::num::NonZero::get)
}

/// Minimum audit-scheduler cadence.
const AUDIT_TICK_INTERVAL_MIN_SECS: u64 = 10 * 60;
/// Maximum audit-scheduler cadence.
const AUDIT_TICK_INTERVAL_MAX_SECS: u64 = 20 * 60;

/// Audit scheduler cadence range (min).
pub const AUDIT_TICK_INTERVAL_MIN: Duration = Duration::from_secs(AUDIT_TICK_INTERVAL_MIN_SECS);

/// Audit scheduler cadence range (max).
pub const AUDIT_TICK_INTERVAL_MAX: Duration = Duration::from_secs(AUDIT_TICK_INTERVAL_MAX_SECS);

/// Floor on the audit response deadline (independent of challenge size).
///
/// Sized to absorb worst-case global RTT for the audit envelope
/// (the request + response messages are KB-scale, not chunk-scale)
/// plus scheduling jitter. Tokyo↔NY round-trip is ~150ms each way,
/// so 2 seconds comfortably covers cross-continent communication
/// for any audit.
const AUDIT_RESPONSE_FLOOR_SECS: u64 = 2;

/// Conservative honest-responder read throughput, in bytes per second.
///
/// Used to size the audit response deadline. An honest peer answers
/// a k-key challenge by reading k chunks from local disk, computing
/// BLAKE3 + path proofs, and signing the response. The bottleneck is
/// disk read; BLAKE3 at ~3 GB/s + ML-DSA signing at ~3 ms are
/// negligible.
///
/// Set conservatively below any modern SSD (typical: 500 MB/s+).
/// At 50 MB/s, a k=10 sample at 4 MiB chunks reads in ~0.8s, well
/// inside even an aggressive timeout. A relay attacker who must
/// fetch the same 40 MB over the network at typical bandwidth
/// (100 Mbps = 12.5 MB/s) takes 3+ seconds for the data alone, plus
/// per-chunk network round-trips. At larger sample sizes the gap
/// is exponential in the relay's disadvantage.
const AUDIT_HONEST_READ_BPS: u64 = 50 * 1024 * 1024;

/// Slack multiplier on the honest-read estimate.
///
/// Set so an honest peer that's slower than HONEST_READ_BPS (e.g. an
/// HDD-backed node, or one under load) still answers within the
/// timeout. 5× is generous; a relay peer fetching the same data
/// over the network sees roughly 10-100× higher latency than disk,
/// so even at 5× the relay falls outside the envelope.
const AUDIT_RESPONSE_HONEST_MULTIPLIER: u64 = 5;

/// Maximum duration a peer may claim bootstrap status before penalties apply.
const BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS: u64 = 24 * 60 * 60; // 24 h
/// Maximum duration a peer may claim bootstrap status before penalties apply.
pub const BOOTSTRAP_CLAIM_GRACE_PERIOD: Duration =
    Duration::from_secs(BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS);

/// Minimum continuous out-of-range duration before pruning a key.
const PRUNE_HYSTERESIS_DURATION_SECS: u64 = 3 * 24 * 60 * 60; // 3 days
/// Minimum continuous out-of-range duration before pruning a key.
pub const PRUNE_HYSTERESIS_DURATION: Duration = Duration::from_secs(PRUNE_HYSTERESIS_DURATION_SECS);

/// Protocol identifier for replication operations.
pub const REPLICATION_PROTOCOL_ID: &str = "autonomi.ant.replication.v1";

/// 10 MiB — maximum replication wire message size (accommodates hint batches).
const REPLICATION_MESSAGE_SIZE_MIB: usize = 10;
/// Maximum replication wire message size.
pub const MAX_REPLICATION_MESSAGE_SIZE: usize = REPLICATION_MESSAGE_SIZE_MIB * 1024 * 1024;

/// Verification request timeout (per-batch).
const VERIFICATION_REQUEST_TIMEOUT_SECS: u64 = 15;
/// Verification request timeout (per-batch).
pub const VERIFICATION_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(VERIFICATION_REQUEST_TIMEOUT_SECS);

/// Fetch request timeout.
const FETCH_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Fetch request timeout.
pub const FETCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(FETCH_REQUEST_TIMEOUT_SECS);

/// Maximum age for pending-verification entries before stale eviction.
const PENDING_VERIFY_MAX_AGE_SECS: u64 = 30 * 60;
/// Maximum age for pending-verification entries before stale eviction.
pub const PENDING_VERIFY_MAX_AGE: Duration = Duration::from_secs(PENDING_VERIFY_MAX_AGE_SECS);

/// Trust event weight for confirmed audit failures.
pub const AUDIT_FAILURE_TRUST_WEIGHT: f64 = 5.0;

/// Maximum number of prune-confirmation audit challenges sent per prune pass.
pub const MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS: usize = 64;

/// Seconds to wait for `DhtNetworkEvent::BootstrapComplete` before proceeding
/// with bootstrap sync. Covers bootstrap nodes with no peers to connect to.
const BOOTSTRAP_COMPLETE_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Runtime-configurable wrapper
// ---------------------------------------------------------------------------

/// Runtime-configurable replication parameters.
///
/// Validated on construction — node rejects invalid configs.
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Close-group width and target holder count per key.
    pub close_group_size: usize,
    /// Required positive presence votes for quorum.
    pub quorum_threshold: usize,
    /// Maximum closest nodes tracking paid status for a key.
    pub paid_list_close_group_size: usize,
    /// Number of closest peers to self eligible for neighbor sync.
    pub neighbor_sync_scope: usize,
    /// Peers synced concurrently per round-robin repair round.
    pub neighbor_sync_peer_count: usize,
    /// Neighbor sync cadence range (min).
    pub neighbor_sync_interval_min: Duration,
    /// Neighbor sync cadence range (max).
    pub neighbor_sync_interval_max: Duration,
    /// Minimum spacing between successive syncs with the same peer.
    pub neighbor_sync_cooldown: Duration,
    /// Self-lookup cadence range (min).
    pub self_lookup_interval_min: Duration,
    /// Self-lookup cadence range (max).
    pub self_lookup_interval_max: Duration,
    /// Audit scheduler cadence range (min).
    pub audit_tick_interval_min: Duration,
    /// Audit scheduler cadence range (max).
    pub audit_tick_interval_max: Duration,
    /// Floor on the audit response deadline. Covers global RTT for
    /// the small request/response envelope plus scheduling jitter.
    /// See [`AUDIT_RESPONSE_FLOOR_SECS`] for sizing.
    pub audit_response_floor: Duration,
    /// Conservative honest-responder read throughput (bytes/sec).
    /// Used to scale the audit response deadline against the size of
    /// the challenge. Slow enough that even an HDD-backed honest peer
    /// fits inside the budget; fast enough that a relay attacker who
    /// must fetch bytes over the network falls outside.
    pub audit_honest_read_bps: u64,
    /// Slack multiplier on the honest-read estimate before
    /// declaring an audit timed out.
    pub audit_response_honest_multiplier: u64,
    /// Maximum duration a peer may claim bootstrap status.
    pub bootstrap_claim_grace_period: Duration,
    /// Minimum continuous out-of-range duration before pruning a key.
    pub prune_hysteresis_duration: Duration,
    /// Verification request timeout (per-batch).
    pub verification_request_timeout: Duration,
    /// Fetch request timeout.
    pub fetch_request_timeout: Duration,
    /// Seconds to wait for `DhtNetworkEvent::BootstrapComplete` before
    /// proceeding with bootstrap sync (covers bootstrap nodes with no peers).
    pub bootstrap_complete_timeout_secs: u64,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            close_group_size: CLOSE_GROUP_SIZE,
            quorum_threshold: QUORUM_THRESHOLD,
            paid_list_close_group_size: PAID_LIST_CLOSE_GROUP_SIZE,
            neighbor_sync_scope: NEIGHBOR_SYNC_SCOPE,
            neighbor_sync_peer_count: NEIGHBOR_SYNC_PEER_COUNT,
            neighbor_sync_interval_min: NEIGHBOR_SYNC_INTERVAL_MIN,
            neighbor_sync_interval_max: NEIGHBOR_SYNC_INTERVAL_MAX,
            neighbor_sync_cooldown: NEIGHBOR_SYNC_COOLDOWN,
            self_lookup_interval_min: SELF_LOOKUP_INTERVAL_MIN,
            self_lookup_interval_max: SELF_LOOKUP_INTERVAL_MAX,
            audit_tick_interval_min: AUDIT_TICK_INTERVAL_MIN,
            audit_tick_interval_max: AUDIT_TICK_INTERVAL_MAX,
            audit_response_floor: Duration::from_secs(AUDIT_RESPONSE_FLOOR_SECS),
            audit_honest_read_bps: AUDIT_HONEST_READ_BPS,
            audit_response_honest_multiplier: AUDIT_RESPONSE_HONEST_MULTIPLIER,
            bootstrap_claim_grace_period: BOOTSTRAP_CLAIM_GRACE_PERIOD,
            prune_hysteresis_duration: PRUNE_HYSTERESIS_DURATION,
            verification_request_timeout: VERIFICATION_REQUEST_TIMEOUT,
            fetch_request_timeout: FETCH_REQUEST_TIMEOUT,
            bootstrap_complete_timeout_secs: BOOTSTRAP_COMPLETE_TIMEOUT_SECS,
        }
    }
}

impl ReplicationConfig {
    /// Validate safety constraints. Returns `Err` with a description if any
    /// constraint is violated.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message describing the first violated
    /// constraint.
    pub fn validate(&self) -> Result<(), String> {
        if self.close_group_size == 0 {
            return Err("close_group_size must be >= 1".to_string());
        }
        if self.quorum_threshold == 0 || self.quorum_threshold > self.close_group_size {
            return Err(format!(
                "quorum_threshold ({}) must satisfy 1 <= quorum_threshold <= close_group_size ({})",
                self.quorum_threshold, self.close_group_size,
            ));
        }
        if self.close_group_size > MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS {
            return Err(format!(
                "close_group_size ({}) must be <= MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS ({})",
                self.close_group_size, MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS,
            ));
        }
        if self.paid_list_close_group_size == 0 {
            return Err("paid_list_close_group_size must be >= 1".to_string());
        }
        if self.neighbor_sync_interval_min > self.neighbor_sync_interval_max {
            return Err(format!(
                "neighbor_sync_interval_min ({:?}) must be <= neighbor_sync_interval_max ({:?})",
                self.neighbor_sync_interval_min, self.neighbor_sync_interval_max,
            ));
        }
        if self.audit_tick_interval_min > self.audit_tick_interval_max {
            return Err(format!(
                "audit_tick_interval_min ({:?}) must be <= audit_tick_interval_max ({:?})",
                self.audit_tick_interval_min, self.audit_tick_interval_max,
            ));
        }
        if self.self_lookup_interval_min > self.self_lookup_interval_max {
            return Err(format!(
                "self_lookup_interval_min ({:?}) must be <= self_lookup_interval_max ({:?})",
                self.self_lookup_interval_min, self.self_lookup_interval_max,
            ));
        }
        if self.neighbor_sync_peer_count == 0 {
            return Err("neighbor_sync_peer_count must be >= 1".to_string());
        }
        if self.neighbor_sync_scope == 0 {
            return Err("neighbor_sync_scope must be >= 1".to_string());
        }
        Ok(())
    }

    /// Effective quorum votes required for a key given the number of
    /// reachable quorum targets.
    ///
    /// `min(self.quorum_threshold, floor(quorum_targets_count / 2) + 1)`
    #[must_use]
    pub fn quorum_needed(&self, quorum_targets_count: usize) -> usize {
        if quorum_targets_count == 0 {
            return 0;
        }
        let majority = quorum_targets_count / 2 + 1;
        self.quorum_threshold.min(majority)
    }

    /// Confirmations required for paid-list consensus given the number of
    /// peers in the paid-list close group for a key.
    ///
    /// `floor(paid_group_size / 2) + 1`
    #[must_use]
    pub fn confirm_needed(paid_group_size: usize) -> usize {
        paid_group_size / 2 + 1
    }

    /// Returns a random duration in `[neighbor_sync_interval_min,
    /// neighbor_sync_interval_max]`.
    #[must_use]
    pub fn random_neighbor_sync_interval(&self) -> Duration {
        random_duration_in_range(
            self.neighbor_sync_interval_min,
            self.neighbor_sync_interval_max,
        )
    }

    /// Compute the number of keys to sample for an audit round, scaled
    /// dynamically by the total number of locally stored keys.
    ///
    /// Formula: `max(floor(sqrt(total_keys)), 1)`, capped at `total_keys`.
    #[must_use]
    pub fn audit_sample_count(total_keys: usize) -> usize {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let sqrt = (total_keys as f64).sqrt() as usize;
        sqrt.max(1).min(total_keys)
    }

    /// Maximum number of keys to accept in an incoming audit challenge.
    ///
    /// Scales dynamically: `2 * audit_sample_count(stored_chunks)`. The 2x
    /// margin accounts for the challenger having a larger store than us and
    /// therefore sampling more keys.
    #[must_use]
    pub fn max_incoming_audit_keys(stored_chunks: usize) -> usize {
        // Allow at least 1 key so a newly-joined node can still be audited.
        (2 * Self::audit_sample_count(stored_chunks)).max(1)
    }

    /// Compute the audit response timeout for a challenge with
    /// `challenged_key_count` keys, **sized to be tight enough that a
    /// relay attacker that must fetch the chunk bytes from elsewhere
    /// falls outside the budget**.
    ///
    /// Formula:
    ///   `floor + (challenged_bytes / honest_read_bps) × multiplier`
    ///
    /// Where `challenged_bytes = k × MAX_CHUNK_SIZE`. An honest peer
    /// reads `k × 4 MiB` from local disk at `honest_read_bps` (set
    /// conservatively at 50 MB/s — well below modern SSDs); the
    /// multiplier of 5 absorbs jitter, BLAKE3, ML-DSA, and slow disks.
    ///
    /// A relay attacker who must fetch the same `k × 4 MiB` over the
    /// network sees roughly 10-100× higher latency than disk for the
    /// data alone, plus per-chunk network round-trips. Even at the 5×
    /// honest multiplier, the relay falls outside the envelope and
    /// the audit times out — which fires an `application_failure`
    /// trust event (per `handle_audit_timeout` → `handle_audit_failure`).
    ///
    /// This is the v12.0 closure of the otherwise-documented §7 relay
    /// limit: relay still passes audits cryptographically, but no
    /// longer passes them inside the time budget.
    #[must_use]
    pub fn audit_response_timeout(&self, challenged_key_count: usize) -> Duration {
        let bytes_per_key = u64::try_from(crate::ant_protocol::MAX_CHUNK_SIZE).unwrap_or(u64::MAX);
        let keys = u64::try_from(challenged_key_count).unwrap_or(u64::MAX);
        let total_bytes = bytes_per_key.saturating_mul(keys);
        let bps = self.audit_honest_read_bps.max(1);
        let honest_read_secs = total_bytes / bps;
        let scaled_secs = honest_read_secs.saturating_mul(self.audit_response_honest_multiplier);
        self.audit_response_floor + Duration::from_secs(scaled_secs)
    }

    /// Returns a random duration in `[audit_tick_interval_min,
    /// audit_tick_interval_max]`.
    #[must_use]
    pub fn random_audit_tick_interval(&self) -> Duration {
        random_duration_in_range(self.audit_tick_interval_min, self.audit_tick_interval_max)
    }

    /// Returns a random duration in `[self_lookup_interval_min,
    /// self_lookup_interval_max]`.
    #[must_use]
    pub fn random_self_lookup_interval(&self) -> Duration {
        random_duration_in_range(self.self_lookup_interval_min, self.self_lookup_interval_max)
    }
}

/// Pick a random `Duration` uniformly in `[min, max]` at millisecond
/// granularity.
///
/// When `min == max` the result is deterministic.
fn random_duration_in_range(min: Duration, max: Duration) -> Duration {
    if min == max {
        return min;
    }
    // Our intervals are minutes/hours, well within u64 range. Saturate to
    // u64::MAX on the impossible overflow path to avoid a lossy cast.
    let to_u64_millis = |d: Duration| -> u64 { u64::try_from(d.as_millis()).unwrap_or(u64::MAX) };
    let chosen = rand::thread_rng().gen_range(to_u64_millis(min)..=to_u64_millis(max));
    Duration::from_millis(chosen)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defaults_pass_validation() {
        let config = ReplicationConfig::default();
        assert!(config.validate().is_ok(), "default config must be valid");
    }

    #[test]
    fn default_prune_hysteresis_is_three_days() {
        let config = ReplicationConfig::default();
        assert_eq!(
            config.prune_hysteresis_duration,
            Duration::from_secs(3 * 24 * 60 * 60)
        );
    }

    #[test]
    fn audit_failure_weight_is_five() {
        assert!((AUDIT_FAILURE_TRUST_WEIGHT - 5.0).abs() <= f64::EPSILON);
    }

    #[test]
    fn audit_response_timeout_floor_at_zero_keys() {
        let config = ReplicationConfig::default();
        assert_eq!(
            config.audit_response_timeout(0),
            Duration::from_secs(AUDIT_RESPONSE_FLOOR_SECS),
            "zero-key challenge should yield the floor exactly"
        );
    }

    #[test]
    fn audit_response_timeout_scales_with_key_count() {
        let config = ReplicationConfig::default();
        let t1 = config.audit_response_timeout(1);
        let t10 = config.audit_response_timeout(10);
        let t100 = config.audit_response_timeout(100);
        // Monotonic non-decreasing: small challenges sit at the floor
        // (integer division collapses sub-second per-key work to 0),
        // larger challenges accrete read time on top.
        assert!(t1 <= t10 && t10 < t100, "timeout must not decrease with k");

        // For k=1 at 4 MiB: 4_194_304 / 52_428_800 = 0s honest read
        // (integer division) × 5 = 0s, + 2s floor = 2s. The per-key
        // contribution only starts mattering once k * 4 MiB rounds up
        // past one second of honest-read time.
        assert_eq!(t1, Duration::from_secs(2));

        // For k=100 at 4 MiB: 419_430_400 / 52_428_800 = 8s honest
        // read, × 5 = 40s, + 2s floor = 42s.
        assert_eq!(t100, Duration::from_secs(42));
    }

    #[test]
    fn audit_response_timeout_relay_is_outside_envelope() {
        // The intended invariant: an honest peer with the SSD-class
        // read budget fits inside `audit_response_timeout(k)`, while a
        // relay attacker fetching k*4MiB over residential bandwidth
        // (≈ 5 MB/s realistic for sustained download) does NOT. Spot-
        // check this at k=100: honest budget is 42s, relay needs at
        // least 100 * 4 MiB / 5 MB/s = 80s for the data alone, which
        // exceeds the budget.
        let config = ReplicationConfig::default();
        let budget = config.audit_response_timeout(100);
        let relay_data_only = Duration::from_secs(100 * 4 * 1024 * 1024 / (5 * 1024 * 1024));
        assert!(
            relay_data_only > budget,
            "relay fetch ({}s) must exceed honest audit budget ({}s)",
            relay_data_only.as_secs(),
            budget.as_secs(),
        );
    }

    #[test]
    fn audit_response_timeout_saturates_on_huge_k() {
        let config = ReplicationConfig::default();
        // Should not panic or overflow at extreme k values.
        let _ = config.audit_response_timeout(usize::MAX);
    }

    #[test]
    fn quorum_threshold_zero_rejected() {
        let config = ReplicationConfig {
            quorum_threshold: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn quorum_threshold_exceeds_close_group_rejected() {
        let defaults = ReplicationConfig::default();
        let config = ReplicationConfig {
            quorum_threshold: defaults.close_group_size + 1,
            ..defaults
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn close_group_size_zero_rejected() {
        let config = ReplicationConfig {
            close_group_size: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn close_group_size_exceeding_prune_audit_budget_rejected() {
        let config = ReplicationConfig {
            close_group_size: MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS + 1,
            quorum_threshold: QUORUM_THRESHOLD,
            ..ReplicationConfig::default()
        };

        let err = config.validate().unwrap_err();

        assert!(
            err.contains("MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS"),
            "error should mention prune audit budget: {err}"
        );
    }

    #[test]
    fn paid_list_close_group_size_zero_rejected() {
        let config = ReplicationConfig {
            paid_list_close_group_size: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn neighbor_sync_interval_inverted_rejected() {
        let config = ReplicationConfig {
            neighbor_sync_interval_min: Duration::from_secs(100),
            neighbor_sync_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn audit_tick_interval_inverted_rejected() {
        let config = ReplicationConfig {
            audit_tick_interval_min: Duration::from_secs(100),
            audit_tick_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn self_lookup_interval_inverted_rejected() {
        let config = ReplicationConfig {
            self_lookup_interval_min: Duration::from_secs(100),
            self_lookup_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn neighbor_sync_peer_count_zero_rejected() {
        let config = ReplicationConfig {
            neighbor_sync_peer_count: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn audit_sample_count_scales_with_sqrt() {
        // Empty store
        assert_eq!(ReplicationConfig::audit_sample_count(0), 0);

        // Single key
        assert_eq!(ReplicationConfig::audit_sample_count(1), 1);

        // Small stores: sqrt(3)=1
        assert_eq!(ReplicationConfig::audit_sample_count(3), 1);

        // sqrt scaling
        assert_eq!(ReplicationConfig::audit_sample_count(4), 2);
        assert_eq!(ReplicationConfig::audit_sample_count(25), 5);
        assert_eq!(ReplicationConfig::audit_sample_count(100), 10);
        assert_eq!(ReplicationConfig::audit_sample_count(1_000), 31);
        assert_eq!(ReplicationConfig::audit_sample_count(10_000), 100);
        assert_eq!(ReplicationConfig::audit_sample_count(1_000_000), 1_000);
    }

    #[test]
    fn max_incoming_audit_keys_scales_dynamically() {
        // Empty store: at least 1 key accepted.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(0), 1);

        // 1 chunk: 2 * sqrt(1) = 2.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(1), 2);

        // 100 chunks: 2 * sqrt(100) = 20.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(100), 20);

        // 1M chunks: 2 * sqrt(1_000_000) = 2_000.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(1_000_000), 2_000);

        // 5M chunks: 2 * sqrt(5_000_000) = 4_472.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(5_000_000), 4_472);
    }

    #[test]
    fn quorum_needed_uses_smaller_of_threshold_and_majority() {
        let config = ReplicationConfig::default();

        // With 7 targets: majority = 7/2+1 = 4, threshold = 4 → min = 4
        assert_eq!(config.quorum_needed(7), 4);

        // With 3 targets: majority = 3/2+1 = 2, threshold = 4 → min = 2
        assert_eq!(config.quorum_needed(3), 2);

        // With 0 targets: quorum is impossible — returns 0
        assert_eq!(config.quorum_needed(0), 0);

        // With 100 targets: majority = 51, threshold = 4 → min = 4
        assert_eq!(config.quorum_needed(100), 4);
    }

    #[test]
    fn confirm_needed_is_strict_majority() {
        assert_eq!(ReplicationConfig::confirm_needed(1), 1);
        assert_eq!(ReplicationConfig::confirm_needed(2), 2);
        assert_eq!(ReplicationConfig::confirm_needed(3), 2);
        assert_eq!(ReplicationConfig::confirm_needed(4), 3);
        assert_eq!(ReplicationConfig::confirm_needed(20), 11);
    }

    #[test]
    fn random_intervals_within_bounds() {
        let config = ReplicationConfig::default();

        // Run several iterations to exercise randomness.
        let iterations = 50;
        for _ in 0..iterations {
            let ns = config.random_neighbor_sync_interval();
            assert!(ns >= config.neighbor_sync_interval_min);
            assert!(ns <= config.neighbor_sync_interval_max);

            let at = config.random_audit_tick_interval();
            assert!(at >= config.audit_tick_interval_min);
            assert!(at <= config.audit_tick_interval_max);

            let sl = config.random_self_lookup_interval();
            assert!(sl >= config.self_lookup_interval_min);
            assert!(sl <= config.self_lookup_interval_max);
        }
    }

    #[test]
    fn random_interval_equal_bounds_is_deterministic() {
        let fixed = Duration::from_secs(42);
        let config = ReplicationConfig {
            neighbor_sync_interval_min: fixed,
            neighbor_sync_interval_max: fixed,
            ..ReplicationConfig::default()
        };
        assert_eq!(config.random_neighbor_sync_interval(), fixed);
    }

    // -----------------------------------------------------------------------
    // Section 18 scenarios
    // -----------------------------------------------------------------------

    /// Scenario 18: Invalid runtime config is rejected by `validate()`.
    #[test]
    fn scenario_18_invalid_config_rejected() {
        // quorum_threshold > close_group_size -> validation fails.
        let config = ReplicationConfig {
            quorum_threshold: 10,
            close_group_size: 7,
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("quorum_threshold"),
            "error should mention quorum_threshold: {err}"
        );

        // close_group_size = 0 -> validation fails.
        let config = ReplicationConfig {
            close_group_size: 0,
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("close_group_size"),
            "error should mention close_group_size: {err}"
        );

        // neighbor_sync interval min > max -> validation fails.
        let config = ReplicationConfig {
            neighbor_sync_interval_min: Duration::from_secs(200),
            neighbor_sync_interval_max: Duration::from_secs(100),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("neighbor_sync_interval"),
            "error should mention neighbor_sync_interval: {err}"
        );

        // self_lookup interval min > max -> validation fails.
        let config = ReplicationConfig {
            self_lookup_interval_min: Duration::from_secs(999),
            self_lookup_interval_max: Duration::from_secs(1),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("self_lookup_interval"),
            "error should mention self_lookup_interval: {err}"
        );

        // audit_tick interval min > max -> validation fails.
        let config = ReplicationConfig {
            audit_tick_interval_min: Duration::from_secs(500),
            audit_tick_interval_max: Duration::from_secs(10),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("audit_tick_interval"),
            "error should mention audit_tick_interval: {err}"
        );
    }

    /// Scenario 26: Dynamic paid-list threshold for undersized set.
    /// With PaidGroupSize=8, `ConfirmNeeded` = floor(8/2)+1 = 5.
    #[test]
    fn scenario_26_dynamic_paid_threshold_undersized() {
        assert_eq!(ReplicationConfig::confirm_needed(8), 5, "floor(8/2)+1 = 5");

        // Additional boundary checks for small paid groups.
        assert_eq!(
            ReplicationConfig::confirm_needed(1),
            1,
            "single peer requires 1 confirmation"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(2),
            2,
            "2 peers require 2 confirmations"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(3),
            2,
            "3 peers require 2 confirmations"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(0),
            1,
            "0 peers yields floor(0/2)+1 = 1 (degenerate case)"
        );
    }

    /// Scenario 31: Consecutive audit ticks occur on randomized intervals
    /// bounded by the configured `[audit_tick_interval_min, audit_tick_interval_max]`
    /// window.
    #[test]
    fn scenario_31_audit_cadence_within_jitter_bounds() {
        let config = ReplicationConfig {
            audit_tick_interval_min: Duration::from_secs(600),
            audit_tick_interval_max: Duration::from_secs(1200),
            ..ReplicationConfig::default()
        };

        // Sample many intervals and verify each is within bounds.
        let iterations = 100;
        let mut saw_different = false;
        let mut prev = Duration::ZERO;

        for _ in 0..iterations {
            let interval = config.random_audit_tick_interval();
            assert!(
                interval >= config.audit_tick_interval_min,
                "interval {interval:?} below min {:?}",
                config.audit_tick_interval_min,
            );
            assert!(
                interval <= config.audit_tick_interval_max,
                "interval {interval:?} above max {:?}",
                config.audit_tick_interval_max,
            );
            if interval != prev && prev != Duration::ZERO {
                saw_different = true;
            }
            prev = interval;
        }

        // With 100 samples from a 10-minute range, at least two should differ
        // (probabilistically near-certain).
        assert!(
            saw_different,
            "audit intervals should exhibit randomized jitter across samples"
        );
    }
}
