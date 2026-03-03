//! Replication tunable parameters (Section 4 of the design spec).
//!
//! All parameters are configurable via [`ReplicationConfig`]. Values here are the
//! reference profile used for logic validation.

use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Section 4 – Reference parameter constants
// ---------------------------------------------------------------------------

/// Maximum peers per k-bucket in the Kademlia routing table.
pub const K_BUCKET_SIZE: usize = 20;

/// Close-group width and target holder count per key.
pub const CLOSE_GROUP_SIZE: usize = 7;

/// Full-network target for required positive presence votes.
/// Effective per-key threshold is `QuorumNeeded(K)`.
/// Equals `floor(CLOSE_GROUP_SIZE / 2) + 1`.
pub const QUORUM_THRESHOLD: usize = 4; // floor(CLOSE_GROUP_SIZE / 2) + 1

/// Maximum closest nodes tracking paid status for a key.
pub const PAID_LIST_CLOSE_GROUP_SIZE: usize = 20;

/// Number of closest peers to self eligible for neighbor sync.
pub const NEIGHBOR_SYNC_SCOPE: usize = 20;

/// Peers synced concurrently per round-robin repair round.
pub const NEIGHBOR_SYNC_PEER_COUNT: usize = 4;

/// Neighbor sync cadence bounds (randomized within range).
pub const NEIGHBOR_SYNC_INTERVAL_MIN_SECS: u64 = 600; // 10 min
/// Upper bound of neighbor sync cadence.
pub const NEIGHBOR_SYNC_INTERVAL_MAX_SECS: u64 = 1200; // 20 min

/// Per-peer minimum spacing between successive syncs with the same peer.
pub const NEIGHBOR_SYNC_COOLDOWN_SECS: u64 = 3600; // 1 hour

/// Self-lookup cadence bounds (randomized within range).
pub const SELF_LOOKUP_INTERVAL_MIN_SECS: u64 = 300; // 5 min
/// Upper bound of self-lookup cadence.
pub const SELF_LOOKUP_INTERVAL_MAX_SECS: u64 = 600; // 10 min

/// Bootstrap concurrent fetches.
pub const MAX_PARALLEL_FETCH_BOOTSTRAP: usize = 20;

/// Audit scheduler cadence bounds (randomized within range).
pub const AUDIT_TICK_INTERVAL_MIN_SECS: u64 = 1800; // 30 min
/// Upper bound of audit tick cadence.
pub const AUDIT_TICK_INTERVAL_MAX_SECS: u64 = 3600; // 1 hour

/// Max local keys sampled per audit round (also max challenge items).
pub const AUDIT_BATCH_SIZE: usize = 8;

/// Audit response deadline.
pub const AUDIT_RESPONSE_TIMEOUT_SECS: u64 = 12;

/// Max duration a peer may claim bootstrap status before penalties apply.
pub const BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS: u64 = 86_400; // 24 hours

/// Minimum continuous out-of-range duration before pruning a key.
pub const PRUNE_HYSTERESIS_DURATION_SECS: u64 = 21_600; // 6 hours

/// Maximum keys in a single batched verification request.
pub const MAX_VERIFY_BATCH_SIZE: usize = 256;

/// Maximum keys in a single sync hint payload.
pub const MAX_SYNC_HINT_KEYS: usize = 1024;

/// Dirty-flag flush interval for `PaidForList` persistence.
pub const PAID_LIST_FLUSH_INTERVAL_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Runtime configuration
// ---------------------------------------------------------------------------

/// Runtime-configurable replication parameters with validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Close-group width.
    #[serde(default = "default_close_group_size")]
    pub close_group_size: usize,

    /// Full-network quorum threshold.
    #[serde(default = "default_quorum_threshold")]
    pub quorum_threshold: usize,

    /// Paid-list close group size.
    #[serde(default = "default_paid_list_close_group_size")]
    pub paid_list_close_group_size: usize,

    /// Neighbor sync scope.
    #[serde(default = "default_neighbor_sync_scope")]
    pub neighbor_sync_scope: usize,

    /// Neighbor sync peer count per round.
    #[serde(default = "default_neighbor_sync_peer_count")]
    pub neighbor_sync_peer_count: usize,

    /// Bootstrap max parallel fetches.
    #[serde(default = "default_max_parallel_fetch_bootstrap")]
    pub max_parallel_fetch_bootstrap: usize,

    /// Audit batch size.
    #[serde(default = "default_audit_batch_size")]
    pub audit_batch_size: usize,

    /// Audit response timeout in seconds.
    #[serde(default = "default_audit_response_timeout_secs")]
    pub audit_response_timeout_secs: u64,

    /// Bootstrap claim grace period in seconds.
    #[serde(default = "default_bootstrap_claim_grace_period_secs")]
    pub bootstrap_claim_grace_period_secs: u64,

    /// Prune hysteresis duration in seconds.
    #[serde(default = "default_prune_hysteresis_duration_secs")]
    pub prune_hysteresis_duration_secs: u64,

    /// Whether replication is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            close_group_size: CLOSE_GROUP_SIZE,
            quorum_threshold: QUORUM_THRESHOLD,
            paid_list_close_group_size: PAID_LIST_CLOSE_GROUP_SIZE,
            neighbor_sync_scope: NEIGHBOR_SYNC_SCOPE,
            neighbor_sync_peer_count: NEIGHBOR_SYNC_PEER_COUNT,
            max_parallel_fetch_bootstrap: MAX_PARALLEL_FETCH_BOOTSTRAP,
            audit_batch_size: AUDIT_BATCH_SIZE,
            audit_response_timeout_secs: AUDIT_RESPONSE_TIMEOUT_SECS,
            bootstrap_claim_grace_period_secs: BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS,
            prune_hysteresis_duration_secs: PRUNE_HYSTERESIS_DURATION_SECS,
            enabled: false,
        }
    }
}

impl ReplicationConfig {
    /// Validate safety constraints (Section 4).
    ///
    /// Returns `Ok(())` if the config is valid, or an error describing
    /// which constraint was violated.
    ///
    /// # Errors
    ///
    /// Returns an error if any parameter safety constraint is violated.
    pub fn validate(&self) -> crate::Result<()> {
        // Constraint 1: 1 <= QUORUM_THRESHOLD <= CLOSE_GROUP_SIZE
        if self.quorum_threshold < 1 || self.quorum_threshold > self.close_group_size {
            return Err(crate::Error::Replication(format!(
                "quorum_threshold ({}) must be in [1, close_group_size ({})]",
                self.quorum_threshold, self.close_group_size
            )));
        }

        if self.close_group_size == 0 {
            return Err(crate::Error::Replication(
                "close_group_size must be >= 1".to_string(),
            ));
        }

        if self.neighbor_sync_peer_count == 0 {
            return Err(crate::Error::Replication(
                "neighbor_sync_peer_count must be >= 1".to_string(),
            ));
        }

        if self.max_parallel_fetch_bootstrap == 0 {
            return Err(crate::Error::Replication(
                "max_parallel_fetch_bootstrap must be >= 1".to_string(),
            ));
        }

        Ok(())
    }

    /// Audit response timeout as [`Duration`].
    #[must_use]
    pub fn audit_response_timeout(&self) -> Duration {
        Duration::from_secs(self.audit_response_timeout_secs)
    }

    /// Bootstrap claim grace period as [`Duration`].
    #[must_use]
    pub fn bootstrap_claim_grace_period(&self) -> Duration {
        Duration::from_secs(self.bootstrap_claim_grace_period_secs)
    }

    /// Prune hysteresis duration as [`Duration`].
    #[must_use]
    pub fn prune_hysteresis_duration(&self) -> Duration {
        Duration::from_secs(self.prune_hysteresis_duration_secs)
    }
}

// Serde default helpers
const fn default_close_group_size() -> usize {
    CLOSE_GROUP_SIZE
}
const fn default_quorum_threshold() -> usize {
    QUORUM_THRESHOLD
}
const fn default_paid_list_close_group_size() -> usize {
    PAID_LIST_CLOSE_GROUP_SIZE
}
const fn default_neighbor_sync_scope() -> usize {
    NEIGHBOR_SYNC_SCOPE
}
const fn default_neighbor_sync_peer_count() -> usize {
    NEIGHBOR_SYNC_PEER_COUNT
}
const fn default_max_parallel_fetch_bootstrap() -> usize {
    MAX_PARALLEL_FETCH_BOOTSTRAP
}
const fn default_audit_batch_size() -> usize {
    AUDIT_BATCH_SIZE
}
const fn default_audit_response_timeout_secs() -> u64 {
    AUDIT_RESPONSE_TIMEOUT_SECS
}
const fn default_bootstrap_claim_grace_period_secs() -> u64 {
    BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS
}
const fn default_prune_hysteresis_duration_secs() -> u64 {
    PRUNE_HYSTERESIS_DURATION_SECS
}
const fn default_enabled() -> bool {
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = ReplicationConfig::default();
        config.validate().expect("default config should be valid");
    }

    #[test]
    fn test_quorum_threshold_too_large() {
        let config = ReplicationConfig {
            quorum_threshold: 100,
            close_group_size: 7,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_quorum_threshold_zero() {
        let config = ReplicationConfig {
            quorum_threshold: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_close_group_size_zero() {
        let config = ReplicationConfig {
            close_group_size: 0,
            quorum_threshold: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_duration_helpers() {
        let config = ReplicationConfig::default();
        assert_eq!(
            config.audit_response_timeout(),
            Duration::from_secs(AUDIT_RESPONSE_TIMEOUT_SECS)
        );
        assert_eq!(
            config.bootstrap_claim_grace_period(),
            Duration::from_secs(BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS)
        );
        assert_eq!(
            config.prune_hysteresis_duration(),
            Duration::from_secs(PRUNE_HYSTERESIS_DURATION_SECS)
        );
    }

    #[test]
    fn test_quorum_threshold_reference_value() {
        // Section 4: QUORUM_THRESHOLD = floor(CLOSE_GROUP_SIZE/2)+1
        assert_eq!(QUORUM_THRESHOLD, CLOSE_GROUP_SIZE / 2 + 1);
    }
}
