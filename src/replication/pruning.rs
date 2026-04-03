//! Post-cycle responsibility pruning (Section 11).
//!
//! On `NeighborSyncCycleComplete`: prune stored records and `PaidForList`
//! entries that have been continuously out of range for at least
//! `PRUNE_HYSTERESIS_DURATION`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::logging::{debug, info, warn};

use saorsa_core::identity::PeerId;
use saorsa_core::{DHTNode, P2PNode};

use crate::replication::config::ReplicationConfig;
use crate::replication::paid_list::PaidList;
use crate::storage::LmdbStorage;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Summary of a prune pass.
#[derive(Debug, Default)]
pub struct PruneResult {
    /// Number of records deleted from storage.
    pub records_pruned: usize,
    /// Number of records with out-of-range timestamp newly set.
    pub records_marked_out_of_range: usize,
    /// Number of records with out-of-range timestamp cleared (back in range).
    pub records_cleared: usize,
    /// Number of `PaidForList` entries removed.
    pub paid_entries_pruned: usize,
    /// Number of `PaidForList` entries with out-of-range timestamp newly set.
    pub paid_entries_marked: usize,
    /// Number of `PaidForList` entries cleared (back in range).
    pub paid_entries_cleared: usize,
}

// ---------------------------------------------------------------------------
// Prune pass
// ---------------------------------------------------------------------------

/// Execute post-cycle responsibility pruning.
///
/// For each stored record K:
/// - If `IsResponsible(self, K)`: clear `RecordOutOfRangeFirstSeen`.
/// - If not responsible: set timestamp if not already set; delete if the
///   timestamp is at least `PRUNE_HYSTERESIS_DURATION` old.
///
/// For each `PaidForList` entry K:
/// - If self is in `PaidCloseGroup(K)`: clear `PaidOutOfRangeFirstSeen`.
/// - If not in group: set timestamp if not already set; remove entry if the
///   timestamp is at least `PRUNE_HYSTERESIS_DURATION` old.
pub async fn run_prune_pass(
    self_id: &PeerId,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> PruneResult {
    let dht = p2p_node.dht_manager();
    let mut result = PruneResult::default();
    let now = Instant::now();

    // -- Prune stored records ---------------------------------------------

    let stored_keys = match storage.all_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read stored keys for pruning: {e}");
            return result;
        }
    };

    let mut keys_to_delete = Vec::new();

    for key in &stored_keys {
        let closest: Vec<DHTNode> = dht
            .find_closest_nodes_local_with_self(key, config.close_group_size)
            .await;
        let is_responsible = closest.iter().any(|n| n.peer_id == *self_id);

        if is_responsible {
            if paid_list.record_out_of_range_since(key).is_some() {
                paid_list.clear_record_out_of_range(key);
                result.records_cleared += 1;
            }
        } else {
            if paid_list.record_out_of_range_since(key).is_none() {
                result.records_marked_out_of_range += 1;
            }
            paid_list.set_record_out_of_range(key);

            if let Some(first_seen) = paid_list.record_out_of_range_since(key) {
                let elapsed = now
                    .checked_duration_since(first_seen)
                    .unwrap_or(Duration::ZERO);
                if elapsed >= config.prune_hysteresis_duration {
                    keys_to_delete.push(*key);
                }
            }
        }
    }

    for key in &keys_to_delete {
        if let Err(e) = storage.delete(key).await {
            warn!("Failed to prune record {}: {e}", hex::encode(key));
        } else {
            result.records_pruned += 1;
            paid_list.clear_record_out_of_range(key);
            // Seed the PaidForList out-of-range timer so the second pass can
            // prune the entry sooner, closing the re-admission window between
            // the storage delete and the PaidForList prune pass.
            paid_list.set_paid_out_of_range(key);
            debug!("Pruned out-of-range record {}", hex::encode(key));
        }
    }

    // -- Prune PaidForList entries -----------------------------------------

    let paid_keys = match paid_list.all_keys() {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read PaidForList for pruning: {e}");
            return result;
        }
    };

    let mut paid_keys_to_delete = Vec::new();

    for key in &paid_keys {
        let closest: Vec<DHTNode> = dht
            .find_closest_nodes_local_with_self(key, config.paid_list_close_group_size)
            .await;
        let in_paid_group = closest.iter().any(|n| n.peer_id == *self_id);

        if in_paid_group {
            if paid_list.paid_out_of_range_since(key).is_some() {
                paid_list.clear_paid_out_of_range(key);
                result.paid_entries_cleared += 1;
            }
        } else {
            if paid_list.paid_out_of_range_since(key).is_none() {
                result.paid_entries_marked += 1;
            }
            paid_list.set_paid_out_of_range(key);

            if let Some(first_seen) = paid_list.paid_out_of_range_since(key) {
                let elapsed = now
                    .checked_duration_since(first_seen)
                    .unwrap_or(Duration::ZERO);
                if elapsed >= config.prune_hysteresis_duration {
                    paid_keys_to_delete.push(*key);
                }
            }
        }
    }

    if !paid_keys_to_delete.is_empty() {
        match paid_list.remove_batch(&paid_keys_to_delete).await {
            Ok(count) => {
                result.paid_entries_pruned = count;
                debug!("Pruned {count} out-of-range PaidForList entries");
            }
            Err(e) => {
                warn!("Failed to prune PaidForList entries: {e}");
            }
        }
    }

    info!(
        "Prune pass complete: records={}/{} pruned, paid={}/{} pruned",
        result.records_pruned,
        stored_keys.len(),
        result.paid_entries_pruned,
        paid_keys.len(),
    );

    result
}
