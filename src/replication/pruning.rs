//! Post-cycle responsibility pruning (Section 11).
//!
//! On `NeighborSyncCycleComplete`: prune stored records and `PaidForList`
//! entries that have been continuously out of range for at least
//! `PRUNE_HYSTERESIS_DURATION`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::logging::{debug, info, warn};

use futures::{stream, StreamExt};
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::{DHTNode, P2PNode};
use tokio::sync::RwLock;

use crate::ant_protocol::XorName;
use crate::replication::config::{
    ReplicationConfig, AUDIT_FAILURE_TRUST_WEIGHT, MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS,
    REPLICATION_PROTOCOL_ID,
};
use crate::replication::paid_list::PaidList;
use crate::replication::protocol::{
    compute_audit_digest, AuditChallenge, AuditResponse, ReplicationMessage,
    ReplicationMessageBody, ABSENT_KEY_DIGEST,
};
use crate::replication::quorum::{self, VerificationTargets};
use crate::replication::types::{
    BootstrapClaimObservation, KeyVerificationEvidence, NeighborSyncState, PaidListEvidence,
    RepairProofs,
};
use crate::storage::LmdbStorage;

use super::REPLICATION_TRUST_WEIGHT;

const MAX_CONCURRENT_PRUNE_AUDIT_CHALLENGES: usize = 32;

/// Maximum expired `PaidForList` entries selected for verification per prune
/// pass. The unique peer fan-out for those entries is capped separately.
const MAX_PAID_PRUNE_VERIFICATIONS_PER_PASS: usize = 32;
/// Maximum unique peers contacted for paid-list verification per prune pass.
/// `quorum::run_verification_round` sends one request per target peer.
const MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS: usize = MAX_CONCURRENT_PRUNE_AUDIT_CHALLENGES;

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

/// Shared dependencies and switches for one prune pass.
pub struct PrunePassContext<'a> {
    /// Local peer id.
    pub self_id: &'a PeerId,
    /// Local record storage.
    pub storage: &'a Arc<LmdbStorage>,
    /// Persistent paid-list state.
    pub paid_list: &'a Arc<PaidList>,
    /// P2P node used for routing lookups and prune-confirmation audits.
    pub p2p_node: &'a Arc<P2PNode>,
    /// Replication configuration.
    pub config: &'a ReplicationConfig,
    /// Neighbor-sync state, including prune cursor and bootstrap claims.
    pub sync_state: &'a Arc<RwLock<NeighborSyncState>>,
    /// Key-specific repair proofs used to gate prune-confirmation audits.
    pub repair_proofs: &'a Arc<RwLock<RepairProofs>>,
    /// Current local neighbor-sync cycle epoch.
    pub current_sync_epoch: u64,
    /// Whether remote prune-confirmation audits are allowed this pass.
    pub allow_remote_prune_audits: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PruneAuditStatus {
    Proven,
    Failed,
    Bootstrapping,
}

#[derive(Debug, Default)]
struct RecordPruneStats {
    marked: usize,
    cleared: usize,
    pruned: usize,
}

#[derive(Debug, Default)]
struct PaidPruneStats {
    marked: usize,
    cleared: usize,
    pruned: usize,
}

#[derive(Debug, Default)]
struct PaidPruneDeferredCounts {
    entry_budget: usize,
    remote_gate: usize,
    peer_budget: usize,
}

impl PaidPruneDeferredCounts {
    fn log(&self) {
        if self.entry_budget > 0 {
            debug!(
                "Deferred {} expired PaidForList entries beyond the per-pass verification cap \
                 ({MAX_PAID_PRUNE_VERIFICATIONS_PER_PASS})",
                self.entry_budget,
            );
        }

        if self.remote_gate > 0 {
            debug!(
                "Deferred {} expired PaidForList entries until bootstrap drain allows remote \
                 paid-prune verification",
                self.remote_gate,
            );
        }

        if self.peer_budget > 0 {
            debug!(
                "Deferred {} expired PaidForList entries beyond the per-pass paid-prune peer cap \
                 ({MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS})",
                self.peer_budget,
            );
        }
    }
}

#[derive(Debug, Clone)]
struct RecordPruneCandidate {
    key: XorName,
    target_peers: Vec<PeerId>,
}

struct RecordPruneKeyOutcome {
    marked: bool,
    state: RecordPruneKeyState,
}

impl Default for RecordPruneKeyOutcome {
    fn default() -> Self {
        Self {
            marked: false,
            state: RecordPruneKeyState::None,
        }
    }
}

enum RecordPruneKeyState {
    None,
    Cleared,
    BootstrapDeferred,
    BudgetDeferred,
    Candidate(RecordPruneCandidate),
}

enum PaidPruneKeyState {
    None,
    RemoteDeferred,
    EntryBudgetDeferred,
    PeerBudgetDeferred,
    Candidate(Vec<PeerId>),
}

#[derive(Default)]
struct PruneAuditReportState {
    audit_failures: RwLock<HashSet<PeerId>>,
    bootstrap_abuse: RwLock<HashSet<PeerId>>,
}

// ---------------------------------------------------------------------------
// Prune pass
// ---------------------------------------------------------------------------

/// Execute post-cycle responsibility pruning.
///
/// For each stored record K:
/// - If `IsResponsible(self, K)`: clear `RecordOutOfRangeFirstSeen`.
/// - If not responsible: set timestamp if not already set; delete if the
///   timestamp is at least `PRUNE_HYSTERESIS_DURATION` old and all but one
///   of the current close group prove they store the record.
///
/// For each `PaidForList` entry K:
/// - If self is in `PaidCloseGroup(K)`: clear `PaidOutOfRangeFirstSeen`.
/// - If not in group: set timestamp if not already set; remove entry if the
///   timestamp is at least `PRUNE_HYSTERESIS_DURATION` old and three
///   quarters of the current paid close group (15 of 20 at production
///   parameters) confirm the key in their own `PaidForList`.
///
/// Compatibility wrapper for callers that have not adopted repair-proof
/// tracking. It preserves the original public signature, but it has no proof
/// table or advanced sync epoch to pass into record prune-confirmation audits.
/// Out-of-range records are therefore marked/deferred rather than deleted via
/// remote confirmation. The replication engine calls
/// [`run_prune_pass_with_context`] so it can pass real repair proofs.
pub async fn run_prune_pass(
    self_id: &PeerId,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    allow_remote_prune_audits: bool,
) -> PruneResult {
    let repair_proofs = Arc::new(RwLock::new(RepairProofs::new()));
    run_prune_pass_with_context(PrunePassContext {
        self_id,
        storage,
        paid_list,
        p2p_node,
        config,
        sync_state,
        repair_proofs: &repair_proofs,
        current_sync_epoch: 0,
        allow_remote_prune_audits,
    })
    .await
}

/// Execute one prune pass with repair-proof-gated remote confirmations.
pub async fn run_prune_pass_with_context(ctx: PrunePassContext<'_>) -> PruneResult {
    let (stored_count, record_stats) = prune_stored_records(&ctx).await;
    let now = Instant::now();
    let (paid_count, paid_stats) = prune_paid_entries(
        ctx.self_id,
        ctx.paid_list,
        ctx.p2p_node,
        ctx.config,
        now,
        ctx.allow_remote_prune_audits,
    )
    .await;

    let result = PruneResult {
        records_pruned: record_stats.pruned,
        records_marked_out_of_range: record_stats.marked,
        records_cleared: record_stats.cleared,
        paid_entries_pruned: paid_stats.pruned,
        paid_entries_marked: paid_stats.marked,
        paid_entries_cleared: paid_stats.cleared,
    };

    info!(
        "Prune pass complete: records={}/{} pruned, paid={}/{} pruned",
        result.records_pruned, stored_count, result.paid_entries_pruned, paid_count,
    );

    result
}

async fn prune_stored_records(ctx: &PrunePassContext<'_>) -> (usize, RecordPruneStats) {
    let stored_keys = match ctx.storage.all_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read stored keys for pruning: {e}");
            return (0, RecordPruneStats::default());
        }
    };

    let now = Instant::now();
    let dht = ctx.p2p_node.dht_manager();
    let mut stats = RecordPruneStats::default();
    let mut candidates = Vec::new();
    let mut audit_challenge_budget = MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS;
    let mut budget_deferred = 0usize;
    let mut bootstrap_deferred = 0usize;
    let scan_start = prune_scan_start(ctx.sync_state, stored_keys.len()).await;
    let mut last_selected_offset = None;

    for offset in 0..stored_keys.len() {
        let key = &stored_keys[(scan_start + offset) % stored_keys.len()];
        let closest: Vec<DHTNode> = dht
            .find_closest_nodes_local_with_self(key, ctx.config.close_group_size)
            .await;

        let outcome =
            evaluate_record_prune_key(ctx, key, &closest, now, &mut audit_challenge_budget).await;
        if outcome.marked {
            stats.marked += 1;
        }
        match outcome.state {
            RecordPruneKeyState::None => {}
            RecordPruneKeyState::Cleared => stats.cleared += 1,
            RecordPruneKeyState::BootstrapDeferred => {
                bootstrap_deferred = bootstrap_deferred.saturating_add(1);
            }
            RecordPruneKeyState::BudgetDeferred => {
                budget_deferred = budget_deferred.saturating_add(1);
            }
            RecordPruneKeyState::Candidate(candidate) => {
                last_selected_offset = Some(offset);
                candidates.push(candidate);
            }
        }
    }

    advance_prune_cursor(
        ctx.sync_state,
        stored_keys.len(),
        scan_start,
        last_selected_offset,
    )
    .await;

    if bootstrap_deferred > 0 {
        debug!(
            "Deferred {bootstrap_deferred} prune candidates until bootstrap drain allows \
             remote prune-confirmation audits"
        );
    }

    if budget_deferred > 0 {
        debug!(
            "Deferred {budget_deferred} prune candidates due to per-pass audit budget \
             ({MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS} challenges)"
        );
    }

    let present_by_key = collect_record_prune_proofs(
        &candidates,
        ctx.storage,
        ctx.p2p_node,
        ctx.config,
        ctx.sync_state,
    )
    .await;
    let (keys_to_delete, revalidated_cleared) = revalidated_record_prune_keys(
        &candidates,
        &present_by_key,
        ctx.self_id,
        ctx.paid_list,
        ctx.p2p_node,
        ctx.config,
    )
    .await;
    stats.cleared += revalidated_cleared;
    stats.pruned = delete_stored_records(
        &keys_to_delete,
        ctx.storage,
        ctx.paid_list,
        ctx.repair_proofs,
    )
    .await;

    (stored_keys.len(), stats)
}

async fn evaluate_record_prune_key(
    ctx: &PrunePassContext<'_>,
    key: &XorName,
    closest: &[DHTNode],
    now: Instant,
    audit_challenge_budget: &mut usize,
) -> RecordPruneKeyOutcome {
    let mut outcome = RecordPruneKeyOutcome::default();
    let is_responsible = closest.iter().any(|node| node.peer_id == *ctx.self_id);

    if is_responsible {
        if ctx.paid_list.record_out_of_range_since(key).is_some() {
            ctx.paid_list.clear_record_out_of_range(key);
            outcome.state = RecordPruneKeyState::Cleared;
        }
        return outcome;
    }

    if ctx.paid_list.record_out_of_range_since(key).is_none() {
        outcome.marked = true;
    }
    ctx.paid_list.set_record_out_of_range(key);

    let Some(first_seen) = ctx.paid_list.record_out_of_range_since(key) else {
        return outcome;
    };
    let elapsed = now
        .checked_duration_since(first_seen)
        .unwrap_or(Duration::ZERO);
    if elapsed < ctx.config.prune_hysteresis_duration {
        return outcome;
    }

    if !ctx.allow_remote_prune_audits {
        outcome.state = RecordPruneKeyState::BootstrapDeferred;
        return outcome;
    }

    let target_peers = remote_close_group_peers(closest, ctx.self_id);
    if target_peers.is_empty() {
        warn!(
            "Cannot prune {}: current close group has no remote peers",
            hex::encode(key)
        );
        return outcome;
    }

    // Only peers we have hinted (mature repair proof) may be audited; the
    // proof threshold must be reachable among them. A never-synced peer in
    // the close group reduces the audit pool instead of vetoing the prune.
    let current_close_peers: HashSet<PeerId> = closest.iter().map(|node| node.peer_id).collect();
    let audit_targets = peers_with_mature_repair_proofs(
        key,
        &target_peers,
        &current_close_peers,
        ctx.repair_proofs,
        ctx.current_sync_epoch,
    )
    .await;
    let proofs_needed = prune_proofs_needed(target_peers.len());
    if proofs_needed == 0 || audit_targets.len() < proofs_needed {
        debug!(
            "Deferring prune for {} until enough of the close group has mature \
             repair proofs",
            hex::encode(key)
        );
        return outcome;
    }

    if audit_targets.len() > *audit_challenge_budget {
        outcome.state = RecordPruneKeyState::BudgetDeferred;
        return outcome;
    }

    *audit_challenge_budget -= audit_targets.len();
    outcome.state = RecordPruneKeyState::Candidate(RecordPruneCandidate {
        key: *key,
        target_peers: audit_targets,
    });
    outcome
}

async fn prune_paid_entries(
    self_id: &PeerId,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    now: Instant,
    allow_remote_prune_audits: bool,
) -> (usize, PaidPruneStats) {
    let paid_keys = match paid_list.all_keys() {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read PaidForList for pruning: {e}");
            return (0, PaidPruneStats::default());
        }
    };

    let dht = p2p_node.dht_manager();
    let mut stats = PaidPruneStats::default();
    let mut expired_candidates: Vec<(XorName, Vec<PeerId>)> = Vec::new();
    let mut deferred_counts = PaidPruneDeferredCounts::default();
    let mut selected_verification_peers = HashSet::new();
    // Rotate the scan start so expired entries beyond the per-pass cap are
    // not starved by the same head-of-list entries every pass.
    let scan_start = paid_list.paid_prune_scan_start(paid_keys.len());
    let mut last_selected_offset = None;

    for offset in 0..paid_keys.len() {
        let key = &paid_keys[(scan_start + offset) % paid_keys.len()];
        let closest: Vec<DHTNode> = dht
            .find_closest_nodes_local_with_self(key, config.paid_list_close_group_size)
            .await;
        let in_paid_group = closest.iter().any(|n| n.peer_id == *self_id);

        if in_paid_group {
            if paid_list.paid_out_of_range_since(key).is_some() {
                paid_list.clear_paid_out_of_range(key);
                stats.cleared += 1;
            }
        } else {
            if paid_list.paid_out_of_range_since(key).is_none() {
                stats.marked += 1;
            }
            paid_list.set_paid_out_of_range(key);

            if let Some(first_seen) = paid_list.paid_out_of_range_since(key) {
                let elapsed = now
                    .checked_duration_since(first_seen)
                    .unwrap_or(Duration::ZERO);
                if elapsed >= config.prune_hysteresis_duration {
                    match select_paid_prune_candidate(
                        key,
                        &closest,
                        self_id,
                        allow_remote_prune_audits,
                        expired_candidates.len(),
                        &mut selected_verification_peers,
                    ) {
                        PaidPruneKeyState::None => {}
                        PaidPruneKeyState::RemoteDeferred => {
                            deferred_counts.remote_gate =
                                deferred_counts.remote_gate.saturating_add(1);
                        }
                        PaidPruneKeyState::EntryBudgetDeferred => {
                            deferred_counts.entry_budget =
                                deferred_counts.entry_budget.saturating_add(1);
                        }
                        PaidPruneKeyState::PeerBudgetDeferred => {
                            deferred_counts.peer_budget =
                                deferred_counts.peer_budget.saturating_add(1);
                        }
                        PaidPruneKeyState::Candidate(target_peers) => {
                            expired_candidates.push((*key, target_peers));
                            last_selected_offset = Some(offset);
                        }
                    }
                }
            }
        }
    }

    paid_list.advance_paid_prune_cursor(paid_keys.len(), scan_start, last_selected_offset);
    deferred_counts.log();

    let confirmed_by_key =
        collect_paid_prune_confirmations(&expired_candidates, p2p_node, config).await;
    let (paid_keys_to_delete, revalidated_cleared) = revalidated_paid_prune_keys(
        &expired_candidates,
        &confirmed_by_key,
        self_id,
        paid_list,
        p2p_node,
        config,
    )
    .await;
    stats.cleared += revalidated_cleared;
    stats.pruned = delete_paid_entries(&paid_keys_to_delete, paid_list).await;

    (paid_keys.len(), stats)
}

fn select_paid_prune_candidate(
    key: &XorName,
    closest: &[DHTNode],
    self_id: &PeerId,
    allow_remote_prune_audits: bool,
    selected_candidate_count: usize,
    selected_verification_peers: &mut HashSet<PeerId>,
) -> PaidPruneKeyState {
    if !allow_remote_prune_audits {
        return PaidPruneKeyState::RemoteDeferred;
    }

    let target_peers = remote_close_group_peers(closest, self_id);
    if target_peers.is_empty() {
        warn!(
            "Cannot prune paid entry {}: current paid close group has no remote peers",
            hex::encode(key)
        );
        return PaidPruneKeyState::None;
    }

    if selected_candidate_count >= MAX_PAID_PRUNE_VERIFICATIONS_PER_PASS {
        return PaidPruneKeyState::EntryBudgetDeferred;
    }

    if !reserve_paid_prune_peer_budget(&target_peers, selected_verification_peers) {
        return PaidPruneKeyState::PeerBudgetDeferred;
    }

    PaidPruneKeyState::Candidate(target_peers)
}

async fn delete_paid_entries(keys_to_delete: &[XorName], paid_list: &Arc<PaidList>) -> usize {
    if keys_to_delete.is_empty() {
        return 0;
    }

    match paid_list.remove_batch(keys_to_delete).await {
        Ok(count) => {
            debug!("Pruned {count} out-of-range PaidForList entries");
            count
        }
        Err(e) => {
            warn!("Failed to prune PaidForList entries: {e}");
            0
        }
    }
}

/// Re-check each confirmed candidate against current local state before
/// deletion.
///
/// The network round in [`collect_paid_prune_confirmations`] takes time;
/// the paid close group may have changed underneath it, including self
/// moving back into range. Mirrors [`revalidated_record_prune_keys`]:
/// confirmations only count from peers still in the current paid close
/// group, against a threshold computed from that current group.
async fn revalidated_paid_prune_keys(
    expired_candidates: &[(XorName, Vec<PeerId>)],
    confirmed_by_key: &HashMap<XorName, HashSet<PeerId>>,
    self_id: &PeerId,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> (Vec<XorName>, usize) {
    let dht = p2p_node.dht_manager();
    let mut keys_to_delete = Vec::new();
    let mut cleared = 0;
    let now = Instant::now();

    for (key, _) in expired_candidates {
        let closest: Vec<DHTNode> = dht
            .find_closest_nodes_local_with_self(key, config.paid_list_close_group_size)
            .await;

        if closest.iter().any(|n| n.peer_id == *self_id) {
            if paid_list.paid_out_of_range_since(key).is_some() {
                paid_list.clear_paid_out_of_range(key);
                cleared += 1;
            }
            continue;
        }

        let Some(first_seen) = paid_list.paid_out_of_range_since(key) else {
            continue;
        };
        let elapsed = now
            .checked_duration_since(first_seen)
            .unwrap_or(Duration::ZERO);
        if elapsed < config.prune_hysteresis_duration {
            continue;
        }

        let current_target_peers = remote_close_group_peers(&closest, self_id);
        if current_target_peers.is_empty() {
            warn!(
                "Cannot prune paid entry {}: current paid close group has no remote peers",
                hex::encode(key)
            );
            continue;
        }

        let confirmations_needed = paid_prune_confirmations_needed(current_target_peers.len());
        if target_peers_reported_present(
            key,
            &current_target_peers,
            confirmed_by_key,
            confirmations_needed,
        ) {
            keys_to_delete.push(*key);
        } else {
            debug!(
                "Deferring paid-entry prune for {} until enough of the current paid \
                 close group confirm it",
                hex::encode(key)
            );
        }
    }

    (keys_to_delete, cleared)
}

fn remote_close_group_peers(close_group: &[DHTNode], self_id: &PeerId) -> Vec<PeerId> {
    close_group
        .iter()
        .filter(|node| node.peer_id != *self_id)
        .map(|node| node.peer_id)
        .collect()
}

/// Confirmations required before removing an out-of-range `PaidForList`
/// entry: three quarters of the paid close group rounded up, 15 of 20 at
/// production parameters.
///
/// Paid-entry pruning is deliberately gated on the paid lists of the current
/// paid close group, never on chunk possession: the paid list is the
/// authorization record, and a wide confirmed majority must already track
/// the key before this node may forget it.
fn paid_prune_confirmations_needed(group_size: usize) -> usize {
    (3 * group_size).div_ceil(4)
}

fn reserve_paid_prune_peer_budget(
    target_peers: &[PeerId],
    selected_verification_peers: &mut HashSet<PeerId>,
) -> bool {
    let new_peer_count = target_peers
        .iter()
        .filter(|peer| !selected_verification_peers.contains(peer))
        .count();
    if selected_verification_peers
        .len()
        .saturating_add(new_peer_count)
        > MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS
    {
        return false;
    }

    selected_verification_peers.extend(target_peers.iter().copied());
    true
}

/// Ask the current paid close group whether they track each expired key in
/// their `PaidForList`, and return the confirming peers per key.
///
/// The deletion decision happens afterwards in
/// [`revalidated_paid_prune_keys`], against the paid close group as it
/// stands once the network round has completed.
async fn collect_paid_prune_confirmations(
    expired_candidates: &[(XorName, Vec<PeerId>)],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> HashMap<XorName, HashSet<PeerId>> {
    if expired_candidates.is_empty() {
        return HashMap::new();
    }

    let mut targets = VerificationTargets::default();
    let mut keys = Vec::new();
    for (key, target_peers) in expired_candidates {
        if target_peers.is_empty() {
            warn!(
                "Cannot prune paid entry {}: current paid close group has no remote peers",
                hex::encode(key)
            );
            continue;
        }
        keys.push(*key);
        for peer in target_peers {
            targets.all_peers.insert(*peer);
            targets.peer_to_keys.entry(*peer).or_default().push(*key);
            targets
                .peer_to_paid_keys
                .entry(*peer)
                .or_default()
                .insert(*key);
        }
        targets.paid_targets.insert(*key, target_peers.clone());
        targets.paid_group_sizes.insert(*key, target_peers.len());
    }
    for keys_list in targets.peer_to_keys.values_mut() {
        keys_list.sort_unstable();
        keys_list.dedup();
    }

    let evidence = quorum::run_verification_round(&keys, &targets, p2p_node, config).await;
    paid_confirmations_by_key(expired_candidates, &evidence)
}

/// Aggregate `Confirmed` paid-list evidence into per-key peer sets.
///
/// Only peers in the candidate's own target set count; `NotFound` and
/// `Unresolved` answers never confirm.
fn paid_confirmations_by_key(
    expired_candidates: &[(XorName, Vec<PeerId>)],
    evidence: &HashMap<XorName, KeyVerificationEvidence>,
) -> HashMap<XorName, HashSet<PeerId>> {
    let mut confirmed_by_key: HashMap<XorName, HashSet<PeerId>> = HashMap::new();
    for (key, target_peers) in expired_candidates {
        let Some(key_evidence) = evidence.get(key) else {
            continue;
        };
        let confirmed: HashSet<PeerId> = key_evidence
            .paid_list
            .iter()
            .filter(|&(peer, status)| {
                *status == PaidListEvidence::Confirmed && target_peers.contains(peer)
            })
            .map(|(peer, _)| *peer)
            .collect();
        if !confirmed.is_empty() {
            confirmed_by_key.insert(*key, confirmed);
        }
    }
    confirmed_by_key
}

/// Filter `target_peers` down to those with a mature repair proof for `key`.
///
/// Per design rule 20, peers without a key-specific mature repair hint proof
/// are never audited for that key.
async fn peers_with_mature_repair_proofs(
    key: &XorName,
    target_peers: &[PeerId],
    current_close_peers: &HashSet<PeerId>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    current_sync_epoch: u64,
) -> Vec<PeerId> {
    let mut proofs = repair_proofs.write().await;
    target_peers
        .iter()
        .filter(|peer| {
            proofs.has_mature_replica_hint(peer, key, current_close_peers, current_sync_epoch)
        })
        .copied()
        .collect()
}

async fn prune_scan_start(
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    stored_key_count: usize,
) -> usize {
    if stored_key_count == 0 {
        return 0;
    }
    sync_state.read().await.prune_cursor % stored_key_count
}

async fn advance_prune_cursor(
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    stored_key_count: usize,
    scan_start: usize,
    last_selected_offset: Option<usize>,
) {
    if stored_key_count == 0 {
        sync_state.write().await.prune_cursor = 0;
        return;
    }

    let advance_by = last_selected_offset.map_or(1, |offset| offset.saturating_add(1));
    sync_state.write().await.prune_cursor = (scan_start + advance_by) % stored_key_count;
}

async fn delete_stored_records(
    keys_to_delete: &[XorName],
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
) -> usize {
    let mut pruned = 0;

    for key in keys_to_delete {
        if let Err(e) = storage.delete(key).await {
            warn!("Failed to prune record {}: {e}", hex::encode(key));
        } else {
            pruned += 1;
            paid_list.clear_record_out_of_range(key);
            repair_proofs.write().await.remove_key(key);
            // Seed the PaidForList out-of-range timer so the second pass can
            // prune the entry sooner, closing the re-admission window between
            // the storage delete and the PaidForList prune pass.
            paid_list.set_paid_out_of_range(key);
            debug!("Pruned out-of-range record {}", hex::encode(key));
        }
    }

    pruned
}

/// Collect positive presence reports for prune candidates.
///
/// A key is deleted once all but one of the current close group prove
/// possession ([`prune_proofs_needed`]). Requiring unanimous proofs left
/// out-of-range records undeletable whenever a single close-group peer
/// lagged, while the all-but-one threshold still demands more copies than
/// the storage quorum used elsewhere. Keys below the proof threshold stay
/// local, and the retained record continues to participate in normal
/// neighbor-sync repair because replica hint construction walks all locally
/// stored keys, including out-of-range keys retained by hysteresis.
async fn collect_record_prune_proofs(
    candidates: &[RecordPruneCandidate],
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
) -> HashMap<XorName, HashSet<PeerId>> {
    if candidates.is_empty() {
        return HashMap::new();
    }

    let report_state = PruneAuditReportState::default();
    let mut requests = stream::iter(build_peer_audit_challenges(candidates))
        .map(|(peer, key)| {
            peer_proves_record(
                peer,
                key,
                storage,
                p2p_node,
                config,
                sync_state,
                &report_state,
            )
        })
        .buffer_unordered(MAX_CONCURRENT_PRUNE_AUDIT_CHALLENGES);

    let mut present_by_key = HashMap::<XorName, HashSet<PeerId>>::new();
    while let Some(proof) = requests.next().await {
        if let Some((peer, key)) = proof {
            present_by_key.entry(key).or_default().insert(peer);
        }
    }

    present_by_key
}

async fn revalidated_record_prune_keys(
    candidates: &[RecordPruneCandidate],
    present_by_key: &HashMap<XorName, HashSet<PeerId>>,
    self_id: &PeerId,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> (Vec<XorName>, usize) {
    let dht = p2p_node.dht_manager();
    let mut keys_to_delete = Vec::new();
    let mut cleared = 0;
    let now = Instant::now();

    for candidate in candidates {
        let closest: Vec<DHTNode> = dht
            .find_closest_nodes_local_with_self(&candidate.key, config.close_group_size)
            .await;

        if closest.iter().any(|n| n.peer_id == *self_id) {
            if paid_list
                .record_out_of_range_since(&candidate.key)
                .is_some()
            {
                paid_list.clear_record_out_of_range(&candidate.key);
                cleared += 1;
            }
            continue;
        }

        let Some(first_seen) = paid_list.record_out_of_range_since(&candidate.key) else {
            continue;
        };
        let elapsed = now
            .checked_duration_since(first_seen)
            .unwrap_or(Duration::ZERO);
        if elapsed < config.prune_hysteresis_duration {
            continue;
        }

        let current_target_peers = remote_close_group_peers(&closest, self_id);
        if current_target_peers.is_empty() {
            warn!(
                "Cannot prune {}: current close group has no remote peers",
                hex::encode(candidate.key)
            );
            continue;
        }

        let proofs_needed = prune_proofs_needed(current_target_peers.len());
        if target_peers_reported_present(
            &candidate.key,
            &current_target_peers,
            present_by_key,
            proofs_needed,
        ) {
            keys_to_delete.push(candidate.key);
        } else {
            debug!(
                "Deferring prune for {} until all but one of the current close group \
                 report it",
                hex::encode(candidate.key)
            );
        }
    }

    (keys_to_delete, cleared)
}

fn build_peer_audit_challenges(candidates: &[RecordPruneCandidate]) -> Vec<(PeerId, XorName)> {
    let mut challenges = Vec::new();
    for candidate in candidates {
        for peer in &candidate.target_peers {
            challenges.push((*peer, candidate.key));
        }
    }
    challenges
}

#[cfg(test)]
fn confirmed_keys_from_presence(
    candidates: &[RecordPruneCandidate],
    present_by_key: &HashMap<XorName, HashSet<PeerId>>,
    proofs_needed: usize,
) -> Vec<XorName> {
    candidates
        .iter()
        .filter(|candidate| {
            target_peers_reported_present(
                &candidate.key,
                &candidate.target_peers,
                present_by_key,
                proofs_needed,
            )
        })
        .map(|candidate| candidate.key)
        .collect()
}

/// Proofs required before deleting an out-of-range record: all but one of
/// the close group (6 of 7 at production parameters).
///
/// Stricter than the storage quorum (`QuorumNeeded`) because pruning only
/// runs after `PRUNE_HYSTERESIS_DURATION` out of range, by which time many
/// sync cycles should have replicated the record across the whole close
/// group. Tolerating exactly one lagging peer keeps a single absent peer
/// from vetoing deletion forever without accepting under-replication.
/// Groups of one or two peers require every proof: tolerating a miss there
/// would allow deletion on a single attestation.
fn prune_proofs_needed(group_size: usize) -> usize {
    if group_size <= 2 {
        group_size
    } else {
        group_size - 1
    }
}

/// Whether enough target peers supplied positive evidence to allow deletion.
///
/// `proofs_needed == 0` means confirmation is impossible (no targets), not
/// trivially met.
fn target_peers_reported_present(
    key: &XorName,
    target_peers: &[PeerId],
    present_by_key: &HashMap<XorName, HashSet<PeerId>>,
    proofs_needed: usize,
) -> bool {
    if proofs_needed == 0 {
        return false;
    }
    let Some(present_peers) = present_by_key.get(key) else {
        return false;
    };
    // Count distinct proven peers: iterating the present set keeps a
    // duplicated entry in `target_peers` from being counted twice.
    let proven = present_peers
        .iter()
        .filter(|peer| target_peers.contains(peer))
        .count();
    proven >= proofs_needed
}

/// Challenge a peer to prove it holds the exact record bytes for `key`.
/// `None` means the peer failed to provide usable proof.
async fn peer_proves_record(
    peer: PeerId,
    key: XorName,
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    report_state: &PruneAuditReportState,
) -> Option<(PeerId, XorName)> {
    let local_bytes = local_record_bytes(&key, storage).await?;

    let (challenge_id, nonce) = {
        let mut rng = rand::thread_rng();
        (rng.gen::<u64>(), rng.gen::<[u8; 32]>())
    };
    let encoded = encode_prune_audit_challenge(&peer, key, challenge_id, nonce)?;
    let Some(decoded) = send_prune_audit_challenge(&peer, &key, encoded, p2p_node, config).await
    else {
        // No decoded response means we did not observe the peer stop claiming
        // bootstrap status. Preserve any active claim so a later claim is not
        // misclassified as repeated abuse.
        report_prune_audit_failure_once(&peer, &key, p2p_node, config, report_state).await;
        return None;
    };

    let status =
        prune_audit_response_status(decoded, challenge_id, &peer, &key, &nonce, &local_bytes);
    if prune_audit_response_clears_bootstrap_claim(status) {
        clear_prune_bootstrap_claim(&peer, sync_state).await;
    }

    match status {
        PruneAuditStatus::Proven => Some((peer, key)),
        PruneAuditStatus::Bootstrapping => {
            report_prune_bootstrap_claim(&peer, &key, p2p_node, config, sync_state, report_state)
                .await;
            None
        }
        PruneAuditStatus::Failed => {
            report_prune_audit_failure_once(&peer, &key, p2p_node, config, report_state).await;
            None
        }
    }
}

fn prune_audit_response_clears_bootstrap_claim(status: PruneAuditStatus) -> bool {
    matches!(status, PruneAuditStatus::Proven | PruneAuditStatus::Failed)
}

fn encode_prune_audit_challenge(
    peer: &PeerId,
    key: XorName,
    challenge_id: u64,
    nonce: [u8; 32],
) -> Option<Vec<u8>> {
    let challenge = AuditChallenge {
        challenge_id,
        nonce,
        challenged_peer_id: *peer.as_bytes(),
        keys: vec![key],
    };
    let msg = ReplicationMessage {
        request_id: challenge_id,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!(
                "Failed to encode prune audit challenge for {} against {peer}: {e}",
                hex::encode(key),
            );
            return None;
        }
    };
    Some(encoded)
}

async fn send_prune_audit_challenge(
    peer: &PeerId,
    key: &XorName,
    encoded: Vec<u8>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> Option<ReplicationMessage> {
    let response = match p2p_node
        .send_request(
            peer,
            REPLICATION_PROTOCOL_ID,
            encoded,
            config.audit_response_timeout(1),
        )
        .await
    {
        Ok(response) => response,
        Err(e) => {
            debug!(
                "Prune audit challenge for {} against {peer} failed: {e}",
                hex::encode(key)
            );
            return None;
        }
    };

    let decoded = match ReplicationMessage::decode(&response.data) {
        Ok(msg) => msg,
        Err(e) => {
            warn!("Failed to decode prune audit response from {peer}: {e}");
            return None;
        }
    };

    Some(decoded)
}

fn prune_audit_response_status(
    decoded: ReplicationMessage,
    challenge_id: u64,
    peer: &PeerId,
    key: &XorName,
    nonce: &[u8; 32],
    local_bytes: &[u8],
) -> PruneAuditStatus {
    match decoded.body {
        ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
            challenge_id: resp_id,
            digests,
        }) => {
            if resp_id != challenge_id {
                warn!("Prune audit challenge ID mismatch from {peer}");
                return PruneAuditStatus::Failed;
            }
            let [digest] = digests.as_slice() else {
                warn!(
                    "Prune audit response from {peer} returned {} digests for one challenged key",
                    digests.len(),
                );
                return PruneAuditStatus::Failed;
            };
            if *digest == ABSENT_KEY_DIGEST {
                warn!(
                    "Prune audit proof from {peer} failed for {}: peer reports key absent",
                    hex::encode(key)
                );
                return PruneAuditStatus::Failed;
            }
            if audit_digest_proves_key(peer, key, nonce, local_bytes, digest) {
                PruneAuditStatus::Proven
            } else {
                warn!(
                    "Prune audit proof from {peer} failed for {}: digest mismatch",
                    hex::encode(key)
                );
                PruneAuditStatus::Failed
            }
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping {
            challenge_id: resp_id,
        }) => {
            if resp_id == challenge_id {
                warn!(
                    "Prune audit proof for {} blocked by bootstrap claim from {peer}",
                    hex::encode(key)
                );
                PruneAuditStatus::Bootstrapping
            } else {
                warn!("Prune audit challenge ID mismatch on Bootstrapping from {peer}");
                PruneAuditStatus::Failed
            }
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::Rejected {
            challenge_id: resp_id,
            reason,
        }) => {
            if resp_id == challenge_id {
                warn!(
                    "Prune audit proof for {} rejected by {peer}: {reason}",
                    hex::encode(key)
                );
            } else {
                warn!("Prune audit challenge ID mismatch on Rejected from {peer}");
            }
            PruneAuditStatus::Failed
        }
        _ => {
            warn!("Unexpected prune audit response type from {peer}");
            PruneAuditStatus::Failed
        }
    }
}

async fn local_record_bytes(key: &XorName, storage: &Arc<LmdbStorage>) -> Option<Vec<u8>> {
    match storage.get_raw(key).await {
        Ok(Some(bytes)) => Some(bytes),
        Ok(None) => {
            debug!(
                "Cannot prune-audit {}: local record disappeared",
                hex::encode(key)
            );
            None
        }
        Err(e) => {
            warn!(
                "Cannot prune-audit {}: failed to read local record: {e}",
                hex::encode(key)
            );
            None
        }
    }
}

fn audit_digest_proves_key(
    peer: &PeerId,
    key: &XorName,
    nonce: &[u8; 32],
    local_bytes: &[u8],
    digest: &[u8; 32],
) -> bool {
    if *digest == ABSENT_KEY_DIGEST {
        return false;
    }
    let expected = compute_audit_digest(nonce, peer.as_bytes(), key, local_bytes);
    *digest == expected
}

async fn report_prune_audit_failure_once(
    peer: &PeerId,
    key: &XorName,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    report_state: &PruneAuditReportState,
) -> bool {
    let should_report = peer_is_currently_responsible(peer, key, p2p_node, config).await
        && reserve_prune_audit_failure_report(report_state, peer).await;
    if !should_report {
        return false;
    }

    p2p_node
        .report_trust_event(
            peer,
            saorsa_core::TrustEvent::ApplicationFailure(AUDIT_FAILURE_TRUST_WEIGHT),
        )
        .await;
    true
}

async fn reserve_prune_audit_failure_report(
    report_state: &PruneAuditReportState,
    peer: &PeerId,
) -> bool {
    report_state.audit_failures.write().await.insert(*peer)
}

async fn reserve_prune_bootstrap_abuse_report(
    report_state: &PruneAuditReportState,
    peer: &PeerId,
) -> bool {
    report_state.bootstrap_abuse.write().await.insert(*peer)
}

async fn report_prune_bootstrap_claim(
    peer: &PeerId,
    key: &XorName,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    report_state: &PruneAuditReportState,
) {
    if !peer_is_currently_responsible(peer, key, p2p_node, config).await {
        return;
    }

    let observation = {
        let now = Instant::now();
        let mut state = sync_state.write().await;
        (
            now,
            state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period),
        )
    };

    let (now, observation) = observation;
    match observation {
        BootstrapClaimObservation::WithinGrace { .. } => {
            debug!("Prune audit: peer {peer} claims bootstrapping (within grace period)");
            return;
        }
        BootstrapClaimObservation::PastGrace { first_seen } => {
            if !reserve_prune_bootstrap_abuse_report(report_state, peer).await {
                debug!("Prune audit: peer {peer} bootstrap abuse already reported this pass");
                return;
            }
            warn!(
                "Prune audit: peer {peer} claiming bootstrap past grace period \
                 ({:?} > {:?}), reporting abuse",
                now.duration_since(first_seen),
                config.bootstrap_claim_grace_period,
            );
        }
        BootstrapClaimObservation::Repeated { first_seen } => {
            if !reserve_prune_bootstrap_abuse_report(report_state, peer).await {
                debug!("Prune audit: peer {peer} bootstrap abuse already reported this pass");
                return;
            }
            warn!(
                "Prune audit: peer {peer} repeated bootstrap claim after previously stopping; \
                 first claim was {:?} ago, reporting abuse",
                now.duration_since(first_seen),
            );
        }
    }

    p2p_node
        .report_trust_event(
            peer,
            saorsa_core::TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
        )
        .await;
}

async fn clear_prune_bootstrap_claim(peer: &PeerId, sync_state: &Arc<RwLock<NeighborSyncState>>) {
    let removed = {
        let mut state = sync_state.write().await;
        state.clear_active_bootstrap_claim(peer)
    };
    if removed {
        debug!("Prune audit: cleared active bootstrap claim for {peer}");
    }
}

async fn peer_is_currently_responsible(
    peer: &PeerId,
    key: &XorName,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> bool {
    let closest = p2p_node
        .dht_manager()
        .find_closest_nodes_local_with_self(key, config.close_group_size)
        .await;
    closest.iter().any(|node| node.peer_id == *peer)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn peer_id_from_byte(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    fn key_from_byte(b: u8) -> XorName {
        [b; 32]
    }

    fn peer_ids(count: usize) -> Vec<PeerId> {
        (0..count)
            .map(|idx| peer_id_from_byte(u8::try_from(idx + 1).expect("peer byte")))
            .collect()
    }

    fn candidate(key: XorName, target_peers: Vec<PeerId>) -> RecordPruneCandidate {
        RecordPruneCandidate { key, target_peers }
    }

    #[test]
    fn prune_audit_challenges_are_one_per_candidate_peer() {
        let peer_a = peer_id_from_byte(1);
        let peer_b = peer_id_from_byte(2);
        let key_a = key_from_byte(0xA);
        let key_b = key_from_byte(0xB);
        let candidates = vec![
            candidate(key_a, vec![peer_a, peer_b]),
            candidate(key_b, vec![peer_b]),
        ];

        let mut challenges = build_peer_audit_challenges(&candidates);
        challenges.sort_unstable_by_key(|(peer, key)| (*peer.as_bytes(), *key));

        let mut expected = vec![(peer_a, key_a), (peer_b, key_a), (peer_b, key_b)];
        expected.sort_unstable_by_key(|(peer, key)| (*peer.as_bytes(), *key));
        assert_eq!(challenges, expected);
    }

    #[test]
    fn confirmed_keys_require_quorum_of_target_peers_present() {
        let peer_a = peer_id_from_byte(1);
        let peer_b = peer_id_from_byte(2);
        let peer_c = peer_id_from_byte(3);
        let key = key_from_byte(0xC);
        let candidates = vec![candidate(key, vec![peer_a, peer_b, peer_c])];
        let mut present_by_key = HashMap::new();
        present_by_key.insert(key, HashSet::from([peer_a, peer_b]));

        // Two of three proofs meet a quorum of 2 even though one peer is
        // missing — unanimity is not required.
        let confirmed = confirmed_keys_from_presence(&candidates, &present_by_key, 2);
        assert_eq!(confirmed, vec![key]);

        // The same evidence fails a quorum of 3.
        let confirmed = confirmed_keys_from_presence(&candidates, &present_by_key, 3);
        assert!(confirmed.is_empty());
    }

    #[test]
    fn confirmed_keys_defer_below_quorum_or_missing_peer_evidence() {
        let peer_a = peer_id_from_byte(1);
        let peer_b = peer_id_from_byte(2);
        let quorum_key = key_from_byte(0xD);
        let below_quorum_key = key_from_byte(0xE);
        let missing_key = key_from_byte(0xF);
        let candidates = vec![
            candidate(quorum_key, vec![peer_a, peer_b]),
            candidate(below_quorum_key, vec![peer_a, peer_b]),
            candidate(missing_key, vec![peer_a, peer_b]),
        ];
        let mut present_by_key = HashMap::new();
        present_by_key.insert(quorum_key, HashSet::from([peer_a, peer_b]));
        present_by_key.insert(below_quorum_key, HashSet::from([peer_a]));

        let confirmed = confirmed_keys_from_presence(&candidates, &present_by_key, 2);

        assert_eq!(confirmed, vec![quorum_key]);
    }

    #[test]
    fn prune_proofs_needed_tolerates_exactly_one_lagging_peer() {
        assert_eq!(prune_proofs_needed(0), 0);
        // Tiny groups require every proof.
        assert_eq!(prune_proofs_needed(1), 1);
        assert_eq!(prune_proofs_needed(2), 2);
        assert_eq!(prune_proofs_needed(3), 2);
        assert_eq!(prune_proofs_needed(5), 4);
        // Production close group: 6 of 7 proofs required.
        assert_eq!(prune_proofs_needed(7), 6);
    }

    #[test]
    fn paid_prune_confirmations_are_three_quarters_rounded_up() {
        assert_eq!(paid_prune_confirmations_needed(0), 0);
        assert_eq!(paid_prune_confirmations_needed(1), 1);
        assert_eq!(paid_prune_confirmations_needed(2), 2);
        assert_eq!(paid_prune_confirmations_needed(4), 3);
        // Production paid close group: 15 of 20 confirmations required.
        assert_eq!(paid_prune_confirmations_needed(20), 15);
    }

    #[test]
    fn paid_prune_peer_budget_allows_overlapping_targets() {
        let peers = peer_ids(MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS);
        let mut selected_peers = HashSet::new();

        assert!(reserve_paid_prune_peer_budget(&peers, &mut selected_peers));
        assert_eq!(
            selected_peers.len(),
            MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS,
        );

        let overlapping_targets = vec![peers[0], peers[1]];
        assert!(reserve_paid_prune_peer_budget(
            &overlapping_targets,
            &mut selected_peers,
        ));
        assert_eq!(
            selected_peers.len(),
            MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS,
        );
    }

    #[test]
    fn paid_prune_peer_budget_rejects_new_peers_past_cap() {
        let peers = peer_ids(MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS + 1);
        let mut selected_peers = HashSet::new();

        assert!(reserve_paid_prune_peer_budget(
            &peers[..MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS],
            &mut selected_peers,
        ));
        assert!(!reserve_paid_prune_peer_budget(
            &peers[MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS..],
            &mut selected_peers,
        ));
        assert_eq!(
            selected_peers.len(),
            MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS,
        );
        assert!(!selected_peers.contains(&peers[MAX_PAID_PRUNE_VERIFICATION_PEERS_PER_PASS]));
    }

    #[test]
    fn paid_confirmations_count_only_confirmed_target_peers() {
        let confirmed_peer = peer_id_from_byte(1);
        let not_found_peer = peer_id_from_byte(2);
        let unresolved_peer = peer_id_from_byte(3);
        let outsider = peer_id_from_byte(4);
        let key = key_from_byte(0x21);
        let candidates = vec![(key, vec![confirmed_peer, not_found_peer, unresolved_peer])];

        let mut evidence = HashMap::new();
        evidence.insert(
            key,
            KeyVerificationEvidence {
                presence: HashMap::new(),
                paid_list: HashMap::from([
                    (confirmed_peer, PaidListEvidence::Confirmed),
                    (not_found_peer, PaidListEvidence::NotFound),
                    (unresolved_peer, PaidListEvidence::Unresolved),
                    // Confirmation from a peer outside the target set.
                    (outsider, PaidListEvidence::Confirmed),
                ]),
            },
        );

        let confirmed_by_key = paid_confirmations_by_key(&candidates, &evidence);

        assert_eq!(
            confirmed_by_key.get(&key),
            Some(&HashSet::from([confirmed_peer])),
            "only Confirmed answers from target peers may count",
        );
    }

    #[test]
    fn paid_confirmations_skip_keys_without_evidence() {
        let peer = peer_id_from_byte(1);
        let key = key_from_byte(0x22);
        let candidates = vec![(key, vec![peer])];

        let confirmed_by_key = paid_confirmations_by_key(&candidates, &HashMap::new());

        assert!(confirmed_by_key.is_empty());
    }

    #[test]
    fn zero_quorum_never_confirms() {
        let peer_a = peer_id_from_byte(1);
        let key = key_from_byte(0x10);
        let mut present_by_key = HashMap::new();
        present_by_key.insert(key, HashSet::from([peer_a]));

        assert!(!target_peers_reported_present(
            &key,
            &[peer_a],
            &present_by_key,
            0
        ));
    }

    #[test]
    fn proofs_from_non_target_peers_do_not_count_toward_quorum() {
        let target = peer_id_from_byte(1);
        let outsider = peer_id_from_byte(2);
        let key = key_from_byte(0x11);
        let mut present_by_key = HashMap::new();
        present_by_key.insert(key, HashSet::from([outsider]));

        assert!(!target_peers_reported_present(
            &key,
            &[target],
            &present_by_key,
            1
        ));
    }

    #[test]
    fn duplicated_target_peer_counts_once_toward_quorum() {
        let peer = peer_id_from_byte(1);
        let key = key_from_byte(0x12);
        let mut present_by_key = HashMap::new();
        present_by_key.insert(key, HashSet::from([peer]));

        assert!(!target_peers_reported_present(
            &key,
            &[peer, peer],
            &present_by_key,
            2
        ));
    }

    #[test]
    fn audit_digest_proof_requires_matching_peer_key_nonce_and_bytes() {
        let peer = peer_id_from_byte(1);
        let other_peer = peer_id_from_byte(2);
        let key = key_from_byte(0x11);
        let other_key = key_from_byte(0x12);
        let nonce = [0xAA; 32];
        let other_nonce = [0xBB; 32];
        let bytes = b"record bytes";
        let digest = compute_audit_digest(&nonce, peer.as_bytes(), &key, bytes);

        assert!(audit_digest_proves_key(&peer, &key, &nonce, bytes, &digest));
        assert!(!audit_digest_proves_key(
            &other_peer,
            &key,
            &nonce,
            bytes,
            &digest
        ));
        assert!(!audit_digest_proves_key(
            &peer, &other_key, &nonce, bytes, &digest
        ));
        assert!(!audit_digest_proves_key(
            &peer,
            &key,
            &other_nonce,
            bytes,
            &digest
        ));
        assert!(!audit_digest_proves_key(
            &peer,
            &key,
            &nonce,
            b"different bytes",
            &digest
        ));
        assert!(!audit_digest_proves_key(
            &peer,
            &key,
            &nonce,
            bytes,
            &ABSENT_KEY_DIGEST
        ));
    }

    #[tokio::test]
    async fn prune_cursor_advances_past_selected_budget_window() {
        let state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![])));
        state.write().await.prune_cursor = 2;

        let start = prune_scan_start(&state, 10).await;
        advance_prune_cursor(&state, 10, start, Some(3)).await;

        assert_eq!(state.read().await.prune_cursor, 6);
    }

    #[tokio::test]
    async fn prune_cursor_advances_even_when_no_candidate_selected() {
        let state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![])));
        state.write().await.prune_cursor = 9;

        let start = prune_scan_start(&state, 10).await;
        advance_prune_cursor(&state, 10, start, None).await;

        assert_eq!(state.read().await.prune_cursor, 0);
    }

    #[tokio::test]
    async fn prune_audit_normal_response_clears_stale_bootstrap_claim() {
        let peer = peer_id_from_byte(1);
        let state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![peer])));
        let first_seen = Instant::now();
        state
            .write()
            .await
            .bootstrap_claims
            .insert(peer, first_seen);
        state
            .write()
            .await
            .bootstrap_claim_history
            .insert(peer, first_seen);

        clear_prune_bootstrap_claim(&peer, &state).await;

        let state = state.read().await;
        assert!(!state.bootstrap_claims.contains_key(&peer));
        assert!(state.bootstrap_claim_history.contains_key(&peer));
    }

    #[test]
    fn prune_audit_clear_policy_requires_decoded_non_bootstrap_response() {
        assert!(prune_audit_response_clears_bootstrap_claim(
            PruneAuditStatus::Proven
        ));
        assert!(prune_audit_response_clears_bootstrap_claim(
            PruneAuditStatus::Failed
        ));
        assert!(!prune_audit_response_clears_bootstrap_claim(
            PruneAuditStatus::Bootstrapping
        ));
    }

    #[tokio::test]
    async fn prune_audit_failure_penalty_is_reserved_once_per_peer_per_pass() {
        let peer = peer_id_from_byte(1);
        let other_peer = peer_id_from_byte(2);
        let report_state = PruneAuditReportState::default();

        assert!(reserve_prune_audit_failure_report(&report_state, &peer).await);
        assert!(!reserve_prune_audit_failure_report(&report_state, &peer).await);
        assert!(reserve_prune_audit_failure_report(&report_state, &other_peer).await);

        let reported = report_state.audit_failures.read().await;
        assert_eq!(reported.len(), 2);
        assert!(reported.contains(&peer));
        assert!(reported.contains(&other_peer));
    }

    #[tokio::test]
    async fn prune_bootstrap_abuse_penalty_is_reserved_once_per_peer_per_pass() {
        let peer = peer_id_from_byte(1);
        let other_peer = peer_id_from_byte(2);
        let report_state = PruneAuditReportState::default();

        assert!(reserve_prune_bootstrap_abuse_report(&report_state, &peer).await);
        assert!(!reserve_prune_bootstrap_abuse_report(&report_state, &peer).await);
        assert!(reserve_prune_bootstrap_abuse_report(&report_state, &other_peer).await);

        let reported = report_state.bootstrap_abuse.read().await;
        assert_eq!(reported.len(), 2);
        assert!(reported.contains(&peer));
        assert!(reported.contains(&other_peer));
    }
}
