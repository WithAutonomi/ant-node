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
use crate::replication::types::{BootstrapClaimObservation, NeighborSyncState};
use crate::storage::LmdbStorage;

use super::REPLICATION_TRUST_WEIGHT;

const MAX_CONCURRENT_PRUNE_AUDIT_CHALLENGES: usize = 32;

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

#[derive(Debug, Clone)]
struct RecordPruneCandidate {
    key: XorName,
    target_peers: Vec<PeerId>,
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
///   timestamp is at least `PRUNE_HYSTERESIS_DURATION` old and the current
///   close group proves it stores the record.
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
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    allow_remote_prune_audits: bool,
) -> PruneResult {
    let (stored_count, record_stats) = prune_stored_records(
        self_id,
        storage,
        paid_list,
        p2p_node,
        config,
        sync_state,
        allow_remote_prune_audits,
    )
    .await;
    let now = Instant::now();
    let (paid_count, paid_stats) =
        prune_paid_entries(self_id, paid_list, p2p_node, config, now).await;

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

async fn prune_stored_records(
    self_id: &PeerId,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    allow_remote_prune_audits: bool,
) -> (usize, RecordPruneStats) {
    let stored_keys = match storage.all_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read stored keys for pruning: {e}");
            return (0, RecordPruneStats::default());
        }
    };

    let now = Instant::now();
    let dht = p2p_node.dht_manager();
    let mut stats = RecordPruneStats::default();
    let mut candidates = Vec::new();
    let mut audit_challenge_budget = MAX_PRUNE_AUDIT_CHALLENGES_PER_PASS;
    let mut budget_deferred = 0usize;
    let mut bootstrap_deferred = 0usize;
    let scan_start = prune_scan_start(sync_state, stored_keys.len()).await;
    let mut last_selected_offset = None;

    for offset in 0..stored_keys.len() {
        let key = &stored_keys[(scan_start + offset) % stored_keys.len()];
        let closest: Vec<DHTNode> = dht
            .find_closest_nodes_local_with_self(key, config.close_group_size)
            .await;
        let is_responsible = closest.iter().any(|n| n.peer_id == *self_id);

        if is_responsible {
            if paid_list.record_out_of_range_since(key).is_some() {
                paid_list.clear_record_out_of_range(key);
                stats.cleared += 1;
            }
        } else {
            if paid_list.record_out_of_range_since(key).is_none() {
                stats.marked += 1;
            }
            paid_list.set_record_out_of_range(key);

            if let Some(first_seen) = paid_list.record_out_of_range_since(key) {
                let elapsed = now
                    .checked_duration_since(first_seen)
                    .unwrap_or(Duration::ZERO);
                if elapsed >= config.prune_hysteresis_duration {
                    if !allow_remote_prune_audits {
                        bootstrap_deferred = bootstrap_deferred.saturating_add(1);
                        continue;
                    }
                    let target_peers = remote_close_group_peers(&closest, self_id);
                    if target_peers.is_empty() {
                        warn!(
                            "Cannot prune {}: current close group has no remote peers",
                            hex::encode(key)
                        );
                        continue;
                    }
                    if target_peers.len() > audit_challenge_budget {
                        budget_deferred = budget_deferred.saturating_add(1);
                        continue;
                    }
                    audit_challenge_budget -= target_peers.len();
                    last_selected_offset = Some(offset);
                    candidates.push(RecordPruneCandidate {
                        key: *key,
                        target_peers,
                    });
                }
            }
        }
    }

    advance_prune_cursor(
        sync_state,
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

    let present_by_key =
        collect_record_prune_proofs(&candidates, storage, p2p_node, config, sync_state).await;
    let (keys_to_delete, revalidated_cleared) = revalidated_record_prune_keys(
        &candidates,
        &present_by_key,
        self_id,
        paid_list,
        p2p_node,
        config,
    )
    .await;
    stats.cleared += revalidated_cleared;
    stats.pruned = delete_stored_records(&keys_to_delete, storage, paid_list).await;

    (stored_keys.len(), stats)
}

async fn prune_paid_entries(
    self_id: &PeerId,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    now: Instant,
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
    let mut paid_keys_to_delete = Vec::new();

    for key in &paid_keys {
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
                    paid_keys_to_delete.push(*key);
                }
            }
        }
    }

    if !paid_keys_to_delete.is_empty() {
        match paid_list.remove_batch(&paid_keys_to_delete).await {
            Ok(count) => {
                stats.pruned = count;
                debug!("Pruned {count} out-of-range PaidForList entries");
            }
            Err(e) => {
                warn!("Failed to prune PaidForList entries: {e}");
            }
        }
    }

    (paid_keys.len(), stats)
}

fn remote_close_group_peers(close_group: &[DHTNode], self_id: &PeerId) -> Vec<PeerId> {
    close_group
        .iter()
        .filter(|node| node.peer_id != *self_id)
        .map(|node| node.peer_id)
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
) -> usize {
    let mut pruned = 0;

    for key in keys_to_delete {
        if let Err(e) = storage.delete(key).await {
            warn!("Failed to prune record {}: {e}", hex::encode(key));
        } else {
            pruned += 1;
            paid_list.clear_record_out_of_range(key);
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
/// Peers that fail to prove storage block pruning for their keys. The
/// retained local record continues to participate in normal neighbor-sync
/// repair because replica hint construction walks all locally stored keys,
/// including out-of-range keys retained by hysteresis.
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

        if target_peers_reported_present(&candidate.key, &current_target_peers, present_by_key) {
            keys_to_delete.push(candidate.key);
        } else {
            debug!(
                "Deferring prune for {} until current close group reports it",
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
) -> Vec<XorName> {
    candidates
        .iter()
        .filter(|candidate| {
            target_peers_reported_present(&candidate.key, &candidate.target_peers, present_by_key)
        })
        .map(|candidate| candidate.key)
        .collect()
}

fn target_peers_reported_present(
    key: &XorName,
    target_peers: &[PeerId],
    present_by_key: &HashMap<XorName, HashSet<PeerId>>,
) -> bool {
    let Some(present_peers) = present_by_key.get(key) else {
        return false;
    };
    target_peers.iter().all(|peer| present_peers.contains(peer))
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
            if digests.len() != 1 {
                warn!(
                    "Prune audit response from {peer} returned {} digests for one challenged key",
                    digests.len(),
                );
                return PruneAuditStatus::Failed;
            }

            if audit_digest_proves_key(peer, key, nonce, local_bytes, &digests[0]) {
                PruneAuditStatus::Proven
            } else {
                warn!(
                    "Prune audit proof from {peer} failed for {}",
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
    fn confirmed_keys_require_all_target_peers_present() {
        let peer_a = peer_id_from_byte(1);
        let peer_b = peer_id_from_byte(2);
        let key = key_from_byte(0xC);
        let candidates = vec![candidate(key, vec![peer_a, peer_b])];
        let mut present_by_key = HashMap::new();
        present_by_key.insert(key, HashSet::from([peer_a, peer_b]));

        let confirmed = confirmed_keys_from_presence(&candidates, &present_by_key);

        assert_eq!(confirmed, vec![key]);
    }

    #[test]
    fn confirmed_keys_defer_absent_or_missing_peer_evidence() {
        let peer_a = peer_id_from_byte(1);
        let peer_b = peer_id_from_byte(2);
        let complete_key = key_from_byte(0xD);
        let absent_key = key_from_byte(0xE);
        let missing_key = key_from_byte(0xF);
        let candidates = vec![
            candidate(complete_key, vec![peer_a, peer_b]),
            candidate(absent_key, vec![peer_a, peer_b]),
            candidate(missing_key, vec![peer_a, peer_b]),
        ];
        let mut present_by_key = HashMap::new();
        present_by_key.insert(complete_key, HashSet::from([peer_a, peer_b]));
        present_by_key.insert(absent_key, HashSet::from([peer_a]));

        let confirmed = confirmed_keys_from_presence(&candidates, &present_by_key);

        assert_eq!(confirmed, vec![complete_key]);
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
