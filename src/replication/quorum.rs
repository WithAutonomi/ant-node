//! Quorum verification logic (Section 9).
//!
//! Single-round batched verification: presence + paid-list evidence collected
//! in one request round to `VerifyTargets = PaidTargets ∪ QuorumTargets`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::logging::{debug, info, warn};
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use tokio::task::JoinHandle;

use crate::ant_protocol::XorName;
use crate::replication::config::{
    ReplicationConfig, MAX_VERIFICATION_KEYS_PER_REQUEST, PAID_LIST_CLOSE_GROUP_SIZE,
    PAID_LIST_FLEX_EDGE_COUNT, REPLICATION_PROTOCOL_ID,
};
use crate::replication::protocol::{
    ReplicationMessage, ReplicationMessageBody, VerificationRequest, VerificationResponse,
};
use crate::replication::types::{KeyVerificationEvidence, PaidListEvidence, PresenceEvidence};

/// Verification round duration that is worth surfacing at info level.
const VERIFICATION_ROUND_SLOW_LOG_MS: u128 = 500;

struct VerificationBatchResult {
    peer: PeerId,
    requested_keys: Vec<XorName>,
    response: Option<ReplicationMessage>,
}

struct PaidListVoteSummary {
    confirmed: usize,
    effective_group_size: usize,
    max_possible_confirmed: usize,
    max_possible_group_size: usize,
}

// ---------------------------------------------------------------------------
// Verification targets
// ---------------------------------------------------------------------------

/// Targets for verifying a set of keys.
#[derive(Debug, Default)]
pub struct VerificationTargets {
    /// Per-key: closest `CLOSE_GROUP_SIZE` peers (excluding self) for presence
    /// quorum.
    pub quorum_targets: HashMap<XorName, Vec<PeerId>>,
    /// Per-key: `PaidCloseGroup` peers for paid-list majority.
    pub paid_targets: HashMap<XorName, Vec<PeerId>>,
    /// Per-key: self-inclusive paid close-group size used to compute
    /// `ConfirmNeeded(K)`.
    pub paid_group_sizes: HashMap<XorName, usize>,
    /// Per-key: remote peers in the furthest paid-list positions.
    ///
    /// These peers are queried, but only positive paid-list evidence from them
    /// expands the paid-list majority denominator once the paid group reaches
    /// the configured 20-peer width. Negative/missing edge evidence is ignored
    /// for that full-width paid-list quorum because boundary peers can
    /// legitimately differ under churn.
    pub paid_edge_targets: HashMap<XorName, HashSet<PeerId>>,
    /// Union of all target peers across all keys.
    pub all_peers: HashSet<PeerId>,
    /// Which keys each peer should be queried about.
    pub peer_to_keys: HashMap<PeerId, Vec<XorName>>,
    /// Which keys need paid-list checks from which peers.
    pub peer_to_paid_keys: HashMap<PeerId, HashSet<XorName>>,
}

/// Compute verification targets for a batch of keys.
///
/// For each key, determines the `QuorumTargets` (closest `CLOSE_GROUP_SIZE`
/// peers excluding self) and `PaidTargets` (`PaidCloseGroup` excluding self),
/// then unions them into per-peer request batches.
pub async fn compute_verification_targets(
    keys: &[XorName],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    self_id: &PeerId,
) -> VerificationTargets {
    let dht = p2p_node.dht_manager();
    let mut targets = VerificationTargets {
        quorum_targets: HashMap::new(),
        paid_targets: HashMap::new(),
        paid_group_sizes: HashMap::new(),
        paid_edge_targets: HashMap::new(),
        all_peers: HashSet::new(),
        peer_to_keys: HashMap::new(),
        peer_to_paid_keys: HashMap::new(),
    };

    for &key in keys {
        // QuorumTargets: up to CLOSE_GROUP_SIZE nearest peers for K, excluding
        // self.
        let closest = dht
            .find_closest_nodes_local(&key, config.close_group_size)
            .await;
        let quorum_peers: Vec<PeerId> = closest
            .iter()
            .filter(|n| n.peer_id != *self_id)
            .map(|n| n.peer_id)
            .collect();

        // PaidTargets: PaidCloseGroup(K) excluding self.
        let paid_closest = dht
            .find_closest_nodes_local_with_self(&key, config.paid_list_close_group_size)
            .await;
        let paid_group_size = paid_closest.len();
        let paid_edge_start = paid_group_size.saturating_sub(PAID_LIST_FLEX_EDGE_COUNT);
        let mut paid_peers = Vec::new();
        let mut paid_edge_peers = HashSet::new();
        for (idx, node) in paid_closest.iter().enumerate() {
            if node.peer_id == *self_id {
                continue;
            }
            paid_peers.push(node.peer_id);
            if idx >= paid_edge_start {
                paid_edge_peers.insert(node.peer_id);
            }
        }

        // VerifyTargets = PaidTargets ∪ QuorumTargets
        for &peer in &quorum_peers {
            targets.all_peers.insert(peer);
            targets.peer_to_keys.entry(peer).or_default().push(key);
        }
        for &peer in &paid_peers {
            targets.all_peers.insert(peer);
            targets.peer_to_keys.entry(peer).or_default().push(key);
            targets
                .peer_to_paid_keys
                .entry(peer)
                .or_default()
                .insert(key);
        }

        targets.quorum_targets.insert(key, quorum_peers);
        targets.paid_targets.insert(key, paid_peers);
        targets.paid_group_sizes.insert(key, paid_group_size);
        targets.paid_edge_targets.insert(key, paid_edge_peers);
    }

    // Deduplicate keys per peer (a peer in both quorum and paid targets for
    // the same key would have it listed twice).
    for keys_list in targets.peer_to_keys.values_mut() {
        keys_list.sort_unstable();
        keys_list.dedup();
    }

    targets
}

/// Compute presence-only verification targets for locally paid keys.
///
/// Local `PaidForList` membership authorizes the key already; this target set
/// is only used to discover peers that can serve the record bytes.
pub async fn compute_presence_targets(
    keys: &[XorName],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    self_id: &PeerId,
) -> VerificationTargets {
    let dht = p2p_node.dht_manager();
    let mut targets = VerificationTargets {
        quorum_targets: HashMap::new(),
        paid_targets: HashMap::new(),
        paid_group_sizes: HashMap::new(),
        paid_edge_targets: HashMap::new(),
        all_peers: HashSet::new(),
        peer_to_keys: HashMap::new(),
        peer_to_paid_keys: HashMap::new(),
    };

    for &key in keys {
        let closest = dht
            .find_closest_nodes_local(&key, config.close_group_size)
            .await;
        let quorum_peers: Vec<PeerId> = closest
            .iter()
            .filter(|n| n.peer_id != *self_id)
            .map(|n| n.peer_id)
            .collect();

        for &peer in &quorum_peers {
            targets.all_peers.insert(peer);
            targets.peer_to_keys.entry(peer).or_default().push(key);
        }

        targets.quorum_targets.insert(key, quorum_peers);
    }

    for keys_list in targets.peer_to_keys.values_mut() {
        keys_list.sort_unstable();
        keys_list.dedup();
    }

    targets
}

// ---------------------------------------------------------------------------
// Verification outcome
// ---------------------------------------------------------------------------

/// Outcome of verifying a single key.
#[derive(Debug, Clone)]
pub enum KeyVerificationOutcome {
    /// Presence quorum passed.
    QuorumVerified {
        /// Peers that responded `Present` (verified fetch sources).
        sources: Vec<PeerId>,
    },
    /// Paid-list authorization succeeded.
    PaidListVerified {
        /// Peers that responded `Present` (potential fetch sources, may be
        /// empty).
        sources: Vec<PeerId>,
    },
    /// Quorum failed definitively (both paths impossible).
    QuorumFailed,
    /// Inconclusive (timeout with neither success nor fail-fast).
    QuorumInconclusive,
}

// ---------------------------------------------------------------------------
// Evidence evaluation (pure logic, no I/O)
// ---------------------------------------------------------------------------

/// Evaluate verification evidence for a single key.
///
/// Returns the outcome based on Section 9 rules:
/// - **Step 10**: If presence positives >= `QuorumNeeded(K)`, `QuorumVerified`.
/// - **Step 9**: If paid confirmations >= `ConfirmNeeded(K)`,
///   `PaidListVerified`.
/// - **Step 14**: Fail fast when both paths are impossible.
/// - **Step 15**: Otherwise inconclusive.
#[must_use]
pub fn evaluate_key_evidence(
    key: &XorName,
    evidence: &KeyVerificationEvidence,
    targets: &VerificationTargets,
    config: &ReplicationConfig,
) -> KeyVerificationOutcome {
    evaluate_key_evidence_with_holder_check(key, evidence, targets, config, |_, _| true)
}

/// Variant of [`evaluate_key_evidence`] that consults a holder-credit
/// predicate before counting a peer's Present evidence (v12 §6).
///
/// `holder_credit` is invoked as `(peer, key) -> bool`. Returning `false`
/// downgrades a Present claim to Unresolved (we don't trust this peer's
/// "I have it" without a recent commitment-bound audit proving it).
/// Returning `true` keeps today's behaviour. Paid-list evidence is
/// independent of holder credit (the paid-list lookup is a property of
/// the receiving peer's own data, not a claim about K being present).
///
/// The non-`_with_holder_check` form preserves prior behaviour by
/// passing a predicate that always returns true. New call sites that
/// have a `RecentProvers` cache + commitment-by-peer table should pass
/// a real predicate.
#[must_use]
pub fn evaluate_key_evidence_with_holder_check(
    key: &XorName,
    evidence: &KeyVerificationEvidence,
    targets: &VerificationTargets,
    config: &ReplicationConfig,
    holder_credit: impl Fn(&PeerId, &XorName) -> bool,
) -> KeyVerificationOutcome {
    let quorum_peers = targets
        .quorum_targets
        .get(key)
        .map_or(&[][..], Vec::as_slice);

    // Count presence evidence from QuorumTargets. v12 §6: a peer that
    // claims Present but is not commitment-credited for K is downgraded
    // to Unresolved (we may have to retry once they re-prove storage).
    let mut presence_positive = 0usize;
    let mut presence_unresolved = 0usize;

    for peer in quorum_peers {
        match evidence.presence.get(peer) {
            Some(PresenceEvidence::Present) => {
                if holder_credit(peer, key) {
                    presence_positive += 1;
                } else {
                    presence_unresolved += 1;
                }
            }
            Some(PresenceEvidence::Absent) => {}
            Some(PresenceEvidence::Unresolved) | None => {
                presence_unresolved += 1;
            }
        }
    }

    // Also collect Present peers from paid targets for fetch sources.
    let paid_peers = targets.paid_targets.get(key).map_or(&[][..], Vec::as_slice);
    let present_peers = collect_present_sources(evidence, quorum_peers, paid_peers);

    let quorum_needed = config.quorum_needed(quorum_peers.len());
    let paid_votes = summarize_paid_list_votes(key, evidence, targets, paid_peers);
    let confirm_needed = ReplicationConfig::confirm_needed(paid_votes.effective_group_size);

    // Step 10: Presence quorum reached.
    // quorum_needed == 0 means zero targets exist — quorum is impossible,
    // not trivially met.
    if quorum_needed > 0 && presence_positive >= quorum_needed {
        return KeyVerificationOutcome::QuorumVerified {
            sources: present_peers,
        };
    }

    // Step 9: Paid-list majority reached.
    // confirm_needed from 0 paid peers is 1, so this naturally fails with
    // 0 confirmed — no special guard needed. But be explicit for clarity.
    if paid_votes.effective_group_size > 0 && paid_votes.confirmed >= confirm_needed {
        return KeyVerificationOutcome::PaidListVerified {
            sources: present_peers,
        };
    }

    // Step 14: Fail fast when both paths are impossible.
    let max_confirm_needed = ReplicationConfig::confirm_needed(paid_votes.max_possible_group_size);
    let paid_possible = paid_votes.max_possible_group_size > 0
        && paid_votes.max_possible_confirmed >= max_confirm_needed;
    let quorum_possible =
        quorum_needed > 0 && presence_positive + presence_unresolved >= quorum_needed;

    if !paid_possible && !quorum_possible {
        return KeyVerificationOutcome::QuorumFailed;
    }

    // Step 15: Neither success nor fail-fast.
    KeyVerificationOutcome::QuorumInconclusive
}

fn summarize_paid_list_votes(
    key: &XorName,
    evidence: &KeyVerificationEvidence,
    targets: &VerificationTargets,
    paid_peers: &[PeerId],
) -> PaidListVoteSummary {
    let paid_group_size = targets
        .paid_group_sizes
        .get(key)
        .copied()
        .unwrap_or(paid_peers.len());
    let paid_edge_count = if paid_group_size >= PAID_LIST_CLOSE_GROUP_SIZE {
        PAID_LIST_FLEX_EDGE_COUNT.min(paid_group_size)
    } else {
        0
    };
    let core_group_size = paid_group_size.saturating_sub(paid_edge_count);
    let edge_targets = (paid_edge_count > 0)
        .then(|| targets.paid_edge_targets.get(key))
        .flatten();

    let mut confirmed = 0usize;
    let mut confirmed_edge = 0usize;
    let mut unresolved_core = 0usize;
    let mut unresolved_edge = 0usize;

    for peer in paid_peers {
        let is_edge = edge_targets.is_some_and(|peers| peers.contains(peer));
        match evidence.paid_list.get(peer) {
            Some(PaidListEvidence::Confirmed) => {
                confirmed += 1;
                if is_edge {
                    confirmed_edge += 1;
                }
            }
            Some(PaidListEvidence::NotFound) => {}
            Some(PaidListEvidence::Unresolved) | None => {
                if is_edge {
                    unresolved_edge += 1;
                } else {
                    unresolved_core += 1;
                }
            }
        }
    }

    let effective_group_size = core_group_size + confirmed_edge;
    PaidListVoteSummary {
        confirmed,
        effective_group_size,
        max_possible_confirmed: confirmed + unresolved_core + unresolved_edge,
        max_possible_group_size: effective_group_size + unresolved_edge,
    }
}

/// Return peers that gave positive presence evidence for a key.
///
/// Only peers in the computed verification target sets are considered.
#[must_use]
pub fn present_sources_for_key(
    key: &XorName,
    evidence: &KeyVerificationEvidence,
    targets: &VerificationTargets,
) -> Vec<PeerId> {
    let quorum_peers = targets
        .quorum_targets
        .get(key)
        .map_or(&[][..], Vec::as_slice);
    let paid_peers = targets.paid_targets.get(key).map_or(&[][..], Vec::as_slice);

    collect_present_sources(evidence, quorum_peers, paid_peers)
}

fn collect_present_sources(
    evidence: &KeyVerificationEvidence,
    quorum_peers: &[PeerId],
    paid_peers: &[PeerId],
) -> Vec<PeerId> {
    let mut present_peers = Vec::new();
    let mut seen = HashSet::new();

    for peer in quorum_peers.iter().chain(paid_peers.iter()) {
        if matches!(evidence.presence.get(peer), Some(PresenceEvidence::Present))
            && seen.insert(*peer)
        {
            present_peers.push(*peer);
        }
    }

    present_peers
}

fn verification_requests_for_peer(
    peer_keys: &[XorName],
    paid_check_keys: Option<&HashSet<XorName>>,
) -> Vec<VerificationRequest> {
    peer_keys
        .chunks(MAX_VERIFICATION_KEYS_PER_REQUEST)
        .map(|key_batch| VerificationRequest {
            keys: key_batch.to_vec(),
            paid_list_check_indices: paid_indices_for_key_batch(key_batch, paid_check_keys),
        })
        .collect()
}

fn paid_indices_for_key_batch(
    key_batch: &[XorName],
    paid_check_keys: Option<&HashSet<XorName>>,
) -> Vec<u32> {
    let Some(paid_keys) = paid_check_keys else {
        return Vec::new();
    };

    key_batch
        .iter()
        .enumerate()
        .filter_map(|(idx, key)| {
            paid_keys
                .contains(key)
                .then_some(idx)
                .and_then(|idx| u32::try_from(idx).ok())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Network verification round
// ---------------------------------------------------------------------------

/// Send batched verification requests to all peers and collect evidence.
///
/// Implements Section 9 requirement: one request per peer carrying many keys.
/// Returns per-key evidence aggregated from all peer responses.
pub async fn run_verification_round(
    keys: &[XorName],
    targets: &VerificationTargets,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> HashMap<XorName, KeyVerificationEvidence> {
    let started = Instant::now();
    let peer_count = targets.peer_to_keys.len();
    let requested_key_refs = targets.peer_to_keys.values().map(Vec::len).sum::<usize>();

    // Initialize empty evidence for all keys.
    let mut evidence: HashMap<XorName, KeyVerificationEvidence> = keys
        .iter()
        .map(|&k| {
            (
                k,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            )
        })
        .collect();

    let handles =
        spawn_verification_batch_tasks(targets, p2p_node, config.verification_request_timeout);
    collect_verification_batch_results(handles, targets, &mut evidence).await;

    let elapsed_ms = started.elapsed().as_millis();
    let batch_count = targets
        .peer_to_keys
        .values()
        .map(|peer_keys| peer_keys.chunks(MAX_VERIFICATION_KEYS_PER_REQUEST).count())
        .sum::<usize>();
    if elapsed_ms >= VERIFICATION_ROUND_SLOW_LOG_MS {
        info!(
            target: "ant_node::replication::verification",
            "Slow quorum verification round: keys={}, peers={peer_count}, batches={batch_count}, requested_key_refs={requested_key_refs}, elapsed_ms={elapsed_ms}",
            keys.len(),
        );
    } else {
        debug!(
            target: "ant_node::replication::verification",
            "Quorum verification round: keys={}, peers={peer_count}, batches={batch_count}, requested_key_refs={requested_key_refs}, elapsed_ms={elapsed_ms}",
            keys.len(),
        );
    }

    evidence
}

fn spawn_verification_batch_tasks(
    targets: &VerificationTargets,
    p2p_node: &Arc<P2PNode>,
    timeout: Duration,
) -> Vec<JoinHandle<VerificationBatchResult>> {
    let mut handles = Vec::new();

    for (&peer, peer_keys) in &targets.peer_to_keys {
        let paid_check_keys = targets.peer_to_paid_keys.get(&peer);

        for request in verification_requests_for_peer(peer_keys, paid_check_keys) {
            let requested_keys = request.keys.clone();
            let msg = ReplicationMessage {
                request_id: rand::random(),
                body: ReplicationMessageBody::VerificationRequest(request),
            };

            handles.push(spawn_verification_batch_task(
                peer,
                requested_keys,
                msg,
                Arc::clone(p2p_node),
                timeout,
            ));
        }
    }

    handles
}

fn spawn_verification_batch_task(
    peer: PeerId,
    requested_keys: Vec<XorName>,
    msg: ReplicationMessage,
    p2p: Arc<P2PNode>,
    timeout: Duration,
) -> JoinHandle<VerificationBatchResult> {
    tokio::spawn(async move {
        let encoded = match msg.encode() {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to encode verification request: {e}");
                return VerificationBatchResult {
                    peer,
                    requested_keys,
                    response: None,
                };
            }
        };

        let response = match p2p
            .send_request(&peer, REPLICATION_PROTOCOL_ID, encoded, timeout)
            .await
        {
            Ok(response) => match ReplicationMessage::decode(&response.data) {
                Ok(decoded) => Some(decoded),
                Err(e) => {
                    warn!("Failed to decode verification response from {peer}: {e}");
                    None
                }
            },
            Err(e) => {
                debug!("Verification request to {peer} failed: {e}");
                None
            }
        };

        VerificationBatchResult {
            peer,
            requested_keys,
            response,
        }
    })
}

async fn collect_verification_batch_results(
    handles: Vec<JoinHandle<VerificationBatchResult>>,
    targets: &VerificationTargets,
    evidence: &mut HashMap<XorName, KeyVerificationEvidence>,
) {
    for handle in handles {
        let batch = match handle.await {
            Ok(result) => result,
            Err(e) => {
                warn!("Verification task panicked: {e}");
                continue;
            }
        };
        let peer = batch.peer;

        let Some(msg) = batch.response else {
            mark_peer_keys_unresolved(&peer, &batch.requested_keys, targets, evidence);
            continue;
        };

        if let ReplicationMessageBody::VerificationResponse(resp) = msg.body {
            process_verification_response_for_keys(
                &peer,
                &batch.requested_keys,
                &resp,
                targets,
                evidence,
            );
        }
    }
}

/// Mark all keys for a peer as unresolved (timeout / decode failure).
#[cfg(test)]
fn mark_peer_unresolved(
    peer: &PeerId,
    targets: &VerificationTargets,
    evidence: &mut HashMap<XorName, KeyVerificationEvidence>,
) {
    if let Some(peer_keys) = targets.peer_to_keys.get(peer) {
        mark_peer_keys_unresolved(peer, peer_keys, targets, evidence);
    }
}

fn mark_peer_keys_unresolved(
    peer: &PeerId,
    requested_keys: &[XorName],
    targets: &VerificationTargets,
    evidence: &mut HashMap<XorName, KeyVerificationEvidence>,
) {
    let paid_check_keys = targets.peer_to_paid_keys.get(peer);
    for key in requested_keys {
        if let Some(ev) = evidence.get_mut(key) {
            ev.presence.insert(*peer, PresenceEvidence::Unresolved);
            if paid_check_keys.is_some_and(|ks| ks.contains(key)) {
                ev.paid_list.insert(*peer, PaidListEvidence::Unresolved);
            }
        }
    }
}

/// Process a single peer's verification response into the evidence map.
#[cfg(test)]
fn process_verification_response(
    peer: &PeerId,
    response: &VerificationResponse,
    targets: &VerificationTargets,
    evidence: &mut HashMap<XorName, KeyVerificationEvidence>,
) {
    let Some(peer_keys) = targets.peer_to_keys.get(peer) else {
        return;
    };

    process_verification_response_for_keys(peer, peer_keys, response, targets, evidence);
}

fn process_verification_response_for_keys(
    peer: &PeerId,
    requested_keys: &[XorName],
    response: &VerificationResponse,
    targets: &VerificationTargets,
    evidence: &mut HashMap<XorName, KeyVerificationEvidence>,
) {
    let paid_check_keys = targets.peer_to_paid_keys.get(peer);

    // Use a HashSet for O(1) key membership checks instead of linear scan,
    // preventing CPU amplification from large responses.
    let requested_keys_set: HashSet<&XorName> = requested_keys.iter().collect();

    // Cap results at 2x requested keys to limit processing of stuffed
    // responses while still tolerating some unsolicited entries.
    let max_results = requested_keys.len().saturating_mul(2);
    let results = if response.results.len() > max_results {
        warn!(
            "Peer {peer} sent {} verification results but only {} keys were requested — truncating",
            response.results.len(),
            requested_keys.len(),
        );
        &response.results[..max_results]
    } else {
        &response.results
    };

    // Match response results to requested keys.
    for result in results {
        if !requested_keys_set.contains(&result.key) {
            continue; // Ignore unsolicited key results.
        }

        if let Some(ev) = evidence.get_mut(&result.key) {
            // Presence evidence.
            let presence = if result.present {
                PresenceEvidence::Present
            } else {
                PresenceEvidence::Absent
            };
            ev.presence.insert(*peer, presence);

            // Paid-list evidence (only if requested).
            if paid_check_keys.is_some_and(|ks| ks.contains(&result.key)) {
                if let Some(is_paid) = result.paid {
                    let paid = if is_paid {
                        PaidListEvidence::Confirmed
                    } else {
                        PaidListEvidence::NotFound
                    };
                    ev.paid_list.insert(*peer, paid);
                }
            }
        }
    }

    // Keys that were requested but not in response -> unresolved.
    for key in requested_keys {
        if let Some(ev) = evidence.get_mut(key) {
            ev.presence
                .entry(*peer)
                .or_insert(PresenceEvidence::Unresolved);
            if paid_check_keys.is_some_and(|ks| ks.contains(key)) {
                ev.paid_list
                    .entry(*peer)
                    .or_insert(PaidListEvidence::Unresolved);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::config::PAID_LIST_CLOSE_GROUP_SIZE;
    use crate::replication::protocol::KeyVerificationResult;

    const PAID_LIST_INNER_GROUP_SIZE: usize =
        PAID_LIST_CLOSE_GROUP_SIZE - PAID_LIST_FLEX_EDGE_COUNT;
    const PAID_LIST_INNER_MAJORITY: usize = PAID_LIST_INNER_GROUP_SIZE / 2 + 1;
    const PAID_LIST_ONE_EDGE_GROUP_SIZE: usize = PAID_LIST_INNER_GROUP_SIZE + 1;
    const PAID_LIST_ONE_EDGE_MAJORITY: usize = PAID_LIST_ONE_EDGE_GROUP_SIZE / 2 + 1;
    const PAID_LIST_FULL_MAJORITY: usize = PAID_LIST_CLOSE_GROUP_SIZE / 2 + 1;
    const FIRST_EDGE_INDEX: usize = PAID_LIST_INNER_GROUP_SIZE;
    const SECOND_EDGE_INDEX: usize = PAID_LIST_INNER_GROUP_SIZE + 1;
    const THIRD_EDGE_INDEX: usize = PAID_LIST_INNER_GROUP_SIZE + 2;
    const FOURTH_EDGE_INDEX: usize = PAID_LIST_INNER_GROUP_SIZE + 3;
    const REMOTE_PAID_PEERS_WITH_SELF_IN_GROUP: usize = PAID_LIST_CLOSE_GROUP_SIZE - 1;
    const REMOTE_EDGE_COUNT_WHEN_SELF_IN_CORE: usize = PAID_LIST_FLEX_EDGE_COUNT;
    const REMOTE_EDGE_COUNT_WHEN_SELF_ON_EDGE: usize = PAID_LIST_FLEX_EDGE_COUNT - 1;
    const SELF_EDGE_REMOTE_FULL_GROUP_SIZE: usize =
        PAID_LIST_INNER_GROUP_SIZE + REMOTE_EDGE_COUNT_WHEN_SELF_ON_EDGE;
    const SELF_EDGE_REMOTE_FULL_MAJORITY: usize = SELF_EDGE_REMOTE_FULL_GROUP_SIZE / 2 + 1;

    /// Build a `PeerId` from a single byte (zero-padded to 32 bytes).
    fn peer_id_from_byte(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    fn peer_id_from_usize(value: usize) -> PeerId {
        peer_id_from_byte(u8::try_from(value).expect("test peer id fits u8"))
    }

    /// Build an `XorName` from a single byte (repeated to 32 bytes).
    fn xor_name_from_byte(b: u8) -> XorName {
        [b; 32]
    }

    fn xor_name_from_usize(value: usize) -> XorName {
        let mut name = [0u8; 32];
        let bytes = u64::try_from(value)
            .expect("test value fits u64")
            .to_le_bytes();
        name[..bytes.len()].copy_from_slice(&bytes);
        name
    }

    fn paid_edge_targets_for_peers(paid_peers: &[PeerId]) -> HashSet<PeerId> {
        paid_peers[paid_peers.len().saturating_sub(PAID_LIST_FLEX_EDGE_COUNT)..]
            .iter()
            .copied()
            .collect()
    }

    fn paid_vote_evidence(
        paid_peers: &[PeerId],
        confirmed_indices: &[usize],
    ) -> Vec<(PeerId, PaidListEvidence)> {
        let confirmed_indices: HashSet<usize> = confirmed_indices.iter().copied().collect();
        paid_peers
            .iter()
            .enumerate()
            .map(|(idx, peer)| {
                (
                    *peer,
                    if confirmed_indices.contains(&idx) {
                        PaidListEvidence::Confirmed
                    } else {
                        PaidListEvidence::NotFound
                    },
                )
            })
            .collect()
    }

    fn paid_vote_evidence_with_unresolved(
        paid_peers: &[PeerId],
        confirmed_indices: &[usize],
        unresolved_indices: &[usize],
    ) -> Vec<(PeerId, PaidListEvidence)> {
        let confirmed_indices: HashSet<usize> = confirmed_indices.iter().copied().collect();
        let unresolved_indices: HashSet<usize> = unresolved_indices.iter().copied().collect();
        paid_peers
            .iter()
            .enumerate()
            .map(|(idx, peer)| {
                let status = if confirmed_indices.contains(&idx) {
                    PaidListEvidence::Confirmed
                } else if unresolved_indices.contains(&idx) {
                    PaidListEvidence::Unresolved
                } else {
                    PaidListEvidence::NotFound
                };
                (*peer, status)
            })
            .collect()
    }

    fn self_inclusive_paid_targets(
        key: &XorName,
        paid_peers: &[PeerId],
        remote_edge_count: usize,
    ) -> VerificationTargets {
        let mut targets = single_key_targets(key, vec![], paid_peers.to_vec());
        targets
            .paid_group_sizes
            .insert(*key, PAID_LIST_CLOSE_GROUP_SIZE);
        let edge_start = paid_peers.len().saturating_sub(remote_edge_count);
        targets
            .paid_edge_targets
            .insert(*key, paid_peers[edge_start..].iter().copied().collect());
        targets
    }

    /// Helper: build minimal `VerificationTargets` for a single key with
    /// explicit quorum and paid peer lists.
    fn single_key_targets(
        key: &XorName,
        quorum_peers: Vec<PeerId>,
        paid_peers: Vec<PeerId>,
    ) -> VerificationTargets {
        let mut all_peers = HashSet::new();
        let mut peer_to_keys: HashMap<PeerId, Vec<XorName>> = HashMap::new();
        let mut peer_to_paid_keys: HashMap<PeerId, HashSet<XorName>> = HashMap::new();

        for &p in &quorum_peers {
            all_peers.insert(p);
            peer_to_keys.entry(p).or_default().push(*key);
        }
        for &p in &paid_peers {
            all_peers.insert(p);
            peer_to_keys.entry(p).or_default().push(*key);
            peer_to_paid_keys.entry(p).or_default().insert(*key);
        }

        // Deduplicate keys per peer.
        for keys_list in peer_to_keys.values_mut() {
            keys_list.sort_unstable();
            keys_list.dedup();
        }

        let paid_group_size = paid_peers.len();
        let paid_edge_targets = paid_edge_targets_for_peers(&paid_peers);
        VerificationTargets {
            quorum_targets: std::iter::once((key.to_owned(), quorum_peers)).collect(),
            paid_group_sizes: std::iter::once((key.to_owned(), paid_group_size)).collect(),
            paid_targets: std::iter::once((key.to_owned(), paid_peers)).collect(),
            paid_edge_targets: std::iter::once((key.to_owned(), paid_edge_targets)).collect(),
            all_peers,
            peer_to_keys,
            peer_to_paid_keys,
        }
    }

    /// Helper: build `KeyVerificationEvidence` from presence and paid-list
    /// maps.
    fn build_evidence(
        presence: Vec<(PeerId, PresenceEvidence)>,
        paid_list: Vec<(PeerId, PaidListEvidence)>,
    ) -> KeyVerificationEvidence {
        KeyVerificationEvidence {
            presence: presence.into_iter().collect(),
            paid_list: paid_list.into_iter().collect(),
        }
    }

    #[test]
    fn present_sources_for_key_filters_targets_and_deduplicates() {
        let key = xor_name_from_byte(0x11);
        let q_present = peer_id_from_byte(1);
        let overlap = peer_id_from_byte(2);
        let q_absent = peer_id_from_byte(3);
        let q_unresolved = peer_id_from_byte(4);
        let paid_present = peer_id_from_byte(5);
        let paid_absent = peer_id_from_byte(6);
        let outside_target = peer_id_from_byte(7);

        let targets = single_key_targets(
            &key,
            vec![q_present, overlap, q_absent, q_unresolved],
            vec![overlap, paid_present, paid_absent],
        );
        let evidence = build_evidence(
            vec![
                (q_present, PresenceEvidence::Present),
                (overlap, PresenceEvidence::Present),
                (q_absent, PresenceEvidence::Absent),
                (q_unresolved, PresenceEvidence::Unresolved),
                (paid_present, PresenceEvidence::Present),
                (paid_absent, PresenceEvidence::Absent),
                (outside_target, PresenceEvidence::Present),
            ],
            vec![],
        );

        let sources = present_sources_for_key(&key, &evidence, &targets);

        assert_eq!(
            sources,
            vec![q_present, overlap, paid_present],
            "sources should preserve quorum-first order, de-duplicate overlap, and ignore non-target/negative evidence"
        );
    }

    // -----------------------------------------------------------------------
    // evaluate_key_evidence: QuorumVerified
    // -----------------------------------------------------------------------

    #[test]
    fn quorum_verified_with_enough_present_responses() {
        let key = xor_name_from_byte(0x10);
        let config = ReplicationConfig::default();

        // 7 quorum peers, threshold = min(4, floor(7/2)+1) = 4
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), vec![]);

        // 4 peers say Present, 3 say Absent.
        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Present),
                (quorum_peers[1], PresenceEvidence::Present),
                (quorum_peers[2], PresenceEvidence::Present),
                (quorum_peers[3], PresenceEvidence::Present),
                (quorum_peers[4], PresenceEvidence::Absent),
                (quorum_peers[5], PresenceEvidence::Absent),
                (quorum_peers[6], PresenceEvidence::Absent),
            ],
            vec![],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumVerified { ref sources } if sources.len() == 4),
            "expected QuorumVerified with 4 sources, got {outcome:?}"
        );
    }

    // -----------------------------------------------------------------------
    // v12 §6 holder-credit predicate downgrades uncredited peers
    // -----------------------------------------------------------------------

    #[test]
    fn quorum_downgrades_uncredited_present_peers() {
        // 7 quorum peers, threshold 4. 4 say Present, 3 say Absent —
        // would normally pass. But with a holder-credit predicate that
        // only credits 2 of them, presence_positive drops to 2 and the
        // 2 uncredited Presents become Unresolved. Total = 2 positive
        // + 2 unresolved + 3 absent = 5 valid → still possible →
        // QuorumInconclusive (not yet failed, but not verified either).
        let key = xor_name_from_byte(0x33);
        let config = ReplicationConfig::default();
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), vec![]);

        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Present),
                (quorum_peers[1], PresenceEvidence::Present),
                (quorum_peers[2], PresenceEvidence::Present),
                (quorum_peers[3], PresenceEvidence::Present),
                (quorum_peers[4], PresenceEvidence::Absent),
                (quorum_peers[5], PresenceEvidence::Absent),
                (quorum_peers[6], PresenceEvidence::Absent),
            ],
            vec![],
        );

        // Credit only the first two peers (the other two Presents are
        // uncredited and will be downgraded to Unresolved).
        let credit = |peer: &PeerId, _: &XorName| -> bool {
            *peer == quorum_peers[0] || *peer == quorum_peers[1]
        };
        let outcome =
            evaluate_key_evidence_with_holder_check(&key, &evidence, &targets, &config, credit);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumInconclusive),
            "credit downgrade should drop presence_positive below threshold, got {outcome:?}"
        );
    }

    #[test]
    fn quorum_passes_when_all_present_peers_are_credited() {
        let key = xor_name_from_byte(0x34);
        let config = ReplicationConfig::default();
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), vec![]);

        let evidence = build_evidence(
            (0..4)
                .map(|i| (quorum_peers[i], PresenceEvidence::Present))
                .chain((4..7).map(|i| (quorum_peers[i], PresenceEvidence::Absent)))
                .collect(),
            vec![],
        );

        let credit = |_: &PeerId, _: &XorName| -> bool { true };
        let outcome =
            evaluate_key_evidence_with_holder_check(&key, &evidence, &targets, &config, credit);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumVerified { .. }),
            "all-credited Present should pass quorum, got {outcome:?}"
        );
    }

    #[test]
    fn paid_list_path_unaffected_by_holder_credit() {
        // v12 §6: holder-credit gates Present claims, NOT paid-list
        // evidence (the paid-list lookup is the receiving peer's own
        // data, not a claim about K). A peer with no credit at all
        // can still contribute to paid-list majority.
        let key = xor_name_from_byte(0x35);
        let config = ReplicationConfig::default();
        let quorum_peers: Vec<PeerId> = (1..=3).map(peer_id_from_byte).collect();
        let paid_peers: Vec<PeerId> = (10..=14).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        let evidence = build_evidence(
            quorum_peers
                .iter()
                .map(|p| (*p, PresenceEvidence::Absent))
                .collect(),
            vec![
                (paid_peers[0], PaidListEvidence::Confirmed),
                (paid_peers[1], PaidListEvidence::Confirmed),
                (paid_peers[2], PaidListEvidence::Confirmed),
                (paid_peers[3], PaidListEvidence::NotFound),
                (paid_peers[4], PaidListEvidence::NotFound),
            ],
        );

        let credit = |_: &PeerId, _: &XorName| -> bool { false };
        let outcome =
            evaluate_key_evidence_with_holder_check(&key, &evidence, &targets, &config, credit);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "paid-list path must not be gated by holder-credit, got {outcome:?}"
        );
    }

    // -----------------------------------------------------------------------
    // evaluate_key_evidence: PaidListVerified
    // -----------------------------------------------------------------------

    #[test]
    fn paid_list_verified_with_enough_confirmations() {
        let key = xor_name_from_byte(0x20);
        let config = ReplicationConfig::default();

        // 5 paid peers, confirm_needed = floor(5/2)+1 = 3
        let paid_peers: Vec<PeerId> = (10..=14).map(peer_id_from_byte).collect();
        // No quorum peers (or quorum fails).
        let quorum_peers: Vec<PeerId> = (1..=3).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // Quorum: all Absent (fails presence path).
        // Paid: 3 Confirmed, 2 NotFound -> majority reached.
        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Absent),
                (quorum_peers[1], PresenceEvidence::Absent),
                (quorum_peers[2], PresenceEvidence::Absent),
            ],
            vec![
                (paid_peers[0], PaidListEvidence::Confirmed),
                (paid_peers[1], PaidListEvidence::Confirmed),
                (paid_peers[2], PaidListEvidence::Confirmed),
                (paid_peers[3], PaidListEvidence::NotFound),
                (paid_peers[4], PaidListEvidence::NotFound),
            ],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "expected PaidListVerified, got {outcome:?}"
        );
    }

    // -----------------------------------------------------------------------
    // evaluate_key_evidence: QuorumFailed
    // -----------------------------------------------------------------------

    #[test]
    fn quorum_failed_when_both_paths_impossible() {
        let key = xor_name_from_byte(0x30);
        let config = ReplicationConfig::default();

        // 5 quorum peers, quorum_needed = min(4, floor(5/2)+1) = min(4,3) = 3
        let quorum_peers: Vec<PeerId> = (1..=5).map(peer_id_from_byte).collect();
        // 3 paid peers, confirm_needed = floor(3/2)+1 = 2
        let paid_peers: Vec<PeerId> = (10..=12).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // Presence: all 5 Absent (0 positive, 0 unresolved) -> can't reach 3.
        // Paid: all 3 NotFound (0 confirmed, 0 unresolved) -> can't reach 2.
        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Absent),
                (quorum_peers[1], PresenceEvidence::Absent),
                (quorum_peers[2], PresenceEvidence::Absent),
                (quorum_peers[3], PresenceEvidence::Absent),
                (quorum_peers[4], PresenceEvidence::Absent),
            ],
            vec![
                (paid_peers[0], PaidListEvidence::NotFound),
                (paid_peers[1], PaidListEvidence::NotFound),
                (paid_peers[2], PaidListEvidence::NotFound),
            ],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumFailed),
            "expected QuorumFailed, got {outcome:?}"
        );
    }

    // -----------------------------------------------------------------------
    // evaluate_key_evidence: QuorumInconclusive
    // -----------------------------------------------------------------------

    #[test]
    fn quorum_inconclusive_with_unresolved_peers() {
        let key = xor_name_from_byte(0x40);
        let config = ReplicationConfig::default();

        // 5 quorum peers, quorum_needed = min(4, 3) = 3
        let quorum_peers: Vec<PeerId> = (1..=5).map(peer_id_from_byte).collect();
        // 3 paid peers, confirm_needed = 2
        let paid_peers: Vec<PeerId> = (10..=12).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // Presence: 2 Present, 1 Absent, 2 Unresolved.
        // positive=2, unresolved=2 -> 2+2=4 >= 3 -> quorum still possible.
        // Paid: 1 Confirmed, 1 Unresolved, 1 NotFound.
        // confirmed=1, unresolved=1 -> 1+1=2 >= 2 -> paid still possible.
        // Neither path reached yet -> Inconclusive.
        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Present),
                (quorum_peers[1], PresenceEvidence::Present),
                (quorum_peers[2], PresenceEvidence::Absent),
                (quorum_peers[3], PresenceEvidence::Unresolved),
                (quorum_peers[4], PresenceEvidence::Unresolved),
            ],
            vec![
                (paid_peers[0], PaidListEvidence::Confirmed),
                (paid_peers[1], PaidListEvidence::Unresolved),
                (paid_peers[2], PaidListEvidence::NotFound),
            ],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumInconclusive),
            "expected QuorumInconclusive, got {outcome:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Dynamic thresholds with undersized sets
    // -----------------------------------------------------------------------

    #[test]
    fn quorum_verified_with_undersized_quorum_targets() {
        let key = xor_name_from_byte(0x50);
        let config = ReplicationConfig::default();

        // Only 2 quorum peers (undersized).
        // quorum_needed = min(4, floor(2/2)+1) = min(4, 2) = 2
        let quorum_peers: Vec<PeerId> = (1..=2).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), vec![]);

        // Both Present -> 2 >= 2 -> QuorumVerified.
        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Present),
                (quorum_peers[1], PresenceEvidence::Present),
            ],
            vec![],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumVerified { ref sources } if sources.len() == 2),
            "expected QuorumVerified with 2 sources, got {outcome:?}"
        );
    }

    #[test]
    fn paid_list_verified_with_single_paid_peer() {
        let key = xor_name_from_byte(0x60);
        let config = ReplicationConfig::default();

        // 1 paid peer, confirm_needed = floor(1/2)+1 = 1
        let paid_peers = vec![peer_id_from_byte(10)];
        // No quorum targets -> quorum path impossible from the start.
        let targets = single_key_targets(&key, vec![], paid_peers.clone());

        let evidence = build_evidence(vec![], vec![(paid_peers[0], PaidListEvidence::Confirmed)]);

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "expected PaidListVerified with single peer, got {outcome:?}"
        );
    }

    #[test]
    fn paid_list_edge_notfound_votes_shrink_denominator_to_inner_group() {
        let key = xor_name_from_byte(0x61);
        let config = ReplicationConfig::default();

        let paid_peers: Vec<PeerId> = (1..=PAID_LIST_CLOSE_GROUP_SIZE)
            .map(peer_id_from_usize)
            .collect();
        let targets = single_key_targets(&key, vec![], paid_peers.clone());

        let below_threshold = build_evidence(
            vec![],
            paid_vote_evidence(&paid_peers, &[0, 1, 2, 3, 4, 5, 6, 7]),
        );
        let outcome = evaluate_key_evidence(&key, &below_threshold, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumFailed),
            "8/{PAID_LIST_INNER_GROUP_SIZE} paid confirmations must not authorize the key, got {outcome:?}"
        );

        let threshold_confirmed = build_evidence(
            vec![],
            paid_vote_evidence(
                &paid_peers,
                &(0..PAID_LIST_INNER_MAJORITY).collect::<Vec<_>>(),
            ),
        );
        let outcome = evaluate_key_evidence(&key, &threshold_confirmed, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "{PAID_LIST_INNER_MAJORITY}/{PAID_LIST_INNER_GROUP_SIZE} paid confirmations should authorize the key, got {outcome:?}"
        );
    }

    #[test]
    fn paid_list_positive_edge_votes_expand_denominator() {
        let key = xor_name_from_byte(0x62);
        let config = ReplicationConfig::default();

        let paid_peers: Vec<PeerId> = (1..=PAID_LIST_CLOSE_GROUP_SIZE)
            .map(peer_id_from_usize)
            .collect();
        let targets = single_key_targets(&key, vec![], paid_peers.clone());

        let one_edge_confirmed = build_evidence(
            vec![],
            paid_vote_evidence(&paid_peers, &[0, 1, 2, 3, 4, 5, 6, 7, THIRD_EDGE_INDEX]),
        );
        let outcome = evaluate_key_evidence(&key, &one_edge_confirmed, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "{PAID_LIST_ONE_EDGE_MAJORITY}/{PAID_LIST_ONE_EDGE_GROUP_SIZE} paid confirmations should authorize the key, got {outcome:?}"
        );

        let ten_with_all_edges = build_evidence(
            vec![],
            paid_vote_evidence(
                &paid_peers,
                &[
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    FIRST_EDGE_INDEX,
                    SECOND_EDGE_INDEX,
                    THIRD_EDGE_INDEX,
                    FOURTH_EDGE_INDEX,
                ],
            ),
        );
        let outcome = evaluate_key_evidence(&key, &ten_with_all_edges, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumFailed),
            "10/{PAID_LIST_CLOSE_GROUP_SIZE} paid confirmations must not authorize when all edge peers are positive, got {outcome:?}"
        );

        let eleven_with_all_edges = build_evidence(
            vec![],
            paid_vote_evidence(
                &paid_peers,
                &[
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    FIRST_EDGE_INDEX,
                    SECOND_EDGE_INDEX,
                    THIRD_EDGE_INDEX,
                    FOURTH_EDGE_INDEX,
                ],
            ),
        );
        let outcome = evaluate_key_evidence(&key, &eleven_with_all_edges, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "{PAID_LIST_FULL_MAJORITY}/{PAID_LIST_CLOSE_GROUP_SIZE} paid confirmations should authorize when all edge peers are positive, got {outcome:?}"
        );
    }

    #[test]
    fn paid_list_self_inclusive_missing_core_keeps_inner_threshold() {
        let key = xor_name_from_byte(0x63);
        let config = ReplicationConfig::default();
        let paid_peers: Vec<PeerId> = (1..=REMOTE_PAID_PEERS_WITH_SELF_IN_GROUP)
            .map(peer_id_from_usize)
            .collect();
        let targets =
            self_inclusive_paid_targets(&key, &paid_peers, REMOTE_EDGE_COUNT_WHEN_SELF_IN_CORE);

        let below_threshold = build_evidence(
            vec![],
            paid_vote_evidence(&paid_peers, &[0, 1, 2, 3, 4, 5, 6, 7]),
        );
        let outcome = evaluate_key_evidence(&key, &below_threshold, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumFailed),
            "8/{PAID_LIST_INNER_GROUP_SIZE} should fail when self is a missing core voter, got {outcome:?}"
        );

        let threshold_confirmed = build_evidence(
            vec![],
            paid_vote_evidence(
                &paid_peers,
                &(0..PAID_LIST_INNER_MAJORITY).collect::<Vec<_>>(),
            ),
        );
        let outcome = evaluate_key_evidence(&key, &threshold_confirmed, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "{PAID_LIST_INNER_MAJORITY}/{PAID_LIST_INNER_GROUP_SIZE} should pass when self is a missing core voter, got {outcome:?}"
        );
    }

    #[test]
    fn paid_list_self_inclusive_missing_edge_discounts_self_edge_only_when_negative() {
        let key = xor_name_from_byte(0x64);
        let config = ReplicationConfig::default();
        let paid_peers: Vec<PeerId> = (1..=REMOTE_PAID_PEERS_WITH_SELF_IN_GROUP)
            .map(peer_id_from_usize)
            .collect();
        let targets =
            self_inclusive_paid_targets(&key, &paid_peers, REMOTE_EDGE_COUNT_WHEN_SELF_ON_EDGE);

        let inner_threshold_confirmed = build_evidence(
            vec![],
            paid_vote_evidence(
                &paid_peers,
                &(0..PAID_LIST_INNER_MAJORITY).collect::<Vec<_>>(),
            ),
        );
        let outcome = evaluate_key_evidence(&key, &inner_threshold_confirmed, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "{PAID_LIST_INNER_MAJORITY}/{PAID_LIST_INNER_GROUP_SIZE} should pass when self is a missing edge voter, got {outcome:?}"
        );

        let all_remote_edges_below = build_evidence(
            vec![],
            paid_vote_evidence(
                &paid_peers,
                &[
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    PAID_LIST_INNER_GROUP_SIZE,
                    PAID_LIST_INNER_GROUP_SIZE + 1,
                    PAID_LIST_INNER_GROUP_SIZE + 2,
                ],
            ),
        );
        let outcome = evaluate_key_evidence(&key, &all_remote_edges_below, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumFailed),
            "9/{SELF_EDGE_REMOTE_FULL_GROUP_SIZE} should fail when all remote edge peers are positive but self-edge is missing, got {outcome:?}"
        );

        let all_remote_edges_threshold = build_evidence(
            vec![],
            paid_vote_evidence(
                &paid_peers,
                &[
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    PAID_LIST_INNER_GROUP_SIZE,
                    PAID_LIST_INNER_GROUP_SIZE + 1,
                    PAID_LIST_INNER_GROUP_SIZE + 2,
                ],
            ),
        );
        let outcome = evaluate_key_evidence(&key, &all_remote_edges_threshold, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "{SELF_EDGE_REMOTE_FULL_MAJORITY}/{SELF_EDGE_REMOTE_FULL_GROUP_SIZE} should pass when all remote edge peers are positive but self-edge is missing, got {outcome:?}"
        );
    }

    #[test]
    fn paid_list_unresolved_core_or_edge_keeps_possible_round_inconclusive() {
        let key = xor_name_from_byte(0x65);
        let config = ReplicationConfig::default();
        let paid_peers: Vec<PeerId> = (1..=PAID_LIST_CLOSE_GROUP_SIZE)
            .map(peer_id_from_usize)
            .collect();
        let targets = single_key_targets(&key, vec![], paid_peers.clone());

        let unresolved_core = build_evidence(
            vec![],
            paid_vote_evidence_with_unresolved(&paid_peers, &[0, 1, 2, 3, 4, 5, 6, 7], &[8]),
        );
        let outcome = evaluate_key_evidence(&key, &unresolved_core, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumInconclusive),
            "8 confirmed plus one unresolved core voter can still become 9/{PAID_LIST_INNER_GROUP_SIZE}, got {outcome:?}"
        );

        let unresolved_edge = build_evidence(
            vec![],
            paid_vote_evidence_with_unresolved(
                &paid_peers,
                &[0, 1, 2, 3, 4, 5, 6, 7],
                &[FIRST_EDGE_INDEX],
            ),
        );
        let outcome = evaluate_key_evidence(&key, &unresolved_edge, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumInconclusive),
            "8 confirmed plus one unresolved edge voter can still become 9/{PAID_LIST_ONE_EDGE_GROUP_SIZE}, got {outcome:?}"
        );
    }

    #[test]
    fn production_paid_list_vote_authorizes_when_storage_majority_missing() {
        const PRODUCTION_PAID_GROUP: u8 = 20;
        const STORAGE_HOLDERS_BELOW_QUORUM: usize = 3;
        const PAID_CONFIRMATIONS_NEEDED: usize = 11;
        const PAID_PEER_OFFSET: u8 = 30;

        let key = xor_name_from_byte(0x62);
        let config = ReplicationConfig::default();

        let quorum_peers: Vec<PeerId> =
            (1..=PRODUCTION_PAID_GROUP).map(peer_id_from_byte).collect();
        let paid_peers: Vec<PeerId> = (1..=PRODUCTION_PAID_GROUP)
            .map(|i| peer_id_from_byte(PAID_PEER_OFFSET + i))
            .collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        let presence = quorum_peers
            .iter()
            .enumerate()
            .map(|(i, peer)| {
                (
                    *peer,
                    if i < STORAGE_HOLDERS_BELOW_QUORUM {
                        PresenceEvidence::Present
                    } else {
                        PresenceEvidence::Absent
                    },
                )
            })
            .collect();
        let paid_list = paid_peers
            .iter()
            .enumerate()
            .map(|(i, peer)| {
                (
                    *peer,
                    if i < PAID_CONFIRMATIONS_NEEDED {
                        PaidListEvidence::Confirmed
                    } else {
                        PaidListEvidence::NotFound
                    },
                )
            })
            .collect();
        let evidence = build_evidence(presence, paid_list);

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);

        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { ref sources } if sources.len() == STORAGE_HOLDERS_BELOW_QUORUM),
            "11/20 paid-list confirmations must authorize repair despite only 3 storage holders, got {outcome:?}"
        );
    }

    #[test]
    fn quorum_fails_with_zero_targets_no_paid() {
        let key = xor_name_from_byte(0x70);
        let config = ReplicationConfig::default();

        // No quorum peers, no paid peers.
        // quorum_needed(0) = min(4, 1) = 1, but 0 positive + 0 unresolved < 1.
        // confirm_needed(0) = 1, but 0 confirmed + 0 unresolved < 1.
        let targets = single_key_targets(&key, vec![], vec![]);

        let evidence = build_evidence(vec![], vec![]);

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumFailed),
            "expected QuorumFailed with zero targets, got {outcome:?}"
        );
    }

    #[test]
    fn quorum_verified_beats_paid_list_when_both_satisfied() {
        // When both presence quorum AND paid-list majority are satisfied,
        // QuorumVerified takes precedence (evaluated first).
        let key = xor_name_from_byte(0x80);
        let config = ReplicationConfig::default();

        let quorum_peers: Vec<PeerId> = (1..=5).map(peer_id_from_byte).collect();
        let paid_peers: Vec<PeerId> = (10..=12).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // quorum_needed(5) = min(4, 3) = 3; all 5 Present -> quorum met.
        // confirm_needed(3) = 2; all 3 Confirmed -> paid met.
        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Present),
                (quorum_peers[1], PresenceEvidence::Present),
                (quorum_peers[2], PresenceEvidence::Present),
                (quorum_peers[3], PresenceEvidence::Present),
                (quorum_peers[4], PresenceEvidence::Present),
            ],
            vec![
                (paid_peers[0], PaidListEvidence::Confirmed),
                (paid_peers[1], PaidListEvidence::Confirmed),
                (paid_peers[2], PaidListEvidence::Confirmed),
            ],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumVerified { .. }),
            "QuorumVerified should take precedence over PaidListVerified, got {outcome:?}"
        );
    }

    // -----------------------------------------------------------------------
    // process_verification_response
    // -----------------------------------------------------------------------

    #[test]
    fn process_response_populates_evidence() {
        let key = xor_name_from_byte(0x90);
        let peer = peer_id_from_byte(1);

        let targets = single_key_targets(&key, vec![peer], vec![peer]);

        let mut evidence: HashMap<XorName, KeyVerificationEvidence> = std::iter::once((
            key,
            KeyVerificationEvidence {
                presence: HashMap::new(),
                paid_list: HashMap::new(),
            },
        ))
        .collect();

        let response = VerificationResponse {
            results: vec![KeyVerificationResult {
                key,
                present: true,
                paid: Some(true),
            }],
        };

        process_verification_response(&peer, &response, &targets, &mut evidence);

        let ev = evidence.get(&key).expect("evidence for key");
        assert_eq!(
            ev.presence.get(&peer),
            Some(&PresenceEvidence::Present),
            "presence should be Present"
        );
        assert_eq!(
            ev.paid_list.get(&peer),
            Some(&PaidListEvidence::Confirmed),
            "paid_list should be Confirmed"
        );
    }

    #[test]
    fn process_response_missing_key_gets_unresolved() {
        let key = xor_name_from_byte(0xA0);
        let peer = peer_id_from_byte(2);

        let targets = single_key_targets(&key, vec![peer], vec![peer]);

        let mut evidence: HashMap<XorName, KeyVerificationEvidence> = std::iter::once((
            key,
            KeyVerificationEvidence {
                presence: HashMap::new(),
                paid_list: HashMap::new(),
            },
        ))
        .collect();

        // Empty response: peer did not include our key.
        let response = VerificationResponse { results: vec![] };

        process_verification_response(&peer, &response, &targets, &mut evidence);

        let ev = evidence.get(&key).expect("evidence for key");
        assert_eq!(
            ev.presence.get(&peer),
            Some(&PresenceEvidence::Unresolved),
            "missing key in response should be Unresolved"
        );
        assert_eq!(
            ev.paid_list.get(&peer),
            Some(&PaidListEvidence::Unresolved),
            "missing paid key in response should be Unresolved"
        );
    }

    #[test]
    fn process_response_ignores_unsolicited_keys() {
        let key = xor_name_from_byte(0xB0);
        let unsolicited_key = xor_name_from_byte(0xB1);
        let peer = peer_id_from_byte(3);

        let targets = single_key_targets(&key, vec![peer], vec![]);

        let mut evidence: HashMap<XorName, KeyVerificationEvidence> = std::iter::once((
            key,
            KeyVerificationEvidence {
                presence: HashMap::new(),
                paid_list: HashMap::new(),
            },
        ))
        .collect();

        // Response includes an unsolicited key.
        let response = VerificationResponse {
            results: vec![
                KeyVerificationResult {
                    key: unsolicited_key,
                    present: true,
                    paid: None,
                },
                KeyVerificationResult {
                    key,
                    present: false,
                    paid: None,
                },
            ],
        };

        process_verification_response(&peer, &response, &targets, &mut evidence);

        // Unsolicited key should not appear in evidence.
        assert!(
            !evidence.contains_key(&unsolicited_key),
            "unsolicited key should not be in evidence"
        );

        let ev = evidence.get(&key).expect("evidence for key");
        assert_eq!(
            ev.presence.get(&peer),
            Some(&PresenceEvidence::Absent),
            "solicited key should have Absent"
        );
    }

    #[test]
    fn process_response_ignores_unsolicited_paid_status() {
        let key = xor_name_from_byte(0xB2);
        let peer = peer_id_from_byte(4);

        let targets = single_key_targets(&key, vec![peer], vec![]);

        let mut evidence: HashMap<XorName, KeyVerificationEvidence> = std::iter::once((
            key,
            KeyVerificationEvidence {
                presence: HashMap::new(),
                paid_list: HashMap::new(),
            },
        ))
        .collect();

        let response = VerificationResponse {
            results: vec![KeyVerificationResult {
                key,
                present: true,
                paid: Some(true),
            }],
        };

        process_verification_response(&peer, &response, &targets, &mut evidence);

        let ev = evidence.get(&key).expect("evidence for key");
        assert_eq!(ev.presence.get(&peer), Some(&PresenceEvidence::Present));
        assert!(
            !ev.paid_list.contains_key(&peer),
            "paid evidence must be recorded only for requested paid-list checks"
        );
    }

    #[test]
    fn process_batch_response_marks_only_batch_keys_unresolved() {
        let key_a = xor_name_from_byte(0xB3);
        let key_b = xor_name_from_byte(0xB4);
        let peer = peer_id_from_byte(6);

        let targets = VerificationTargets {
            quorum_targets: [(key_a, vec![peer]), (key_b, vec![peer])]
                .into_iter()
                .collect(),
            paid_targets: [(key_a, vec![peer]), (key_b, vec![peer])]
                .into_iter()
                .collect(),
            paid_group_sizes: [(key_a, 1), (key_b, 1)].into_iter().collect(),
            paid_edge_targets: [
                (key_a, std::iter::once(peer).collect()),
                (key_b, std::iter::once(peer).collect()),
            ]
            .into_iter()
            .collect(),
            all_peers: std::iter::once(peer).collect(),
            peer_to_keys: std::iter::once((peer, vec![key_a, key_b])).collect(),
            peer_to_paid_keys: std::iter::once((
                peer,
                [key_a, key_b].into_iter().collect::<HashSet<_>>(),
            ))
            .collect(),
        };
        let mut evidence: HashMap<XorName, KeyVerificationEvidence> = [
            (
                key_a,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            ),
            (
                key_b,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            ),
        ]
        .into_iter()
        .collect();

        process_verification_response_for_keys(
            &peer,
            &[key_a],
            &VerificationResponse {
                results: Vec::new(),
            },
            &targets,
            &mut evidence,
        );

        let ev_a = evidence.get(&key_a).expect("evidence for key_a");
        assert_eq!(
            ev_a.presence.get(&peer),
            Some(&PresenceEvidence::Unresolved)
        );
        assert_eq!(
            ev_a.paid_list.get(&peer),
            Some(&PaidListEvidence::Unresolved)
        );

        let ev_b = evidence.get(&key_b).expect("evidence for key_b");
        assert!(
            !ev_b.presence.contains_key(&peer),
            "keys outside the failed batch must wait for their own batch result"
        );
        assert!(
            !ev_b.paid_list.contains_key(&peer),
            "paid status outside the failed batch must not be prefilled"
        );
    }

    #[test]
    fn verification_requests_for_peer_splits_large_batches_and_rebases_paid_indices() {
        let keys: Vec<XorName> = (0..=MAX_VERIFICATION_KEYS_PER_REQUEST)
            .map(xor_name_from_usize)
            .collect();
        let paid_keys: HashSet<XorName> = [keys[0], keys[MAX_VERIFICATION_KEYS_PER_REQUEST]]
            .into_iter()
            .collect();

        let requests = verification_requests_for_peer(&keys, Some(&paid_keys));

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].keys.len(), MAX_VERIFICATION_KEYS_PER_REQUEST);
        assert_eq!(requests[0].paid_list_check_indices, vec![0]);
        assert_eq!(
            requests[1].keys,
            vec![keys[MAX_VERIFICATION_KEYS_PER_REQUEST]]
        );
        assert_eq!(requests[1].paid_list_check_indices, vec![0]);
    }

    // -----------------------------------------------------------------------
    // mark_peer_unresolved
    // -----------------------------------------------------------------------

    #[test]
    fn mark_unresolved_sets_all_keys_for_peer() {
        let key_a = xor_name_from_byte(0xC0);
        let key_b = xor_name_from_byte(0xC1);
        let peer = peer_id_from_byte(5);

        // Peer is a quorum target for key_a and a paid target for key_b.
        let targets = VerificationTargets {
            quorum_targets: std::iter::once((key_a, vec![peer])).collect(),
            paid_targets: std::iter::once((key_b, vec![peer])).collect(),
            paid_group_sizes: [(key_a, 0), (key_b, 1)].into_iter().collect(),
            paid_edge_targets: std::iter::once((key_b, std::iter::once(peer).collect())).collect(),
            all_peers: std::iter::once(peer).collect(),
            peer_to_keys: std::iter::once((peer, vec![key_a, key_b])).collect(),
            peer_to_paid_keys: std::iter::once((peer, std::iter::once(key_b).collect())).collect(),
        };

        let mut evidence: HashMap<XorName, KeyVerificationEvidence> = [
            (
                key_a,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            ),
            (
                key_b,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            ),
        ]
        .into_iter()
        .collect();

        mark_peer_unresolved(&peer, &targets, &mut evidence);

        let ev_a = evidence.get(&key_a).expect("evidence for key_a");
        assert_eq!(
            ev_a.presence.get(&peer),
            Some(&PresenceEvidence::Unresolved)
        );
        // key_a is not in peer_to_paid_keys, so no paid_list entry.
        assert!(!ev_a.paid_list.contains_key(&peer));

        let ev_b = evidence.get(&key_b).expect("evidence for key_b");
        assert_eq!(
            ev_b.presence.get(&peer),
            Some(&PresenceEvidence::Unresolved)
        );
        assert_eq!(
            ev_b.paid_list.get(&peer),
            Some(&PaidListEvidence::Unresolved)
        );
    }

    // -----------------------------------------------------------------------
    // Section 18 scenarios
    // -----------------------------------------------------------------------

    /// Scenario 4: All peers respond Absent with no paid confirmations.
    /// Both presence and paid-list paths are impossible -> `QuorumFailed`.
    #[test]
    fn scenario_4_quorum_fail_transitions_to_abandoned() {
        let key = xor_name_from_byte(0xD0);
        let config = ReplicationConfig::default();

        // 7 quorum peers, threshold = min(4, floor(7/2)+1) = 4
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        // 5 paid peers, confirm_needed = floor(5/2)+1 = 3
        let paid_peers: Vec<PeerId> = (10..=14).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // All quorum peers respond Absent, all paid peers respond NotFound.
        let evidence = build_evidence(
            quorum_peers
                .iter()
                .map(|p| (*p, PresenceEvidence::Absent))
                .collect(),
            paid_peers
                .iter()
                .map(|p| (*p, PaidListEvidence::NotFound))
                .collect(),
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumFailed),
            "all-Absent with no paid confirmations should yield QuorumFailed, got {outcome:?}"
        );
    }

    /// Scenario 16: All peers unresolved (timeout). Neither success nor
    /// fail-fast is possible because unresolved counts keep both paths alive.
    #[test]
    fn scenario_16_timeout_yields_inconclusive() {
        let key = xor_name_from_byte(0xD1);
        let config = ReplicationConfig::default();

        // 7 quorum peers, quorum_needed = 4
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        // 5 paid peers, confirm_needed = 3
        let paid_peers: Vec<PeerId> = (10..=14).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // Every peer is Unresolved (simulating full timeout).
        let evidence = build_evidence(
            quorum_peers
                .iter()
                .map(|p| (*p, PresenceEvidence::Unresolved))
                .collect(),
            paid_peers
                .iter()
                .map(|p| (*p, PaidListEvidence::Unresolved))
                .collect(),
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumInconclusive),
            "all-unresolved should yield QuorumInconclusive, got {outcome:?}"
        );
    }

    /// Scenario 27: A single verification round collects both presence
    /// evidence from `QuorumTargets` and paid-list confirmations from
    /// `PaidTargets`. Paid-list success triggers `PaidListVerified` even when
    /// presence quorum fails.
    #[test]
    fn scenario_27_single_round_collects_both_presence_and_paid() {
        let key = xor_name_from_byte(0xD2);
        let config = ReplicationConfig::default();

        // 7 quorum peers: only 1 Present (quorum_needed=4, so quorum fails).
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        // 5 paid peers: 3 Confirmed (confirm_needed=3, so paid passes).
        let paid_peers: Vec<PeerId> = (10..=14).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Present),
                (quorum_peers[1], PresenceEvidence::Absent),
                (quorum_peers[2], PresenceEvidence::Absent),
                (quorum_peers[3], PresenceEvidence::Absent),
                (quorum_peers[4], PresenceEvidence::Absent),
                (quorum_peers[5], PresenceEvidence::Absent),
                (quorum_peers[6], PresenceEvidence::Absent),
            ],
            vec![
                (paid_peers[0], PaidListEvidence::Confirmed),
                (paid_peers[1], PaidListEvidence::Confirmed),
                (paid_peers[2], PaidListEvidence::Confirmed),
                (paid_peers[3], PaidListEvidence::NotFound),
                (paid_peers[4], PaidListEvidence::NotFound),
            ],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "paid-list majority should trigger PaidListVerified when quorum fails, got {outcome:?}"
        );
    }

    /// Scenario 28: With |QuorumTargets|=3,
    /// `QuorumNeeded` = min(4, floor(3/2)+1) = min(4, 2) = 2.
    /// 2 Present responses should pass.
    #[test]
    fn scenario_28_dynamic_threshold_with_3_targets() {
        let key = xor_name_from_byte(0xD3);
        let config = ReplicationConfig::default();

        let quorum_peers: Vec<PeerId> = (1..=3).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), vec![]);

        // Verify the dynamic threshold is indeed 2.
        assert_eq!(config.quorum_needed(3), 2, "quorum_needed(3) should be 2");

        // 2 Present, 1 Absent -> 2 >= 2 -> QuorumVerified.
        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Present),
                (quorum_peers[1], PresenceEvidence::Present),
                (quorum_peers[2], PresenceEvidence::Absent),
            ],
            vec![],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumVerified { ref sources } if sources.len() == 2),
            "2 Present in 3-target set should QuorumVerify, got {outcome:?}"
        );
    }

    /// Helper: build `VerificationTargets` for two keys with shared or
    /// separate peer sets.
    fn two_key_targets(
        key_a: &XorName,
        key_b: &XorName,
        quorum_peers_a: Vec<PeerId>,
        quorum_peers_b: Vec<PeerId>,
        paid_peers_a: Vec<PeerId>,
        paid_peers_b: Vec<PeerId>,
    ) -> VerificationTargets {
        let mut all_peers = HashSet::new();
        let mut peer_to_keys: HashMap<PeerId, Vec<XorName>> = HashMap::new();
        let mut peer_to_paid_keys: HashMap<PeerId, HashSet<XorName>> = HashMap::new();

        for &p in &quorum_peers_a {
            all_peers.insert(p);
            peer_to_keys.entry(p).or_default().push(*key_a);
        }
        for &p in &quorum_peers_b {
            all_peers.insert(p);
            peer_to_keys.entry(p).or_default().push(*key_b);
        }
        for &p in &paid_peers_a {
            all_peers.insert(p);
            peer_to_keys.entry(p).or_default().push(*key_a);
            peer_to_paid_keys.entry(p).or_default().insert(*key_a);
        }
        for &p in &paid_peers_b {
            all_peers.insert(p);
            peer_to_keys.entry(p).or_default().push(*key_b);
            peer_to_paid_keys.entry(p).or_default().insert(*key_b);
        }

        for keys_list in peer_to_keys.values_mut() {
            keys_list.sort_unstable();
            keys_list.dedup();
        }

        let mut quorum_targets = HashMap::new();
        quorum_targets.insert(*key_a, quorum_peers_a);
        quorum_targets.insert(*key_b, quorum_peers_b);

        let mut paid_targets = HashMap::new();
        let paid_group_size_a = paid_peers_a.len();
        let paid_group_size_b = paid_peers_b.len();
        let paid_edge_targets_a = paid_edge_targets_for_peers(&paid_peers_a);
        let paid_edge_targets_b = paid_edge_targets_for_peers(&paid_peers_b);
        paid_targets.insert(*key_a, paid_peers_a);
        paid_targets.insert(*key_b, paid_peers_b);

        VerificationTargets {
            quorum_targets,
            paid_targets,
            paid_group_sizes: [(*key_a, paid_group_size_a), (*key_b, paid_group_size_b)]
                .into_iter()
                .collect(),
            paid_edge_targets: [(*key_a, paid_edge_targets_a), (*key_b, paid_edge_targets_b)]
                .into_iter()
                .collect(),
            all_peers,
            peer_to_keys,
            peer_to_paid_keys,
        }
    }

    /// Scenario 33: `process_verification_response` correctly attributes
    /// per-key evidence when a single peer responds for multiple keys.
    #[test]
    fn scenario_33_batched_response_per_key_evidence() {
        let key_a = xor_name_from_byte(0xD4);
        let key_b = xor_name_from_byte(0xD5);
        let peer = peer_id_from_byte(1);

        // Peer is a quorum+paid target for both keys.
        let targets = two_key_targets(
            &key_a,
            &key_b,
            vec![peer],
            vec![peer],
            vec![peer],
            vec![peer],
        );

        let mut evidence: HashMap<XorName, KeyVerificationEvidence> = [
            (
                key_a,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            ),
            (
                key_b,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            ),
        ]
        .into_iter()
        .collect();

        // Peer responds: key_a Present+Confirmed, key_b Absent+NotFound.
        let response = VerificationResponse {
            results: vec![
                KeyVerificationResult {
                    key: key_a,
                    present: true,
                    paid: Some(true),
                },
                KeyVerificationResult {
                    key: key_b,
                    present: false,
                    paid: Some(false),
                },
            ],
        };

        process_verification_response(&peer, &response, &targets, &mut evidence);

        // key_a: Present + Confirmed.
        let ev_a = evidence.get(&key_a).expect("evidence for key_a");
        assert_eq!(ev_a.presence.get(&peer), Some(&PresenceEvidence::Present));
        assert_eq!(
            ev_a.paid_list.get(&peer),
            Some(&PaidListEvidence::Confirmed)
        );

        // key_b: Absent + NotFound.
        let ev_b = evidence.get(&key_b).expect("evidence for key_b");
        assert_eq!(ev_b.presence.get(&peer), Some(&PresenceEvidence::Absent));
        assert_eq!(ev_b.paid_list.get(&peer), Some(&PaidListEvidence::NotFound));
    }

    /// Scenario 34: Peer responds for `key_a` but omits `key_b`.
    /// `key_a` gets explicit evidence, `key_b` gets Unresolved.
    #[test]
    fn scenario_34_partial_response_unresolved_per_key() {
        let key_a = xor_name_from_byte(0xD6);
        let key_b = xor_name_from_byte(0xD7);
        let peer = peer_id_from_byte(2);

        // Peer is a quorum target for both keys, paid target for key_b only.
        let targets = two_key_targets(&key_a, &key_b, vec![peer], vec![peer], vec![], vec![peer]);

        let mut evidence: HashMap<XorName, KeyVerificationEvidence> = [
            (
                key_a,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            ),
            (
                key_b,
                KeyVerificationEvidence {
                    presence: HashMap::new(),
                    paid_list: HashMap::new(),
                },
            ),
        ]
        .into_iter()
        .collect();

        // Peer responds only for key_a, omits key_b entirely.
        let response = VerificationResponse {
            results: vec![KeyVerificationResult {
                key: key_a,
                present: true,
                paid: None,
            }],
        };

        process_verification_response(&peer, &response, &targets, &mut evidence);

        // key_a: explicit Present.
        let ev_a = evidence.get(&key_a).expect("evidence for key_a");
        assert_eq!(
            ev_a.presence.get(&peer),
            Some(&PresenceEvidence::Present),
            "key_a should have explicit Present"
        );

        // key_b: missing from response -> Unresolved for both presence and
        // paid_list.
        let ev_b = evidence.get(&key_b).expect("evidence for key_b");
        assert_eq!(
            ev_b.presence.get(&peer),
            Some(&PresenceEvidence::Unresolved),
            "omitted key_b should get Unresolved presence"
        );
        assert_eq!(
            ev_b.paid_list.get(&peer),
            Some(&PaidListEvidence::Unresolved),
            "omitted key_b (paid target) should get Unresolved paid_list"
        );
    }

    /// Scenario 42: `QuorumVerified` outcome populates sources correctly,
    /// which downstream uses to add the key to `PaidForList`.
    #[test]
    fn scenario_42_quorum_pass_derives_paid_list_auth() {
        let key = xor_name_from_byte(0xD8);
        let config = ReplicationConfig::default();

        // 5 quorum peers, quorum_needed = min(4, 3) = 3.
        let quorum_peers: Vec<PeerId> = (1..=5).map(peer_id_from_byte).collect();
        // 3 paid peers (some overlap with quorum peers for realistic scenario).
        let paid_peers: Vec<PeerId> = (3..=5).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // 4 quorum peers Present, 1 Absent -> quorum met.
        // Also mark paid_peers[0] (peer 3) as Present so it's collected from
        // paid targets too.
        let evidence = build_evidence(
            vec![
                (quorum_peers[0], PresenceEvidence::Present),
                (quorum_peers[1], PresenceEvidence::Present),
                (quorum_peers[2], PresenceEvidence::Present), // peer 3
                (quorum_peers[3], PresenceEvidence::Present), // peer 4
                (quorum_peers[4], PresenceEvidence::Absent),  // peer 5
            ],
            vec![
                (paid_peers[0], PaidListEvidence::NotFound),
                (paid_peers[1], PaidListEvidence::NotFound),
                (paid_peers[2], PaidListEvidence::NotFound),
            ],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        match outcome {
            KeyVerificationOutcome::QuorumVerified { ref sources } => {
                // Sources should include peers that responded Present from
                // both quorum and paid targets.
                assert!(
                    sources.len() >= 4,
                    "QuorumVerified sources should contain at least the 4 quorum-positive peers, got {}",
                    sources.len()
                );
                // The sources list is used downstream to authorize
                // PaidForList insertion. Verify specific peers are present.
                assert!(
                    sources.contains(&quorum_peers[0]),
                    "source peer 1 should be in sources"
                );
                assert!(
                    sources.contains(&quorum_peers[1]),
                    "source peer 2 should be in sources"
                );
            }
            other => panic!("expected QuorumVerified, got {other:?}"),
        }
    }

    /// Scenario 44: Paid-list cold-start recovery via replica majority.
    ///
    /// Multiple nodes restart simultaneously and lose their `PaidForList`
    /// (persistence corrupted). Key `K` still has `>= QuorumNeeded(K)`
    /// replicas in the close group. During neighbor-sync verification,
    /// presence quorum passes and all verifying nodes re-derive `K` into
    /// their `PaidForList` via close-group replica majority (Section 7.2
    /// rule 4).
    ///
    /// This test verifies that when paid-list evidence is entirely
    /// `NotFound` (simulating data loss) but presence evidence meets
    /// quorum, the outcome is `QuorumVerified` with sources that enable
    /// `PaidForList` re-derivation.
    #[test]
    fn scenario_44_cold_start_recovery_via_replica_majority() {
        let key = xor_name_from_byte(0xD9);
        let config = ReplicationConfig::default();

        // 7 quorum peers, quorum_needed = min(4, floor(7/2)+1) = 4.
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        // 10 paid peers (wider group), confirm_needed = floor(10/2)+1 = 6.
        let paid_peers: Vec<PeerId> = (10..=19).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // Cold-start scenario: ALL paid-list entries are lost across every
        // peer in PaidCloseGroup. Every paid peer reports NotFound.
        let paid_evidence: Vec<(PeerId, PaidListEvidence)> = paid_peers
            .iter()
            .map(|p| (*p, PaidListEvidence::NotFound))
            .collect();

        // But the replicas still exist: 5 out of 7 quorum peers report
        // Present (>= QuorumNeeded(K) = 4).
        let presence_evidence = vec![
            (quorum_peers[0], PresenceEvidence::Present),
            (quorum_peers[1], PresenceEvidence::Present),
            (quorum_peers[2], PresenceEvidence::Present),
            (quorum_peers[3], PresenceEvidence::Present),
            (quorum_peers[4], PresenceEvidence::Present),
            (quorum_peers[5], PresenceEvidence::Absent),
            (quorum_peers[6], PresenceEvidence::Absent),
        ];

        let evidence = build_evidence(presence_evidence, paid_evidence);
        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);

        match outcome {
            KeyVerificationOutcome::QuorumVerified { ref sources } => {
                // Quorum passed despite total paid-list loss. The caller
                // re-derives PaidForList from close-group replica majority.
                assert!(
                    sources.len() >= 4,
                    "QuorumVerified should have >= 4 sources (the presence-positive peers), got {}",
                    sources.len()
                );

                // Verify the specific Present peers are in sources.
                for (i, peer) in quorum_peers.iter().enumerate().take(5) {
                    assert!(
                        sources.contains(peer),
                        "quorum_peer[{i}] responded Present and should be a fetch source"
                    );
                }

                // Absent peers are NOT sources.
                assert!(
                    !sources.contains(&quorum_peers[5]),
                    "absent peer should not be a fetch source"
                );
                assert!(
                    !sources.contains(&quorum_peers[6]),
                    "absent peer should not be a fetch source"
                );
            }
            other => panic!(
                "Cold-start recovery should succeed via replica majority \
                 (QuorumVerified), got {other:?}"
            ),
        }
    }

    /// Scenario 20: Unknown replica key found in local `PaidForList` bypasses
    /// presence quorum.
    ///
    /// When a key's paid-list evidence shows confirmation from enough peers,
    /// `PaidListVerified` is returned even without a single presence-positive
    /// response.  This models the local-hit fast-path: the caller already
    /// checked the local paid list and the network confirms majority — no
    /// presence quorum needed.
    #[test]
    fn scenario_20_paid_list_local_hit_bypasses_presence_quorum() {
        let key = xor_name_from_byte(0xE0);
        let config = ReplicationConfig::default();

        // 7 quorum peers, quorum_needed = 4.
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        // 5 paid peers, confirm_needed = floor(5/2)+1 = 3.
        let paid_peers: Vec<PeerId> = (10..=14).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // ALL quorum peers Absent (presence quorum impossible) but 3/5 paid
        // peers confirm → PaidListVerified.
        let evidence = build_evidence(
            quorum_peers
                .iter()
                .map(|p| (*p, PresenceEvidence::Absent))
                .collect(),
            vec![
                (paid_peers[0], PaidListEvidence::Confirmed),
                (paid_peers[1], PaidListEvidence::Confirmed),
                (paid_peers[2], PaidListEvidence::Confirmed),
                (paid_peers[3], PaidListEvidence::NotFound),
                (paid_peers[4], PaidListEvidence::NotFound),
            ],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::PaidListVerified { .. }),
            "paid-list majority should bypass failed presence quorum, got {outcome:?}"
        );
    }

    /// Scenario 22: Paid-list confirmation below threshold AND presence quorum
    /// fails → `QuorumFailed`.
    ///
    /// Neither path can succeed: presence peers are all Absent (can't reach
    /// `quorum_needed`) and paid confirmations are below `confirm_needed`.
    #[test]
    fn scenario_22_paid_list_rejection_below_threshold() {
        let key = xor_name_from_byte(0xE2);
        let config = ReplicationConfig::default();

        // 7 quorum peers, quorum_needed = 4.
        let quorum_peers: Vec<PeerId> = (1..=7).map(peer_id_from_byte).collect();
        // 5 paid peers, confirm_needed = 3.
        let paid_peers: Vec<PeerId> = (10..=14).map(peer_id_from_byte).collect();
        let targets = single_key_targets(&key, quorum_peers.clone(), paid_peers.clone());

        // All quorum peers Absent; only one paid confirmation, below the
        // dynamic edge-aware paid-list threshold.
        let evidence = build_evidence(
            quorum_peers
                .iter()
                .map(|p| (*p, PresenceEvidence::Absent))
                .collect(),
            vec![
                (paid_peers[0], PaidListEvidence::Confirmed),
                (paid_peers[1], PaidListEvidence::NotFound),
                (paid_peers[2], PaidListEvidence::NotFound),
                (paid_peers[3], PaidListEvidence::NotFound),
                (paid_peers[4], PaidListEvidence::NotFound),
            ],
        );

        let outcome = evaluate_key_evidence(&key, &evidence, &targets, &config);
        assert!(
            matches!(outcome, KeyVerificationOutcome::QuorumFailed),
            "below-threshold paid confirmations with all-Absent quorum should yield QuorumFailed, got {outcome:?}"
        );
    }
}
