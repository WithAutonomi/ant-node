//! Quorum verification logic (Section 9).
//!
//! This module implements the single-round verification protocol:
//! - Compute `QuorumTargets`, `PaidTargets`, `VerifyTargets`
//! - Collect dual-evidence (presence + paid-list) in a single round
//! - Drive state machine transitions based on collected evidence
//! - Fast-fail when both quorum and paid-list success are impossible
//! - Short-circuit on local `PaidForList` hit (Section 9 step 4)

use crate::client::XorName;
use crate::replication::params::MAX_VERIFY_BATCH_SIZE;
use crate::replication::routing;
use crate::replication::types::{
    HintPipeline, PaidListEvidence, PeerKeyEvidence, PresenceEvidence,
};
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Verify plan: what to send to which peers
// ---------------------------------------------------------------------------

/// Plan for a single key's verification round.
///
/// Computed locally; the caller sends actual network requests.
#[derive(Debug, Clone)]
pub struct KeyVerifyPlan {
    /// The key being verified.
    pub key: XorName,
    /// Which pipeline this key follows.
    pub pipeline: HintPipeline,
    /// Peers to query for presence (up to `CLOSE_GROUP_SIZE` nearest in `LocalRT`).
    pub quorum_targets: Vec<(String, XorName)>,
    /// Peers to query for paid-list membership (`PaidCloseGroup(K)`).
    pub paid_targets: Vec<(String, XorName)>,
    /// Threshold: presence positives needed for quorum success.
    pub quorum_needed: usize,
    /// Threshold: paid confirmations needed for paid-list success.
    pub confirm_needed: usize,
}

/// Compute the verification plan for a single key.
///
/// `local_rt` is `LocalRT(self)` — the set of peers excluding self.
#[must_use]
pub fn plan_key_verification(
    self_id: &str,
    self_xor: &XorName,
    key: &XorName,
    pipeline: HintPipeline,
    local_rt: &[(String, XorName)],
) -> KeyVerifyPlan {
    let quorum_targets = routing::quorum_targets(key, local_rt);
    let paid_group = routing::paid_close_group(self_id, self_xor, key, local_rt);

    // Paid targets: members of PaidCloseGroup excluding self
    let paid_targets: Vec<(String, XorName)> = paid_group
        .into_iter()
        .filter(|(id, _)| id != self_id)
        .collect();

    let quorum_needed = routing::quorum_needed(quorum_targets.len());
    let confirm_needed = routing::confirm_needed(paid_targets.len() + 1); // +1 for self

    KeyVerifyPlan {
        key: *key,
        pipeline,
        quorum_targets,
        paid_targets,
        quorum_needed,
        confirm_needed,
    }
}

/// Compute the unified `VerifyTargets` set for a plan (Section 9 step 7).
///
/// Returns `PaidTargets ∪ QuorumTargets` (deduplicated by peer ID).
#[must_use]
pub fn verify_targets(plan: &KeyVerifyPlan) -> Vec<(String, XorName)> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    for (id, xor) in &plan.quorum_targets {
        if seen.insert(id.clone()) {
            targets.push((id.clone(), *xor));
        }
    }
    for (id, xor) in &plan.paid_targets {
        if seen.insert(id.clone()) {
            targets.push((id.clone(), *xor));
        }
    }

    targets
}

// ---------------------------------------------------------------------------
// Batch plan: coalesce multiple keys into per-peer requests
// ---------------------------------------------------------------------------

/// A batched verification request for a single peer.
#[derive(Debug, Clone)]
pub struct PeerVerifyBatch {
    /// Peer ID.
    pub peer_id: String,
    /// Keys to check for presence on this peer.
    pub presence_keys: Vec<XorName>,
    /// Keys to check for paid-list membership on this peer.
    pub paid_list_keys: Vec<XorName>,
}

/// Coalesce multiple key verification plans into batched per-peer requests.
///
/// Each peer receives at most one request carrying many keys (Section 9
/// batching requirement). Batch size is capped at `MAX_VERIFY_BATCH_SIZE`.
#[must_use]
pub fn batch_verify_plans(plans: &[KeyVerifyPlan]) -> Vec<PeerVerifyBatch> {
    let mut presence_by_peer: HashMap<String, Vec<XorName>> = HashMap::new();
    let mut paid_by_peer: HashMap<String, Vec<XorName>> = HashMap::new();

    for plan in plans {
        let quorum_ids: HashSet<&str> = plan
            .quorum_targets
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();
        let paid_ids: HashSet<&str> = plan
            .paid_targets
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();

        // All verify targets get presence queries
        for peer_id in quorum_ids.union(&paid_ids) {
            let keys = presence_by_peer.entry((*peer_id).to_string()).or_default();
            if keys.len() < MAX_VERIFY_BATCH_SIZE && !keys.contains(&plan.key) {
                keys.push(plan.key);
            }
        }

        // Only paid targets get paid-list queries
        for peer_id in &paid_ids {
            let keys = paid_by_peer.entry((*peer_id).to_string()).or_default();
            if keys.len() < MAX_VERIFY_BATCH_SIZE && !keys.contains(&plan.key) {
                keys.push(plan.key);
            }
        }
    }

    let all_peers: HashSet<String> = presence_by_peer
        .keys()
        .chain(paid_by_peer.keys())
        .cloned()
        .collect();

    all_peers
        .into_iter()
        .map(|peer_id| PeerVerifyBatch {
            presence_keys: presence_by_peer.remove(&peer_id).unwrap_or_default(),
            paid_list_keys: paid_by_peer.remove(&peer_id).unwrap_or_default(),
            peer_id,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Evidence evaluation: drive state machine transitions
// ---------------------------------------------------------------------------

/// Outcome of evaluating collected evidence for a single key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Presence quorum reached: `>= QuorumNeeded(K)` positives.
    QuorumVerified {
        /// Peer IDs that responded `Present` (verified fetch sources).
        present_peers: Vec<String>,
    },
    /// Paid-list confirmation reached: `>= ConfirmNeeded(K)` paid confirmations.
    PaidListVerified {
        /// Peer IDs that responded `Present` (verified fetch sources).
        present_peers: Vec<String>,
    },
    /// Both quorum and paid-list success are impossible this round.
    QuorumFailed,
    /// Still pending — more evidence could change the outcome.
    Pending,
}

/// Tally of evidence collected so far for a single key.
#[derive(Debug, Clone)]
pub struct KeyEvidenceTally {
    /// Key being verified.
    pub key: XorName,
    /// Pipeline for this key.
    pub pipeline: HintPipeline,
    /// Required presence positives.
    pub quorum_needed: usize,
    /// Required paid confirmations.
    pub confirm_needed: usize,
    /// Per-peer evidence collected so far.
    evidence: HashMap<String, PeerKeyEvidence>,
    /// Set of peer IDs in `QuorumTargets`.
    quorum_peer_ids: HashSet<String>,
    /// Set of peer IDs in `PaidTargets`.
    paid_peer_ids: HashSet<String>,
}

impl KeyEvidenceTally {
    /// Create a new tally from a verification plan.
    #[must_use]
    pub fn from_plan(plan: &KeyVerifyPlan) -> Self {
        Self {
            key: plan.key,
            pipeline: plan.pipeline,
            quorum_needed: plan.quorum_needed,
            confirm_needed: plan.confirm_needed,
            evidence: HashMap::new(),
            quorum_peer_ids: plan
                .quorum_targets
                .iter()
                .map(|(id, _)| id.clone())
                .collect(),
            paid_peer_ids: plan.paid_targets.iter().map(|(id, _)| id.clone()).collect(),
        }
    }

    /// Record evidence from a peer.
    pub fn record_evidence(&mut self, peer_id: &str, evidence: PeerKeyEvidence) {
        self.evidence.insert(peer_id.to_string(), evidence);
    }

    /// Mark a peer as timed-out/unresolved.
    pub fn record_timeout(&mut self, peer_id: &str) {
        self.evidence
            .insert(peer_id.to_string(), PeerKeyEvidence::unresolved());
    }

    /// Evaluate the current tally and determine the verification outcome.
    ///
    /// Implements Section 9 steps 9-14: checks quorum success, paid-list
    /// success, and fast-fail conditions.
    #[must_use]
    pub fn evaluate(&self) -> VerifyOutcome {
        let (quorum_positive, quorum_unresolved) = self.count_quorum_evidence();
        let (paid_yes, paid_unresolved) = self.count_paid_evidence();

        // Section 9 step 10: quorum success
        if quorum_positive >= self.quorum_needed {
            return VerifyOutcome::QuorumVerified {
                present_peers: self.collect_present_peers(),
            };
        }

        // Section 9 step 9: paid-list success
        if paid_yes >= self.confirm_needed {
            return VerifyOutcome::PaidListVerified {
                present_peers: self.collect_present_peers(),
            };
        }

        // Section 9 step 14: fast-fail when both conditions impossible
        let quorum_max_possible = quorum_positive + quorum_unresolved;
        let paid_max_possible = paid_yes + paid_unresolved;

        if quorum_max_possible < self.quorum_needed && paid_max_possible < self.confirm_needed {
            return VerifyOutcome::QuorumFailed;
        }

        VerifyOutcome::Pending
    }

    /// Count presence positives and unresolved among `QuorumTargets`.
    fn count_quorum_evidence(&self) -> (usize, usize) {
        let mut positive = 0;
        let mut unresolved = 0;

        for peer_id in &self.quorum_peer_ids {
            match self.evidence.get(peer_id) {
                Some(e) => match e.presence {
                    PresenceEvidence::Present => positive += 1,
                    PresenceEvidence::Absent => {}
                    PresenceEvidence::Unresolved => unresolved += 1,
                },
                None => unresolved += 1, // no response yet
            }
        }

        (positive, unresolved)
    }

    /// Count paid confirmations and unresolved among `PaidTargets`.
    fn count_paid_evidence(&self) -> (usize, usize) {
        let mut paid_yes = 0;
        let mut unresolved = 0;

        for peer_id in &self.paid_peer_ids {
            match self.evidence.get(peer_id) {
                Some(e) => match e.paid_list {
                    PaidListEvidence::Paid => paid_yes += 1,
                    PaidListEvidence::NotPaid => {}
                    PaidListEvidence::Unresolved => unresolved += 1,
                },
                None => unresolved += 1, // no response yet
            }
        }

        (paid_yes, unresolved)
    }

    /// Collect peer IDs that responded `Present` during this round.
    fn collect_present_peers(&self) -> Vec<String> {
        self.evidence
            .iter()
            .filter(|(_, e)| e.presence == PresenceEvidence::Present)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Number of peers that have responded (resolved, not pending).
    #[must_use]
    pub fn responded_count(&self) -> usize {
        self.evidence.len()
    }

    /// Total number of peers in the verify target set.
    #[must_use]
    pub fn total_targets(&self) -> usize {
        let all: HashSet<&String> = self
            .quorum_peer_ids
            .iter()
            .chain(self.paid_peer_ids.iter())
            .collect();
        all.len()
    }
}

// ---------------------------------------------------------------------------
// Local PaidForList short-circuit (Section 9 step 4)
// ---------------------------------------------------------------------------

/// Check if verification can be short-circuited because the key is
/// already in the local `PaidForList`.
///
/// Returns `true` if the key is locally paid-authorized, meaning:
/// - For `Replica` pipeline: skip to `PaidListVerified`, run presence-only
///   probe to discover holders, then fetch.
/// - For `PaidOnly` pipeline: lifecycle terminates immediately (no fetch).
#[must_use]
pub fn is_locally_paid_authorized(key: &XorName, paid_for_list: &[XorName]) -> bool {
    paid_for_list.contains(key)
}

/// Compute a presence-only probe plan for a locally-paid key.
///
/// Used when a key is already in the local `PaidForList` but needs
/// holder discovery for fetching (Section 9 step 4, fetch-eligible case).
#[must_use]
pub fn plan_presence_probe(
    key: &XorName,
    local_rt: &[(String, XorName)],
) -> Vec<(String, XorName)> {
    routing::quorum_targets(key, local_rt)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::params::CLOSE_GROUP_SIZE;

    /// Build a local routing table with `n` peers at known XOR distances.
    fn make_local_rt(n: usize) -> Vec<(String, XorName)> {
        (0..n)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let byte = (i + 1) as u8;
                let mut xor = [0x00; 32];
                xor[0] = byte;
                (format!("peer_{i}"), xor)
            })
            .collect()
    }

    #[test]
    fn test_plan_key_verification_targets() {
        let self_id = "self";
        let self_xor = [0xFF; 32]; // far from target
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);

        // QuorumTargets: up to CLOSE_GROUP_SIZE nearest to key in LocalRT
        assert!(plan.quorum_targets.len() <= CLOSE_GROUP_SIZE);
        assert!(!plan.quorum_targets.is_empty());

        // PaidTargets excludes self
        assert!(plan.paid_targets.iter().all(|(id, _)| id != self_id));
    }

    #[test]
    fn test_plan_key_verification_thresholds() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);

        // QuorumNeeded = min(QUORUM_THRESHOLD, floor(|targets|/2)+1)
        let expected_quorum = routing::quorum_needed(plan.quorum_targets.len());
        assert_eq!(plan.quorum_needed, expected_quorum);
        assert!(plan.quorum_needed > 0);
    }

    #[test]
    fn test_verify_targets_union_deduplicates() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let key = [0x00; 32];
        let local_rt = make_local_rt(5);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);
        let targets = verify_targets(&plan);

        // No duplicates
        let ids: HashSet<&str> = targets.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids.len(), targets.len());

        // Contains all quorum targets
        for (id, _) in &plan.quorum_targets {
            assert!(ids.contains(id.as_str()));
        }
        // Contains all paid targets
        for (id, _) in &plan.paid_targets {
            assert!(ids.contains(id.as_str()));
        }
    }

    #[test]
    fn test_batch_verify_plans_coalesces() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let local_rt = make_local_rt(5);

        let key1 = [0x01; 32];
        let key2 = [0x02; 32];
        let plan1 =
            plan_key_verification(self_id, &self_xor, &key1, HintPipeline::Replica, &local_rt);
        let plan2 =
            plan_key_verification(self_id, &self_xor, &key2, HintPipeline::Replica, &local_rt);

        let batches = batch_verify_plans(&[plan1, plan2]);

        // Each peer appears at most once
        let peer_ids: Vec<&str> = batches.iter().map(|b| b.peer_id.as_str()).collect();
        let unique: HashSet<&str> = peer_ids.iter().copied().collect();
        assert_eq!(peer_ids.len(), unique.len());

        // At least one peer has both keys in presence_keys
        let has_multi = batches.iter().any(|b| b.presence_keys.len() > 1);
        assert!(has_multi);
    }

    #[test]
    fn test_evidence_tally_quorum_verified() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);
        let mut tally = KeyEvidenceTally::from_plan(&plan);

        // Feed enough positive evidence to reach quorum
        for (i, (peer_id, _)) in plan.quorum_targets.iter().enumerate() {
            let evidence = PeerKeyEvidence {
                presence: PresenceEvidence::Present,
                paid_list: PaidListEvidence::Unresolved,
            };
            tally.record_evidence(peer_id, evidence);

            if i + 1 >= plan.quorum_needed {
                break;
            }
        }

        let outcome = tally.evaluate();
        assert!(matches!(outcome, VerifyOutcome::QuorumVerified { .. }));

        if let VerifyOutcome::QuorumVerified { present_peers } = outcome {
            assert!(!present_peers.is_empty());
        }
    }

    #[test]
    fn test_evidence_tally_paid_list_verified() {
        let self_id = "self";
        let self_xor = [0x00; 32]; // close to key so self is in paid group
        let key = [0x01; 32];
        let local_rt = make_local_rt(10);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);
        let mut tally = KeyEvidenceTally::from_plan(&plan);

        // All quorum targets respond Absent for presence (no quorum possible)
        for (peer_id, _) in &plan.quorum_targets {
            tally.record_evidence(
                peer_id,
                PeerKeyEvidence {
                    presence: PresenceEvidence::Absent,
                    paid_list: PaidListEvidence::Unresolved,
                },
            );
        }

        // Make enough paid targets confirm (Absent presence, Paid paid-list).
        // Peers in both sets get their evidence overwritten with correct
        // presence=Absent to prevent accidental quorum success.
        let mut paid_count = 0;
        for (peer_id, _) in &plan.paid_targets {
            // All paid targets respond Absent for presence
            // (preventing accidental quorum success from overlapping peers)
            tally.record_evidence(
                peer_id,
                PeerKeyEvidence {
                    presence: PresenceEvidence::Absent,
                    paid_list: PaidListEvidence::Paid,
                },
            );
            paid_count += 1;
            if paid_count >= plan.confirm_needed {
                break;
            }
        }

        let outcome = tally.evaluate();
        assert!(matches!(outcome, VerifyOutcome::PaidListVerified { .. }));
    }

    #[test]
    fn test_evidence_tally_fast_fail() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);
        let mut tally = KeyEvidenceTally::from_plan(&plan);

        // All quorum targets respond Absent
        for (peer_id, _) in &plan.quorum_targets {
            tally.record_evidence(
                peer_id,
                PeerKeyEvidence {
                    presence: PresenceEvidence::Absent,
                    paid_list: PaidListEvidence::Unresolved,
                },
            );
        }

        // All paid targets respond NotPaid
        for (peer_id, _) in &plan.paid_targets {
            tally.record_evidence(
                peer_id,
                PeerKeyEvidence {
                    presence: PresenceEvidence::Absent,
                    paid_list: PaidListEvidence::NotPaid,
                },
            );
        }

        let outcome = tally.evaluate();
        assert_eq!(outcome, VerifyOutcome::QuorumFailed);
    }

    #[test]
    fn test_evidence_tally_pending_while_unresolved() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);
        let tally = KeyEvidenceTally::from_plan(&plan);

        // No evidence recorded yet — all peers unresolved
        let outcome = tally.evaluate();
        assert_eq!(outcome, VerifyOutcome::Pending);
    }

    #[test]
    fn test_evidence_tally_partial_still_pending() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);
        let mut tally = KeyEvidenceTally::from_plan(&plan);

        // Only one peer responds Absent — not enough to fast-fail
        if let Some((peer_id, _)) = plan.quorum_targets.first() {
            tally.record_evidence(
                peer_id,
                PeerKeyEvidence {
                    presence: PresenceEvidence::Absent,
                    paid_list: PaidListEvidence::NotPaid,
                },
            );
        }

        let outcome = tally.evaluate();
        assert_eq!(outcome, VerifyOutcome::Pending);
    }

    #[test]
    fn test_tally_responded_and_total() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let key = [0x00; 32];
        let local_rt = make_local_rt(5);

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);
        let mut tally = KeyEvidenceTally::from_plan(&plan);

        assert_eq!(tally.responded_count(), 0);
        assert!(tally.total_targets() > 0);

        if let Some((peer_id, _)) = plan.quorum_targets.first() {
            tally.record_evidence(peer_id, PeerKeyEvidence::unresolved());
        }
        assert_eq!(tally.responded_count(), 1);
    }

    #[test]
    fn test_locally_paid_authorized() {
        let key = [0xAA; 32];
        let other = [0xBB; 32];
        let list = vec![key, other];

        assert!(is_locally_paid_authorized(&key, &list));
        assert!(!is_locally_paid_authorized(&[0xCC; 32], &list));
    }

    #[test]
    fn test_presence_probe_plan() {
        let key = [0x00; 32];
        let local_rt = make_local_rt(10);

        let targets = plan_presence_probe(&key, &local_rt);
        assert!(targets.len() <= CLOSE_GROUP_SIZE);
        assert!(!targets.is_empty());
    }

    #[test]
    fn test_empty_network_verification() {
        let self_id = "self";
        let self_xor = [0xFF; 32];
        let key = [0x00; 32];
        let local_rt: Vec<(String, XorName)> = Vec::new();

        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);

        assert!(plan.quorum_targets.is_empty());
        assert!(plan.paid_targets.is_empty());

        let tally = KeyEvidenceTally::from_plan(&plan);
        // With 0 targets: quorum_needed = min(4, 0/2+1) = 1
        // quorum_max_possible = 0 + 0 = 0 < 1
        // confirm_needed = floor(1/2)+1 = 1 (self counts in paid group)
        // paid_max_possible = 0 + 0 = 0 < 1
        // Both impossible → QuorumFailed
        let outcome = tally.evaluate();
        assert_eq!(outcome, VerifyOutcome::QuorumFailed);
    }
}
