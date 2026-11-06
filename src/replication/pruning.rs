//! Post-cycle responsibility pruning (Section 11).
//!
//! On `NeighborSyncCycleComplete`: prune stored records and `PaidForList`
//! entries that have been continuously out of range for at least
//! `PRUNE_HYSTERESIS_DURATION`.
//!
//! # Pressure-gated retention (ADR-0028)
//!
//! Being a candidate makes a stored record *eligible* to be erased, never due.
//! While the partition holding the record store has room, every candidate is
//! retained and served, and no prune-confirmation audit is sent: none could
//! lead to a deletion. Under disk pressure (see [`crate::replication::retention`])
//! candidates are audited and erased farthest from this node first, records
//! whose proofs failed in the current spell of pressure last, and the pass
//! measures free space again before each deletion and stops once the pressure
//! has ended.
//!
//! `PaidForList` entries are not part of this: a retained record keeps the entry
//! that authorises its repair. They are evicted only once the list passes
//! `paid_list_evict_start_entries`, whatever the disk, to make room for new
//! keys. Entries far outside this node's range go first, and neither entries
//! near it nor those of records it still stores go at all.
//!
//! # Stored-record prune lifecycle
//!
//! Each stored record is classified per pass against the current local
//! routing table:
//!
//! - `InRange`: self is within the storage-retention width
//!   (`close_group_size + STORAGE_ADMISSION_MARGIN`, 9 at production
//!   parameters); any out-of-range state is cleared once bootstrap has
//!   drained. Until then the routing table may still be filling, and a node
//!   that knows few peers looks in range for everything.
//! - `HysteresisPending`: outside the retention width, but not yet for the
//!   full `PRUNE_HYSTERESIS_DURATION`. The first-seen timestamp is recorded
//!   immediately on leaving range — a retained commitment vetoes DELETION,
//!   never the start of this clock. The timestamp is saved after each pass,
//!   so a restart doesn't restart the clock (see
//!   `replication::out_of_range_clocks`).
//! - `Candidate`: continuously outside the retention width for the full
//!   hysteresis. Candidacy is unconditional: it never depends on repair-hint
//!   proofs, bootstrap state, audit budget, or prior neighbor-sync contact.
//! - `HeldByCommitment` / `BootstrapDeferred` / `Unauditable`: candidate
//!   deferrals. They defer deletion, but never remove candidacy or restart
//!   the hysteresis clock. The request/candidate budget is a separate, later
//!   deferral applied after classification (not a disposition variant) so
//!   whole proof sets are either scheduled or deferred as a unit.
//! - `AuditFailed`: an audited candidate whose current strict close group
//!   returned fewer than the required positive possession proofs
//!   (`prune_proofs_needed`, 6 of 7 at production parameters). The record
//!   and its first-seen timestamp are retained and retried on later passes.
//! - `Pruned`: deleted after immediately re-passing the applicable checks
//!   against the then-current routing table.
//!
//! Distance alone never authorises deletion. However far outside the group
//! self has moved, a candidate is deleted only once the current strict close
//! group proves possession: a local routing-table view says which peers are
//! closer, not that any of them holds the bytes.
//!
//! Prune-confirmation audits challenge the CURRENT strict closest
//! `close_group_size` peers to the key, taken directly from the local
//! routing table — never filtered through `RepairProofs` or prior
//! neighbor-sync hints. The repair-proof maturity gate remains a
//! prerequisite for the responsible-chunk storage audit (see
//! `audit_tick_with_repair_proofs`), which is a different mechanism with a
//! different threat model.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::logging::{debug, info, warn};

use futures::{stream, StreamExt};
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use tokio::sync::RwLock;

use crate::ant_protocol::XorName;
use crate::error::Result;
use crate::replication::audit_coordinator::AuditChallengeCoordinator;
use crate::replication::audit_metrics::{self, AuditFailureClass, AuditType};
use crate::replication::commitment_state::ResponderCommitmentState;
use crate::replication::config::{
    storage_admission_width, ReplicationConfig, AUDIT_FAILURE_TRUST_WEIGHT,
    MAX_PAID_EVICTIONS_PER_PASS, MAX_PRUNE_AUDIT_CANDIDATES_PER_PASS,
    MAX_PRUNE_AUDIT_REQUESTS_PER_PASS, REPLICATION_PROTOCOL_ID,
};
use crate::replication::neighbor_sync::paid_near_bits;
use crate::replication::out_of_range_clocks::elapsed;
use crate::replication::paid_list::PaidList;
use crate::replication::protocol::{
    compute_audit_digest, AuditChallenge, AuditResponse, ReplicationMessage,
    ReplicationMessageBody, ABSENT_KEY_DIGEST,
};
use crate::replication::retention::{DiskPressure, RecordKind};
use crate::replication::types::{BootstrapClaimObservation, NeighborSyncState, RepairProofs};
use crate::storage::ChunkStore;

// `RepairProofs` remains in the prune-pass context only so records deleted by
// pruning also drop their (audit-path) repair-proof entries; it plays no part
// in prune candidacy or prune-audit target selection.

use super::REPLICATION_TRUST_WEIGHT;

const MAX_CONCURRENT_PRUNE_AUDIT_CHALLENGES: usize = 32;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Summary of a prune pass.
#[derive(Debug, Default)]
pub struct PruneResult {
    /// Total stored records scanned.
    pub records_total: usize,
    /// Number of records for which self is within the storage-retention width.
    pub records_in_range: usize,
    /// Number of records deleted from storage.
    pub records_pruned: usize,
    /// Number of records with out-of-range timestamp newly set.
    pub records_marked_out_of_range: usize,
    /// Number of records with out-of-range timestamp cleared (back in range).
    pub records_cleared: usize,
    /// Out-of-range records still inside the hysteresis window.
    pub records_hysteresis_pending: usize,
    /// Records continuously out of range for the full hysteresis (candidates),
    /// regardless of whether their audit could be scheduled this pass.
    pub records_candidates: usize,
    /// Candidates whose deletion (and audit) is vetoed by a retained
    /// recently-gossiped commitment.
    pub records_held_by_commitment: usize,
    /// Candidates whose audit is deferred until bootstrap drains.
    pub records_bootstrap_deferred: usize,
    /// Candidates whose audit is deferred by the per-pass challenge budget.
    pub records_budget_deferred: usize,
    /// Candidates audited against their current strict close group this pass.
    pub records_audits_attempted: usize,
    /// Audited candidates confirmed below the proof threshold (retained).
    pub records_audit_below_threshold: usize,
    /// Whether the partition holding the record store was under pressure.
    pub disk_pressure: bool,
    /// Candidates kept this pass, for any reason: room on the disk, a
    /// deferral, a failed proof, or the pressure ending before their turn.
    pub records_retained: usize,
    /// Number of `PaidForList` entries evicted.
    pub paid_entries_evicted: usize,
}

/// Shared dependencies and switches for one prune pass.
pub struct PrunePassContext<'a> {
    /// Local peer id.
    pub self_id: &'a PeerId,
    /// Local record storage.
    pub storage: &'a Arc<ChunkStore>,
    /// Persistent paid-list state.
    pub paid_list: &'a Arc<PaidList>,
    /// P2P node used for routing lookups and prune-confirmation audits.
    pub p2p_node: &'a Arc<P2PNode>,
    /// Replication configuration.
    pub config: &'a ReplicationConfig,
    /// Neighbor-sync state, including bootstrap claims.
    pub sync_state: &'a Arc<RwLock<NeighborSyncState>>,
    /// Repair-proof table, consulted ONLY to drop a deleted record's proof
    /// entries. Prune candidacy and prune-audit target selection never read it.
    pub repair_proofs: &'a Arc<RwLock<RepairProofs>>,
    /// Whether bootstrap has drained enough to permit pruning this pass.
    /// This gates the remote confirmation audits every deletion requires.
    pub allow_remote_prune_audits: bool,
    /// Responder commitment state, used to veto deleting a chunk still held
    /// under a recently-gossiped commitment (so the storage-commitment audit's
    /// round-2 byte challenge cannot false-positive an honest node). `None` on
    /// the legacy/test-only prune path, which keeps the pre-retention behavior.
    pub commitment_state: Option<&'a Arc<ResponderCommitmentState>>,
    /// Shared outbound limiter for digest `AuditChallenge`s.
    pub audit_challenge_coordinator: &'a Arc<AuditChallengeCoordinator>,
    /// The node's disk-pressure state, shared with the pointer prune pass.
    /// Candidates are erased only while it reports pressure (ADR-0028).
    pub disk_pressure: &'a DiskPressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PruneAuditStatus {
    Proven,
    Failed,
    /// The responder refused the challenge (capacity or routing). Never a
    /// possession signal; treated as an attributable failure under the
    /// assumed close-group store spread (see [`peer_proves_records`]).
    Rejected,
    Bootstrapping,
}

enum PruneAuditChallengeResult {
    Response(Box<ReplicationMessage>),
    NoResponse(AuditFailureClass),
    MalformedResponse,
}

#[derive(Debug, Default)]
struct RecordPruneStats {
    in_range: usize,
    marked: usize,
    cleared: usize,
    hysteresis_pending: usize,
    candidates: usize,
    held_by_commitment: usize,
    bootstrap_deferred: usize,
    budget_deferred: usize,
    audits_attempted: usize,
    audit_requests: usize,
    audit_below_threshold: usize,
    disk_pressure: bool,
    retained: usize,
    pruned: usize,
}

/// A prune candidate scheduled for a prune-confirmation audit this pass.
/// `target_peers` is the current strict close group for the key (self
/// excluded), taken directly from the local routing table.
#[derive(Debug, Clone)]
struct RecordPruneCandidate {
    key: XorName,
    target_peers: Vec<PeerId>,
}

struct RecordPruneLookupGroups {
    retention: Vec<PeerId>,
    strict: Vec<PeerId>,
}

struct RecordPruneKeyOutcome {
    /// Whether the out-of-range timestamp was newly set for this key.
    marked: bool,
    state: RecordPruneKeyState,
}

/// Per-pass lifecycle classification of one stored record (see module docs).
enum RecordPruneKeyState {
    /// Self is within the storage-retention width for this key. `cleared` is
    /// true when a stale out-of-range timestamp was removed.
    InRange { cleared: bool },
    /// Outside the retention width, but not yet for the full hysteresis.
    HysteresisPending,
    /// Continuously outside the retention width for at least the hysteresis
    /// duration. Candidacy is unconditional; the disposition only says how the
    /// candidate is scheduled this pass.
    Candidate(PruneCandidateDisposition),
}

/// How a prune candidate is scheduled within one pass.
enum PruneCandidateDisposition {
    /// Still committed under a recently-gossiped commitment: a neighbour can
    /// pin that root and demand the bytes in a round-2 byte challenge, so
    /// deletion is vetoed (and the audit skipped) until the key ages out of
    /// the retention window. Bounded reprieve: the commitment rebuild only
    /// commits to keys we are still responsible for, so the key drops out of
    /// the next rebuilt commitment and `is_held` flips false within at most
    /// `RETAINED_GOSSIPED_COMMITMENTS` gossip rotations.
    HeldByCommitment,
    /// Remote prune-confirmation audits are not allowed yet (bootstrap has
    /// not drained).
    BootstrapDeferred,
    /// The current close group has no remote peers to audit; retain
    /// conservatively.
    Unauditable,
    /// Audit the current strict close group this pass.
    Auditable(RecordPruneCandidate),
}

/// Outcome of revalidating one candidate immediately before deletion.
enum PruneRevalidationOutcome {
    /// Every check re-passed against the current routing table: delete.
    Delete,
    /// Self moved back inside the retention width; state cleared, record kept.
    ClearedBackInRange,
    /// The hysteresis condition no longer holds (timestamp cleared or reset
    /// concurrently); record kept.
    HysteresisPending,
    /// (Re-)committed under a retained commitment; deletion vetoed.
    HeldByCommitment,
    /// Fewer than the required positive proofs from the CURRENT strict close
    /// group — including when the group's membership changed after the audit
    /// round, which invalidates stale positive reports. Record kept, retried
    /// on later passes.
    AuditFailed,
    /// The current close group has no remote peers; retain conservatively.
    Unauditable,
}

#[derive(Default)]
struct PruneAuditReportState {
    audit_failures: RwLock<HashSet<PeerId>>,
    bootstrap_abuse: RwLock<HashSet<PeerId>>,
}

#[derive(Clone, Copy)]
struct PruneAuditContext<'a> {
    storage: &'a Arc<ChunkStore>,
    paid_list: &'a PaidList,
    p2p_node: &'a Arc<P2PNode>,
    config: &'a ReplicationConfig,
    sync_state: &'a Arc<RwLock<NeighborSyncState>>,
    audit_challenge_coordinator: &'a Arc<AuditChallengeCoordinator>,
    report_state: &'a PruneAuditReportState,
}

// ---------------------------------------------------------------------------
// Prune pass
// ---------------------------------------------------------------------------

/// Execute one prune pass (see the module docs for the record lifecycle).
pub async fn run_prune_pass_with_context(ctx: PrunePassContext<'_>) -> PruneResult {
    let (stored_count, record_stats) = prune_stored_records(&ctx).await;
    let (paid_count, paid_evicted) = evict_excess_paid_entries(&ctx).await;

    let result = PruneResult {
        records_total: stored_count,
        records_in_range: record_stats.in_range,
        records_pruned: record_stats.pruned,
        records_marked_out_of_range: record_stats.marked,
        records_cleared: record_stats.cleared,
        records_hysteresis_pending: record_stats.hysteresis_pending,
        records_candidates: record_stats.candidates,
        records_held_by_commitment: record_stats.held_by_commitment,
        records_bootstrap_deferred: record_stats.bootstrap_deferred,
        records_budget_deferred: record_stats.budget_deferred,
        records_audits_attempted: record_stats.audits_attempted,
        records_audit_below_threshold: record_stats.audit_below_threshold,
        disk_pressure: record_stats.disk_pressure,
        records_retained: record_stats.retained,
        paid_entries_evicted: paid_evicted,
    };

    // One aggregate line per pass: the full lifecycle census (never per-chunk).
    info!(
        "Prune pass complete: records total={} in_range={} newly_marked={} cleared={} \
         hysteresis_pending={} candidates={} held_by_commitment={} bootstrap_deferred={} \
         disk_pressure={} retained={} budget_deferred={} audits_attempted={} audit_requests={} \
         audit_below_threshold={} pruned={}; paid total={} evicted={}",
        result.records_total,
        result.records_in_range,
        result.records_marked_out_of_range,
        result.records_cleared,
        result.records_hysteresis_pending,
        result.records_candidates,
        result.records_held_by_commitment,
        result.records_bootstrap_deferred,
        result.disk_pressure,
        result.records_retained,
        result.records_budget_deferred,
        result.records_audits_attempted,
        record_stats.audit_requests,
        result.records_audit_below_threshold,
        result.records_pruned,
        paid_count,
        result.paid_entries_evicted,
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

    let now = SystemTime::now();
    let mut stats = RecordPruneStats::default();
    let mut audit_candidates = Vec::new();
    let deps = RecordPruneKeyDeps {
        self_id: ctx.self_id,
        paid_list: ctx.paid_list,
        config: ctx.config,
        allow_remote_prune_audits: ctx.allow_remote_prune_audits,
        commitment_state: ctx.commitment_state,
    };

    for key in &stored_keys {
        let groups = record_prune_lookup_groups(key, ctx.p2p_node, ctx.config).await;

        let outcome = evaluate_record_prune_key(&deps, key, &groups.retention, &groups.strict, now);
        if let Some(candidate) = tally_record_prune_outcome(&mut stats, outcome, key) {
            audit_candidates.push(candidate);
        }
    }

    // Saved clocks must not outlive their records.
    let stored: HashSet<&XorName> = stored_keys.iter().collect();
    ctx.paid_list
        .retain_record_out_of_range(|key| stored.contains(key));
    // Before any audit or deletion, so a restart during those can't bring back
    // a clock this pass stopped.
    ctx.paid_list.persist_record_out_of_range().await;

    // A candidate is eligible, not due: with room on the disk it stays, and
    // no audit is sent, since none could lead to a deletion.
    if !ctx.disk_pressure.observe_store(ctx.storage) {
        stats.retained = stats.candidates;
        return (stored_keys.len(), stats);
    }
    stats.disk_pressure = true;

    // The whole order, not a prefix: request budgets may pass over a
    // candidate, and the next in line should still be considered.
    let candidate_count = audit_candidates.len();
    let audit_candidates = ctx.disk_pressure.erasure_order(
        RecordKind::Chunk,
        ctx.self_id,
        audit_candidates,
        candidate_count,
        |candidate| candidate.key,
    );
    // Batches are sized from the records this node is in range for, not all
    // it holds: responders size what they accept the same way from their own
    // stores, and retained records would otherwise make a pruner's batches
    // too large for a newer peer to accept.
    let max_keys_per_challenge = ReplicationConfig::responsible_audit_key_limit(stats.in_range);
    let audit_selection = select_record_prune_audits(
        &audit_candidates,
        max_keys_per_challenge,
        MAX_PRUNE_AUDIT_CANDIDATES_PER_PASS,
        MAX_PRUNE_AUDIT_REQUESTS_PER_PASS,
    );
    stats.budget_deferred = audit_selection.deferred;
    stats.audits_attempted = audit_selection.candidates.len();
    stats.audit_requests = audit_selection.request_count;

    let present_by_key =
        collect_record_prune_proofs(&audit_selection.candidates, stats.in_range, ctx).await;
    let (keys_to_delete, revalidated_cleared, audit_below_threshold) =
        revalidated_record_prune_keys(&audit_selection.candidates, &present_by_key, ctx).await;
    stats.cleared += revalidated_cleared;
    stats.audit_below_threshold = audit_below_threshold;
    stats.pruned = delete_stored_records(&keys_to_delete, ctx).await;
    stats.retained = stats.candidates.saturating_sub(stats.pruned);

    (stored_keys.len(), stats)
}

/// Fold one record's per-pass classification into the pass stats. Returns the
/// auditable candidate when the record was scheduled for a prune audit.
fn tally_record_prune_outcome(
    stats: &mut RecordPruneStats,
    outcome: RecordPruneKeyOutcome,
    key: &XorName,
) -> Option<RecordPruneCandidate> {
    if outcome.marked {
        stats.marked += 1;
    }
    match outcome.state {
        RecordPruneKeyState::InRange { cleared } => {
            stats.in_range += 1;
            if cleared {
                stats.cleared += 1;
            }
            None
        }
        RecordPruneKeyState::HysteresisPending => {
            stats.hysteresis_pending += 1;
            None
        }
        RecordPruneKeyState::Candidate(disposition) => {
            stats.candidates += 1;
            match disposition {
                PruneCandidateDisposition::HeldByCommitment => {
                    stats.held_by_commitment += 1;
                    None
                }
                PruneCandidateDisposition::BootstrapDeferred => {
                    stats.bootstrap_deferred += 1;
                    None
                }
                PruneCandidateDisposition::Unauditable => {
                    debug!(
                        "Cannot prune-audit {}: current close group has no remote peers",
                        hex::encode(key)
                    );
                    None
                }
                PruneCandidateDisposition::Auditable(candidate) => Some(candidate),
            }
        }
    }
}

/// Current self-inclusive storage-retention group and strict close group for
/// `key`, from the local routing table, reduced to peer ids.
async fn record_prune_lookup_groups(
    key: &XorName,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> RecordPruneLookupGroups {
    // Closest first, so the strict group is the head of the retention group.
    let retention: Vec<PeerId> = p2p_node
        .dht_manager()
        .find_closest_nodes_local_with_self(key, storage_admission_width(config.close_group_size))
        .await
        .iter()
        .map(|node| node.peer_id)
        .collect();
    let strict = retention
        .iter()
        .take(config.close_group_size)
        .copied()
        .collect();
    RecordPruneLookupGroups { retention, strict }
}

/// The subset of [`PrunePassContext`] needed to classify one stored record.
/// Split out (with routing-table lookups precomputed by the caller) so unit
/// tests can drive the classification without a live `P2PNode`.
struct RecordPruneKeyDeps<'a> {
    self_id: &'a PeerId,
    paid_list: &'a Arc<PaidList>,
    config: &'a ReplicationConfig,
    allow_remote_prune_audits: bool,
    commitment_state: Option<&'a Arc<ResponderCommitmentState>>,
}

/// Classify one stored record for this pass (see the module docs).
///
/// The out-of-range timestamp is recorded the moment self is outside the
/// storage-retention width — even while the key is still held by a retained
/// commitment. Candidacy (past-hysteresis) is unconditional; commitment
/// retention, bootstrap state, and the audit budget only defer the audit or
/// veto the deletion.
fn evaluate_record_prune_key(
    deps: &RecordPruneKeyDeps<'_>,
    key: &XorName,
    storage_admission_peers: &[PeerId],
    strict_close_peers: &[PeerId],
    now: SystemTime,
) -> RecordPruneKeyOutcome {
    if storage_admission_peers.contains(deps.self_id) {
        // Until bootstrap has drained the routing table may still be filling,
        // and a node that knows few peers looks in range for everything. The
        // clocks restored after a restart have to survive that.
        let cleared = deps.allow_remote_prune_audits
            && deps.paid_list.record_out_of_range_since(key).is_some();
        if cleared {
            deps.paid_list.clear_record_out_of_range(key);
        }
        return RecordPruneKeyOutcome {
            marked: false,
            state: RecordPruneKeyState::InRange { cleared },
        };
    }

    // Outside the retention width: start (or continue) the hysteresis clock
    // immediately. A retained commitment vetoes DELETION further down, never
    // the timer — otherwise commitment retention would postpone when a record
    // can become a candidate instead of only protecting answerability.
    let marked = deps.paid_list.record_out_of_range_since(key).is_none();
    deps.paid_list.set_record_out_of_range(key);

    let Some(first_seen) = deps.paid_list.record_out_of_range_since(key) else {
        // The timestamp was just set; its absence means a concurrent clear.
        return RecordPruneKeyOutcome {
            marked,
            state: RecordPruneKeyState::HysteresisPending,
        };
    };
    if elapsed(first_seen, now) < deps.config.prune_hysteresis_duration {
        return RecordPruneKeyOutcome {
            marked,
            state: RecordPruneKeyState::HysteresisPending,
        };
    }

    RecordPruneKeyOutcome {
        marked,
        state: RecordPruneKeyState::Candidate(schedule_prune_candidate(
            deps,
            key,
            strict_close_peers,
        )),
    }
}

/// Decide how a prune candidate is scheduled this pass. Deferrals retain the
/// record, its first-seen timestamp, and its candidacy.
///
/// Audit targets are the CURRENT strict close group from the local routing
/// table — never filtered through `RepairProofs` or prior neighbor-sync
/// contact: prune confirmation concerns the peers now closest to the KEY,
/// while neighbor sync contacts the peers closest to SELF, and nothing
/// guarantees those sets overlap for an out-of-range key.
fn schedule_prune_candidate(
    deps: &RecordPruneKeyDeps<'_>,
    key: &XorName,
    strict_close_peers: &[PeerId],
) -> PruneCandidateDisposition {
    if let Some(cs) = deps.commitment_state {
        if cs.is_held(key) {
            return PruneCandidateDisposition::HeldByCommitment;
        }
    }

    if !deps.allow_remote_prune_audits {
        return PruneCandidateDisposition::BootstrapDeferred;
    }

    let target_peers = remote_close_group_peers(strict_close_peers, deps.self_id);
    if target_peers.is_empty() {
        return PruneCandidateDisposition::Unauditable;
    }

    PruneCandidateDisposition::Auditable(RecordPruneCandidate {
        key: *key,
        target_peers,
    })
}

struct RecordPruneAuditSelection {
    candidates: Vec<RecordPruneCandidate>,
    deferred: usize,
    request_count: usize,
}

/// Select whole candidates, in the order given, while bounding actual batched
/// network requests.
///
/// Adding a candidate consumes another request for a peer only when that
/// peer's current batch is full. This avoids the old accounting where every
/// candidate-to-peer edge consumed one unit despite sharing a request.
fn select_record_prune_audits(
    candidates: &[RecordPruneCandidate],
    max_keys_per_challenge: usize,
    max_candidates: usize,
    max_requests: usize,
) -> RecordPruneAuditSelection {
    let max_keys_per_challenge = max_keys_per_challenge.max(1);
    let mut selected = Vec::new();
    let mut keys_by_peer = HashMap::<PeerId, usize>::new();
    let mut request_count = 0usize;
    let mut deferred = 0usize;

    for candidate in candidates {
        if selected.len() >= max_candidates {
            deferred += 1;
            continue;
        }

        let unique_target_peers: HashSet<PeerId> = candidate.target_peers.iter().copied().collect();
        let additional_requests = unique_target_peers
            .iter()
            .filter(|peer| {
                keys_by_peer.get(peer).copied().unwrap_or_default() % max_keys_per_challenge == 0
            })
            .count();
        if request_count.saturating_add(additional_requests) > max_requests {
            deferred += 1;
            continue;
        }

        for peer in unique_target_peers {
            *keys_by_peer.entry(peer).or_default() += 1;
        }
        request_count += additional_requests;
        selected.push(candidate.clone());
    }

    debug_assert_eq!(
        build_peer_audit_challenges(&selected, max_keys_per_challenge).len(),
        request_count
    );
    RecordPruneAuditSelection {
        candidates: selected,
        deferred,
        request_count,
    }
}

/// Evict `PaidForList` entries once the list has passed its threshold, and
/// return how many entries it now holds and how many went.
///
/// Only entries far outside this node's range go, farthest first: with evenly
/// spread IDs this node has no vote on them. An entry whose record is still stored
/// stays, since it authorises that record's repair (see [`keeps_paid_entry`]). So
/// does everything while this node knows too few peers to say what is near.
async fn evict_excess_paid_entries(ctx: &PrunePassContext<'_>) -> (usize, usize) {
    let count = match ctx.paid_list.count() {
        Ok(count) => usize::try_from(count).unwrap_or(usize::MAX),
        Err(e) => {
            warn!("Failed to count PaidForList entries: {e}");
            return (0, 0);
        }
    };
    let excess = count.saturating_sub(ctx.config.paid_list_evict_start_entries);
    if excess == 0 {
        return (count, 0);
    }
    let near_bits = paid_near_bits(ctx.p2p_node, ctx.config.paid_list_close_group_size).await;
    let evicted = evict_paid_entries(
        ctx.paid_list,
        ctx.storage,
        *ctx.self_id.as_bytes(),
        near_bits,
        excess.min(MAX_PAID_EVICTIONS_PER_PASS),
    )
    .await;
    match evicted {
        Ok(evicted) => (count.saturating_sub(evicted), evicted),
        Err(e) => {
            warn!("Failed to evict PaidForList entries: {e}");
            (count, 0)
        }
    }
}

/// Evict up to `limit` paid entries outside the `near_bits` around `center`,
/// farthest first, keeping those [`keeps_paid_entry`] keeps. Returns how many
/// went.
///
/// The removal asks [`keeps_paid_entry`] again inside its write transaction,
/// with new record admissions held back until it has committed. So a record
/// stored after the scan, or under way when the removal decides, keeps its
/// entry and its price-contested mark (ADR-0006). A record admitted after the
/// removal finds no entry, as after any eviction.
async fn evict_paid_entries(
    paid_list: &PaidList,
    storage: &Arc<ChunkStore>,
    center: XorName,
    near_bits: usize,
    limit: usize,
) -> Result<usize> {
    let keep_storage = Arc::clone(storage);
    paid_list
        .evict_far(
            center,
            near_bits,
            limit,
            move |key| keeps_paid_entry(&keep_storage, key),
            storage.hold_admissions(),
        )
        .await
}

/// Whether eviction keeps `key`'s paid entry: while its record is in the store's
/// index, whether or not it can be read at the moment, or on its way there
/// (`ChunkStore::holds_or_admits`). The entry authorises the
/// record's repair and carries its price-contested mark (ADR-0006); a record that
/// failed a read is out of service, not gone, and losing its mark would let it be
/// hinted as a replica once it reads again.
fn keeps_paid_entry(storage: &ChunkStore, key: &XorName) -> bool {
    storage.holds_or_admits(key)
}

fn remote_close_group_peers(close_group: &[PeerId], self_id: &PeerId) -> Vec<PeerId> {
    close_group
        .iter()
        .filter(|peer| *peer != self_id)
        .copied()
        .collect()
}

/// Erase `keys_to_delete`, in order, while the disk stays under pressure.
///
/// Free space is measured again before each erasure: once the pressure has
/// ended, the rest are kept.
async fn delete_stored_records(keys_to_delete: &[XorName], ctx: &PrunePassContext<'_>) -> usize {
    let (storage, paid_list, repair_proofs) = (ctx.storage, ctx.paid_list, ctx.repair_proofs);
    let mut pruned = 0;

    for (index, key) in keys_to_delete.iter().enumerate() {
        if !ctx.disk_pressure.observe_store(storage) {
            debug!(
                "Disk pressure ended; keeping {} further prune candidates",
                keys_to_delete.len() - index
            );
            break;
        }
        if let Err(e) = storage.delete(key).await {
            warn!("Failed to prune record {}: {e}", hex::encode(key));
        } else {
            pruned += 1;
            paid_list.clear_record_out_of_range(key);
            repair_proofs.write().await.remove_key(key);
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
///
/// A price-contested key still needs its proofs before it is deleted, but no
/// absent peer is scored for it (see `fresh::record_paid_key`).
async fn collect_record_prune_proofs(
    candidates: &[RecordPruneCandidate],
    local_stored_key_count: usize,
    ctx: &PrunePassContext<'_>,
) -> HashMap<XorName, HashSet<PeerId>> {
    if candidates.is_empty() {
        return HashMap::new();
    }

    let max_keys_per_challenge =
        ReplicationConfig::responsible_audit_key_limit(local_stored_key_count);
    let challenges = build_peer_audit_challenges(candidates, max_keys_per_challenge);
    let report_state = PruneAuditReportState::default();
    let audit_context = PruneAuditContext {
        storage: ctx.storage,
        paid_list: ctx.paid_list,
        p2p_node: ctx.p2p_node,
        config: ctx.config,
        sync_state: ctx.sync_state,
        audit_challenge_coordinator: ctx.audit_challenge_coordinator,
        report_state: &report_state,
    };
    let mut requests = stream::iter(challenges)
        .map(|(peer, keys)| peer_proves_records(peer, keys, audit_context))
        .buffer_unordered(MAX_CONCURRENT_PRUNE_AUDIT_CHALLENGES);

    let mut present_by_key = HashMap::<XorName, HashSet<PeerId>>::new();
    while let Some(proofs) = requests.next().await {
        for (peer, key) in proofs {
            present_by_key.entry(key).or_default().insert(peer);
        }
    }

    present_by_key
}

async fn stored_record_still_exists(key: &XorName, storage: &Arc<ChunkStore>) -> bool {
    match storage.get_raw(key).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => {
            warn!(
                "Cannot revalidate prune candidate {}: failed to read local record: {error}",
                hex::encode(key)
            );
            false
        }
    }
}

/// Re-check every audited candidate against current local state immediately
/// before deletion, returning the keys to delete, the number of out-of-range
/// timestamps cleared (self back in range), and the number of candidates
/// confirmed below the proof threshold.
///
/// The audit round takes time; the routing table may have changed underneath
/// it, including self moving back into range or the strict close group
/// changing membership. Positive reports only count from peers still in the
/// CURRENT strict close group, against a threshold computed from that
/// current group.
async fn revalidated_record_prune_keys(
    candidates: &[RecordPruneCandidate],
    present_by_key: &HashMap<XorName, HashSet<PeerId>>,
    ctx: &PrunePassContext<'_>,
) -> (Vec<XorName>, usize, usize) {
    let mut keys_to_delete = Vec::new();
    let mut cleared = 0;
    let mut audit_below_threshold = 0;
    let now = SystemTime::now();

    for candidate in candidates {
        if !stored_record_still_exists(&candidate.key, ctx.storage).await {
            continue;
        }
        let groups = record_prune_lookup_groups(&candidate.key, ctx.p2p_node, ctx.config).await;
        let held_by_commitment = ctx
            .commitment_state
            .is_some_and(|cs| cs.is_held(&candidate.key));
        let inputs = PruneRevalidationInputs {
            self_id: ctx.self_id,
            first_seen: ctx.paid_list.record_out_of_range_since(&candidate.key),
            prune_hysteresis_duration: ctx.config.prune_hysteresis_duration,
            held_by_commitment,
            storage_admission_peers: &groups.retention,
            strict_close_peers: &groups.strict,
            now,
        };

        match revalidate_record_prune_candidate(candidate, present_by_key, &inputs) {
            PruneRevalidationOutcome::Delete => keys_to_delete.push(candidate.key),
            PruneRevalidationOutcome::ClearedBackInRange => {
                ctx.paid_list.clear_record_out_of_range(&candidate.key);
                cleared += 1;
            }
            PruneRevalidationOutcome::AuditFailed => {
                audit_below_threshold += 1;
                ctx.disk_pressure.demote(RecordKind::Chunk, candidate.key);
                debug!(
                    "Deferring prune for {} until all but one of the current close group \
                     report it",
                    hex::encode(candidate.key)
                );
            }
            PruneRevalidationOutcome::HysteresisPending
            | PruneRevalidationOutcome::HeldByCommitment => {}
            PruneRevalidationOutcome::Unauditable => {
                debug!(
                    "Cannot prune {}: current close group has no remote peers",
                    hex::encode(candidate.key)
                );
            }
        }
    }

    (keys_to_delete, cleared, audit_below_threshold)
}

/// Inputs for revalidating one audited candidate immediately before deletion.
struct PruneRevalidationInputs<'a> {
    self_id: &'a PeerId,
    /// The candidate's out-of-range first-seen timestamp as it stands NOW.
    first_seen: Option<SystemTime>,
    prune_hysteresis_duration: Duration,
    /// Whether a retained commitment holds the key NOW (TOCTOU re-check: a
    /// rotation/gossip may have re-committed it since candidate selection).
    held_by_commitment: bool,
    /// Current self-inclusive storage-retention group for the key.
    storage_admission_peers: &'a [PeerId],
    /// Current strict close group for the key.
    strict_close_peers: &'a [PeerId],
    now: SystemTime,
}

/// Pure deletion decision for one audited candidate (see
/// [`revalidated_record_prune_keys`]). Deletion requires that, against the
/// CURRENT routing table: self is still outside the storage-retention width,
/// the hysteresis still holds, no retained commitment holds the key, and at
/// least [`prune_proofs_needed`] of the current strict close group supplied
/// positive possession proofs. Stale positive reports from peers no longer in
/// the current close group never count, and no topology — however far outside
/// the group self has moved — substitutes for the proofs.
fn revalidate_record_prune_candidate(
    candidate: &RecordPruneCandidate,
    present_by_key: &HashMap<XorName, HashSet<PeerId>>,
    inputs: &PruneRevalidationInputs<'_>,
) -> PruneRevalidationOutcome {
    if inputs.storage_admission_peers.contains(inputs.self_id) {
        return PruneRevalidationOutcome::ClearedBackInRange;
    }

    if inputs.held_by_commitment {
        return PruneRevalidationOutcome::HeldByCommitment;
    }

    let Some(first_seen) = inputs.first_seen else {
        return PruneRevalidationOutcome::HysteresisPending;
    };
    if elapsed(first_seen, inputs.now) < inputs.prune_hysteresis_duration {
        return PruneRevalidationOutcome::HysteresisPending;
    }

    let current_target_peers = remote_close_group_peers(inputs.strict_close_peers, inputs.self_id);
    if current_target_peers.is_empty() {
        return PruneRevalidationOutcome::Unauditable;
    }

    let proofs_needed = prune_proofs_needed(current_target_peers.len());
    if target_peers_reported_present(
        &candidate.key,
        &current_target_peers,
        present_by_key,
        proofs_needed,
    ) {
        PruneRevalidationOutcome::Delete
    } else {
        PruneRevalidationOutcome::AuditFailed
    }
}

fn build_peer_audit_challenges(
    candidates: &[RecordPruneCandidate],
    max_keys_per_challenge: usize,
) -> Vec<(PeerId, Vec<XorName>)> {
    let max_keys_per_challenge = max_keys_per_challenge.max(1);
    let mut keys_by_peer: HashMap<PeerId, Vec<XorName>> = HashMap::new();
    for candidate in candidates {
        for peer in &candidate.target_peers {
            keys_by_peer.entry(*peer).or_default().push(candidate.key);
        }
    }

    let mut challenges = Vec::new();
    for (peer, mut keys) in keys_by_peer {
        keys.sort_unstable();
        keys.dedup();
        challenges.extend(
            keys.chunks(max_keys_per_challenge)
                .map(|chunk| (peer, chunk.to_vec())),
        );
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
pub(crate) fn prune_proofs_needed(group_size: usize) -> usize {
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
pub(crate) fn target_peers_reported_present(
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

/// Challenge a peer to prove it holds the exact record bytes for one or more keys.
///
/// Batching by peer prevents a prune pass from firing many simultaneous one-key
/// `AuditChallenge`s at the same target. The responder already supports
/// multi-key challenges, so we preserve per-key proof accounting while reducing
/// per-peer request bursts.
///
/// A size rejection is not accommodated: the responder's
/// `max_incoming_audit_keys` already grants a 2x margin over its own sender
/// limit, so an honestly-sized peer only rejects our batch once the close-group
/// store spread exceeds 4x. Under the assumed spread that is attributable
/// misbehaviour, so a `Rejected` response flows through the normal failure path
/// (labelled `size_reject` for observability) rather than triggering a
/// wire-compatible split-and-retry.
async fn peer_proves_records(
    peer: PeerId,
    keys: Vec<XorName>,
    context: PruneAuditContext<'_>,
) -> Vec<(PeerId, XorName)> {
    let (challenge_id, nonce) = {
        let mut rng = rand::thread_rng();
        (rng.gen::<u64>(), rng.gen::<[u8; 32]>())
    };
    let mut challenge_material = Vec::new();
    for key in keys {
        if let Some(expected_digest) =
            local_record_digest(&peer, &key, &nonce, context.storage).await
        {
            challenge_material.push((key, expected_digest));
        }
    }
    if challenge_material.is_empty() {
        return Vec::new();
    }

    let challenge_keys: Vec<XorName> = challenge_material.iter().map(|(key, _)| *key).collect();
    let Some((encoded, key_count)) =
        encode_prune_audit_challenge(&peer, &challenge_keys, challenge_id, nonce)
    else {
        return Vec::new();
    };
    let Some(decoded) = receive_prune_audit_response(
        &peer,
        &challenge_keys,
        encoded,
        key_count,
        challenge_id,
        context,
    )
    .await
    else {
        return Vec::new();
    };

    let statuses = prune_audit_response_statuses(decoded, challenge_id, &peer, &challenge_material);
    let mut clear_bootstrap_claim = false;
    let mut audit_failure_reported = false;
    let mut proven = Vec::new();

    for (key, status) in statuses {
        if prune_audit_response_clears_bootstrap_claim(status) {
            clear_bootstrap_claim = true;
        }

        match status {
            PruneAuditStatus::Proven => proven.push((peer, key)),
            PruneAuditStatus::Bootstrapping => {
                report_prune_bootstrap_claim(
                    &peer,
                    &key,
                    context.p2p_node,
                    context.config,
                    context.sync_state,
                    context.report_state,
                )
                .await;
            }
            PruneAuditStatus::Failed | PruneAuditStatus::Rejected => {
                let failure_class = if matches!(status, PruneAuditStatus::Rejected) {
                    "size_reject"
                } else {
                    "failed"
                };
                if !audit_failure_reported
                    && report_prune_audit_failure_once(&peer, &key, context, failure_class).await
                {
                    audit_failure_reported = true;
                }
            }
        }
    }

    if clear_bootstrap_claim {
        clear_prune_bootstrap_claim(&peer, context.sync_state).await;
    }

    proven
}

async fn receive_prune_audit_response(
    peer: &PeerId,
    challenge_keys: &[XorName],
    encoded: Vec<u8>,
    key_count: usize,
    challenge_id: u64,
    context: PruneAuditContext<'_>,
) -> Option<ReplicationMessage> {
    let result = send_prune_audit_challenge(
        peer,
        encoded,
        key_count,
        challenge_id,
        context.p2p_node,
        context.config,
        context.audit_challenge_coordinator,
    )
    .await;
    let failure_class = match result {
        PruneAuditChallengeResult::Response(decoded) => return Some(*decoded),
        PruneAuditChallengeResult::NoResponse(class) => {
            // Keep the local class split so timeout metrics are not polluted
            // by failures that happened before delivery.
            audit_metrics::record_audit_no_response(AuditType::Prune, class);
            class.as_str()
        }
        PruneAuditChallengeResult::MalformedResponse => "malformed",
    };

    for key in challenge_keys {
        if report_prune_audit_failure_once(peer, key, context, failure_class).await {
            break;
        }
    }
    None
}

fn prune_audit_response_clears_bootstrap_claim(status: PruneAuditStatus) -> bool {
    matches!(
        status,
        PruneAuditStatus::Proven | PruneAuditStatus::Failed | PruneAuditStatus::Rejected
    )
}

// The responder for an incoming `AuditChallenge` (including prune-confirmation
// challenges, which reuse the same wire message) lives in
// `super::handle_audit_challenge_msg` -> `audit::handle_audit_challenge`, the
// responsible-chunk audit responder. No separate prune-only responder is needed.
fn encode_prune_audit_challenge(
    peer: &PeerId,
    keys: &[XorName],
    challenge_id: u64,
    nonce: [u8; 32],
) -> Option<(Vec<u8>, usize)> {
    if keys.is_empty() {
        return None;
    }
    let challenge = AuditChallenge {
        challenge_id,
        nonce,
        challenged_peer_id: *peer.as_bytes(),
        keys: keys.to_vec(),
    };
    let key_count = challenge.keys.len();
    let msg = ReplicationMessage {
        request_id: challenge_id,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!(
                "Failed to encode prune audit challenge with {} keys against {peer}: {e}",
                keys.len(),
            );
            return None;
        }
    };
    Some((encoded, key_count))
}

pub(crate) fn prune_audit_response_timeout(
    config: &ReplicationConfig,
    key_count: usize,
) -> Duration {
    config.audit_response_timeout(key_count)
}

async fn send_prune_audit_challenge(
    peer: &PeerId,
    encoded: Vec<u8>,
    key_count: usize,
    challenge_id: u64,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    audit_challenge_coordinator: &Arc<AuditChallengeCoordinator>,
) -> PruneAuditChallengeResult {
    let Some(_slot) = audit_challenge_coordinator.acquire(*peer).await else {
        warn!(
            "Prune audit challenge with {key_count} keys against {peer} could not acquire coordinator slot"
        );
        return PruneAuditChallengeResult::MalformedResponse;
    };
    let timeout = prune_audit_response_timeout(config, key_count);
    info!(
        target: "ant_node::replication::audit_requester",
        event = "started",
        audit_origin = AuditType::Prune.as_str(),
        audit_round = "digest",
        challenged_peer = %peer,
        challenge_id,
        work_items = key_count,
        timeout_ms = timeout.as_millis(),
        "Outbound audit request started"
    );
    let request_started = Instant::now();
    let response = match p2p_node
        .send_request(peer, REPLICATION_PROTOCOL_ID, encoded, timeout)
        .await
    {
        Ok(response) => {
            info!(
                target: "ant_node::replication::audit_requester",
                event = "completed",
                audit_origin = AuditType::Prune.as_str(),
                audit_round = "digest",
                challenged_peer = %peer,
                challenge_id,
                work_items = key_count,
                elapsed_ms = request_started.elapsed().as_millis(),
                outcome = "response",
                "Outbound audit request completed"
            );
            response
        }
        Err(e) => {
            let error = e.to_string();
            let (send_error_class, audit_failure_class) =
                audit_metrics::classify_audit_send_error(&error);
            warn!(
                target: "ant_node::replication::audit_requester",
                event = "completed",
                audit_origin = AuditType::Prune.as_str(),
                audit_round = "digest",
                challenged_peer = %peer,
                challenge_id,
                work_items = key_count,
                elapsed_ms = request_started.elapsed().as_millis(),
                outcome = "no_response",
                audit_type = AuditType::Prune.as_str(),
                audit_failure_class = audit_failure_class.as_str(),
                send_error_class,
                "Prune audit challenge with {key_count} keys against {peer} failed: {e}",
            );
            return PruneAuditChallengeResult::NoResponse(audit_failure_class);
        }
    };

    let decoded = match ReplicationMessage::decode(&response.data) {
        Ok(msg) => msg,
        Err(e) => {
            warn!("Failed to decode prune audit response from {peer}: {e}");
            return PruneAuditChallengeResult::MalformedResponse;
        }
    };

    PruneAuditChallengeResult::Response(Box::new(decoded))
}

fn prune_audit_response_statuses(
    decoded: ReplicationMessage,
    challenge_id: u64,
    peer: &PeerId,
    challenge_material: &[(XorName, [u8; 32])],
) -> Vec<(XorName, PruneAuditStatus)> {
    let failed_all = |reason: &str| {
        warn!(
            "Prune audit proof batch from {peer} failed for {} keys: {reason}",
            challenge_material.len()
        );
        challenge_material
            .iter()
            .map(|(key, _)| (*key, PruneAuditStatus::Failed))
            .collect()
    };

    match decoded.body {
        ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
            challenge_id: resp_id,
            digests,
        }) => {
            if resp_id != challenge_id {
                return failed_all("challenge id mismatch");
            }
            if digests.len() != challenge_material.len() {
                return failed_all(&format!(
                    "returned {} digests for {} challenged keys",
                    digests.len(),
                    challenge_material.len()
                ));
            }

            challenge_material
                .iter()
                .zip(digests.iter())
                .map(|((key, expected_digest), digest)| {
                    if *digest == ABSENT_KEY_DIGEST {
                        warn!(
                            "Prune audit proof from {peer} failed for {}: peer reports key absent",
                            hex::encode(key)
                        );
                        return (*key, PruneAuditStatus::Failed);
                    }
                    if digest == expected_digest {
                        (*key, PruneAuditStatus::Proven)
                    } else {
                        warn!(
                            "Prune audit proof from {peer} failed for {}: digest mismatch",
                            hex::encode(key)
                        );
                        (*key, PruneAuditStatus::Failed)
                    }
                })
                .collect()
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping {
            challenge_id: resp_id,
        }) => {
            if resp_id == challenge_id {
                warn!(
                    "Prune audit proof batch for {} keys blocked by bootstrap claim from {peer}",
                    challenge_material.len()
                );
                challenge_material
                    .iter()
                    .map(|(key, _)| (*key, PruneAuditStatus::Bootstrapping))
                    .collect()
            } else {
                failed_all("challenge id mismatch on Bootstrapping")
            }
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::Rejected {
            challenge_id: resp_id,
            reason,
        }) => {
            if resp_id != challenge_id {
                return failed_all("challenge id mismatch on Rejected");
            }
            warn!(
                "Prune audit proof batch for {} keys rejected by {peer}: {reason}",
                challenge_material.len()
            );
            challenge_material
                .iter()
                .map(|(key, _)| (*key, PruneAuditStatus::Rejected))
                .collect()
        }
        _ => failed_all("unexpected response type"),
    }
}

async fn local_record_digest(
    peer: &PeerId,
    key: &XorName,
    nonce: &[u8; 32],
    storage: &Arc<ChunkStore>,
) -> Option<[u8; 32]> {
    local_record_bytes(key, storage)
        .await
        .map(|bytes| compute_audit_digest(nonce, peer.as_bytes(), key, &bytes))
}

/// The local copy a prune audit judges peers against. Read through the verifying
/// path: a local file that no longer hashes to its key would fail every honest
/// holder and hold the prune back indefinitely, so it is taken out of service by the
/// read instead, and the key is not audited.
async fn local_record_bytes(key: &XorName, storage: &Arc<ChunkStore>) -> Option<Vec<u8>> {
    match storage.get(key).await {
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

#[cfg(test)]
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
    context: PruneAuditContext<'_>,
    audit_failure_class: &'static str,
) -> bool {
    let PruneAuditContext {
        paid_list,
        p2p_node,
        config,
        report_state,
        ..
    } = context;
    // No peer is scored for a price-contested key (see
    // `fresh::record_paid_key`); a mark that cannot be read counts as set.
    if paid_list.counts_as_price_contested(key) {
        debug!(
            "Prune audit: not scoring {peer} for {}, a price-contested key",
            hex::encode(key)
        );
        return false;
    }
    let should_report = peer_is_currently_responsible(peer, key, p2p_node, config).await
        && reserve_prune_audit_failure_report(report_state, peer).await;
    if !should_report {
        return false;
    }

    warn!(
        audit_type = AuditType::Prune.as_str(),
        audit_failure_class,
        peer = %peer,
        key = %hex::encode(key),
        trust_weight = AUDIT_FAILURE_TRUST_WEIGHT,
        "Prune audit failure: peer={peer}, audit_failure_class={audit_failure_class}, key={}",
        hex::encode(key)
    );
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
    use crate::replication::fresh::record_paid_key;
    use crate::replication::paid_list::XORNAME_BITS;
    use crate::storage::chunk_store::CHUNKS_DIR_NAME;
    use crate::storage::ChunkStoreConfig;
    use futures::FutureExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::TempDir;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

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

    /// ADR-0006 with ADR-0028: eviction keeps the paid entry of a record that
    /// cannot be read for the moment, so a retained price-contested record keeps
    /// its mark through a read fault; an entry with no record does not stay.
    #[cfg(unix)]
    #[tokio::test]
    async fn eviction_keeps_the_entry_of_a_record_that_cannot_be_read_for_now() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir");
        let storage = ChunkStore::new(ChunkStoreConfig {
            root_dir: dir.path().to_path_buf(),
            ..ChunkStoreConfig::test_default()
        })
        .await
        .expect("chunk store");
        let bytes = b"retained price-contested record".to_vec();
        let key = ChunkStore::compute_address(&bytes);
        storage.put(&key, &bytes).await.expect("put");
        let path = dir
            .path()
            .join(CHUNKS_DIR_NAME)
            .join(format!("{:02x}", key.last().copied().unwrap_or(0)))
            .join(hex::encode(key));
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&path, perms).expect("chmod");

        assert!(storage.get(&key).await.is_err(), "the read must fail");
        assert!(!storage.exists(&key).expect("exists"), "out of service");
        assert!(keeps_paid_entry(&storage, &key), "but its entry stays");
        assert!(
            !keeps_paid_entry(&storage, &[0x5A; 32]),
            "an entry with no record does not"
        );

        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).expect("chmod back");
    }

    /// A chunk store and a paid list, as one node holds them.
    async fn eviction_fixture() -> (Arc<ChunkStore>, Arc<PaidList>, TempDir) {
        let dir = TempDir::new().expect("temp dir");
        let storage = ChunkStore::new(ChunkStoreConfig {
            root_dir: dir.path().join("store"),
            ..ChunkStoreConfig::test_default()
        })
        .await
        .expect("chunk store");
        let paid_list = PaidList::new(&dir.path().join("paid"))
            .await
            .expect("paid list");
        (Arc::new(storage), Arc::new(paid_list), dir)
    }

    /// A record to admit, and its key.
    fn test_record() -> (Vec<u8>, XorName) {
        let content = b"price-contested record admitted during an eviction".to_vec();
        let key = ChunkStore::compute_address(&content);
        (content, key)
    }

    /// Evict up to ten entries far from a center whose top bit differs from
    /// `key`'s, so `key` is a candidate.
    fn spawn_eviction(
        storage: &Arc<ChunkStore>,
        paid_list: &Arc<PaidList>,
        key: XorName,
    ) -> JoinHandle<Result<usize>> {
        let (storage, paid_list) = (Arc::clone(storage), Arc::clone(paid_list));
        let mut center = key;
        if let Some(first) = center.first_mut() {
            *first ^= 0x80;
        }
        tokio::spawn(async move {
            evict_paid_entries(&paid_list, &storage, center, XORNAME_BITS - 1, 10).await
        })
    }

    /// Store `content` under `key` as a fresh offer does, recording the key's
    /// marked entry first. The record waits after the entry until `store` fires,
    /// and `recorded` fires once the entry is in.
    fn spawn_fresh_admission(
        storage: &Arc<ChunkStore>,
        paid_list: &Arc<PaidList>,
        (content, key): (Vec<u8>, XorName),
        recorded: oneshot::Sender<()>,
        store: oneshot::Receiver<()>,
    ) -> JoinHandle<(bool, Result<bool>)> {
        let (storage, paid_list) = (Arc::clone(storage), Arc::clone(paid_list));
        tokio::spawn(async move {
            storage
                .put_after(&key, &content, async move {
                    let marked = record_paid_key(&key, true, &paid_list).await;
                    let _ = recorded.send(());
                    let _ = store.await;
                    marked
                })
                .await
        })
    }

    async fn wait_until(reached: impl Fn() -> bool + Send + Sync) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !reached() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("reached in time");
    }

    /// Hold the write half of `gate` on a blocking thread until the returned
    /// sender is dropped, so whatever takes its read half parks there.
    async fn hold_gate(
        gate: Arc<parking_lot::RwLock<()>>,
    ) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let (held_tx, held_rx) = oneshot::channel::<()>();
        let holder = tokio::task::spawn_blocking(move || {
            let _held = gate.write();
            let _ = held_tx.send(());
            let _ = release_rx.blocking_recv();
        });
        held_rx.await.expect("gate held");
        (release_tx, holder)
    }

    /// The record is stored and its paid entry still carries the mark, in the
    /// database and in memory, so it goes out in paid hints only.
    fn assert_stored_with_its_mark(storage: &ChunkStore, paid_list: &PaidList, key: &XorName) {
        assert!(storage.exists(key).expect("exists"), "the record is stored");
        assert!(
            paid_list.is_price_contested(key).expect("read mark"),
            "its paid entry and its mark stay"
        );
        assert_eq!(
            paid_list.split_marked(vec![*key]),
            (Vec::new(), vec![*key]),
            "and the in-memory copy still marks it"
        );
    }

    /// ADR-0006 with ADR-0028: an eviction scan finds the key's marked entry
    /// with no record, and a fresh offer then records (finding that entry) and
    /// stores the record, all before the eviction removes anything. The entry
    /// and its mark must stay, or the stored record would be hinted as a
    /// replica.
    #[tokio::test]
    async fn eviction_keeps_the_entry_of_a_record_stored_after_its_scan() {
        let (storage, paid_list, _dir) = eviction_fixture().await;
        let (content, key) = test_record();
        assert!(record_paid_key(&key, true, &paid_list).await);

        let scan_gate = paid_list.test_eviction_scan_gate();
        let scanned = scan_gate.write().await;
        let eviction = spawn_eviction(&storage, &paid_list, key);
        wait_until(|| paid_list.test_evictions_scanned() == 1).await;

        let (marked, stored) = storage
            .put_after(&key, &content, record_paid_key(&key, true, &paid_list))
            .await;
        assert!(marked);
        assert!(stored.expect("put"));

        drop(scanned);
        let evicted = eviction.await.expect("eviction task").expect("evict");
        assert_eq!(evicted, 0);
        assert_eq!(
            paid_list.test_removals_committing(),
            1,
            "the removal ran with the key as a candidate"
        );
        assert_stored_with_its_mark(&storage, &paid_list, &key);
    }

    /// The eviction removes while a fresh offer has recorded the key's entry
    /// but not yet stored its record. The offer's admission keeps the entry.
    #[tokio::test]
    async fn eviction_keeps_the_entry_of_a_record_recorded_but_not_yet_stored() {
        let (storage, paid_list, _dir) = eviction_fixture().await;
        let record = test_record();
        let key = record.1;
        // Already recorded when the eviction scans: by a `PaidNotify`, or by
        // this offer an instant earlier.
        assert!(record_paid_key(&key, true, &paid_list).await);

        let scan_gate = paid_list.test_eviction_scan_gate();
        let scanned = scan_gate.write().await;
        let eviction = spawn_eviction(&storage, &paid_list, key);
        wait_until(|| paid_list.test_evictions_scanned() == 1).await;

        let (recorded_tx, recorded_rx) = oneshot::channel();
        let (store_tx, store_rx) = oneshot::channel();
        let admission = spawn_fresh_admission(&storage, &paid_list, record, recorded_tx, store_rx);
        recorded_rx.await.expect("entry recorded");

        drop(scanned);
        let evicted = eviction.await.expect("eviction task").expect("evict");
        assert_eq!(evicted, 0);
        assert_eq!(
            paid_list.test_removals_committing(),
            1,
            "the removal ran with the key as a candidate"
        );

        store_tx.send(()).expect("store the record");
        let (marked, stored) = admission.await.expect("admission task");
        assert!(marked);
        assert!(stored.expect("put"));
        assert_stored_with_its_mark(&storage, &paid_list, &key);
    }

    /// The eviction removes while a put of the key has started but is not yet
    /// writing. The put's admission keeps the entry.
    #[tokio::test]
    async fn eviction_keeps_the_entry_of_a_record_whose_put_is_not_yet_writing() {
        let (storage, paid_list, _dir) = eviction_fixture().await;
        let (content, key) = test_record();
        assert!(record_paid_key(&key, true, &paid_list).await);

        let scan_gate = paid_list.test_eviction_scan_gate();
        let scanned = scan_gate.write().await;
        let eviction = spawn_eviction(&storage, &paid_list, key);
        wait_until(|| paid_list.test_evictions_scanned() == 1).await;

        let put_gate = storage.test_pre_registration_gate();
        let put_parked = put_gate.write().await;
        let put = {
            let storage = Arc::clone(&storage);
            tokio::spawn(async move { storage.put(&key, &content).await })
        };
        wait_until(|| storage.test_reached_pre_registration() == 1).await;

        drop(scanned);
        let evicted = eviction.await.expect("eviction task").expect("evict");
        assert_eq!(evicted, 0);
        assert_eq!(
            paid_list.test_removals_committing(),
            1,
            "the removal ran with the key as a candidate"
        );

        drop(put_parked);
        assert!(put.await.expect("put task").expect("put"));
        assert_stored_with_its_mark(&storage, &paid_list, &key);
    }

    /// The eviction removes while a put whose caller has gone away still has
    /// its write on the blocking pool. That write lands afterwards, so the
    /// entry stays.
    #[tokio::test]
    async fn eviction_keeps_the_entry_of_a_record_a_cancelled_put_is_still_writing() {
        let (storage, paid_list, _dir) = eviction_fixture().await;
        let (content, key) = test_record();
        assert!(record_paid_key(&key, true, &paid_list).await);

        let scan_gate = paid_list.test_eviction_scan_gate();
        let scanned = scan_gate.write().await;
        let eviction = spawn_eviction(&storage, &paid_list, key);
        wait_until(|| paid_list.test_evictions_scanned() == 1).await;

        let (release_write, write_parked) = hold_gate(storage.test_put_gate()).await;
        let put = {
            let storage = Arc::clone(&storage);
            tokio::spawn(async move { storage.put(&key, &content).await })
        };
        wait_until(|| storage.test_file_tasks_in_flight() == 1).await;
        put.abort();
        assert!(put.await.expect_err("aborted").is_cancelled());

        drop(scanned);
        let evicted = eviction.await.expect("eviction task").expect("evict");
        assert_eq!(evicted, 0);
        assert_eq!(
            paid_list.test_removals_committing(),
            1,
            "the removal ran with the key as a candidate"
        );

        drop(release_write);
        write_parked.await.expect("gate holder");
        storage.wait_idle().await;
        assert_stored_with_its_mark(&storage, &paid_list, &key);
    }

    /// An admission that starts while an eviction is removing the key's entry
    /// waits until the removal has committed, without getting past registering,
    /// so it records the entry afresh rather than trusting one about to go.
    #[tokio::test]
    async fn an_admission_waits_for_an_eviction_to_commit() {
        let (storage, paid_list, _dir) = eviction_fixture().await;
        let (content, key) = test_record();
        assert!(record_paid_key(&key, true, &paid_list).await);

        let (release_commit, committing) = hold_gate(paid_list.test_removal_commit_gate()).await;
        let eviction = spawn_eviction(&storage, &paid_list, key);
        wait_until(|| paid_list.test_removals_committing() == 1).await;

        let started = AtomicBool::new(false);
        let admission = storage.put_after(&key, &content, async {
            started.store(true, Ordering::Release);
            record_paid_key(&key, true, &paid_list).await
        });
        tokio::pin!(admission);
        assert!(
            (&mut admission).now_or_never().is_none(),
            "the admission waits for the commit"
        );
        assert!(
            !started.load(Ordering::Acquire),
            "without getting past registering"
        );

        drop(release_commit);
        committing.await.expect("gate holder");
        let evicted = eviction.await.expect("eviction task").expect("evict");
        assert_eq!(evicted, 1, "the entry with no record goes");
        let (marked, stored) = admission.await;
        assert!(started.load(Ordering::Acquire));
        assert!(marked, "the entry is recorded afresh, marked");
        assert!(stored.expect("put"));
        assert_stored_with_its_mark(&storage, &paid_list, &key);
    }

    /// A client PUT of a chunk the index names but whose file has gone finds
    /// the file missing, drops the stale index entry, and on Unix puts the
    /// offered copy back. An eviction that removes in between keeps the
    /// entry: the check counts as an admission from its start.
    #[tokio::test]
    async fn eviction_keeps_the_entry_of_a_record_a_put_check_is_putting_back() {
        let (storage, paid_list, _dir) = eviction_fixture().await;
        let (content, key) = test_record();
        assert!(storage.put(&key, &content).await.expect("put"));
        assert!(record_paid_key(&key, true, &paid_list).await);
        std::fs::remove_file(storage.test_chunk_path(&key)).expect("lose the file");

        let repair_gate = storage.test_pre_repair_gate();
        let repair_parked = repair_gate.write().await;
        let check = {
            let (storage, offered) = (Arc::clone(&storage), content.clone());
            tokio::spawn(async move { storage.holds_verified(&key, &offered).await })
        };
        wait_until(|| storage.test_reached_pre_repair() == 1).await;
        assert!(!storage.is_indexed(&key), "the stale index entry is gone");

        let evicted = spawn_eviction(&storage, &paid_list, key)
            .await
            .expect("eviction task")
            .expect("evict");
        assert_eq!(evicted, 0);

        drop(repair_parked);
        // Off Unix a repair rewrites the file in place and cannot recreate a missing
        // one, so the check answers no and the PUT stores the copy, as the handler does.
        let put_back = check.await.expect("check task");
        #[cfg(unix)]
        assert!(put_back, "on Unix the check puts the offered copy back");
        if !put_back {
            assert!(storage.put(&key, &content).await.expect("put"));
        }
        assert_stored_with_its_mark(&storage, &paid_list, &key);
    }

    /// A prune audit judges holders against this node's own copy. A copy that
    /// no longer hashes to its key would fail every honest holder and hold the
    /// prune back forever, so it is not used as a reference: the read takes it
    /// out of service instead, and an intact copy is used as before.
    #[tokio::test]
    async fn a_rotted_local_copy_is_not_used_to_judge_holders() {
        let dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(
            ChunkStore::new(ChunkStoreConfig {
                root_dir: dir.path().to_path_buf(),
                ..ChunkStoreConfig::test_default()
            })
            .await
            .expect("chunk store"),
        );
        let good_bytes = b"intact prune candidate".to_vec();
        let bad_bytes = b"rotted prune candidate".to_vec();
        let good = ChunkStore::compute_address(&good_bytes);
        let bad = ChunkStore::compute_address(&bad_bytes);
        storage.put(&good, &good_bytes).await.expect("put good");
        storage.put(&bad, &bad_bytes).await.expect("put bad");
        let path = dir
            .path()
            .join(CHUNKS_DIR_NAME)
            .join(format!("{:02x}", bad.last().copied().unwrap_or(0)))
            .join(hex::encode(bad));
        std::fs::write(&path, b"rotted").expect("corrupt the file");

        assert_eq!(local_record_bytes(&good, &storage).await, Some(good_bytes));
        assert_eq!(local_record_bytes(&bad, &storage).await, None);
        assert!(!storage.exists(&bad).expect("exists"));
        assert!(!path.exists(), "the rotted local copy is removed");
    }

    #[test]
    fn prune_audit_challenges_are_batched_by_target_peer() {
        let peer_a = peer_id_from_byte(1);
        let peer_b = peer_id_from_byte(2);
        let key_a = key_from_byte(0xA);
        let key_b = key_from_byte(0xB);
        let candidates = vec![
            candidate(key_a, vec![peer_a, peer_b]),
            candidate(key_b, vec![peer_b]),
        ];

        let mut challenges = build_peer_audit_challenges(&candidates, 2);
        for (_, keys) in &mut challenges {
            keys.sort_unstable();
        }
        challenges.sort_unstable_by_key(|(peer, keys)| (*peer.as_bytes(), keys.clone()));

        let mut expected = vec![(peer_a, vec![key_a]), (peer_b, vec![key_a, key_b])];
        expected.sort_unstable_by_key(|(peer, keys)| (*peer.as_bytes(), keys.clone()));
        assert_eq!(challenges, expected);
    }

    #[test]
    fn prune_audit_challenges_split_peer_batches_at_responsible_audit_limit() {
        let peer = peer_id_from_byte(1);
        let candidates = vec![
            candidate(key_from_byte(0xA), vec![peer]),
            candidate(key_from_byte(0xB), vec![peer]),
            candidate(key_from_byte(0xC), vec![peer]),
            candidate(key_from_byte(0xD), vec![peer]),
            candidate(key_from_byte(0xE), vec![peer]),
        ];

        let mut challenges = build_peer_audit_challenges(&candidates, 2);
        for (_, keys) in &mut challenges {
            keys.sort_unstable();
        }
        challenges.sort_unstable_by_key(|(_, keys)| keys.clone());

        assert_eq!(
            challenges,
            vec![
                (peer, vec![key_from_byte(0xA), key_from_byte(0xB)]),
                (peer, vec![key_from_byte(0xC), key_from_byte(0xD)]),
                (peer, vec![key_from_byte(0xE)]),
            ]
        );
    }

    #[test]
    fn prune_audit_batched_digest_response_is_evaluated_per_key() {
        let peer = peer_id_from_byte(7);
        let key_a = key_from_byte(0xA);
        let key_b = key_from_byte(0xB);
        let nonce = [0x7A; 32];
        let bytes_a = b"record-a".to_vec();
        let expected_a = compute_audit_digest(&nonce, peer.as_bytes(), &key_a, &bytes_a);
        let expected_b = compute_audit_digest(&nonce, peer.as_bytes(), &key_b, b"record-b");
        let msg = ReplicationMessage {
            request_id: 42,
            body: ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
                challenge_id: 42,
                digests: vec![expected_a, ABSENT_KEY_DIGEST],
            }),
        };

        let statuses = prune_audit_response_statuses(
            msg,
            42,
            &peer,
            &[(key_a, expected_a), (key_b, expected_b)],
        );

        assert_eq!(
            statuses,
            vec![
                (key_a, PruneAuditStatus::Proven),
                (key_b, PruneAuditStatus::Failed),
            ]
        );
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
        assert!(
            confirmed.is_empty(),
            "expected no confirmed keys at a quorum of 3, got {confirmed:?}"
        );
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

    // -- Prune lifecycle classification (see module docs) --------------------

    /// Production strict close-group size.
    const PROD_CLOSE_GROUP: usize = 7;
    /// Production storage-retention width (`close_group_size + margin`).
    const PROD_RETENTION_WIDTH: usize = 9;
    /// A self id outside every `peer_ids(..)` helper group.
    const SELF_BYTE: u8 = 99;

    async fn test_paid_list() -> (Arc<PaidList>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paid_list = Arc::new(PaidList::new(dir.path()).await.expect("paid list"));
        (paid_list, dir)
    }

    fn record_deps<'a>(
        self_id: &'a PeerId,
        paid_list: &'a Arc<PaidList>,
        config: &'a ReplicationConfig,
        allow_remote_prune_audits: bool,
        commitment_state: Option<&'a Arc<ResponderCommitmentState>>,
    ) -> RecordPruneKeyDeps<'a> {
        RecordPruneKeyDeps {
            self_id,
            paid_list,
            config,
            allow_remote_prune_audits,
            commitment_state,
        }
    }

    /// A responder commitment state whose retained (gossiped) commitment
    /// contains exactly `key`, so `is_held(key)` is true.
    fn held_commitment_state(key: XorName, content: &[u8]) -> Arc<ResponderCommitmentState> {
        let (pk, sk) = saorsa_pqc::api::sig::ml_dsa_65()
            .generate_keypair()
            .expect("keypair");
        let bytes_hash = *blake3::hash(content).as_bytes();
        let built = crate::replication::commitment_state::BuiltCommitment::build(
            vec![(key, bytes_hash)],
            &[0; 32],
            &sk,
            &pk.to_bytes(),
        )
        .expect("build commitment");
        let hash = built.hash();
        let state = ResponderCommitmentState::new();
        state.rotate(built);
        state.mark_gossiped(hash);
        Arc::new(state)
    }

    fn instant_after(base: SystemTime, delta: Duration) -> SystemTime {
        base.checked_add(delta).expect("test instant overflow")
    }

    /// #1 + #4: a record outside the retention width is marked the moment it
    /// is observed there — even while a retained commitment still holds the
    /// key. Retention vetoes deletion, never the hysteresis clock.
    #[tokio::test]
    async fn out_of_range_record_is_marked_immediately_even_when_held_by_commitment() {
        let (paid_list, _dir) = test_paid_list().await;
        let config = ReplicationConfig::default();
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xA0);
        let commitment = held_commitment_state(key, b"held bytes");
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let deps = record_deps(&self_id, &paid_list, &config, true, Some(&commitment));

        let outcome = evaluate_record_prune_key(
            &deps,
            &key,
            &admission_peers,
            &strict_close_peers,
            SystemTime::now(),
        );

        assert!(
            outcome.marked,
            "first out-of-range observation must set the timestamp"
        );
        assert!(matches!(
            outcome.state,
            RecordPruneKeyState::HysteresisPending
        ));
        assert!(
            paid_list.record_out_of_range_since(&key).is_some(),
            "a retained commitment must not delay the start of hysteresis"
        );
    }

    /// #2: a record outside the retention width for less than the hysteresis
    /// duration is not a prune candidate.
    #[tokio::test]
    async fn record_outside_range_within_hysteresis_is_not_a_candidate() {
        let (paid_list, _dir) = test_paid_list().await;
        let config = ReplicationConfig::default();
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xA1);
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let deps = record_deps(&self_id, &paid_list, &config, true, None);

        paid_list.set_record_out_of_range(&key);
        let outcome = evaluate_record_prune_key(
            &deps,
            &key,
            &admission_peers,
            &strict_close_peers,
            SystemTime::now(),
        );

        assert!(!outcome.marked, "timestamp was already set");
        assert!(matches!(
            outcome.state,
            RecordPruneKeyState::HysteresisPending
        ));
    }

    /// #3 + #8: after the full hysteresis the record becomes an auditable
    /// candidate whose targets are the CURRENT strict close group — with an
    /// empty `RepairProofs` table and no prior neighbor-sync contact.
    #[tokio::test]
    async fn record_past_hysteresis_is_candidate_targeting_current_close_group() {
        let (paid_list, _dir) = test_paid_list().await;
        let config = ReplicationConfig::default();
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xA2);
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let deps = record_deps(&self_id, &paid_list, &config, true, None);

        paid_list.set_record_out_of_range(&key);
        let first_seen = paid_list
            .record_out_of_range_since(&key)
            .expect("first seen");
        let outcome = evaluate_record_prune_key(
            &deps,
            &key,
            &admission_peers,
            &strict_close_peers,
            instant_after(first_seen, config.prune_hysteresis_duration),
        );

        let RecordPruneKeyState::Candidate(PruneCandidateDisposition::Auditable(candidate)) =
            outcome.state
        else {
            panic!("record past hysteresis must be an auditable candidate");
        };
        let targets: HashSet<PeerId> = candidate.target_peers.iter().copied().collect();
        let expected: HashSet<PeerId> = strict_close_peers.iter().copied().collect();
        assert_eq!(
            targets, expected,
            "audit targets must be the current strict close group, unfiltered by repair proofs"
        );
    }

    /// #5: a retained commitment vetoes deletion after candidacy without
    /// touching the first-seen timestamp or the audit budget.
    #[tokio::test]
    async fn held_commitment_defers_candidate_without_losing_state() {
        let (paid_list, _dir) = test_paid_list().await;
        let config = ReplicationConfig::default();
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xA3);
        let commitment = held_commitment_state(key, b"still committed");
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let deps = record_deps(&self_id, &paid_list, &config, true, Some(&commitment));

        paid_list.set_record_out_of_range(&key);
        let first_seen = paid_list
            .record_out_of_range_since(&key)
            .expect("first seen");
        let outcome = evaluate_record_prune_key(
            &deps,
            &key,
            &admission_peers,
            &strict_close_peers,
            instant_after(first_seen, config.prune_hysteresis_duration),
        );

        assert!(matches!(
            outcome.state,
            RecordPruneKeyState::Candidate(PruneCandidateDisposition::HeldByCommitment)
        ));
        assert_eq!(
            paid_list.record_out_of_range_since(&key),
            Some(first_seen),
            "the retention veto must not restart hysteresis"
        );
    }

    /// #6: bootstrap state defers the audit but preserves candidacy and the
    /// first-seen timestamp.
    #[tokio::test]
    async fn bootstrap_gate_defers_audit_but_preserves_candidacy() {
        let (paid_list, _dir) = test_paid_list().await;
        let config = ReplicationConfig::default();
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xA4);
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let deps = record_deps(&self_id, &paid_list, &config, false, None);

        paid_list.set_record_out_of_range(&key);
        let first_seen = paid_list
            .record_out_of_range_since(&key)
            .expect("first seen");
        let outcome = evaluate_record_prune_key(
            &deps,
            &key,
            &admission_peers,
            &strict_close_peers,
            instant_after(first_seen, config.prune_hysteresis_duration),
        );

        assert!(matches!(
            outcome.state,
            RecordPruneKeyState::Candidate(PruneCandidateDisposition::BootstrapDeferred)
        ));
        assert_eq!(
            paid_list.record_out_of_range_since(&key),
            Some(first_seen),
            "bootstrap deferral must preserve the first-seen time"
        );
    }

    /// The request budget counts multi-key peer requests, not
    /// candidate-to-peer edges, and never schedules a partial candidate.
    #[test]
    fn audit_selection_batches_keys_and_defers_whole_candidates() {
        let peers = peer_ids(2);
        let candidates = vec![
            candidate(key_from_byte(0xA5), peers.clone()),
            candidate(key_from_byte(0xA6), peers.clone()),
            candidate(key_from_byte(0xA7), peers),
        ];

        let selected = select_record_prune_audits(&candidates, 2, 10, 2);

        assert_eq!(selected.candidates.len(), 2);
        assert_eq!(selected.request_count, 2);
        assert_eq!(selected.deferred, 1);
        let selected_keys: Vec<XorName> = selected.candidates.iter().map(|c| c.key).collect();
        assert_eq!(
            selected_keys,
            vec![key_from_byte(0xA5), key_from_byte(0xA6)],
            "candidates are taken in the order given"
        );
    }

    /// #12 (part): moving back inside the retention width clears the
    /// out-of-range state.
    #[tokio::test]
    async fn record_back_in_range_clears_out_of_range_state() {
        let (paid_list, _dir) = test_paid_list().await;
        let config = ReplicationConfig::default();
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xA6);
        let mut admission_peers = peer_ids(PROD_RETENTION_WIDTH - 1);
        admission_peers.push(self_id);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let deps = record_deps(&self_id, &paid_list, &config, true, None);

        paid_list.set_record_out_of_range(&key);
        let outcome = evaluate_record_prune_key(
            &deps,
            &key,
            &admission_peers,
            &strict_close_peers,
            SystemTime::now(),
        );

        assert!(matches!(
            outcome.state,
            RecordPruneKeyState::InRange { cleared: true }
        ));
        assert!(
            paid_list.record_out_of_range_since(&key).is_none(),
            "re-entering range must clear the out-of-range timestamp"
        );
    }

    /// A restarted node knows few peers until bootstrap drains, so it looks in
    /// range for everything. That must not restart the clocks it restored.
    #[tokio::test]
    async fn record_in_range_during_bootstrap_keeps_its_clock() {
        let (paid_list, _dir) = test_paid_list().await;
        let config = ReplicationConfig::default();
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xA7);
        let mut admission_peers = peer_ids(PROD_RETENTION_WIDTH - 1);
        admission_peers.push(self_id);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let deps = record_deps(&self_id, &paid_list, &config, false, None);

        paid_list.set_record_out_of_range(&key);
        let outcome = evaluate_record_prune_key(
            &deps,
            &key,
            &admission_peers,
            &strict_close_peers,
            SystemTime::now(),
        );

        assert!(matches!(
            outcome.state,
            RecordPruneKeyState::InRange { cleared: false }
        ));
        assert!(paid_list.record_out_of_range_since(&key).is_some());
    }

    // -- Pre-deletion revalidation -------------------------------------------

    fn revalidation_inputs<'a>(
        self_id: &'a PeerId,
        first_seen: Option<SystemTime>,
        held_by_commitment: bool,
        storage_admission_peers: &'a [PeerId],
        strict_close_peers: &'a [PeerId],
        now: SystemTime,
    ) -> PruneRevalidationInputs<'a> {
        PruneRevalidationInputs {
            self_id,
            first_seen,
            prune_hysteresis_duration: ReplicationConfig::default().prune_hysteresis_duration,
            held_by_commitment,
            storage_admission_peers,
            strict_close_peers,
            now,
        }
    }

    fn matured(first_seen: SystemTime) -> SystemTime {
        instant_after(
            first_seen,
            ReplicationConfig::default().prune_hysteresis_duration,
        )
    }

    /// #9 + #10: six positive proofs from the current seven-strong close group
    /// permit deletion; five do not.
    #[test]
    fn revalidation_deletes_at_six_of_seven_and_retains_at_five() {
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xB0);
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let candidate = candidate(key, strict_close_peers.clone());
        let first_seen = SystemTime::now();
        let now = matured(first_seen);

        for (proofs, expect_delete) in [(6usize, true), (5usize, false)] {
            let mut present_by_key = HashMap::new();
            present_by_key.insert(
                key,
                strict_close_peers[..proofs]
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>(),
            );
            let inputs = revalidation_inputs(
                &self_id,
                Some(first_seen),
                false,
                &admission_peers,
                &strict_close_peers,
                now,
            );
            let outcome = revalidate_record_prune_candidate(&candidate, &present_by_key, &inputs);
            if expect_delete {
                assert!(
                    matches!(outcome, PruneRevalidationOutcome::Delete),
                    "6 of 7 proofs must permit deletion"
                );
            } else {
                assert!(
                    matches!(outcome, PruneRevalidationOutcome::AuditFailed),
                    "5 of 7 proofs must retain the record"
                );
            }
        }
    }

    /// Distance is not possession: a node outside a complete retention group
    /// still keeps a mature record its close group has not proven. How far
    /// outside it is cannot matter, since revalidation is given no distance.
    #[test]
    fn revalidation_retains_record_outside_complete_group_without_proofs() {
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xB5);
        let retention_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let candidate = candidate(key, strict_close_peers.clone());
        let first_seen = SystemTime::now();
        let inputs = revalidation_inputs(
            &self_id,
            Some(first_seen),
            false,
            &retention_peers,
            &strict_close_peers,
            matured(first_seen),
        );

        let outcome = revalidate_record_prune_candidate(&candidate, &HashMap::new(), &inputs);

        assert!(
            matches!(outcome, PruneRevalidationOutcome::AuditFailed),
            "a record no close-group member proved must never be deleted"
        );
    }

    /// #12: self moving back inside the retention width between the audit and
    /// deletion clears the state and prevents deletion, even with full proofs.
    #[test]
    fn revalidation_clears_and_prevents_deletion_when_back_in_range() {
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xB1);
        let mut admission_peers = peer_ids(PROD_RETENTION_WIDTH - 1);
        admission_peers.push(self_id);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let candidate = candidate(key, strict_close_peers.clone());
        let mut present_by_key = HashMap::new();
        present_by_key.insert(key, strict_close_peers.iter().copied().collect());
        let first_seen = SystemTime::now();
        let inputs = revalidation_inputs(
            &self_id,
            Some(first_seen),
            false,
            &admission_peers,
            &strict_close_peers,
            matured(first_seen),
        );

        let outcome = revalidate_record_prune_candidate(&candidate, &present_by_key, &inputs);

        assert!(matches!(
            outcome,
            PruneRevalidationOutcome::ClearedBackInRange
        ));
    }

    /// #12: a strict-close-group membership change after the audit round
    /// invalidates stale positive reports — only proofs from CURRENT members
    /// count toward the CURRENT group's threshold.
    #[test]
    fn revalidation_rejects_proofs_from_stale_close_group() {
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xB2);
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let old_close_group = peer_ids(PROD_CLOSE_GROUP);
        // Six positive proofs — a passing audit against the OLD group.
        let mut present_by_key = HashMap::new();
        present_by_key.insert(
            key,
            old_close_group[..6].iter().copied().collect::<HashSet<_>>(),
        );
        // The close group churned: only three audited peers remain members.
        let churned_close_group: Vec<PeerId> = old_close_group[4..7]
            .iter()
            .copied()
            .chain((20..24).map(peer_id_from_byte))
            .collect();
        let candidate = candidate(key, old_close_group);
        let first_seen = SystemTime::now();
        let inputs = revalidation_inputs(
            &self_id,
            Some(first_seen),
            false,
            &admission_peers,
            &churned_close_group,
            matured(first_seen),
        );

        let outcome = revalidate_record_prune_candidate(&candidate, &present_by_key, &inputs);

        assert!(
            matches!(outcome, PruneRevalidationOutcome::AuditFailed),
            "stale proofs must not satisfy the churned current close group"
        );
    }

    /// A commitment re-gossiped between candidate selection and deletion
    /// vetoes the deletion even with a full set of proofs (TOCTOU re-check).
    #[test]
    fn revalidation_vetoes_deletion_for_recommitted_key() {
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xB3);
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let candidate = candidate(key, strict_close_peers.clone());
        let mut present_by_key = HashMap::new();
        present_by_key.insert(key, strict_close_peers.iter().copied().collect());
        let first_seen = SystemTime::now();
        let inputs = revalidation_inputs(
            &self_id,
            Some(first_seen),
            true,
            &admission_peers,
            &strict_close_peers,
            matured(first_seen),
        );

        let outcome = revalidate_record_prune_candidate(&candidate, &present_by_key, &inputs);

        assert!(matches!(
            outcome,
            PruneRevalidationOutcome::HeldByCommitment
        ));
    }

    /// A concurrently cleared or reset out-of-range timestamp downgrades the
    /// candidate back to hysteresis-pending instead of deleting.
    #[test]
    fn revalidation_requires_hysteresis_to_still_hold() {
        let self_id = peer_id_from_byte(SELF_BYTE);
        let key = key_from_byte(0xB4);
        let admission_peers = peer_ids(PROD_RETENTION_WIDTH);
        let strict_close_peers = peer_ids(PROD_CLOSE_GROUP);
        let candidate = candidate(key, strict_close_peers.clone());
        let mut present_by_key = HashMap::new();
        present_by_key.insert(
            key,
            strict_close_peers
                .iter()
                .copied()
                .collect::<HashSet<PeerId>>(),
        );
        let now = SystemTime::now();

        for first_seen in [None, Some(now)] {
            let inputs = revalidation_inputs(
                &self_id,
                first_seen,
                false,
                &admission_peers,
                &strict_close_peers,
                now,
            );
            let outcome = revalidate_record_prune_candidate(&candidate, &present_by_key, &inputs);
            assert!(matches!(
                outcome,
                PruneRevalidationOutcome::HysteresisPending
            ));
        }
    }

    // -- Prune-audit response grading (#11) -----------------------------------

    const TEST_CHALLENGE_ID: u64 = 0x00C0_FFEE;
    const TEST_NONCE: [u8; 32] = [0xAB; 32];
    const TEST_RECORD_BYTES: &[u8] = b"prune audit record bytes";

    fn digests_response(challenge_id: u64, digests: Vec<[u8; 32]>) -> ReplicationMessage {
        ReplicationMessage {
            request_id: challenge_id,
            body: ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
                challenge_id,
                digests,
            }),
        }
    }

    fn graded_status(peer: &PeerId, key: &XorName, msg: ReplicationMessage) -> PruneAuditStatus {
        let expected = compute_audit_digest(&TEST_NONCE, peer.as_bytes(), key, TEST_RECORD_BYTES);
        let statuses =
            prune_audit_response_statuses(msg, TEST_CHALLENGE_ID, peer, &[(*key, expected)]);
        statuses
            .into_iter()
            .next()
            .map(|(_, status)| status)
            .expect("single-key batch returns exactly one status")
    }

    #[test]
    fn prune_audit_status_accepts_only_a_matching_digest() {
        let peer = peer_id_from_byte(1);
        let key = key_from_byte(0xC0);
        let valid = compute_audit_digest(&TEST_NONCE, peer.as_bytes(), &key, TEST_RECORD_BYTES);

        let status = graded_status(
            &peer,
            &key,
            digests_response(TEST_CHALLENGE_ID, vec![valid]),
        );

        assert_eq!(status, PruneAuditStatus::Proven);
    }

    #[test]
    fn prune_audit_status_rejects_absent_malformed_and_mismatching_responses() {
        let peer = peer_id_from_byte(1);
        let key = key_from_byte(0xC1);
        let valid = compute_audit_digest(&TEST_NONCE, peer.as_bytes(), &key, TEST_RECORD_BYTES);

        // Absent-key sentinel is a negative answer.
        let absent = digests_response(TEST_CHALLENGE_ID, vec![ABSENT_KEY_DIGEST]);
        assert_eq!(graded_status(&peer, &key, absent), PruneAuditStatus::Failed);

        // A digest over different bytes does not prove possession.
        let mismatch = digests_response(TEST_CHALLENGE_ID, vec![[0x11; 32]]);
        assert_eq!(
            graded_status(&peer, &key, mismatch),
            PruneAuditStatus::Failed
        );

        // A malformed digest count never counts.
        let wrong_count = digests_response(TEST_CHALLENGE_ID, vec![valid, valid]);
        assert_eq!(
            graded_status(&peer, &key, wrong_count),
            PruneAuditStatus::Failed
        );

        // A response bound to a different challenge never counts.
        let stale_challenge = digests_response(TEST_CHALLENGE_ID + 1, vec![valid]);
        assert_eq!(
            graded_status(&peer, &key, stale_challenge),
            PruneAuditStatus::Failed
        );

        // An explicit rejection never counts as a positive proof; it grades to
        // the distinct `Rejected` status (a non-recovering, labelled failure).
        let rejected = ReplicationMessage {
            request_id: TEST_CHALLENGE_ID,
            body: ReplicationMessageBody::AuditResponse(AuditResponse::Rejected {
                challenge_id: TEST_CHALLENGE_ID,
                reason: "test".to_string(),
            }),
        };
        assert_eq!(
            graded_status(&peer, &key, rejected),
            PruneAuditStatus::Rejected
        );

        // An unexpected message type never counts.
        let unexpected = ReplicationMessage {
            request_id: TEST_CHALLENGE_ID,
            body: ReplicationMessageBody::AuditChallenge(AuditChallenge {
                challenge_id: TEST_CHALLENGE_ID,
                nonce: TEST_NONCE,
                challenged_peer_id: *peer.as_bytes(),
                keys: vec![key],
            }),
        };
        assert_eq!(
            graded_status(&peer, &key, unexpected),
            PruneAuditStatus::Failed
        );
    }

    /// A rejection is never a possession signal, so it maps to the distinct
    /// `Rejected` status (which drives a labelled, non-recovering penalty), and
    /// its `reason` text is never parsed. A challenge-id mismatch stays a plain
    /// `Failed`.
    #[test]
    fn any_rejection_reason_maps_to_the_rejected_status_without_parsing() {
        let peer = peer_id_from_byte(1);
        let key = key_from_byte(0xC3);

        for reason in [
            "challenge contains 83 keys, limit is 60",
            "challenged_peer_id does not match this node",
            "some future reason we have never seen",
        ] {
            let rejected = ReplicationMessage {
                request_id: TEST_CHALLENGE_ID,
                body: ReplicationMessageBody::AuditResponse(AuditResponse::Rejected {
                    challenge_id: TEST_CHALLENGE_ID,
                    reason: reason.to_string(),
                }),
            };
            assert_eq!(
                graded_status(&peer, &key, rejected),
                PruneAuditStatus::Rejected,
                "reason {reason:?} should map to Rejected regardless of wording"
            );
        }

        let mismatched = ReplicationMessage {
            request_id: TEST_CHALLENGE_ID,
            body: ReplicationMessageBody::AuditResponse(AuditResponse::Rejected {
                challenge_id: TEST_CHALLENGE_ID + 1,
                reason: "challenge contains 83 keys, limit is 60".to_string(),
            }),
        };
        assert_eq!(
            graded_status(&peer, &key, mismatched),
            PruneAuditStatus::Failed,
            "a challenge-id mismatch is a plain failure, not a capacity signal"
        );
    }

    #[test]
    fn prune_audit_status_bootstrap_claim_is_not_a_positive_proof() {
        let peer = peer_id_from_byte(1);
        let key = key_from_byte(0xC2);

        let bootstrapping = ReplicationMessage {
            request_id: TEST_CHALLENGE_ID,
            body: ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping {
                challenge_id: TEST_CHALLENGE_ID,
            }),
        };
        assert_eq!(
            graded_status(&peer, &key, bootstrapping),
            PruneAuditStatus::Bootstrapping
        );

        let mismatched = ReplicationMessage {
            request_id: TEST_CHALLENGE_ID,
            body: ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping {
                challenge_id: TEST_CHALLENGE_ID + 1,
            }),
        };
        assert_eq!(
            graded_status(&peer, &key, mismatched),
            PruneAuditStatus::Failed
        );
    }
}
