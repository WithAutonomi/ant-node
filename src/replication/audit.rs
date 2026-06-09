//! Storage audit protocol (Section 15).
//!
//! Challenge-response for claimed holders. Anti-outsourcing protection.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::logging::{debug, info, warn};
use rand::seq::SliceRandom;
use rand::Rng;

use crate::ant_protocol::XorName;
use crate::replication::commitment::{commitment_hash, CommitmentBoundResult, StorageCommitment};
use crate::replication::commitment_audit::{
    verify_commitment_bound_metadata, verify_commitment_bound_per_key,
};
use crate::replication::commitment_state::PeerCommitmentRecord;
use crate::replication::config::{ReplicationConfig, REPLICATION_PROTOCOL_ID};
use crate::replication::protocol::{
    compute_audit_digest, AuditChallenge, AuditResponse, ReplicationMessage,
    ReplicationMessageBody, ABSENT_KEY_DIGEST,
};
use crate::replication::recent_provers::RecentProvers;
use crate::replication::types::{
    AuditFailureReason, AuditFailureSummary, FailureEvidence, PeerSyncRecord, RepairProofs,
};
use crate::storage::LmdbStorage;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Audit tick result
// ---------------------------------------------------------------------------

/// Result of an audit tick.
#[derive(Debug)]
pub enum AuditTickResult {
    /// Audit completed successfully (all digests matched).
    Passed {
        /// The peer that was challenged.
        challenged_peer: PeerId,
        /// Number of keys verified.
        keys_checked: usize,
    },
    /// Audit found failures (after responsibility confirmation).
    Failed {
        /// Evidence of the failure for trust engine.
        evidence: FailureEvidence,
    },
    /// Audit target claimed bootstrapping.
    BootstrapClaim {
        /// The peer claiming bootstrap status.
        peer: PeerId,
    },
    /// No eligible peers for audit this tick.
    Idle,
    /// Audit skipped (not enough local keys).
    InsufficientKeys,
}

// ---------------------------------------------------------------------------
// Main audit tick
// ---------------------------------------------------------------------------

/// Read-only context the auditor uses to issue commitment-bound audits.
///
/// Bundled into one struct so [`audit_tick_with_repair_proofs`] stays
/// readable when v12 enforcement is enabled. Passing `None` falls back
/// to today's plain-digest audit; passing `Some` opts in on a per-peer
/// basis (a peer with no entry in `last_commitment_by_peer` still gets
/// the legacy path).
///
/// `last_commitment_by_peer` and `recent_provers` are owned by
/// [`crate::replication::ReplicationEngine`]; this struct borrows them.
pub struct CommitmentAuditCtx<'a> {
    /// Per-peer record: last-known commitment + sticky `commitment_capable`
    /// flag (populated from gossip ingest). The auditor pins
    /// `commitment_hash(record.last_commitment)` into the challenge for
    /// any peer whose record carries a commitment.
    pub last_commitment_by_peer: &'a Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    /// Sticky "ever v12-capable" set, independent of
    /// `last_commitment_by_peer` (whose entries can be evicted by
    /// `PeerRemoved` and the sybil cap). The §3 audit shield consults
    /// this so a previously-v12 peer whose LRU record was evicted
    /// still gets the no-legacy-fallback treatment until they
    /// re-gossip a fresh commitment.
    pub ever_capable_peers: &'a Arc<RwLock<HashSet<PeerId>>>,
    /// Holder-eligibility cache. On a successful commitment-bound audit
    /// the auditor records `(challenged_peer, key, commitment_hash)` so
    /// downstream code (quorum, paid lists) can credit the peer as a
    /// real holder.
    pub recent_provers: &'a Arc<RwLock<RecentProvers>>,
}

/// Execute one audit tick (Section 15 steps 2-9).
///
/// Returns the audit result. Caller is responsible for emitting trust events.
///
/// **Invariant 19**: Returns [`AuditTickResult::Idle`] immediately if
/// `is_bootstrapping` is `true` — a node must not audit others while it
/// is still bootstrapping.
#[allow(clippy::implicit_hasher)]
pub async fn audit_tick(
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    config: &ReplicationConfig,
    sync_history: &HashMap<PeerId, PeerSyncRecord>,
    is_bootstrapping: bool,
) -> AuditTickResult {
    let repair_proofs = Arc::new(RwLock::new(RepairProofs::new()));
    audit_tick_with_repair_proofs(
        p2p_node,
        storage,
        config,
        sync_history,
        &repair_proofs,
        0,
        is_bootstrapping,
        None,
    )
    .await
}

/// Execute one repair-proof-gated audit tick.
///
/// This is the production path used by the replication engine. The
/// compatibility [`audit_tick`] wrapper passes an empty proof table, so direct
/// callers that have not adopted repair proofs remain conservative and do not
/// audit peers for unproven keys.
#[allow(
    clippy::implicit_hasher,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
pub async fn audit_tick_with_repair_proofs(
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    config: &ReplicationConfig,
    sync_history: &HashMap<PeerId, PeerSyncRecord>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    current_sync_epoch: u64,
    is_bootstrapping: bool,
    commitment_ctx: Option<&CommitmentAuditCtx<'_>>,
) -> AuditTickResult {
    // Invariant 19: never audit while still bootstrapping.
    if is_bootstrapping {
        return AuditTickResult::Idle;
    }

    let dht = p2p_node.dht_manager();

    // Step 2: Select one eligible peer (has RepairOpportunity) at random.
    // Peers with active bootstrap claims remain eligible. A follow-up audit is
    // how we observe a continued claim and apply past-grace abuse handling.
    let eligible_peers = eligible_audit_peers(sync_history);

    if eligible_peers.is_empty() {
        return AuditTickResult::Idle;
    }

    let (challenged_peer, nonce, challenge_id) = {
        let mut rng = rand::thread_rng();
        let selected = match eligible_peers.choose(&mut rng) {
            Some(p) => *p,
            None => return AuditTickResult::Idle,
        };
        let n: [u8; 32] = rng.gen();
        let c: u64 = rng.gen();
        (selected, n, c)
    };

    // Step 3: Sample keys from local store and keep those the peer is
    // responsible for (appears in the close group via local RT lookup).
    let all_keys = match storage.all_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Audit: failed to read local keys: {e}");
            return AuditTickResult::Idle;
        }
    };

    if all_keys.is_empty() {
        return AuditTickResult::Idle;
    }

    let sample_count = ReplicationConfig::audit_sample_count(all_keys.len());
    let sampled_keys: Vec<XorName> = {
        let mut rng = rand::thread_rng();
        all_keys
            .choose_multiple(&mut rng, sample_count)
            .copied()
            .collect()
    };

    // Step 4: Filter to keys where the chosen peer is in the close group and
    // this node has proof that it already sent the peer a repair hint for the
    // specific key.
    let mut sampled_key_groups = Vec::new();
    for key in &sampled_keys {
        let closest = dht
            .find_closest_nodes_local_with_self(key, config.close_group_size)
            .await;
        let close_peers: HashSet<PeerId> = closest.iter().map(|node| node.peer_id).collect();
        if close_peers.contains(&challenged_peer) {
            sampled_key_groups.push((*key, close_peers));
        }
    }

    let peer_keys = {
        let mut proofs = repair_proofs.write().await;
        mature_audit_keys_for_peer(
            &challenged_peer,
            sampled_key_groups,
            &mut proofs,
            current_sync_epoch,
        )
    };

    if peer_keys.is_empty() {
        return AuditTickResult::Idle;
    }

    // peer_keys is naturally bounded by audit_sample_count (sqrt-scaled),
    // so no explicit truncation needed.

    // Step 6: Send challenge.
    //
    // Phase 3: if we have a commitment audit context AND we have a last
    // known commitment from this peer (received via gossip), pin its
    // hash into the challenge so the responder must answer against the
    // exact commitment whose hash we pinned. Defeats fresh-commitment
    // substitution by lazy nodes (v12 §5 gate 2b).
    //
    // We snapshot the pinned commitment alongside the hash so the
    // response-handling code can verify against the SAME commitment we
    // pinned (avoids a race where the peer's last_commitment_by_peer
    // entry rotates between issue and response handling).
    // Snapshot the peer record once; we use it both for pinning the
    // challenge and (below) for the §3 commitment_capable downgrade
    // check. Record carries last_commitment + sticky `commitment_capable`.
    let peer_record = match commitment_ctx {
        Some(ctx) => ctx
            .last_commitment_by_peer
            .read()
            .await
            .get(&challenged_peer)
            .cloned(),
        None => None,
    };
    // Only the pin (hash) is needed to issue the challenge; the
    // responder answers against its own retained commitment, so we
    // never need to clone the full StorageCommitment here.
    let expected_commitment_hash = peer_record
        .as_ref()
        .and_then(|r| r.last_commitment.as_ref())
        .and_then(commitment_hash);

    // §3 + §6 bootstrap-claim shield: if this peer has EVER gossiped a
    // commitment we MUST NOT fall back to legacy plain-digest audits
    // when we currently lack their cached commitment. The peer is
    // expected to speak v12; falling back would let them downgrade to
    // the weaker path. Return Idle until they re-gossip a fresh
    // commitment.
    //
    // We consult two sources for the sticky-capable signal: the per-
    // record `commitment_capable` bit (still set on the active LRU
    // entry) AND the `ever_capable_peers` set (preserved across
    // PeerRemoved cleanup and sybil-cap eviction of the LRU). Either
    // one being true engages the shield.
    let is_capable = peer_record.as_ref().is_some_and(|r| r.commitment_capable)
        || match commitment_ctx {
            Some(ctx) => ctx
                .ever_capable_peers
                .read()
                .await
                .contains(&challenged_peer),
            None => false,
        };
    let has_current_commitment = peer_record
        .as_ref()
        .is_some_and(|r| r.last_commitment.is_some());
    if is_capable && !has_current_commitment {
        // BY DESIGN this is a no-penalty path: a capable-but-silent peer is
        // never strike-penalised here (Idle records no strike). It gains
        // nothing by going silent — its §6 holder credit independently
        // expires (PROVER_ENTRY_TTL), so it stops being counted as a holder
        // for quorum/paid-list. We skip rather than penalise because the
        // missing commitment is indistinguishable from honest TTL/restart
        // churn; the next fresh gossip re-enables auditing.
        info!(
            "Audit: peer {challenged_peer} is commitment-capable but we have no \
             cached commitment (TTL/restart/silence); skipping audit until fresh gossip"
        );
        return AuditTickResult::Idle;
    }

    let challenge = AuditChallenge {
        challenge_id,
        nonce,
        challenged_peer_id: *challenged_peer.as_bytes(),
        keys: peer_keys.clone(),
        expected_commitment_hash,
    };

    let msg = ReplicationMessage {
        request_id: challenge_id,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };

    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Audit: failed to encode challenge: {e}");
            return AuditTickResult::Idle;
        }
    };

    let response = match p2p_node
        .send_request(
            &challenged_peer,
            REPLICATION_PROTOCOL_ID,
            encoded,
            config.audit_response_timeout(peer_keys.len()),
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            debug!("Audit: challenge to {challenged_peer} failed: {e}");
            // Timeout — need responsibility confirmation before penalty.
            return handle_audit_timeout(
                &challenged_peer,
                challenge_id,
                &peer_keys,
                p2p_node,
                config,
            )
            .await;
        }
    };

    // Step 7: Parse response.
    let resp_msg = match ReplicationMessage::decode(&response.data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Audit: failed to decode response from {challenged_peer}: {e}");
            return handle_audit_failure(
                &challenged_peer,
                challenge_id,
                &peer_keys,
                AuditFailureReason::MalformedResponse,
                p2p_node,
                config,
            )
            .await;
        }
    };

    match resp_msg.body {
        ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping {
            challenge_id: resp_id,
        }) => {
            if resp_id != challenge_id {
                warn!("Audit: challenge ID mismatch on Bootstrapping from {challenged_peer}");
                return handle_audit_failure(
                    &challenged_peer,
                    challenge_id,
                    &peer_keys,
                    AuditFailureReason::MalformedResponse,
                    p2p_node,
                    config,
                )
                .await;
            }
            // Step 7b: Bootstrapping claim.
            AuditTickResult::BootstrapClaim {
                peer: challenged_peer,
            }
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
            challenge_id: resp_id,
            digests,
        }) => {
            if resp_id != challenge_id {
                warn!("Audit: challenge ID mismatch from {challenged_peer}");
                return handle_audit_failure(
                    &challenged_peer,
                    challenge_id,
                    &peer_keys,
                    AuditFailureReason::MalformedResponse,
                    p2p_node,
                    config,
                )
                .await;
            }
            // Wire-contract enforcement (codex round-9 MAJOR): when we
            // pinned a commitment hash into the challenge, the responder
            // MUST answer with CommitmentBound or Rejected/Bootstrapping.
            // Falling back to plain Digests would let a peer that has
            // already gossiped a commitment ignore the storage-bound
            // path and pass via on-demand fetch under the weaker legacy
            // verifier. Treat as malformed.
            if expected_commitment_hash.is_some() {
                warn!(
                    "Audit: peer {challenged_peer} answered Digests to a pinned challenge \
                     (commitment-bound contract violation) — treating as malformed"
                );
                return handle_audit_failure(
                    &challenged_peer,
                    challenge_id,
                    &peer_keys,
                    AuditFailureReason::MalformedResponse,
                    p2p_node,
                    config,
                )
                .await;
            }
            verify_digests(
                &challenged_peer,
                challenge_id,
                &nonce,
                &peer_keys,
                &digests,
                storage,
                p2p_node,
                config,
            )
            .await
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::Rejected {
            challenge_id: resp_id,
            reason,
        }) => {
            if resp_id != challenge_id {
                warn!("Audit: challenge ID mismatch on Rejected from {challenged_peer}");
                return handle_audit_failure(
                    &challenged_peer,
                    challenge_id,
                    &peer_keys,
                    AuditFailureReason::MalformedResponse,
                    p2p_node,
                    config,
                )
                .await;
            }
            // v12 paragraph 5 conditional invalidation, refined:
            //
            // When we issued a pinned challenge and the peer responds
            // "unknown commitment hash", DO NOT drop the pin and DO NOT
            // give a free pass. Two reasons:
            //
            //   1. If the peer genuinely rotated past our pin (honest
            //      case), their two-slot retention (current+previous)
            //      means they could still answer one rotation back —
            //      so "unknown" here means we are at least two
            //      rotations behind their gossip. The next gossip round
            //      (a few minutes) will bring us a fresh commitment to
            //      pin, and the cache entry will be replaced naturally
            //      via the gossip ingest path. We don't need to drop
            //      anything ourselves.
            //
            //   2. If we drop the pin on "unknown", a malicious peer
            //      can claim "unknown" to shed every pinned audit they
            //      receive — the next tick has no pin → legacy plain-
            //      digest path → on-demand fetch attack reopens
            //      (codex round-8 MAJOR).
            //
            // So: when the responder says "unknown" AND we pinned, log
            // and return Idle without penalty (one tick wasted) but
            // KEEP the pin. The honest case self-resolves via gossip;
            // the malicious case keeps re-failing pinned audits until
            // their trust drops naturally through other mechanisms or
            // we receive a fresh gossiped commitment. Strict gating on
            // exact reason + pinned challenge prevents the round-6
            // bypass (a peer cannot trigger this path on a legacy
            // unpinned audit because expected_commitment_hash is None).
            if expected_commitment_hash.is_some() && reason == "unknown commitment hash" {
                // v12 §5 conditional invalidation:
                // - Case 1 (lazy rotation): peer dropped bytes, no fresh
                //   gossip, still pinned to H. Stored hash == H. Clear
                //   the pin → recent_provers entries lose their match
                //   basis → credit dropped via is_credited_holder. This
                //   is now safe because §3 above causes the next audit
                //   to return Idle (commitment_capable but no
                //   last_commitment) instead of falling back to legacy.
                // - Case 2 (honest rotation): peer gossiped C2 between
                //   our challenge and processing. Stored hash != H.
                //   Keep the new C2 entry, drop credits anchored to H.
                // - Case 3 (stale auditor): same as case 1; clear pin,
                //   wait for next gossip.
                if let (Some(ctx), Some(pin)) = (commitment_ctx, expected_commitment_hash) {
                    let mut last = ctx.last_commitment_by_peer.write().await;
                    if let Some(rec) = last.get_mut(&challenged_peer) {
                        let stored_h = rec.last_commitment.as_ref().and_then(commitment_hash);
                        if stored_h == Some(pin) {
                            // Still the rejected commitment — clear it
                            // but keep `commitment_capable` sticky.
                            rec.last_commitment = None;
                        }
                        // else: a fresh commitment arrived in the meantime;
                        // leave it untouched (don't clobber).
                    }
                    drop(last);
                    // Drop credit anchored to the now-stale pin so the
                    // peer must re-prove every key under the new
                    // commitment to keep holder status (v12 §6).
                    ctx.recent_provers.write().await.forget_commitment(&pin);
                }
                info!(
                    "Audit: peer {challenged_peer} rotated past pinned commitment; \
                     dropped stale pin and credits (no trust penalty)"
                );
                return AuditTickResult::Idle;
            }
            // v12 paragraph 5: "key not in commitment" is also a benign
            // staleness signal, NOT a failure. The auditor sampled a key
            // it holds and that the peer SHOULD hold (close-group), but
            // which the peer hasn't yet committed to (e.g. just-replicated
            // after their last rotation). Penalising this would punish
            // honest peers who have the bytes but haven't rebuilt their
            // Merkle tree yet (codex round-11 MAJOR #2).
            if expected_commitment_hash.is_some() && reason.starts_with("key not in commitment") {
                info!(
                    "Audit: peer {challenged_peer} reports key-not-in-commitment; \
                     skipping (responder commitment is stale relative to its key set)"
                );
                return AuditTickResult::Idle;
            }
            warn!("Audit: challenge rejected by {challenged_peer}: {reason}");
            handle_audit_failure(
                &challenged_peer,
                challenge_id,
                &peer_keys,
                AuditFailureReason::Rejected,
                p2p_node,
                config,
            )
            .await
        }
        ReplicationMessageBody::AuditResponse(AuditResponse::CommitmentBound {
            challenge_id: resp_id,
            commitment,
            per_key,
        }) => {
            if resp_id != challenge_id {
                warn!("Audit: challenge ID mismatch on CommitmentBound from {challenged_peer}");
                return handle_audit_failure(
                    &challenged_peer,
                    challenge_id,
                    &peer_keys,
                    AuditFailureReason::MalformedResponse,
                    p2p_node,
                    config,
                )
                .await;
            }
            verify_commitment_bound(
                &challenged_peer,
                challenge_id,
                &nonce,
                &peer_keys,
                expected_commitment_hash.as_ref(),
                &commitment,
                &per_key,
                storage,
                p2p_node,
                config,
                commitment_ctx,
            )
            .await
        }
        _ => {
            warn!("Audit: unexpected response type from {challenged_peer}");
            handle_audit_failure(
                &challenged_peer,
                challenge_id,
                &peer_keys,
                AuditFailureReason::MalformedResponse,
                p2p_node,
                config,
            )
            .await
        }
    }
}

fn eligible_audit_peers(sync_history: &HashMap<PeerId, PeerSyncRecord>) -> Vec<PeerId> {
    sync_history
        .iter()
        .filter(|(_, record)| record.has_repair_opportunity())
        .map(|(peer, _)| *peer)
        .collect()
}

fn mature_audit_keys_for_peer(
    challenged_peer: &PeerId,
    sampled_key_groups: Vec<(XorName, HashSet<PeerId>)>,
    repair_proofs: &mut RepairProofs,
    current_sync_epoch: u64,
) -> Vec<XorName> {
    sampled_key_groups
        .into_iter()
        .filter_map(|(key, close_peers)| {
            repair_proofs
                .has_mature_replica_hint(challenged_peer, &key, &close_peers, current_sync_epoch)
                .then_some(key)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditKeyFailureKind {
    Absent,
    DigestMismatch,
    Unclassified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuditKeyFailure {
    key: XorName,
    kind: AuditKeyFailureKind,
}

impl AuditKeyFailure {
    fn absent(key: XorName) -> Self {
        Self {
            key,
            kind: AuditKeyFailureKind::Absent,
        }
    }

    fn digest_mismatch(key: XorName) -> Self {
        Self {
            key,
            kind: AuditKeyFailureKind::DigestMismatch,
        }
    }

    fn unclassified(key: XorName) -> Self {
        Self {
            key,
            kind: AuditKeyFailureKind::Unclassified,
        }
    }
}

fn build_audit_failure_summary(
    challenged_key_count: usize,
    confirmed_failures: &[AuditKeyFailure],
) -> AuditFailureSummary {
    let mut summary = AuditFailureSummary {
        challenged_keys: challenged_key_count,
        failed_keys: confirmed_failures.len(),
        ..AuditFailureSummary::default()
    };

    for failure in confirmed_failures {
        match failure.kind {
            AuditKeyFailureKind::Absent => summary.absent_keys += 1,
            AuditKeyFailureKind::DigestMismatch => summary.digest_mismatch_keys += 1,
            AuditKeyFailureKind::Unclassified => {}
        }
    }

    summary
}

fn audit_digest_failure_reason(confirmed_failures: &[AuditKeyFailure]) -> AuditFailureReason {
    if confirmed_failures
        .iter()
        .all(|failure| failure.kind == AuditKeyFailureKind::Absent)
    {
        AuditFailureReason::KeyAbsent
    } else {
        AuditFailureReason::DigestMismatch
    }
}

// ---------------------------------------------------------------------------
// Digest verification
// ---------------------------------------------------------------------------

/// Verify per-key digests from audit response (Step 8).
#[allow(clippy::too_many_arguments)]
async fn verify_digests(
    challenged_peer: &PeerId,
    challenge_id: u64,
    nonce: &[u8; 32],
    keys: &[XorName],
    digests: &[[u8; 32]],
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> AuditTickResult {
    // Requirement: response must have exactly one digest per key.
    if digests.len() != keys.len() {
        warn!(
            "Audit: malformed response from {challenged_peer}: {} digests for {} keys",
            digests.len(),
            keys.len()
        );
        return handle_audit_failure(
            challenged_peer,
            challenge_id,
            keys,
            AuditFailureReason::MalformedResponse,
            p2p_node,
            config,
        )
        .await;
    }

    let challenged_peer_bytes = challenged_peer.as_bytes();
    let mut failed_keys = Vec::new();

    for (i, key) in keys.iter().enumerate() {
        let received_digest = &digests[i];

        // Check for absent sentinel.
        if *received_digest == ABSENT_KEY_DIGEST {
            failed_keys.push(AuditKeyFailure::absent(*key));
            continue;
        }

        // Recompute expected digest from local copy.
        let local_bytes = match storage.get_raw(key).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // We should hold this key (we sampled it), but it's gone.
                warn!(
                    "Audit: local key {} disappeared during audit",
                    hex::encode(key)
                );
                continue;
            }
            Err(e) => {
                warn!("Audit: failed to read local key {}: {e}", hex::encode(key));
                continue;
            }
        };

        let expected = compute_audit_digest(nonce, challenged_peer_bytes, key, &local_bytes);
        if *received_digest != expected {
            failed_keys.push(AuditKeyFailure::digest_mismatch(*key));
        }
    }

    if failed_keys.is_empty() {
        info!(
            "Audit: peer {challenged_peer} passed (all {} keys verified)",
            keys.len()
        );
        return AuditTickResult::Passed {
            challenged_peer: *challenged_peer,
            keys_checked: keys.len(),
        };
    }

    // Step 9: Responsibility confirmation for failed keys.
    handle_classified_audit_failure(
        challenged_peer,
        challenge_id,
        &failed_keys,
        AuditFailureReason::DigestMismatch,
        keys.len(),
        p2p_node,
        config,
    )
    .await
}

// ---------------------------------------------------------------------------
// Commitment-bound verification (v12)
// ---------------------------------------------------------------------------

/// Verify a `CommitmentBound` audit response (Step 8, v12 path).
///
/// Runs the pure verifier `verify_commitment_bound_response` against the
/// commitment we pinned (NOT the one in the response — the response's
/// commitment must hash-match the pin), then on success records the
/// challenged peer as a recent prover for each verified key.
///
/// The verifier checks five gates: structural, peer-id binding, pin,
/// signature (using the pubkey embedded in the commitment), and per-key
/// (`bytes_hash` + Merkle path + audit digest). Any failure path → standard
/// `AUDIT_FAILURE_TRUST_WEIGHT × keys` penalty.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn verify_commitment_bound(
    challenged_peer: &PeerId,
    challenge_id: u64,
    nonce: &[u8; 32],
    keys: &[XorName],
    expected_commitment_hash: Option<&[u8; 32]>,
    response_commitment: &StorageCommitment,
    response_per_key: &[CommitmentBoundResult],
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    commitment_ctx: Option<&CommitmentAuditCtx<'_>>,
) -> AuditTickResult {
    // Sanity: a CommitmentBound response must have been answered to a
    // pinned challenge. If we didn't pin (or have no ctx), this is a
    // protocol violation by the peer.
    let Some(pin) = expected_commitment_hash else {
        warn!(
            "Audit: peer {challenged_peer} sent CommitmentBound for an unpinned challenge — \
             treating as malformed"
        );
        return handle_audit_failure(
            challenged_peer,
            challenge_id,
            keys,
            AuditFailureReason::MalformedResponse,
            p2p_node,
            config,
        )
        .await;
    };

    // Metadata gates (structural / peer-id / pin / sig). One-shot, cheap.
    if let Err(e) = verify_commitment_bound_metadata(
        keys,
        challenged_peer.as_bytes(),
        pin,
        response_commitment,
        response_per_key,
    ) {
        warn!(
            "Audit: peer {challenged_peer} failed commitment-bound metadata: {e} (pin={})",
            hex::encode(pin),
        );
        return handle_audit_failure(
            challenged_peer,
            challenge_id,
            keys,
            AuditFailureReason::DigestMismatch,
            p2p_node,
            config,
        )
        .await;
    }

    // Per-key gates streamed one chunk at a time. Avoids the
    // sqrt(n)*MAX_CHUNK_SIZE worst case of preloading every challenged
    // chunk (~4 GiB at 1M stored chunks).
    //
    // Verified keys are collected for holder-credit attribution at the
    // end of the loop. A key that disappears locally between sampling
    // and verification is skipped without penalising the responder
    // (matches the legacy `verify_digests` `continue` semantics; the
    // responder is not at fault for the auditor's storage churn).
    let mut verified_keys: Vec<XorName> = Vec::with_capacity(response_per_key.len());
    let mut failed_keys: Vec<XorName> = Vec::new();
    for (i, result) in response_per_key.iter().enumerate() {
        let local_bytes = match storage.get_raw(&result.key).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                debug!(
                    "Audit: local key {} disappeared between sampling and verification; skipping",
                    hex::encode(result.key)
                );
                continue;
            }
            Err(e) => {
                warn!(
                    "Audit: failed to read local key {}: {e}",
                    hex::encode(result.key)
                );
                continue;
            }
        };

        if let Err(e) = verify_commitment_bound_per_key(
            i,
            nonce,
            challenged_peer.as_bytes(),
            response_commitment,
            result,
            &local_bytes,
        ) {
            warn!(
                "Audit: peer {challenged_peer} failed commitment-bound per-key #{i}: {e} \
                 (pin={})",
                hex::encode(pin),
            );
            // Track only the failing key. Match the legacy
            // `verify_digests` semantics: continue verifying other keys
            // and penalise only the ones that actually failed, rather
            // than escalating a single per-key failure to the whole
            // challenge batch. `local_bytes` drops here, bounding peak
            // memory at one chunk.
            failed_keys.push(result.key);
            continue;
        }
        verified_keys.push(result.key);
    }

    if !failed_keys.is_empty() {
        return handle_audit_failure(
            challenged_peer,
            challenge_id,
            &failed_keys,
            AuditFailureReason::DigestMismatch,
            p2p_node,
            config,
        )
        .await;
    }

    if verified_keys.is_empty() {
        // Every challenged key was locally unavailable. We have no
        // evidence either way — return Idle without trust events.
        debug!(
            "Audit: peer {challenged_peer} commitment-bound audit had no locally-verifiable keys"
        );
        return AuditTickResult::Idle;
    }

    info!(
        "Audit: peer {challenged_peer} passed commitment-bound audit ({}/{} keys verified, pin={})",
        verified_keys.len(),
        keys.len(),
        hex::encode(pin),
    );
    // Credit the peer as a holder for each VERIFIED key under this
    // exact commitment hash (skipped keys are not credited — we never
    // confirmed them). Downstream (quorum, paid lists) can read
    // `recent_provers.is_credited_holder(...)`.
    if let Some(ctx) = commitment_ctx {
        let now = std::time::Instant::now();
        let mut guard = ctx.recent_provers.write().await;
        for key in &verified_keys {
            guard.record_proof(*key, *challenged_peer, *pin, now);
        }
    }
    AuditTickResult::Passed {
        challenged_peer: *challenged_peer,
        keys_checked: verified_keys.len(),
    }
}

// ---------------------------------------------------------------------------
// Failure handling with responsibility confirmation
// ---------------------------------------------------------------------------

/// Handle audit failure: confirm responsibility before emitting evidence (Step 9).
async fn handle_audit_failure(
    challenged_peer: &PeerId,
    challenge_id: u64,
    failed_keys: &[XorName],
    reason: AuditFailureReason,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> AuditTickResult {
    let failures = failed_keys
        .iter()
        .copied()
        .map(AuditKeyFailure::unclassified)
        .collect::<Vec<_>>();
    handle_classified_audit_failure(
        challenged_peer,
        challenge_id,
        &failures,
        reason,
        failed_keys.len(),
        p2p_node,
        config,
    )
    .await
}

async fn handle_classified_audit_failure(
    challenged_peer: &PeerId,
    challenge_id: u64,
    failed_keys: &[AuditKeyFailure],
    reason: AuditFailureReason,
    challenged_key_count: usize,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> AuditTickResult {
    let dht = p2p_node.dht_manager();
    let mut confirmed_failures = Vec::new();

    // Step 9a-b: Fresh local RT lookup for each failed key.
    for failure in failed_keys {
        let closest = dht
            .find_closest_nodes_local_with_self(&failure.key, config.close_group_size)
            .await;
        if closest.iter().any(|n| n.peer_id == *challenged_peer) {
            confirmed_failures.push(*failure);
        } else {
            debug!(
                "Audit: peer {challenged_peer} not responsible for {} (removed from failure set)",
                hex::encode(failure.key)
            );
        }
    }

    // Step 9c: Empty confirmed set -> peer is no longer responsible for any
    // of the failed keys (topology churn). This is NOT a pass — the peer did
    // not prove it stores the data. Return Idle to avoid granting unearned
    // positive trust.
    if confirmed_failures.is_empty() {
        info!("Audit: all failures for {challenged_peer} cleared by responsibility confirmation");
        return AuditTickResult::Idle;
    }

    let summary = build_audit_failure_summary(challenged_key_count, &confirmed_failures);
    let reason = if reason == AuditFailureReason::DigestMismatch {
        audit_digest_failure_reason(&confirmed_failures)
    } else {
        reason
    };
    let confirmed_failed_keys = confirmed_failures
        .iter()
        .map(|failure| failure.key)
        .collect();

    // Step 9d: Non-empty confirmed set -> emit evidence.
    let evidence = FailureEvidence::AuditFailure {
        challenge_id,
        challenged_peer: *challenged_peer,
        confirmed_failed_keys,
        summary,
        reason,
    };

    AuditTickResult::Failed { evidence }
}

/// Handle audit timeout (no response received).
async fn handle_audit_timeout(
    challenged_peer: &PeerId,
    challenge_id: u64,
    keys: &[XorName],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> AuditTickResult {
    handle_audit_failure(
        challenged_peer,
        challenge_id,
        keys,
        AuditFailureReason::Timeout,
        p2p_node,
        config,
    )
    .await
}

// ---------------------------------------------------------------------------
// Responder-side handler
// ---------------------------------------------------------------------------

/// Handle an incoming audit challenge (responder side).
///
/// Validates that the challenge targets this node, computes per-key digests,
/// and returns the response.  Rejects challenges where
/// `challenged_peer_id` does not match `self_peer_id` to prevent an oracle
/// attack where a malicious challenger forges digests for a different peer.
pub async fn handle_audit_challenge(
    challenge: &AuditChallenge,
    storage: &LmdbStorage,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    stored_chunks: usize,
) -> AuditResponse {
    handle_audit_challenge_with_commitment(
        challenge,
        storage,
        self_peer_id,
        is_bootstrapping,
        stored_chunks,
        None,
    )
    .await
}

/// Like [`handle_audit_challenge`] but also accepts a responder's
/// `ResponderCommitmentState`. If the challenge carries
/// `expected_commitment_hash: Some(h)`, dispatches to the v12
/// commitment-bound response path (gates: structural / pin / signature
/// / per-key path+digest); otherwise falls through to the legacy
/// plain-digest path.
///
/// Backwards-compatible: existing callers that don't have a
/// `ResponderCommitmentState` keep calling `handle_audit_challenge`,
/// which forwards here with `commitment_state = None`.
#[allow(clippy::too_long_first_doc_paragraph, clippy::too_many_lines)]
pub async fn handle_audit_challenge_with_commitment(
    challenge: &AuditChallenge,
    storage: &LmdbStorage,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    stored_chunks: usize,
    commitment_state: Option<
        &std::sync::Arc<crate::replication::commitment_state::ResponderCommitmentState>,
    >,
) -> AuditResponse {
    if is_bootstrapping {
        return AuditResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    if challenge.challenged_peer_id != *self_peer_id.as_bytes() {
        warn!(
            "Audit challenge targeted wrong peer: expected {}, got {}",
            hex::encode(self_peer_id.as_bytes()),
            hex::encode(challenge.challenged_peer_id),
        );
        return AuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: "challenged_peer_id does not match this node".to_string(),
        };
    }

    let max_keys = ReplicationConfig::max_incoming_audit_keys(stored_chunks);
    if challenge.keys.len() > max_keys {
        warn!(
            "Audit challenge rejected: {} keys exceeds dynamic limit of {max_keys} \
             (stored_chunks={stored_chunks})",
            challenge.keys.len(),
        );
        return AuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: format!(
                "challenge contains {} keys, limit is {max_keys}",
                challenge.keys.len()
            ),
        };
    }

    // v12 commitment-bound path: when the auditor pinned a specific
    // commitment, look it up in our state and produce a CommitmentBound
    // response. If we don't have that commitment (rotated away, never
    // gossiped, etc.) reject with reason="unknown commitment hash" —
    // the auditor's v12 paragraph 5 handler keeps the pin (no penalty)
    // and waits for fresh gossip to replace it.
    if let (Some(expected_hash), Some(state)) = (
        challenge.expected_commitment_hash.as_ref(),
        commitment_state,
    ) {
        // Precheck WITHOUT reading any chunk bytes (codex round-9 MAJOR:
        // the prior preload-into-HashMap pattern hit O(sample×4MiB)
        // peak memory). Cheap: hash-map lookup + per-key proof_for.
        let built = match crate::replication::commitment_state::precheck_commitment_bound_challenge(
            state,
            expected_hash,
            &challenge.keys,
        ) {
            Ok(b) => b,
            Err(
                crate::replication::commitment_state::CommitmentBoundOutcome::UnknownCommitmentHash,
            ) => {
                return AuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    reason: "unknown commitment hash".to_string(),
                };
            }
            Err(
                crate::replication::commitment_state::CommitmentBoundOutcome::KeyNotInCommitment {
                    key,
                },
            ) => {
                return AuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    reason: format!("key not in commitment: {}", hex::encode(key)),
                };
            }
            Err(_) => {
                // precheck only returns UnknownCommitmentHash /
                // KeyNotInCommitment today. Reject gracefully rather
                // than panic if a future variant is added — the
                // project bans panics on production paths.
                return AuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    reason: "unrecognized commitment precheck outcome".to_string(),
                };
            }
        };

        // Stream per-key: read one chunk, build its proof entry, drop
        // the bytes, move to the next. Peak memory is bounded at
        // MAX_CHUNK_SIZE (4 MiB) regardless of sample size.
        let mut per_key = Vec::with_capacity(challenge.keys.len());
        for key in &challenge.keys {
            let Ok(Some(bytes)) = storage.get_raw(key).await else {
                // Key IS in the commitment (precheck above ensured
                // it) but we cannot read the bytes anymore. That's
                // real storage loss / deliberate non-response, not
                // benign staleness. Use a distinct reason string so
                // the auditor penalises (codex round-12 MAJOR #1).
                return AuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    reason: format!("missing bytes for committed key: {}", hex::encode(key)),
                };
            };
            let Some(entry) =
                crate::replication::commitment_state::build_commitment_bound_result_for_key(
                    &built,
                    key,
                    &challenge.nonce,
                    &challenge.challenged_peer_id,
                    &bytes,
                )
            else {
                // Precheck guaranteed proof_for(key) returns Some, so
                // this is unreachable. Defensive only.
                return AuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    reason: format!("key not in commitment: {}", hex::encode(key)),
                };
            };
            per_key.push(entry);
            // bytes drops here.
        }

        return AuditResponse::CommitmentBound {
            challenge_id: challenge.challenge_id,
            commitment: built.commitment().clone(),
            per_key,
        };
    }

    // Legacy plain-digest path (unchanged from pre-v12).
    let mut digests = Vec::with_capacity(challenge.keys.len());

    for key in &challenge.keys {
        match storage.get_raw(key).await {
            Ok(Some(data)) => {
                let digest = compute_audit_digest(
                    &challenge.nonce,
                    &challenge.challenged_peer_id,
                    key,
                    &data,
                );
                digests.push(digest);
            }
            Ok(None) => {
                digests.push(ABSENT_KEY_DIGEST);
            }
            Err(e) => {
                warn!(
                    "Audit responder: failed to read key {}: {e}",
                    hex::encode(key)
                );
                digests.push(ABSENT_KEY_DIGEST);
            }
        }
    }

    AuditResponse::Digests {
        challenge_id: challenge.challenge_id,
        digests,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::protocol::compute_audit_digest;
    use crate::replication::types::{BootstrapClaimObservation, NeighborSyncState};
    use crate::storage::LmdbStorageConfig;
    use std::time::Instant;
    use tempfile::TempDir;

    /// Simulated stored chunk count for tests. Large enough that the dynamic
    /// incoming audit limit (`2 * sqrt(N)`) never rejects small test challenges.
    const TEST_STORED_CHUNKS: usize = 1_000_000;

    /// Create a test `LmdbStorage` backed by a temp directory.
    async fn create_test_storage() -> (LmdbStorage, TempDir) {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = LmdbStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            verify_on_read: false,
            max_map_size: 0,
            disk_reserve: 0,
        };
        let storage = LmdbStorage::new(config).await.expect("create storage");
        (storage, temp_dir)
    }

    /// Build a challenge with the given parameters.
    fn make_challenge(
        challenge_id: u64,
        nonce: [u8; 32],
        peer_id: [u8; 32],
        keys: Vec<XorName>,
    ) -> AuditChallenge {
        AuditChallenge {
            challenge_id,
            nonce,
            challenged_peer_id: peer_id,
            keys,
            expected_commitment_hash: None,
        }
    }

    /// Build a `PeerId` matching the raw bytes used in a challenge.
    fn peer_id_from_bytes(bytes: [u8; 32]) -> PeerId {
        PeerId::from_bytes(bytes)
    }

    // -- handle_audit_challenge: present keys ---------------------------------

    #[tokio::test]
    async fn handle_challenge_present_keys_returns_correct_digests() {
        let (storage, _temp) = create_test_storage().await;

        // Store two chunks.
        let content_a = b"chunk alpha";
        let addr_a = LmdbStorage::compute_address(content_a);
        storage.put(&addr_a, content_a).await.expect("put a");

        let content_b = b"chunk beta";
        let addr_b = LmdbStorage::compute_address(content_b);
        storage.put(&addr_b, content_b).await.expect("put b");

        let nonce = [0xAA; 32];
        let peer_id = [0xBB; 32];
        let challenge = make_challenge(42, nonce, peer_id, vec![addr_a, addr_b]);
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests {
                challenge_id,
                digests,
            } => {
                assert_eq!(challenge_id, 42);
                assert_eq!(digests.len(), 2);

                let expected_a = compute_audit_digest(&nonce, &peer_id, &addr_a, content_a);
                let expected_b = compute_audit_digest(&nonce, &peer_id, &addr_b, content_b);
                assert_eq!(digests[0], expected_a);
                assert_eq!(digests[1], expected_b);
            }
            AuditResponse::Bootstrapping { .. } => {
                panic!("expected Digests, got Bootstrapping");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        }
    }

    // -- handle_audit_challenge: absent keys ----------------------------------

    #[tokio::test]
    async fn handle_challenge_absent_keys_returns_sentinel() {
        let (storage, _temp) = create_test_storage().await;

        let absent_key = [0xFF; 32];
        let nonce = [0x11; 32];
        let peer_id = [0x22; 32];
        let challenge = make_challenge(99, nonce, peer_id, vec![absent_key]);
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests {
                challenge_id,
                digests,
            } => {
                assert_eq!(challenge_id, 99);
                assert_eq!(digests.len(), 1);
                assert_eq!(
                    digests[0], ABSENT_KEY_DIGEST,
                    "absent key should produce sentinel digest"
                );
            }
            AuditResponse::Bootstrapping { .. } => {
                panic!("expected Digests, got Bootstrapping");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        }
    }

    // -- handle_audit_challenge: mixed present and absent ---------------------

    #[tokio::test]
    async fn handle_challenge_mixed_present_and_absent() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"present chunk";
        let addr_present = LmdbStorage::compute_address(content);
        storage.put(&addr_present, content).await.expect("put");

        let addr_absent = [0xDE; 32];
        let nonce = [0x33; 32];
        let peer_id = [0x44; 32];
        let challenge = make_challenge(7, nonce, peer_id, vec![addr_present, addr_absent]);
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests { digests, .. } => {
                assert_eq!(digests.len(), 2);

                let expected_present =
                    compute_audit_digest(&nonce, &peer_id, &addr_present, content);
                assert_eq!(digests[0], expected_present);
                assert_eq!(
                    digests[1], ABSENT_KEY_DIGEST,
                    "absent key should be sentinel"
                );
            }
            AuditResponse::Bootstrapping { .. } => {
                panic!("expected Digests, got Bootstrapping");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        }
    }

    // -- handle_audit_challenge: bootstrapping --------------------------------

    #[tokio::test]
    async fn handle_challenge_bootstrapping_returns_bootstrapping_response() {
        let (storage, _temp) = create_test_storage().await;

        let challenge = make_challenge(55, [0x00; 32], [0x01; 32], vec![[0x02; 32]]);
        let self_id = peer_id_from_bytes([0x01; 32]);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, true, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Bootstrapping { challenge_id } => {
                assert_eq!(challenge_id, 55);
            }
            AuditResponse::Digests { .. } => {
                panic!("expected Bootstrapping, got Digests");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        }
    }

    // -- handle_audit_challenge: empty key list -------------------------------

    #[tokio::test]
    async fn handle_challenge_empty_keys_returns_empty_digests() {
        let (storage, _temp) = create_test_storage().await;

        let challenge = make_challenge(100, [0x10; 32], [0x20; 32], vec![]);
        let self_id = peer_id_from_bytes([0x20; 32]);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests {
                challenge_id,
                digests,
            } => {
                assert_eq!(challenge_id, 100);
                assert!(
                    digests.is_empty(),
                    "empty key list should yield empty digests"
                );
            }
            AuditResponse::Bootstrapping { .. } => {
                panic!("expected Digests, got Bootstrapping");
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response");
            }
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        }
    }

    // -- Digest verification: matching ----------------------------------------

    #[test]
    fn digest_verification_matching() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];
        let data = b"correct data";

        let expected = compute_audit_digest(&nonce, &peer_id, &key, data);
        let recomputed = compute_audit_digest(&nonce, &peer_id, &key, data);

        assert_eq!(
            expected, recomputed,
            "same inputs must produce identical digests"
        );
        assert_ne!(
            expected, ABSENT_KEY_DIGEST,
            "real digest must not be sentinel"
        );
    }

    // -- Digest verification: mismatching -------------------------------------

    #[test]
    fn digest_verification_mismatching_data() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];

        let digest_a = compute_audit_digest(&nonce, &peer_id, &key, b"data version A");
        let digest_b = compute_audit_digest(&nonce, &peer_id, &key, b"data version B");

        assert_ne!(
            digest_a, digest_b,
            "different data must produce different digests"
        );
    }

    #[test]
    fn digest_verification_mismatching_nonce() {
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];
        let data = b"same data";

        let digest_a = compute_audit_digest(&[0x01; 32], &peer_id, &key, data);
        let digest_b = compute_audit_digest(&[0xFF; 32], &peer_id, &key, data);

        assert_ne!(
            digest_a, digest_b,
            "different nonces must produce different digests"
        );
    }

    #[test]
    fn digest_verification_mismatching_peer() {
        let nonce = [0x01; 32];
        let key: XorName = [0x03; 32];
        let data = b"same data";

        let digest_a = compute_audit_digest(&nonce, &[0x02; 32], &key, data);
        let digest_b = compute_audit_digest(&nonce, &[0xFE; 32], &key, data);

        assert_ne!(
            digest_a, digest_b,
            "different peers must produce different digests"
        );
    }

    #[test]
    fn digest_verification_mismatching_key() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let data = b"same data";

        let digest_a = compute_audit_digest(&nonce, &peer_id, &[0x03; 32], data);
        let digest_b = compute_audit_digest(&nonce, &peer_id, &[0xFC; 32], data);

        assert_ne!(
            digest_a, digest_b,
            "different keys must produce different digests"
        );
    }

    // -- Absent sentinel is all zeros -----------------------------------------

    #[test]
    fn absent_sentinel_is_all_zeros() {
        assert_eq!(ABSENT_KEY_DIGEST, [0u8; 32], "sentinel must be all zeros");
    }

    // -- Bootstrapping skips digest computation even with stored keys ---------

    #[tokio::test]
    async fn bootstrapping_skips_digest_computation() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"stored but bootstrapping";
        let addr = LmdbStorage::compute_address(content);
        storage.put(&addr, content).await.expect("put");

        let challenge = make_challenge(200, [0xCC; 32], [0xDD; 32], vec![addr]);
        let self_id = peer_id_from_bytes([0xDD; 32]);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, true, TEST_STORED_CHUNKS).await;

        assert!(
            matches!(response, AuditResponse::Bootstrapping { challenge_id: 200 }),
            "bootstrapping node must not compute digests"
        );
    }

    // -- Scenario 19/53: Partial failure with mixed responsibility ----------------

    #[tokio::test]
    async fn scenario_19_partial_failure_mixed_responsibility() {
        // Three keys challenged: K1 matches, K2 mismatches, K3 absent.
        // After responsibility confirmation, only K2 is confirmed responsible.
        // AuditFailure emitted for {K2} only.
        // Test handle_audit_challenge with mixed results, then verify
        // the digest logic manually.

        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x42u8; 32];
        let peer_id = [0xAA; 32];

        // Store K1 and K2, but NOT K3
        let content_k1 = b"key one data";
        let addr_k1 = LmdbStorage::compute_address(content_k1);
        storage.put(&addr_k1, content_k1).await.unwrap();

        let content_k2 = b"key two data";
        let addr_k2 = LmdbStorage::compute_address(content_k2);
        storage.put(&addr_k2, content_k2).await.unwrap();

        let addr_k3 = [0xFF; 32]; // Not stored

        let challenge = AuditChallenge {
            challenge_id: 100,
            nonce,
            challenged_peer_id: peer_id,
            keys: vec![addr_k1, addr_k2, addr_k3],
            expected_commitment_hash: None,
        };
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;

        match response {
            AuditResponse::Digests { digests, .. } => {
                assert_eq!(digests.len(), 3);

                // K1 should have correct digest
                let expected_k1 = compute_audit_digest(&nonce, &peer_id, &addr_k1, content_k1);
                assert_eq!(digests[0], expected_k1);

                // K2 should have correct digest
                let expected_k2 = compute_audit_digest(&nonce, &peer_id, &addr_k2, content_k2);
                assert_eq!(digests[1], expected_k2);

                // K3 absent -> sentinel
                assert_eq!(digests[2], ABSENT_KEY_DIGEST);
            }
            AuditResponse::Bootstrapping { .. } => panic!("Expected Digests response"),
            AuditResponse::Rejected { .. } => panic!("Unexpected Rejected response"),
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        }
    }

    // -- Scenario 54: All digests pass -------------------------------------------

    #[tokio::test]
    async fn scenario_54_all_digests_pass() {
        // All challenged keys present and digests match.
        // Multiple keys to strengthen coverage beyond existing two-key tests.
        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x10; 32];
        let peer_id = [0x20; 32];

        let c1 = b"chunk alpha";
        let c2 = b"chunk beta";
        let c3 = b"chunk gamma";
        let a1 = LmdbStorage::compute_address(c1);
        let a2 = LmdbStorage::compute_address(c2);
        let a3 = LmdbStorage::compute_address(c3);
        storage.put(&a1, c1).await.unwrap();
        storage.put(&a2, c2).await.unwrap();
        storage.put(&a3, c3).await.unwrap();

        let challenge = AuditChallenge {
            challenge_id: 200,
            nonce,
            challenged_peer_id: peer_id,
            keys: vec![a1, a2, a3],
            expected_commitment_hash: None,
        };
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;
        match response {
            AuditResponse::Digests { digests, .. } => {
                assert_eq!(digests.len(), 3);
                for (i, (addr, content)) in [(a1, &c1[..]), (a2, &c2[..]), (a3, &c3[..])]
                    .iter()
                    .enumerate()
                {
                    let expected = compute_audit_digest(&nonce, &peer_id, addr, content);
                    assert_eq!(digests[i], expected, "Key {i} digest should match");
                }
            }
            AuditResponse::Bootstrapping { .. } => panic!("Expected Digests"),
            AuditResponse::Rejected { .. } => panic!("Unexpected Rejected response"),
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        }
    }

    // -- Scenario 55: Empty failure set means no evidence -------------------------

    /// Scenario 55: Peer challenged on {K1, K2}. Both digests mismatch.
    /// Responsibility confirmation shows the peer is NOT responsible for
    /// either key. The confirmed failure set is empty — no `AuditFailure`
    /// evidence is emitted.
    ///
    /// Full `verify_digests` requires a live `P2PNode` for network lookups.
    /// This test exercises the deterministic sub-steps:
    ///   (1) Digest comparison identifies K1 and K2 as mismatches.
    ///   (2) Responsibility confirmation removes both keys.
    ///   (3) Empty confirmed failure set means no evidence.
    #[tokio::test]
    async fn scenario_55_no_confirmed_responsibility_no_evidence() {
        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x55; 32];
        let peer_id = [0x55; 32];

        // Store K1 and K2 on the challenger (for expected digest computation).
        let c1 = b"scenario 55 key one";
        let c2 = b"scenario 55 key two";
        let k1 = LmdbStorage::compute_address(c1);
        let k2 = LmdbStorage::compute_address(c2);
        storage.put(&k1, c1).await.expect("put k1");
        storage.put(&k2, c2).await.expect("put k2");

        // Challenger computes expected digests.
        let expected_d1 = compute_audit_digest(&nonce, &peer_id, &k1, c1);
        let expected_d2 = compute_audit_digest(&nonce, &peer_id, &k2, c2);

        // Simulate peer returning WRONG digests for both keys.
        let wrong_d1 = compute_audit_digest(&nonce, &peer_id, &k1, b"corrupted k1");
        let wrong_d2 = compute_audit_digest(&nonce, &peer_id, &k2, b"corrupted k2");
        assert_ne!(wrong_d1, expected_d1, "K1 digest should mismatch");
        assert_ne!(wrong_d2, expected_d2, "K2 digest should mismatch");

        // Step 1: Identify failed keys via digest comparison.
        let keys = [k1, k2];
        let expected = [expected_d1, expected_d2];
        let received = [wrong_d1, wrong_d2];

        let mut failed_keys = Vec::new();
        for i in 0..keys.len() {
            if received[i] != expected[i] {
                failed_keys.push(keys[i]);
            }
        }
        assert_eq!(
            failed_keys.len(),
            2,
            "Both keys should be identified as digest mismatches"
        );

        // Step 2: Responsibility confirmation — peer is NOT responsible for
        // either key (simulated by filtering them all out).
        let confirmed_responsible_keys: Vec<XorName> = Vec::new();
        let confirmed_failures: Vec<XorName> = failed_keys
            .into_iter()
            .filter(|k| confirmed_responsible_keys.contains(k))
            .collect();

        // Step 3: Empty confirmed failure set → no AuditFailure evidence.
        assert!(
            confirmed_failures.is_empty(),
            "With no confirmed responsibility, failure set must be empty — \
             no AuditFailure evidence should be emitted"
        );

        // Verify that constructing evidence with empty keys results in a
        // no-penalty outcome (the caller checks is_empty before emitting).
        let peer = PeerId::from_bytes(peer_id);
        let evidence = FailureEvidence::AuditFailure {
            challenge_id: 5500,
            challenged_peer: peer,
            confirmed_failed_keys: confirmed_failures,
            summary: AuditFailureSummary::default(),
            reason: AuditFailureReason::DigestMismatch,
        };
        if let FailureEvidence::AuditFailure {
            confirmed_failed_keys,
            ..
        } = evidence
        {
            assert!(
                confirmed_failed_keys.is_empty(),
                "Evidence with empty failure set should not trigger a trust penalty"
            );
        }
    }

    // -- Scenario 56: RepairOpportunity filters never-synced peers ----------------

    #[test]
    fn scenario_56_repair_opportunity_filters_never_synced() {
        // PeerSyncRecord with last_sync=None should not pass
        // has_repair_opportunity().

        let never_synced = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 5,
        };
        assert!(!never_synced.has_repair_opportunity());

        let synced_no_cycle = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 0,
        };
        assert!(!synced_no_cycle.has_repair_opportunity());

        let synced_with_cycle = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 1,
        };
        assert!(synced_with_cycle.has_repair_opportunity());
    }

    #[test]
    fn expired_bootstrap_claim_does_not_remove_peer_from_audit_eligibility() {
        let peer = peer_id_from_bytes([0x57; 32]);
        let mut sync_history = HashMap::new();
        sync_history.insert(
            peer,
            PeerSyncRecord {
                last_sync: Some(Instant::now()),
                cycles_since_sync: 1,
            },
        );

        let mut bootstrap_claims = HashMap::new();
        let first_seen = Instant::now()
            .checked_sub(
                crate::replication::config::BOOTSTRAP_CLAIM_GRACE_PERIOD
                    + std::time::Duration::from_secs(1),
            )
            .unwrap_or_else(Instant::now);
        bootstrap_claims.insert(peer, first_seen);

        let eligible = eligible_audit_peers(&sync_history);

        assert!(bootstrap_claims.contains_key(&peer));
        assert!(
            eligible.contains(&peer),
            "continued bootstrap claims must remain auditable so past-grace abuse can be observed"
        );
    }

    #[test]
    fn audit_failure_summary_counts_confirmed_absent_and_mismatch_keys() {
        let absent_key = [0xA1; 32];
        let mismatch_key = [0xB2; 32];
        let confirmed = vec![
            AuditKeyFailure::absent(absent_key),
            AuditKeyFailure::digest_mismatch(mismatch_key),
        ];

        let summary = build_audit_failure_summary(5, &confirmed);

        assert_eq!(summary.challenged_keys, 5);
        assert_eq!(summary.failed_keys, 2);
        assert_eq!(summary.absent_keys, 1);
        assert_eq!(summary.digest_mismatch_keys, 1);
    }

    #[test]
    fn audit_failure_summary_leaves_unclassified_rejections_out_of_absent_mismatch_counts() {
        let rejected_key = [0xC3; 32];
        let confirmed = vec![AuditKeyFailure::unclassified(rejected_key)];

        let summary = build_audit_failure_summary(3, &confirmed);

        assert_eq!(summary.challenged_keys, 3);
        assert_eq!(summary.failed_keys, 1);
        assert_eq!(summary.absent_keys, 0);
        assert_eq!(summary.digest_mismatch_keys, 0);
    }

    #[test]
    fn audit_digest_failure_reason_is_key_absent_when_all_confirmed_failures_are_absent() {
        let failures = vec![AuditKeyFailure::absent([0xD4; 32])];

        assert_eq!(
            audit_digest_failure_reason(&failures),
            AuditFailureReason::KeyAbsent
        );
    }

    #[test]
    fn audit_digest_failure_reason_is_digest_mismatch_for_mixed_failures() {
        let failures = vec![
            AuditKeyFailure::absent([0xD5; 32]),
            AuditKeyFailure::digest_mismatch([0xE6; 32]),
        ];

        assert_eq!(
            audit_digest_failure_reason(&failures),
            AuditFailureReason::DigestMismatch
        );
    }

    #[test]
    fn audit_key_filter_retains_stable_proofs_and_rejects_evicted_peers() {
        const HINT_EPOCH: u64 = 7;
        const CURRENT_EPOCH: u64 = HINT_EPOCH + 1;
        const CHALLENGED_PEER_BYTE: u8 = 0xA1;
        const OTHER_PEER_BYTE: u8 = 0xA2;
        const NEW_PEER_BYTE: u8 = 0xA3;
        const MATURE_KEY_BYTE: u8 = 0xB1;
        const SAME_EPOCH_KEY_BYTE: u8 = 0xB2;
        const MISSING_PROOF_KEY_BYTE: u8 = 0xB3;
        const STABLE_CHURN_KEY_BYTE: u8 = 0xB4;
        const EVICTED_KEY_BYTE: u8 = 0xB5;
        const XOR_NAME_LEN: usize = 32;

        let challenged_peer = peer_id_from_bytes([CHALLENGED_PEER_BYTE; XOR_NAME_LEN]);
        let other_peer = peer_id_from_bytes([OTHER_PEER_BYTE; XOR_NAME_LEN]);
        let new_peer = peer_id_from_bytes([NEW_PEER_BYTE; XOR_NAME_LEN]);
        let mature_key = [MATURE_KEY_BYTE; XOR_NAME_LEN];
        let same_epoch_key = [SAME_EPOCH_KEY_BYTE; XOR_NAME_LEN];
        let missing_proof_key = [MISSING_PROOF_KEY_BYTE; XOR_NAME_LEN];
        let stable_churn_key = [STABLE_CHURN_KEY_BYTE; XOR_NAME_LEN];
        let evicted_key = [EVICTED_KEY_BYTE; XOR_NAME_LEN];
        let close_group = HashSet::from([challenged_peer, other_peer]);
        let changed_close_group = HashSet::from([challenged_peer, new_peer]);
        let evicted_close_group = HashSet::from([other_peer, new_peer]);
        let mut repair_proofs = RepairProofs::new();

        assert!(repair_proofs.record_replica_hint_sent(
            challenged_peer,
            mature_key,
            &close_group,
            HINT_EPOCH,
        ));
        assert!(repair_proofs.record_replica_hint_sent(
            challenged_peer,
            same_epoch_key,
            &close_group,
            CURRENT_EPOCH,
        ));
        assert!(repair_proofs.record_replica_hint_sent(
            challenged_peer,
            stable_churn_key,
            &close_group,
            HINT_EPOCH,
        ));
        assert!(repair_proofs.record_replica_hint_sent(
            challenged_peer,
            evicted_key,
            &close_group,
            HINT_EPOCH,
        ));

        let sampled_key_groups = vec![
            (mature_key, close_group.clone()),
            (same_epoch_key, close_group.clone()),
            (missing_proof_key, close_group.clone()),
            (stable_churn_key, changed_close_group),
            (evicted_key, evicted_close_group),
        ];
        let peer_keys = mature_audit_keys_for_peer(
            &challenged_peer,
            sampled_key_groups,
            &mut repair_proofs,
            CURRENT_EPOCH,
        );

        assert_eq!(
            peer_keys,
            vec![mature_key, stable_churn_key],
            "mature proofs for stable close-group peers should become audit keys, while same-epoch, missing, and evicted-peer proofs should not"
        );
    }

    // -- Audit response must match key count --------------------------------------

    #[tokio::test]
    async fn audit_response_must_match_key_count() {
        // Section 15: "A response is invalid if it has fewer or more entries
        // than challenged keys."
        // Verify handle_audit_challenge always produces exactly N digests for
        // N keys, including edge cases.

        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x50; 32];
        let peer_id = [0x60; 32];

        // Store a single chunk
        let content = b"single chunk";
        let addr = LmdbStorage::compute_address(content);
        storage.put(&addr, content).await.unwrap();

        // Challenge with 1 stored + 4 absent = 5 keys total
        let absent_keys: Vec<XorName> = (1..=4u8).map(|i| [i; 32]).collect();
        let mut keys = vec![addr];
        keys.extend_from_slice(&absent_keys);

        let key_count = keys.len();
        let challenge = make_challenge(300, nonce, peer_id, keys);
        let self_id = peer_id_from_bytes(peer_id);

        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;
        match response {
            AuditResponse::Digests { digests, .. } => {
                assert_eq!(
                    digests.len(),
                    key_count,
                    "must produce exactly one digest per challenged key"
                );
            }
            AuditResponse::Bootstrapping { .. } => panic!("Expected Digests"),
            AuditResponse::Rejected { .. } => panic!("Unexpected Rejected response"),
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        }
    }

    // -- Audit digest uses full record bytes --------------------------------------

    #[test]
    fn audit_digest_uses_full_record_bytes() {
        // Verify digest changes when record content changes.
        let nonce = [1u8; 32];
        let peer = [2u8; 32];
        let key = [3u8; 32];

        let d1 = compute_audit_digest(&nonce, &peer, &key, b"data version 1");
        let d2 = compute_audit_digest(&nonce, &peer, &key, b"data version 2");
        assert_ne!(
            d1, d2,
            "Different record bytes must produce different digests"
        );
    }

    // -- Scenario 29: Audit start gate ------------------------------------------

    /// Scenario 29: `handle_audit_challenge` returns `Bootstrapping` when the
    /// node is still bootstrapping — audit digests are never computed, and no
    /// `AuditFailure` evidence is emitted by the caller.
    ///
    /// This is the responder-side gate.  The challenger-side gate is enforced
    /// by `audit_tick`'s `is_bootstrapping` guard (Invariant 19) and by
    /// `check_bootstrap_drained()` in the engine loop; this test confirms the
    /// complementary responder behavior.
    #[tokio::test]
    async fn scenario_29_audit_start_gate_during_bootstrap() {
        let (storage, _temp) = create_test_storage().await;

        // Store data so there *would* be work to audit.
        let content = b"should not be audited during bootstrap";
        let addr = LmdbStorage::compute_address(content);
        storage.put(&addr, content).await.expect("put");

        let challenge = make_challenge(2900, [0x29; 32], [0x29; 32], vec![addr]);
        let self_id = peer_id_from_bytes([0x29; 32]);

        // Responder is bootstrapping → Bootstrapping response, NOT Digests.
        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, true, TEST_STORED_CHUNKS).await;
        assert!(
            matches!(
                response,
                AuditResponse::Bootstrapping { challenge_id: 2900 }
            ),
            "bootstrapping node must not compute digests — audit start gate"
        );

        // Responder is NOT bootstrapping → normal Digests.
        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, false, TEST_STORED_CHUNKS).await;
        assert!(
            matches!(response, AuditResponse::Digests { .. }),
            "drained node should compute digests normally"
        );
    }

    // -- Scenario 30: Audit peer selection from sampled keys --------------------

    /// Scenario 30: Key sampling uses dynamic sqrt-based batch sizing and
    /// `RepairOpportunity` filtering excludes never-synced peers.
    ///
    /// Full `audit_tick` requires a live network.  This test verifies the two
    /// deterministic sub-steps the function relies on:
    ///   (a) `audit_sample_count` scales with `sqrt(total_keys)`.
    ///   (b) `PeerSyncRecord::has_repair_opportunity` gates peer eligibility.
    #[test]
    fn scenario_30_audit_peer_selection_from_sampled_keys() {
        // (a) Dynamic sample count scales with sqrt(total_keys).
        assert_eq!(
            ReplicationConfig::audit_sample_count(100),
            10,
            "sample count should scale with sqrt(total_keys)"
        );

        assert_eq!(ReplicationConfig::audit_sample_count(3), 1, "sqrt(3) = 1");

        assert_eq!(
            ReplicationConfig::audit_sample_count(10_000),
            100,
            "sqrt(10000) = 100"
        );

        // (b) Peer eligibility via RepairOpportunity.
        // Never synced → not eligible.
        let never = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 10,
        };
        assert!(!never.has_repair_opportunity());

        // Synced but zero subsequent cycles → not eligible.
        let too_soon = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 0,
        };
        assert!(!too_soon.has_repair_opportunity());

        // Synced with ≥1 cycle → eligible.
        let eligible = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 2,
        };
        assert!(eligible.has_repair_opportunity());
    }

    // -- Scenario 32: Dynamic challenge size ------------------------------------

    /// Scenario 32: Challenge key count equals `|PeerKeySet(challenged_peer)|`,
    /// which is dynamic per round.  If no eligible peer remains after filtering,
    /// the tick is idle.
    ///
    /// Verified via `handle_audit_challenge`: the response digest count always
    /// equals the number of keys in the challenge.
    #[tokio::test]
    async fn scenario_32_dynamic_challenge_size() {
        let (storage, _temp) = create_test_storage().await;

        // Store varying numbers of chunks.
        let mut addrs = Vec::new();
        for i in 0u8..5 {
            let content = format!("dynamic challenge key {i}");
            let addr = LmdbStorage::compute_address(content.as_bytes());
            storage.put(&addr, content.as_bytes()).await.expect("put");
            addrs.push(addr);
        }

        let nonce = [0x32; 32];
        let peer_id = [0x32; 32];
        let self_id = peer_id_from_bytes(peer_id);

        // Challenge with 1 key.
        let challenge1 = make_challenge(3201, nonce, peer_id, vec![addrs[0]]);
        let resp1 =
            handle_audit_challenge(&challenge1, &storage, &self_id, false, TEST_STORED_CHUNKS)
                .await;
        if let AuditResponse::Digests { digests, .. } = resp1 {
            assert_eq!(digests.len(), 1, "|PeerKeySet| = 1 → 1 digest");
        }

        // Challenge with 3 keys.
        let challenge3 = make_challenge(3203, nonce, peer_id, addrs[0..3].to_vec());
        let resp3 =
            handle_audit_challenge(&challenge3, &storage, &self_id, false, TEST_STORED_CHUNKS)
                .await;
        if let AuditResponse::Digests { digests, .. } = resp3 {
            assert_eq!(digests.len(), 3, "|PeerKeySet| = 3 → 3 digests");
        }

        // Challenge with all 5 keys.
        let challenge5 = make_challenge(3205, nonce, peer_id, addrs.clone());
        let resp5 =
            handle_audit_challenge(&challenge5, &storage, &self_id, false, TEST_STORED_CHUNKS)
                .await;
        if let AuditResponse::Digests { digests, .. } = resp5 {
            assert_eq!(digests.len(), 5, "|PeerKeySet| = 5 → 5 digests");
        }

        // Challenge with 0 keys (idle equivalent — no work).
        let challenge0 = make_challenge(3200, nonce, peer_id, vec![]);
        let resp0 =
            handle_audit_challenge(&challenge0, &storage, &self_id, false, TEST_STORED_CHUNKS)
                .await;
        if let AuditResponse::Digests { digests, .. } = resp0 {
            assert!(digests.is_empty(), "|PeerKeySet| = 0 → 0 digests (idle)");
        }
    }

    // -- Scenario 47: Bootstrap claim grace period (audit) ----------------------

    /// Scenario 47: Challenged peer responds with bootstrapping claim during
    /// audit.  `handle_audit_challenge` returns `Bootstrapping`; caller records
    /// `BootstrapClaimFirstSeen`.  No `AuditFailure` evidence is emitted.
    #[tokio::test]
    async fn scenario_47_bootstrap_claim_grace_period_audit() {
        let (storage, _temp) = create_test_storage().await;

        // Store data so there is an auditable key.
        let content = b"bootstrap grace test";
        let addr = LmdbStorage::compute_address(content);
        storage.put(&addr, content).await.expect("put");

        let challenge = make_challenge(4700, [0x47; 32], [0x47; 32], vec![addr]);
        let self_id = peer_id_from_bytes([0x47; 32]);

        // Bootstrapping peer → Bootstrapping response (grace period start).
        let response =
            handle_audit_challenge(&challenge, &storage, &self_id, true, TEST_STORED_CHUNKS).await;
        let challenge_id = match response {
            AuditResponse::Bootstrapping { challenge_id } => challenge_id,
            AuditResponse::Digests { .. } => {
                panic!("Expected Bootstrapping response during grace period")
            }
            AuditResponse::Rejected { .. } => {
                panic!("Unexpected Rejected response")
            }
            AuditResponse::CommitmentBound { .. } => {
                panic!("Unexpected CommitmentBound response in legacy-digest test")
            }
        };
        assert_eq!(challenge_id, 4700);

        // Caller records BootstrapClaimFirstSeen — verify the types support it.
        let peer = PeerId::from_bytes([0x47; 32]);
        let mut state = NeighborSyncState::new_cycle(vec![peer]);
        let now = Instant::now();
        let observed = state.observe_bootstrap_claim(
            peer,
            now,
            crate::replication::config::BOOTSTRAP_CLAIM_GRACE_PERIOD,
        );

        assert_eq!(
            observed,
            BootstrapClaimObservation::WithinGrace { first_seen: now }
        );
        assert!(
            state.bootstrap_claims.contains_key(&peer),
            "BootstrapClaimFirstSeen should be recorded after grace-period claim"
        );
        assert!(
            state.bootstrap_claim_history.contains_key(&peer),
            "Bootstrap claim history should remember that the grace window was used"
        );
    }

    // -- Scenario 53: Audit partial per-key failure with mixed responsibility ---

    /// Scenario 53: P challenged on {K1, K2, K3}.  K1 matches, K2 and K3
    /// mismatch.  Responsibility confirmation: P is responsible for K2 but
    /// not K3.  `AuditFailure` emitted for {K2} only.
    ///
    /// Full `verify_digests` + `handle_audit_failure` requires a `P2PNode` for
    /// network lookups.  This test verifies the conceptual steps:
    ///   (1) Digest comparison correctly identifies K2 and K3 as failures.
    ///   (2) `FailureEvidence::AuditFailure` carries only confirmed keys.
    #[tokio::test]
    async fn scenario_53_partial_failure_mixed_responsibility() {
        let (storage, _temp) = create_test_storage().await;
        let nonce = [0x53; 32];
        let peer_id = [0x53; 32];

        // Store K1, K2, K3.
        let c1 = b"scenario 53 key one";
        let c2 = b"scenario 53 key two";
        let c3 = b"scenario 53 key three";
        let k1 = LmdbStorage::compute_address(c1);
        let k2 = LmdbStorage::compute_address(c2);
        let k3 = LmdbStorage::compute_address(c3);
        storage.put(&k1, c1).await.expect("put k1");
        storage.put(&k2, c2).await.expect("put k2");
        storage.put(&k3, c3).await.expect("put k3");

        // Correct digests from challenger's local store.
        let d1_expected = compute_audit_digest(&nonce, &peer_id, &k1, c1);
        let d2_expected = compute_audit_digest(&nonce, &peer_id, &k2, c2);
        let d3_expected = compute_audit_digest(&nonce, &peer_id, &k3, c3);

        // Simulate peer response: K1 matches, K2 wrong data, K3 wrong data.
        let d2_wrong = compute_audit_digest(&nonce, &peer_id, &k2, b"tampered k2");
        let d3_wrong = compute_audit_digest(&nonce, &peer_id, &k3, b"tampered k3");

        assert_eq!(d1_expected, d1_expected, "K1 should match");
        assert_ne!(d2_wrong, d2_expected, "K2 should mismatch");
        assert_ne!(d3_wrong, d3_expected, "K3 should mismatch");

        // Step 1: Identify failed keys (digest comparison).
        let digests = [d1_expected, d2_wrong, d3_wrong];
        let keys = [k1, k2, k3];
        let contents: [&[u8]; 3] = [c1, c2, c3];

        let mut failed_keys = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            if digests[i] == ABSENT_KEY_DIGEST {
                failed_keys.push(*key);
                continue;
            }
            let expected = compute_audit_digest(&nonce, &peer_id, key, contents[i]);
            if digests[i] != expected {
                failed_keys.push(*key);
            }
        }

        assert_eq!(failed_keys.len(), 2, "K2 and K3 should be in failure set");
        assert!(failed_keys.contains(&k2));
        assert!(failed_keys.contains(&k3));
        assert!(!failed_keys.contains(&k1), "K1 passed digest check");

        // Step 2: Responsibility confirmation removes K3 (not responsible).
        // Simulate: P is in closest peers for K2 but not K3.
        let responsible_for_k2 = true;
        let responsible_for_k3 = false;
        let mut confirmed = Vec::new();
        for key in &failed_keys {
            let is_responsible = if *key == k2 {
                responsible_for_k2
            } else {
                responsible_for_k3
            };
            if is_responsible {
                confirmed.push(*key);
            }
        }

        assert_eq!(confirmed, vec![k2], "Only K2 should be in confirmed set");

        // Step 3: Construct evidence for confirmed failures only.
        let challenged_peer = PeerId::from_bytes(peer_id);
        let evidence = FailureEvidence::AuditFailure {
            challenge_id: 5300,
            challenged_peer,
            confirmed_failed_keys: confirmed,
            summary: AuditFailureSummary::default(),
            reason: AuditFailureReason::DigestMismatch,
        };

        match evidence {
            FailureEvidence::AuditFailure {
                confirmed_failed_keys,
                ..
            } => {
                assert_eq!(
                    confirmed_failed_keys.len(),
                    1,
                    "Only K2 should generate evidence"
                );
                assert_eq!(confirmed_failed_keys[0], k2);
            }
            _ => panic!("Expected AuditFailure evidence"),
        }
    }
}
