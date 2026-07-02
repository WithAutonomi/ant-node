//! Gossip-triggered contiguous-subtree storage audit (ADR-0002).
//!
//! A node commits to what it stores (a signed Merkle [`StorageCommitment`]
//! gossiped to neighbours). On receiving a peer's changed commitment, a
//! neighbour may audit it: pin the just-gossiped root, send a fresh nonce that
//! deterministically selects one contiguous subtree, and require the peer to
//! prove that subtree (structure + real bytes) within a deadline. This module
//! owns the auditor entry point [`run_subtree_audit`] and the responder handler
//! [`handle_subtree_challenge`]; the pure proof maths live in
//! [`crate::replication::subtree`].

use std::sync::Arc;
use std::time::Duration;

use crate::logging::{debug, info, warn};
use rand::Rng;

use crate::ant_protocol::XorName;
use crate::replication::commitment::{commitment_hash, StorageCommitment};
use crate::replication::commitment_state::ResponderCommitmentState;
use crate::replication::config::{
    ReplicationConfig, MAX_BYTE_CHALLENGE_KEYS, REPLICATION_PROTOCOL_ID,
};
use crate::replication::protocol::{
    RejectKind, ReplicationMessage, ReplicationMessageBody, SubtreeAuditChallenge,
    SubtreeAuditResponse, SubtreeByteChallenge, SubtreeByteItem, SubtreeByteResponse,
};
use crate::replication::recent_provers::RecentProvers;
use crate::replication::subtree::{
    select_subtree_path, subtree_plan, verify_subtree_proof, StructureVerdict, SubtreeProof,
};
use crate::replication::types::{AuditFailureReason, AuditFailureSummary, FailureEvidence};
use crate::storage::LmdbStorage;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use tokio::sync::RwLock;

// The gossip-triggered auditor shares the engine's [`AuditTickResult`] outcome
// type with the responsible-chunk audit (defined in [`super::audit`]), so the
// engine can dispatch both audits' results through one match.
use crate::replication::audit::AuditTickResult;

// ---------------------------------------------------------------------------
// Auditor side
// ---------------------------------------------------------------------------

/// ADR-0002 round-2 byte challenge samples a SMALL surprise set of the proven
/// leaves (3..=5). Small enough that the responder's honest local-disk read of
/// the original chunks stays well inside the possession-in-time deadline, while
/// a relay forced to fetch them over the network blows it; large enough that
/// faking a fraction `x` of leaves survives only `(1 - x)^k`.
const BYTE_SPOTCHECK_MIN: u32 = 3;
const BYTE_SPOTCHECK_MAX: u32 = 5;

/// ADR-0004 A1: with grace removed, the responder retries a TRANSIENT chunk-read
/// error a few times before rejecting `Transient` (which routes to the timeout
/// lane). A momentary disk blip usually clears within these attempts; only a
/// persistent read failure — the node genuinely cannot serve committed bytes —
/// falls through. Total added latency ((attempts − 1) × backoff) stays well inside the
/// audit response deadline.
const AUDIT_READ_RETRY_ATTEMPTS: u32 = 3;
const AUDIT_READ_RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Read a committed chunk's bytes, retrying a transient read error up to
/// [`AUDIT_READ_RETRY_ATTEMPTS`] times with [`AUDIT_READ_RETRY_BACKOFF`] between
/// tries. `Ok(None)` (bytes definitively absent — real loss) is NOT retried; only
/// an `Err` (transient IO) is. A persistent `Err` is returned so the caller emits
/// `RejectKind::Transient` (timeout lane).
async fn get_raw_retrying(
    storage: &LmdbStorage,
    key: &XorName,
) -> crate::error::Result<Option<Vec<u8>>> {
    let mut attempt = 1u32;
    loop {
        match storage.get_raw(key).await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < AUDIT_READ_RETRY_ATTEMPTS => {
                debug!(
                    "Audit: transient read error for {} (attempt {attempt}/{AUDIT_READ_RETRY_ATTEMPTS}): {e}; retrying",
                    hex::encode(key)
                );
                attempt += 1;
                tokio::time::sleep(AUDIT_READ_RETRY_BACKOFF).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// How the auditor grades a *responsive* audit rejection (ADR-0004 A1: grace
/// removed). The decision is a pure function of the [`RejectKind`] so it can be
/// unit-tested independently of the P2P/side-effect machinery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectGrade {
    /// Provable misbehaviour → confirmed failure (trust penalty + credit
    /// revocation downstream).
    Confirmed,
    /// Non-response/timeout lane: no trust penalty, but the pinned commitment's
    /// holder credit is revoked (the peer answered but could not prove possession).
    TimeoutLane,
}

/// Grade a responsive rejection. Repudiating a pinned root (`UnknownCommitment`)
/// or an explicit protocol fault is a confirmed failure; a `Transient` read error
/// (already retried by the responder) routes to the timeout lane.
const fn grade_reject(kind: RejectKind) -> RejectGrade {
    match kind {
        RejectKind::UnknownCommitment | RejectKind::Protocol => RejectGrade::Confirmed,
        RejectKind::Transient => RejectGrade::TimeoutLane,
    }
}

/// Holder-eligibility cache the auditor credits on a passing audit.
///
/// Owned by [`crate::replication::ReplicationEngine`]; borrowed here so a
/// passing audit can record `(peer, commitment_hash)` as a proven holder for
/// downstream quorum / paid-list credit.
pub struct AuditCredit<'a> {
    /// Holder-eligibility cache.
    pub recent_provers: &'a Arc<RwLock<RecentProvers>>,
}

/// The cross-cutting context for verifying one audit response, bundled so the
/// response-dispatch and verification functions stay readable.
struct AuditCtx<'a> {
    p2p_node: &'a Arc<P2PNode>,
    challenged_peer: &'a PeerId,
    challenge_id: u64,
    nonce: [u8; 32],
    expected_commitment_hash: [u8; 32],
    config: &'a ReplicationConfig,
    credit: Option<&'a AuditCredit<'a>>,
}

/// Run one gossip-triggered subtree audit against `challenged_peer`, pinned to
/// the commitment hash the peer just gossiped (`expected_commitment_hash`).
///
/// ADR-0002 two-round audit. The auditor sends a fresh random nonce and runs:
///
/// 1. **Structure** (round 1) — the returned subtree rebuilds to the pinned
///    root, within a size-scaled deadline.
/// 2. **Real bytes** (round 2) — the auditor demands the ORIGINAL chunk content
///    for a 3..=5 FRESHLY-RANDOM sample of the proven leaves (chosen after the
///    proof arrives, not nonce-derived — see `random_spotcheck_leaves`) FROM the
///    responder, and recomputes both the content-address hash and the nonce
///    freshness hash from that served content. The auditor holds none of the
///    peer's chunks.
/// 3. **Timing** — each round's deadline is sized to an honest local-disk read,
///    so a relay forced to fetch over the network blows it.
///
/// A timeout (either round) is reported as [`AuditFailureReason::Timeout`] (the
/// caller applies the strike/grace policy). Any structural failure, served
/// content that fails a hash, an explicit `Absent` for a committed sampled key,
/// or a rejection of a recently gossiped commitment, is a confirmed failure
/// acted on immediately. On a full pass, records the peer as a proven holder.
pub async fn run_subtree_audit(
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    challenged_peer: &PeerId,
    expected_commitment_hash: [u8; 32],
    key_count: u32,
    credit: Option<&AuditCredit<'_>>,
) -> AuditTickResult {
    let (nonce, challenge_id) = {
        let mut rng = rand::thread_rng();
        (rng.gen::<[u8; 32]>(), rng.gen::<u64>())
    };

    let challenge = SubtreeAuditChallenge {
        challenge_id,
        nonce,
        challenged_peer_id: *challenged_peer.as_bytes(),
        expected_commitment_hash,
    };
    let msg = ReplicationMessage {
        request_id: challenge_id,
        body: ReplicationMessageBody::SubtreeAuditChallenge(challenge),
    };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Audit: failed to encode subtree challenge for {challenged_peer}: {e}");
            return AuditTickResult::Idle;
        }
    };

    // Size the proof deadline from the ACTUAL selected subtree (its real-leaf
    // count for this nonce + key_count), not a fixed worst-case hint. This keeps
    // the deadline tight to "responder hashes ~sqrt(N) chunks at local-disk
    // speed", so a relay that must fetch the subtree over the network blows it.
    // The auditor and responder derive the same selection, so we know the leaf
    // count before the response arrives.
    let subtree_leaves = select_subtree_path(&nonce, key_count).map_or_else(
        || config.subtree_audit_timeout_leaf_hint(),
        |p| p.real_leaf_count() as usize,
    );
    let timeout = config.audit_response_timeout(subtree_leaves);

    let response = match p2p_node
        .send_request(challenged_peer, REPLICATION_PROTOCOL_ID, encoded, timeout)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            debug!("Audit: subtree challenge to {challenged_peer} timed out / failed: {e}");
            return failed(challenged_peer, challenge_id, AuditFailureReason::Timeout);
        }
    };

    let resp_msg = match ReplicationMessage::decode(&response.data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Audit: failed to decode subtree response from {challenged_peer}: {e}");
            return failed(
                challenged_peer,
                challenge_id,
                AuditFailureReason::MalformedResponse,
            );
        }
    };

    let ctx = AuditCtx {
        p2p_node,
        challenged_peer,
        challenge_id,
        nonce,
        expected_commitment_hash,
        config,
        credit,
    };
    dispatch_subtree_response(resp_msg.body, &ctx).await
}

/// Outcome of the round-2 byte challenge round-trip (auditor side).
enum ByteRound {
    /// The responder returned per-key items (verified by the caller).
    Served(Vec<SubtreeByteItem>),
    /// The responder rejected the byte challenge (confirmed failure for a
    /// recently pinned commitment).
    Rejected,
    /// The responder rejected with `Transient` (a local read error): routed to
    /// the non-response/timeout lane — no trust penalty, but holder credit is
    /// revoked, because the peer answered and could not prove possession, so it
    /// must not keep stale credit. Distinct from a silent network `Timeout`,
    /// which keeps credit (a dropped packet is not evidence of loss).
    TransientReject,
    /// No response within the byte deadline, or a transport error (graced
    /// timeout). Keeps holder credit.
    Timeout,
    /// Malformed / unexpected round-2 response body.
    Malformed,
}

/// Round 2: ask the responder for the ORIGINAL chunk content of one BATCH of
/// auditor-selected spot-check `keys` (at most [`MAX_BYTE_CHALLENGE_KEYS`], so
/// the worst-case response of max-size chunks fits the wire cap), sized to a
/// possession-in-time deadline (honest local-disk read of `keys.len()` chunks).
/// The responder cannot have predicted which keys are sampled.
async fn request_byte_proof(ctx: &AuditCtx<'_>, keys: &[XorName]) -> ByteRound {
    let challenge = SubtreeByteChallenge {
        challenge_id: ctx.challenge_id,
        nonce: ctx.nonce,
        challenged_peer_id: *ctx.challenged_peer.as_bytes(),
        expected_commitment_hash: ctx.expected_commitment_hash,
        keys: keys.to_vec(),
    };
    let msg = ReplicationMessage {
        request_id: ctx.challenge_id,
        body: ReplicationMessageBody::SubtreeByteChallenge(challenge),
    };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Audit: failed to encode byte challenge: {e}");
            return ByteRound::Malformed;
        }
    };

    // Deadline sized to "honest responder reads `keys.len()` local chunks AND
    // ships them back": a relay forced to fetch them over the network blows it
    // (graced timeout, never a confirmed failure — same possession-in-time
    // principle as round 1). Uses the byte-round floor, which is high enough for
    // the multi-MiB reply (handshake + upload + busy disk) — the round-1
    // hashes-only floor would be too tight for 2 × 4 MiB (§4).
    let timeout = ctx.config.byte_audit_response_timeout(keys.len());
    let response = match ctx
        .p2p_node
        .send_request(
            ctx.challenged_peer,
            REPLICATION_PROTOCOL_ID,
            encoded,
            timeout,
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            debug!(
                "Audit: byte challenge to {} timed out / failed: {e}",
                ctx.challenged_peer
            );
            return ByteRound::Timeout;
        }
    };

    let resp_msg = match ReplicationMessage::decode(&response.data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Audit: failed to decode byte response: {e}");
            return ByteRound::Malformed;
        }
    };

    match resp_msg.body {
        ReplicationMessageBody::SubtreeByteResponse(SubtreeByteResponse::Items {
            challenge_id,
            items,
        }) if challenge_id == ctx.challenge_id => ByteRound::Served(items),
        ReplicationMessageBody::SubtreeByteResponse(SubtreeByteResponse::Rejected {
            challenge_id,
            kind,
            reason,
        }) if challenge_id == ctx.challenge_id => {
            // ADR-0004 A1: grace removed. UnknownCommitment/Protocol repudiation
            // of a pinned root is a confirmed failure; a Transient read error
            // routes to the timeout lane (credit revoked, no trust penalty) — the
            // responder retries reads first, so a Transient reaching round 2 means
            // it still could not serve committed bytes.
            match grade_reject(kind) {
                RejectGrade::Confirmed => {
                    warn!(
                        "Audit: {} rejected byte challenge ({kind:?}; confirmed): {reason}",
                        ctx.challenged_peer
                    );
                    ByteRound::Rejected
                }
                RejectGrade::TimeoutLane => {
                    debug!(
                        "Audit: {} returned Transient for byte challenge (timeout lane): {reason}",
                        ctx.challenged_peer
                    );
                    ByteRound::TransientReject
                }
            }
        }
        // A node claiming bootstrap MID-AUDIT (it answered round 1) is treated
        // as a timeout: it didn't prove possession but the round-1 proof shows
        // it isn't bootstrapping, so the bootstrap-claim-abuse detector (round 1)
        // owns that lane; here we just don't credit it.
        ReplicationMessageBody::SubtreeByteResponse(SubtreeByteResponse::Bootstrapping {
            challenge_id,
        }) if challenge_id == ctx.challenge_id => ByteRound::Timeout,
        _ => ByteRound::Malformed,
    }
}

/// Map a decoded response body to an audit outcome (auditor side). A response
/// whose `challenge_id` doesn't match, or any non-subtree body, is malformed.
async fn dispatch_subtree_response(
    body: ReplicationMessageBody,
    ctx: &AuditCtx<'_>,
) -> AuditTickResult {
    let challenged_peer = ctx.challenged_peer;
    let challenge_id = ctx.challenge_id;
    let malformed = || {
        failed(
            challenged_peer,
            challenge_id,
            AuditFailureReason::MalformedResponse,
        )
    };
    match body {
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Bootstrapping {
            challenge_id: resp_id,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            AuditTickResult::BootstrapClaim {
                peer: *challenged_peer,
            }
        }
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Rejected {
            challenge_id: resp_id,
            kind,
            reason,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            // ADR-0004 A1: audit grace is REMOVED. Answerability is now
            // restart-durable (persisted retention) and the auditor only pins
            // in-window roots, so an honest node can always answer a pin it could
            // be challenged on. A responsive rejection is therefore graded on the
            // kind, with no grace:
            match grade_reject(kind) {
                // Repudiating a pinned root the node published (`UnknownCommitment`)
                // or an explicit protocol fault is provable misbehaviour →
                // confirmed failure (trust penalty + credit revocation happen
                // downstream in handle_subtree_failed_audit).
                RejectGrade::Confirmed => {
                    warn!(
                        "Audit: peer {challenged_peer} rejected subtree challenge \
                         ({kind:?}; confirmed — grace removed): {reason}"
                    );
                    failed(challenged_peer, challenge_id, AuditFailureReason::Rejected)
                }
                // A transient local read error (already retried by the responder)
                // is not a provable cheat, but not graced-with-standing either:
                // route it to the non-response/timeout lane — no trust penalty, but
                // revoke the holder credit for THIS pinned commitment so it gains
                // no positive standing (a Transient-spammer profits nothing).
                // Scoped to the commitment hash, not the whole peer, so a stale
                // audit of an old commitment cannot erase credit re-earned for a
                // newer one.
                RejectGrade::TimeoutLane => {
                    if let Some(credit) = ctx.credit {
                        credit
                            .recent_provers
                            .write()
                            .await
                            .forget_commitment(&ctx.expected_commitment_hash);
                    }
                    debug!(
                        "Audit: peer {challenged_peer} returned Transient for subtree challenge \
                         (timeout lane; credit for the pinned commitment revoked): {reason}"
                    );
                    failed(challenged_peer, challenge_id, AuditFailureReason::Timeout)
                }
            }
        }
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Proof {
            challenge_id: resp_id,
            commitment,
            proof,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            verify_subtree_response(ctx, &commitment, &proof).await
        }
        _ => {
            warn!("Audit: unexpected response type from {challenged_peer}");
            malformed()
        }
    }
}

/// The pure verdict of evaluating a subtree-audit response, independent of
/// storage/network. Tests call this directly so the SHIPPED gate logic is what
/// gets exercised (no reimplementation that could drift).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditVerdict {
    /// All gates passed and at least one leaf was byte-verified.
    Pass {
        /// Number of leaves whose real bytes were verified in round 2.
        checked: usize,
    },
    /// A confirmed failure with this reason (penalizable / acted upon).
    Fail(AuditFailureReason),
}

/// Round-1 structural evaluation of a subtree-audit proof (ADR-0002).
///
/// Runs the cheap gates in fail-fast order: pin / identity / signature →
/// structure (the returned subtree rebuilds to the pinned root). It does **not**
/// prove byte possession — the leaves carry only the public `bytes_hash` (the
/// chunk address) and a `nonced_hash` the responder computed itself. Possession
/// is proven in round 2 ([`verify_byte_response`]), where the auditor demands
/// the original chunk bytes for a freshly-random (post-proof) sample and
/// recomputes both hashes from the SERVED content. This removes any dependency
/// on the auditor holding the peer's chunks.
///
/// Returns [`StructureVerdict::Valid`] (proceed to round 2) or a confirmed
/// [`AuditFailureReason`] mapped from the failing gate.
pub(crate) fn evaluate_subtree_structure(
    commitment: &StorageCommitment,
    proof: &SubtreeProof,
    nonce: &[u8; 32],
    expected_commitment_hash: &[u8; 32],
    challenged_peer_bytes: &[u8; 32],
) -> Result<(), AuditFailureReason> {
    // -- Pin + identity + signature --
    if &commitment.sender_peer_id != challenged_peer_bytes {
        return Err(AuditFailureReason::Rejected);
    }
    let derived_peer_id = *blake3::hash(&commitment.sender_public_key).as_bytes();
    if derived_peer_id != commitment.sender_peer_id {
        return Err(AuditFailureReason::Rejected);
    }
    match commitment_hash(commitment) {
        Some(h) if &h == expected_commitment_hash => {}
        _ => return Err(AuditFailureReason::Rejected),
    }
    if !crate::replication::commitment::verify_commitment_signature(commitment) {
        return Err(AuditFailureReason::Rejected);
    }

    // -- Structure --
    if let StructureVerdict::Invalid(_) = verify_subtree_proof(proof, nonce, commitment) {
        return Err(AuditFailureReason::DigestMismatch);
    }
    Ok(())
}

/// The auditor's **freshly-randomised** spot-check sample of the round-1 proof:
/// `count` distinct leaves (deduplicated, in increasing-index order) whose
/// original bytes the auditor will demand in round 2.
///
/// CRITICAL (ADR-0002 soundness): the sample MUST NOT be derivable from
/// anything the responder knew when it built the round-1 proof. The structural
/// root check binds only `(key, bytes_hash)` (both public — `bytes_hash` is the
/// chunk's network address), NOT `nonced_hash`. So a relay holding only public
/// addresses can fabricate a structurally-valid proof with bogus `nonced_hash`
/// on every leaf and, if it could predict which leaves round 2 opens, fetch
/// only those and pass — earning holder credit for leaves it never held.
///
/// Picking the sample with fresh CSPRNG randomness AFTER the proof is received
/// turns round 1 into a commitment and round 2 into an unpredictable challenge
/// (cut-and-choose): to pass with probability above `(1 - faked_fraction)^count`
/// the responder must have produced a correct `nonced_hash` — which requires the
/// real bytes — for essentially every leaf at round-1 commit time. The auditor
/// still holds none of the peer's chunks.
fn random_spotcheck_leaves(
    proof: &SubtreeProof,
    count: u32,
) -> Vec<&crate::replication::subtree::SubtreeLeaf> {
    let n = proof.leaves.len();
    if n == 0 {
        return Vec::new();
    }
    let want = (count as usize).min(n);
    let mut rng = rand::thread_rng();
    let mut picked = std::collections::BTreeSet::new();
    // n >= want, so this terminates quickly; bound the loop defensively against
    // a pathological RNG rather than risk spinning.
    let mut guard = 0u32;
    while picked.len() < want && guard < count.saturating_mul(64).max(64) {
        picked.insert(rng.gen_range(0..n));
        guard = guard.saturating_add(1);
    }
    // Deterministic top-up if the RNG kept colliding (astronomically unlikely):
    // fill the lowest missing indices so the sample is never silently short.
    for idx in 0..n {
        if picked.len() >= want {
            break;
        }
        picked.insert(idx);
    }
    picked
        .into_iter()
        .filter_map(|idx| proof.leaves.get(idx))
        .collect()
}

/// Round-2 verdict (ADR-0002): the responder served the original chunk content
/// for the auditor's spot-check sample; verify possession from THAT content.
///
/// `served(key)` returns what the responder returned for a requested key:
/// `Some(Some(bytes))` for [`SubtreeByteItem::Present`], `Some(None)` for an
/// explicit [`SubtreeByteItem::Absent`], and `None` if the responder omitted the
/// key entirely (treated like `Absent` — a committed key it would not serve).
///
/// For each sampled leaf the auditor recomputes, from the SERVED content:
///   - `BLAKE3(content) == leaf.bytes_hash` (the chunk's content address), AND
///   - `BLAKE3(nonce ‖ peer ‖ key ‖ content) == leaf.nonced_hash` (freshness),
///     i.e. `compute_audit_digest(nonce, peer, key, content)`.
///
/// The freshness inputs are byte-identical to what the responder used to BUILD
/// the leaf in round 1 (`subtree_leaf` → `nonced_leaf_hash`): the SAME four
/// inputs, so an honest holder's served content reproduces `nonced_hash`
/// exactly. Round 1 commits over the data (the `nonced_hash` is uncomputable
/// without the bytes); round 2 reveals a random subset to prove the commitment
/// was not fabricated.
///
/// Both checks are over the content the responder sent, so the auditor needs to
/// hold none of the peer's chunks. Any `Absent`/omitted committed key, or any
/// served content that fails a hash, is a provable lie → confirmed
/// [`AuditFailureReason::DigestMismatch`]. All sampled leaves verifying →
/// `Pass { checked }`.
pub(crate) fn verify_byte_response(
    leaves: &[&crate::replication::subtree::SubtreeLeaf],
    nonce: &[u8; 32],
    challenged_peer_bytes: &[u8; 32],
    served: impl Fn(&XorName) -> Option<Option<Vec<u8>>>,
) -> AuditVerdict {
    let mut checked = 0usize;
    for leaf in leaves {
        // Present{bytes} -> Some(Some(bytes)); Absent -> Some(None); omitted -> None.
        // A committed key the responder cannot / will not serve is a provable lie.
        let Some(Some(content)) = served(&leaf.key) else {
            return AuditVerdict::Fail(AuditFailureReason::DigestMismatch);
        };
        let plain = *blake3::hash(&content).as_bytes();
        let nonced = crate::replication::subtree::nonced_leaf_hash(
            nonce,
            challenged_peer_bytes,
            &leaf.key,
            &content,
        );
        if leaf.bytes_hash != plain || leaf.nonced_hash != nonced {
            // Served content does not hash to the committed address / freshness
            // hash: cannot be the chunk it committed to.
            return AuditVerdict::Fail(AuditFailureReason::DigestMismatch);
        }
        checked += 1;
    }
    AuditVerdict::Pass { checked }
}

/// Verify a subtree-proof response (auditor side), ADR-0002 two-round audit.
///
/// **Round 1** (this proof): pin + identity + signature + structure. If the
/// proof structurally rebuilds to the pinned root, the tree SHAPE is committed —
/// but not yet that the bytes are held. **Round 2**: the auditor picks a small
/// freshly-random (post-proof) sample of the just-proven leaves and sends a
/// [`SubtreeByteChallenge`] demanding their original chunk content FROM the
/// responder, then verifies that content against the committed `bytes_hash`
/// (content address) and `nonced_hash` (freshness). A responder that committed
/// to a chunk it no longer holds cannot serve content that hashes to the
/// committed address, so it fails — regardless of what the auditor holds. On a
/// full pass, credits the peer as a proven holder.
async fn verify_subtree_response(
    ctx: &AuditCtx<'_>,
    commitment: &StorageCommitment,
    proof: &SubtreeProof,
) -> AuditTickResult {
    let challenged_peer = ctx.challenged_peer;
    let challenge_id = ctx.challenge_id;

    // -- Round 1: pin/identity/signature + structure (no bytes). --
    if let Err(reason) = evaluate_subtree_structure(
        commitment,
        proof,
        &ctx.nonce,
        &ctx.expected_commitment_hash,
        challenged_peer.as_bytes(),
    ) {
        warn!("Audit: {challenged_peer} failed subtree structure ({reason:?})");
        return failed(challenged_peer, challenge_id, reason);
    }

    // -- Round 2: surprise byte challenge for a 3..=5 FRESHLY-RANDOM sample. --
    // The sample is chosen now, with CSPRNG randomness, AFTER the round-1 proof
    // is in hand — NOT derived from the round-1 nonce. The responder committed
    // every leaf's `nonced_hash` in round 1 without knowing which leaves we will
    // open, so it cannot have fabricated the un-opened ones (cut-and-choose).
    // We cap the sample at the ADR's 3..=5 band (clamped to the subtree size) so
    // the round-2 message and the responder's disk read stay cheap.
    let sample_n = ctx
        .config
        .audit_spotcheck_count()
        .clamp(BYTE_SPOTCHECK_MIN, BYTE_SPOTCHECK_MAX);
    let sampled = random_spotcheck_leaves(proof, sample_n);
    if sampled.is_empty() {
        // Cannot happen after a valid structure (subtree is never empty), but
        // guard rather than credit an unproven peer.
        warn!("Audit: {challenged_peer} produced an empty spot-check sample; rejecting");
        return failed(
            challenged_peer,
            challenge_id,
            AuditFailureReason::DigestMismatch,
        );
    }
    // The sample is challenged in batches of MAX_BYTE_CHALLENGE_KEYS so each
    // response — worst case, every requested chunk at MAX_CHUNK_SIZE — still
    // encodes under MAX_REPLICATION_MESSAGE_SIZE. Each batch carries its own
    // possession-in-time deadline (sized to its own length), so splitting does
    // not widen the per-chunk window a relay would need to fetch over the
    // network.
    //
    // CRITICAL: verify each batch's served bytes AS IT ARRIVES, against that
    // batch's own sampled leaves, and return a CONFIRMED failure immediately.
    // Deferring all verification until every batch is collected would let a
    // later batch's timeout-lane Timeout (`round_failure`) mask a deterministic
    // failure already proven by an earlier batch (an absent committed key or a
    // hash mismatch) — a confirmed cheat would be downgraded to a timeout. A
    // Timeout/Rejected/Malformed only becomes the verdict if NO earlier batch
    // already produced confirmed bad bytes.
    let verdict = 'rounds: {
        for batch in sampled.chunks(MAX_BYTE_CHALLENGE_KEYS) {
            let batch_keys: Vec<XorName> = batch.iter().map(|l| l.key).collect();
            match request_byte_proof(ctx, &batch_keys).await {
                ByteRound::Served(items) => {
                    // Verify THIS batch now. A confirmed failure here is final —
                    // a later batch's timeout must not be able to overwrite it.
                    let v = verify_byte_response(
                        batch,
                        &ctx.nonce,
                        challenged_peer.as_bytes(),
                        |key| {
                            items.iter().find_map(|it| match it {
                                SubtreeByteItem::Present { key: k, bytes } if k == key => {
                                    Some(Some(bytes.clone()))
                                }
                                SubtreeByteItem::Absent { key: k } if k == key => Some(None),
                                _ => None,
                            })
                        },
                    );
                    if let AuditVerdict::Fail(reason) = v {
                        break 'rounds AuditVerdict::Fail(reason);
                    }
                }
                // The responder rejected the byte challenge for a recently
                // pinned commitment → confirmed failure, same as round 1.
                ByteRound::Rejected => {
                    break 'rounds AuditVerdict::Fail(AuditFailureReason::Rejected)
                }
                // Transient reject (a local read error): ADR-0004 A1 routes it to
                // the timeout lane — no trust penalty, but revoke the holder
                // credit for THIS pinned commitment (the peer answered and could
                // not prove possession) before taking the Timeout verdict. Scoped
                // to the commitment hash, not the whole peer, so it never erases
                // credit the peer re-earned for a newer commitment.
                ByteRound::TransientReject => {
                    if let Some(credit) = ctx.credit {
                        credit
                            .recent_provers
                            .write()
                            .await
                            .forget_commitment(&ctx.expected_commitment_hash);
                    }
                    break 'rounds AuditVerdict::Fail(AuditFailureReason::Timeout);
                }
                // No response within the byte deadline (or transport error) →
                // timeout (graced by the caller's strike policy — could be
                // honest slowness). Keeps credit (a dropped packet is not
                // evidence of loss). Only reached when no earlier batch already
                // confirmed bad bytes.
                ByteRound::Timeout => {
                    break 'rounds AuditVerdict::Fail(AuditFailureReason::Timeout)
                }
                // Malformed/unexpected round-2 body.
                ByteRound::Malformed => {
                    break 'rounds AuditVerdict::Fail(AuditFailureReason::MalformedResponse)
                }
            }
        }
        // Every batch served bytes that verified.
        AuditVerdict::Pass {
            checked: sampled.len(),
        }
    };

    match verdict {
        AuditVerdict::Fail(reason) => {
            warn!("Audit: {challenged_peer} failed subtree audit ({reason:?})");
            failed(challenged_peer, challenge_id, reason)
        }
        AuditVerdict::Pass { checked } => {
            // Closeness (ADR-0002, soft/observe-only) — see observe_closeness.
            observe_closeness(ctx.p2p_node, ctx.config, challenged_peer, proof).await;
            // Credit the peer as a proven holder of its committed keys.
            if let (Some(credit), Some(pin)) = (ctx.credit, commitment_hash(commitment)) {
                let now = std::time::Instant::now();
                let mut provers = credit.recent_provers.write().await;
                for leaf in &proof.leaves {
                    provers.record_proof(leaf.key, *challenged_peer, pin, now);
                }
            }
            info!(
                "Audit: peer {challenged_peer} passed subtree audit ({} leaves, {checked} \
                 byte-checked)",
                proof.leaves.len()
            );
            AuditTickResult::Passed {
                challenged_peer: *challenged_peer,
                keys_checked: checked,
            }
        }
    }
}

/// Soft, density-aware closeness observation (ADR-0002). Logs — never fails —
/// when a suspicious fraction of the proof's leaves are keys the auditor itself
/// is NOT responsible for (a proxy for "implausibly far from the peer").
///
/// Using the auditor's own `SelfInclusiveRT` responsibility as the yardstick
/// makes this density-aware for free: on a small/dense network the auditor is
/// close to nearly every key, so almost nothing reads as far and no honest peer
/// is ever flagged. Enforcement is intentionally deferred until a testnet
/// calibrates the density threshold.
async fn observe_closeness(
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    challenged_peer: &PeerId,
    proof: &SubtreeProof,
) {
    /// Max leaves probed for the closeness estimate (bounds the DHT lookups).
    const CLOSENESS_SAMPLE_CAP: usize = 8;

    // This is an observe-only DEBUG signal (never enforced). The check costs one
    // DHT responsibility lookup per inspected leaf, so (§12): (a) skip it
    // entirely unless debug logging is on — there is no other consumer — and
    // (b) inspect at most a bounded SAMPLE of leaves rather than all ~sqrt(N),
    // which still reveals the "mostly far" padding shape without N lookups.
    if !crate::logging::enabled!(crate::logging::Level::DEBUG) {
        return;
    }

    let self_id = *p2p_node.peer_id();
    let inspected = proof.leaves.len().min(CLOSENESS_SAMPLE_CAP);
    let mut far = 0usize;
    for leaf in proof.leaves.iter().take(inspected) {
        if !crate::replication::admission::is_responsible(
            &self_id,
            &leaf.key,
            p2p_node,
            config.close_group_size,
        )
        .await
        {
            far += 1;
        }
    }
    // Only worth a line when MOST of the inspected sample is far — that's the
    // padding shape. A normal proof on a sparse network has some far keys.
    if inspected > 0 && far * 2 > inspected {
        debug!(
            "Audit: closeness signal — {far}/{inspected} sampled of {challenged_peer}'s proven \
             leaves are keys this auditor is not close to (observe-only; possible padding, not \
             penalized)"
        );
    }
}

/// Build a confirmed-failure result. The auditor pinned a commitment the peer
/// committed to itself, so there is no per-key responsibility to re-confirm:
/// the failure is about the peer's own committed tree.
///
/// The subtree audit fails a peer as a whole (one challenge, one verdict) rather
/// than per-key, so the [`AuditFailureSummary`] is a single-failure rollup
/// mapped from `reason` — enough for the shared audit-failure diagnostics log
/// line (`absent_keys`/`digest_mismatch_keys`) without inventing per-key counts
/// this audit shape does not have.
fn failed(
    challenged_peer: &PeerId,
    challenge_id: u64,
    reason: AuditFailureReason,
) -> AuditTickResult {
    let summary = subtree_failure_summary(&reason);
    AuditTickResult::Failed {
        evidence: FailureEvidence::AuditFailure {
            challenge_id,
            challenged_peer: *challenged_peer,
            confirmed_failed_keys: Vec::new(),
            summary,
            reason,
        },
    }
}

/// Map a subtree-audit `reason` to a single-failure [`AuditFailureSummary`].
///
/// A `Timeout` is not a confirmed failure (it is the non-response/timeout lane),
/// so it rolls up as zero confirmed failures; every other reason is one confirmed failure,
/// categorised where the category is meaningful (byte/nonce/root mismatch →
/// `digest_mismatch_keys`; explicit absent → `absent_keys`).
fn subtree_failure_summary(reason: &AuditFailureReason) -> AuditFailureSummary {
    let mut summary = AuditFailureSummary {
        challenged_keys: 1,
        ..AuditFailureSummary::default()
    };
    match reason {
        AuditFailureReason::Timeout => {}
        AuditFailureReason::DigestMismatch => {
            summary.failed_keys = 1;
            summary.digest_mismatch_keys = 1;
        }
        AuditFailureReason::KeyAbsent => {
            summary.failed_keys = 1;
            summary.absent_keys = 1;
        }
        AuditFailureReason::MalformedResponse | AuditFailureReason::Rejected => {
            summary.failed_keys = 1;
        }
    }
    summary
}

// ---------------------------------------------------------------------------
// Responder side
// ---------------------------------------------------------------------------

/// Handle an incoming subtree audit challenge (responder side).
///
/// Validates the challenge targets this node, looks up the pinned commitment in
/// the retained (last-two-gossiped) set, and builds the subtree proof for the
/// nonce-selected branch. If this node is bootstrapping it says so; if it
/// genuinely does not retain the pinned commitment it rejects (which the
/// auditor treats as a confirmed failure for a recently gossiped root).
pub async fn handle_subtree_challenge(
    challenge: &SubtreeAuditChallenge,
    storage: &LmdbStorage,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    commitment_state: Option<&Arc<ResponderCommitmentState>>,
) -> SubtreeAuditResponse {
    if is_bootstrapping {
        return SubtreeAuditResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    if challenge.challenged_peer_id != *self_peer_id.as_bytes() {
        warn!(
            "Subtree audit challenge targeted wrong peer: expected {}, got {}",
            hex::encode(self_peer_id.as_bytes()),
            hex::encode(challenge.challenged_peer_id),
        );
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: "challenged_peer_id does not match this node".to_string(),
        };
    }

    let Some(state) = commitment_state else {
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: "no commitment state".to_string(),
        };
    };

    // Look up the pinned commitment among the last-two-gossiped retained set.
    // A miss is `UnknownCommitment` — the auditor GRACES it (the peer may have
    // legitimately rotated past a root the auditor still had cached), rather
    // than treating legitimate rotation as a confirmed repudiation (§6).
    let Some(built) = state.lookup_by_hash(&challenge.expected_commitment_hash) else {
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::UnknownCommitment,
            reason: "unknown commitment hash".to_string(),
        };
    };

    // Geometry first (no bytes touched): which leaves to prove + the sibling
    // cut-hashes from the committed tree.
    let plan = match subtree_plan(built.tree(), &challenge.nonce) {
        Ok(p) => p,
        Err(e) => {
            warn!("Subtree audit: failed to plan proof: {e:?}");
            return SubtreeAuditResponse::Rejected {
                challenge_id: challenge.challenge_id,
                kind: RejectKind::Protocol,
                reason: "could not build subtree proof".to_string(),
            };
        }
    };

    // Read chunk bytes one leaf at a time so peak memory is bounded regardless
    // of subtree size, hashing each into its plain + nonced leaf.
    let mut leaves = Vec::with_capacity(plan.leaf_keys.len());
    for key in &plan.leaf_keys {
        let bytes = match get_raw_retrying(storage, key).await {
            Ok(Some(bytes)) => bytes,
            // Key is in our committed tree but definitively NOT stored — real
            // storage loss / the classic deleter. For a recently gossiped pin
            // the auditor counts this as a CONFIRMED failure.
            Ok(None) => {
                warn!(
                    "Subtree audit: missing bytes for committed key {}",
                    hex::encode(key)
                );
                return SubtreeAuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    kind: RejectKind::Protocol,
                    reason: format!("missing bytes for committed key: {}", hex::encode(key)),
                };
            }
            // Persistent transient read error after retries — NOT proof of missing
            // data. Reject `Transient`; the auditor routes it to the timeout lane
            // (no confirmed penalty) so a genuinely flaky disk is not branded a
            // deleter, while gaining no positive standing.
            Err(e) => {
                warn!(
                    "Subtree audit: storage read error for committed key {}: {e} \
                     (rejecting as transient, not a confirmed failure)",
                    hex::encode(key)
                );
                return SubtreeAuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    kind: RejectKind::Transient,
                    reason: format!("transient storage read error: {e}"),
                };
            }
        };
        leaves.push(crate::replication::subtree::subtree_leaf(
            &challenge.nonce,
            &challenge.challenged_peer_id,
            key,
            &bytes,
        ));
        // bytes drops here.
    }

    SubtreeAuditResponse::Proof {
        challenge_id: challenge.challenge_id,
        commitment: built.commitment().clone(),
        proof: SubtreeProof {
            leaves,
            sibling_cut_hashes: plan.sibling_cut_hashes,
        },
    }
}

/// Handle a round-2 byte challenge (responder side), ADR-0002.
///
/// The auditor has already structurally verified this node's round-1 subtree
/// proof and now demands the ORIGINAL chunk bytes for a small freshly-random
/// sample of those leaves. For each requested key the responder either returns
/// the bytes ([`SubtreeByteItem::Present`]) or — if it committed to the key but
/// can no longer produce it — an explicit [`SubtreeByteItem::Absent`], which the
/// auditor counts as a provable failure (committing to bytes you don't hold).
///
/// A key the responder never committed to (not in the pinned tree) is also
/// returned `Absent`: the auditor only ever samples keys it saw in round 1, so
/// in practice this guards against a malformed/forged byte challenge rather than
/// an honest mismatch.
pub async fn handle_subtree_byte_challenge(
    challenge: &SubtreeByteChallenge,
    storage: &LmdbStorage,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    commitment_state: Option<&Arc<ResponderCommitmentState>>,
) -> SubtreeByteResponse {
    if is_bootstrapping {
        return SubtreeByteResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    if challenge.challenged_peer_id != *self_peer_id.as_bytes() {
        return SubtreeByteResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: "challenged_peer_id does not match this node".to_string(),
        };
    }

    // An honest auditor batches its sample to MAX_BYTE_CHALLENGE_KEYS per
    // challenge so the worst-case response fits the wire cap. Reject larger
    // requests up front: serving them could only produce an unencodable
    // response (and invites disk-read amplification from a forged auditor).
    if challenge.keys.len() > MAX_BYTE_CHALLENGE_KEYS {
        let requested = challenge.keys.len();
        return SubtreeByteResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: format!(
                "byte challenge requests {requested} keys; max {MAX_BYTE_CHALLENGE_KEYS} per challenge"
            ),
        };
    }

    let Some(state) = commitment_state else {
        return SubtreeByteResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: "no commitment state".to_string(),
        };
    };
    // Resolve the SAME commitment the auditor pinned in round 1. If we no longer
    // retain it (rotated past it), reject as `UnknownCommitment` — the auditor
    // GRACES that (legitimate rotation it may not have observed, §6), rather
    // than confirming a failure. We serve bytes only for keys committed under
    // this pin.
    let Some(built) = state.lookup_by_hash(&challenge.expected_commitment_hash) else {
        return SubtreeByteResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::UnknownCommitment,
            reason: "unknown commitment hash".to_string(),
        };
    };

    let mut items = Vec::with_capacity(challenge.keys.len());
    for key in &challenge.keys {
        // Serve ONLY keys committed under this pin. A key the auditor asks for
        // that is not in the pinned tree is `Absent` — never served from local
        // storage just because we happen to hold it (§15: serving an
        // uncommitted-but-held key would let a forged challenge harvest bytes
        // and muddy the possession proof, which must be about THIS commitment).
        if built.proof_for(key).is_none() {
            items.push(SubtreeByteItem::Absent { key: *key });
            continue;
        }
        match get_raw_retrying(storage, key).await {
            // Committed key, bytes present → serve them.
            Ok(Some(bytes)) => items.push(SubtreeByteItem::Present { key: *key, bytes }),
            // Committed key, definitively absent → provable failure (§7: this is
            // a real "I don't hold it" answer, distinct from a read error).
            Ok(None) => {
                warn!(
                    "Subtree byte audit: committed key {} requested but bytes absent",
                    hex::encode(key)
                );
                items.push(SubtreeByteItem::Absent { key: *key });
            }
            // Persistent transient read error after retries → do NOT brand the
            // peer a deleter. Reject `Transient`; the auditor routes it to the
            // timeout lane so a flaky LMDB read never manufactures a confirmed
            // possession failure on an honest holder (which also gains no credit).
            Err(e) => {
                warn!(
                    "Subtree byte audit: storage read error for committed key {}: {e} \
                     (rejecting as transient, not a confirmed failure)",
                    hex::encode(key)
                );
                return SubtreeByteResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    kind: RejectKind::Transient,
                    reason: format!("transient storage read error: {e}"),
                };
            }
        }
    }

    SubtreeByteResponse::Items {
        challenge_id: challenge.challenge_id,
        items,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::commitment_state::BuiltCommitment;
    use crate::replication::subtree::{build_subtree_proof, nonced_leaf_hash, SubtreeLeaf};
    use saorsa_pqc::api::sig::ml_dsa_65;

    /// ADR-0004 A1 grade flip (grace removed): a responsive `UnknownCommitment`
    /// or `Protocol` rejection is a CONFIRMED failure; only `Transient` routes to
    /// the timeout lane. This pure decision backs both audit rounds
    /// (`Confirmed → AuditFailureReason::Rejected` / `ByteRound::Rejected`;
    /// `TimeoutLane → AuditFailureReason::Timeout` + pinned-credit revocation).
    #[test]
    fn grade_reject_removes_grace_for_unknown_commitment() {
        assert_eq!(
            grade_reject(RejectKind::UnknownCommitment),
            RejectGrade::Confirmed,
            "an unanswerable pinned root is now a confirmed failure, not graced"
        );
        assert_eq!(grade_reject(RejectKind::Protocol), RejectGrade::Confirmed);
        assert_eq!(
            grade_reject(RejectKind::Transient),
            RejectGrade::TimeoutLane,
            "a transient read error routes to the timeout lane (no confirmed penalty)"
        );
    }

    // The two-round audit splits into SHIPPED pure functions exercised directly
    // here (no reimplementation that could drift):
    //   - round 1: `evaluate_subtree_structure` (pin/identity/signature +
    //     structural root rebuild),
    //   - sampling: `random_spotcheck_leaves` (3..=5 FRESHLY-RANDOM leaves chosen
    //     after the proof is in hand — see its doc for the soundness argument), and
    //   - round 2: `verify_byte_response` (recompute content-address + freshness
    //     from the bytes the RESPONDER served — the auditor holds nothing).

    fn key(i: u32) -> XorName {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        k
    }
    /// The "chunk content" for a key in these fixtures. The committed tree's leaf
    /// `bytes_hash` is `BLAKE3(chunk_bytes(key))`, mirroring the general
    /// `(key, BLAKE3(content))` commitment; round 2 serves exactly this content.
    fn chunk_bytes(k: &XorName) -> Vec<u8> {
        let mut v = k.to_vec();
        v.extend_from_slice(b"chunk-body");
        v
    }

    /// Build an honest committed tree of `n` keys + a valid round-1 proof for
    /// `nonce`. Returns `(built, proof, peer_id)`. The auditor pins `built.hash()`.
    fn honest(n: u32, nonce: &[u8; 32]) -> (BuiltCommitment, SubtreeProof, [u8; 32]) {
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let pk_b = pk.to_bytes();
        let entries: Vec<_> = (0..n)
            .map(|i| {
                let k = key(i);
                (k, *blake3::hash(&chunk_bytes(&k)).as_bytes())
            })
            .collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_b).unwrap();
        let proof =
            build_subtree_proof(built.tree(), nonce, &peer_id, |k| Some(chunk_bytes(k))).unwrap();
        (built, proof, peer_id)
    }

    /// Round-1 verdict against the pinned commitment.
    fn structure(
        built: &BuiltCommitment,
        proof: &SubtreeProof,
        nonce: &[u8; 32],
        peer: &[u8; 32],
    ) -> Result<(), AuditFailureReason> {
        evaluate_subtree_structure(built.commitment(), proof, nonce, &built.hash(), peer)
    }

    /// The 3..=5 spot-check leaves the auditor would demand bytes for in round 2.
    /// Now freshly-random (post-proof) rather than nonce-derived; the `_nonce`/
    /// `_key_count` params are kept so existing call sites read unchanged.
    fn sample<'a>(
        proof: &'a SubtreeProof,
        _nonce: &[u8; 32],
        _key_count: u32,
    ) -> Vec<&'a SubtreeLeaf> {
        random_spotcheck_leaves(proof, 8u32.clamp(BYTE_SPOTCHECK_MIN, BYTE_SPOTCHECK_MAX))
    }

    // A round-2 `served` closure that returns the HONEST content for every key.
    // The nested-Option shape is the `verify_byte_response` callback contract:
    // Present{bytes} -> Some(Some(bytes)); Absent -> Some(None); omitted -> None.
    #[allow(clippy::option_option, clippy::unnecessary_wraps)]
    fn served_honest(key: &XorName) -> Option<Option<Vec<u8>>> {
        Some(Some(chunk_bytes(key)))
    }

    // ---- round 1: structure --------------------------------------------------

    #[test]
    fn honest_structure_then_bytes_passes() {
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        // Round 1.
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        // Round 2: honest responder serves the real content for the sample.
        let s = sample(&proof, &nonce, built.commitment().key_count);
        assert!(!s.is_empty());
        match verify_byte_response(&s, &nonce, &peer, served_honest) {
            AuditVerdict::Pass { checked } => assert!(checked >= 1, "must verify >=1 leaf"),
            other @ AuditVerdict::Fail(_) => panic!("expected Pass, got {other:?}"),
        }
    }

    #[test]
    fn commitment_bound_to_another_peer_rejected() {
        let nonce = [3u8; 32];
        let (built, proof, _peer) = honest(200, &nonce);
        let other = [0xAAu8; 32];
        assert_eq!(
            structure(&built, &proof, &nonce, &other),
            Err(AuditFailureReason::Rejected)
        );
    }

    #[test]
    fn wrong_pinned_commitment_rejected() {
        let nonce = [3u8; 32];
        let (built, proof, peer) = honest(200, &nonce);
        let mut wrong_pin = built.hash();
        wrong_pin[0] ^= 0x01;
        assert_eq!(
            evaluate_subtree_structure(built.commitment(), &proof, &nonce, &wrong_pin, &peer),
            Err(AuditFailureReason::Rejected)
        );
    }

    #[test]
    fn tampered_leaf_structure_rejected() {
        let nonce = [3u8; 32];
        let (built, mut proof, peer) = honest(200, &nonce);
        if let Some(first) = proof.leaves.first_mut() {
            first.bytes_hash[0] ^= 0x01; // breaks root reconstruction
        }
        assert_eq!(
            structure(&built, &proof, &nonce, &peer),
            Err(AuditFailureReason::DigestMismatch)
        );
    }

    #[test]
    fn wrong_leaf_count_structure_rejected() {
        let nonce = [3u8; 32];
        let (built, mut proof, peer) = honest(200, &nonce);
        proof.leaves.pop();
        assert_eq!(
            structure(&built, &proof, &nonce, &peer),
            Err(AuditFailureReason::DigestMismatch)
        );
    }

    // ---- round 2: responder-served bytes ------------------------------------

    #[test]
    fn deleter_absent_bytes_is_confirmed_failure() {
        // THE headline fix: a node whose round-1 proof is structurally perfect
        // but which has DELETED a committed chunk cannot serve its bytes. It
        // signals `Absent` for the sampled key → provable lie → confirmed
        // failure. Crucially, the auditor holds NONE of the peer's chunks; the
        // verdict depends only on what the responder serves.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        let s = sample(&proof, &nonce, built.commitment().key_count);
        // Responder returns Absent for the FIRST sampled key, honest for the rest.
        let victim = s.first().map(|l| l.key).unwrap();
        let v = verify_byte_response(&s, &nonce, &peer, |k| {
            if *k == victim {
                Some(None) // explicit Absent
            } else {
                Some(Some(chunk_bytes(k)))
            }
        });
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn omitted_committed_key_is_confirmed_failure() {
        // A responder that simply omits a sampled committed key from its items
        // (neither Present nor Absent) is treated identically to Absent: it
        // committed to the key and won't serve it → confirmed failure.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let victim = s.first().map(|l| l.key).unwrap();
        let v = verify_byte_response(&s, &nonce, &peer, |k| {
            if *k == victim {
                None // omitted entirely
            } else {
                Some(Some(chunk_bytes(k)))
            }
        });
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn fake_storage_garbage_bytes_is_confirmed_failure() {
        // A "fake-storage" responder claims possession but serves garbage. The
        // garbage does not hash to the committed content address (`bytes_hash`),
        // so the round-2 content-address check fails → confirmed failure. No
        // auditor holdings involved.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let v = verify_byte_response(&s, &nonce, &peer, |k| {
            let mut garbage = blake3::hash(k).as_bytes().to_vec();
            garbage.extend_from_slice(b"adversary-fake-storage");
            Some(Some(garbage))
        });
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn correct_content_address_but_stale_freshness_fails() {
        // Suppose a responder could serve bytes that hash to the content address
        // (it holds the chunk) — then BOTH checks pass; that is honest. But if
        // it serves bytes whose freshness hash does not match (e.g. replaying a
        // different nonce's digest is impossible since we recompute it here), the
        // freshness check must catch any content that doesn't reproduce the
        // committed `nonced_hash`. We model a leaf whose committed nonced_hash was
        // built under a DIFFERENT nonce, so the audit nonce's recompute differs.
        let nonce = [9u8; 32];
        let (built, mut proof, peer) = honest(400, &nonce);
        // Rewrite EVERY leaf's nonced_hash to one bound to a different nonce but
        // keep its bytes_hash correct (so each leaf's content-address check is
        // fine; only freshness is wrong). Tampering all leaves means the
        // freshly-random sample is guaranteed to land on a stale-freshness leaf.
        let other_nonce = [0xEEu8; 32];
        for leaf in &mut proof.leaves {
            leaf.nonced_hash =
                nonced_leaf_hash(&other_nonce, &peer, &leaf.key, &chunk_bytes(&leaf.key));
        }
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let v = verify_byte_response(&s, &nonce, &peer, served_honest);
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn auditor_holds_nothing_still_catches_deleter() {
        // Explicit contract: the auditor's own storage is irrelevant. A deleter
        // is caught purely from its served (absent) response. (Compare the OLD
        // design, where an auditor holding none of the chunks went Inconclusive
        // and the deleter walked free.)
        let nonce = [0x21u8; 32];
        let (built, proof, peer) = honest(256, &nonce);
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        let s = sample(&proof, &nonce, built.commitment().key_count);
        // Responder is a total deleter: Absent for everything.
        let v = verify_byte_response(&s, &nonce, &peer, |_| Some(None));
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn sample_size_is_in_3_to_5_band() {
        // ADR-0002: round-2 samples a SMALL surprise set (3..=5) of the proven
        // leaves. For a large subtree the sample is capped at 5.
        let nonce = [7u8; 32];
        let (built, proof, _peer) = honest(1024, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        assert!(
            (BYTE_SPOTCHECK_MIN as usize..=BYTE_SPOTCHECK_MAX as usize).contains(&s.len()),
            "sample {} must be within 3..=5",
            s.len()
        );
    }

    #[test]
    fn full_pass_requires_every_sampled_leaf() {
        // checked must equal the number of sampled leaves on a pass (no leaf is
        // silently skipped — every sampled, committed key must verify).
        let nonce = [11u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        match verify_byte_response(&s, &nonce, &peer, served_honest) {
            AuditVerdict::Pass { checked } => assert_eq!(checked, s.len()),
            other @ AuditVerdict::Fail(_) => panic!("expected Pass, got {other:?}"),
        }
    }

    // ---- end-to-end gate composition ----------------------------------------

    #[test]
    fn structure_fail_short_circuits_before_round_2() {
        // A structurally invalid proof is rejected in round 1; the byte challenge
        // is never issued. We assert the round-1 gate returns Err so the auditor
        // (verify_subtree_response) never reaches request_byte_proof.
        let nonce = [5u8; 32];
        let (built, mut proof, peer) = honest(300, &nonce);
        if let Some(first) = proof.leaves.first_mut() {
            first.bytes_hash[0] ^= 0x01;
        }
        assert!(structure(&built, &proof, &nonce, &peer).is_err());
    }

    /// Build an honest committed tree whose keys are deliberately "FAR": their
    /// addresses live at the high end of the XOR space (top bytes = 0xFF). On the
    /// auditor side these are the leaves `observe_closeness` counts toward `far`.
    fn honest_far(n: u32, nonce: &[u8; 32]) -> (BuiltCommitment, SubtreeProof, [u8; 32]) {
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let pk_b = pk.to_bytes();
        let entries: Vec<_> = (0..n)
            .map(|i| {
                let mut k = [0xFFu8; 32];
                k[28..].copy_from_slice(&i.to_be_bytes());
                (k, *blake3::hash(&chunk_bytes(&k)).as_bytes())
            })
            .collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_b).unwrap();
        let proof =
            build_subtree_proof(built.tree(), nonce, &peer_id, |k| Some(chunk_bytes(k))).unwrap();
        (built, proof, peer_id)
    }

    /// ADR-0002 "Closeness" is OBSERVE-ONLY: far-keyed honest proofs verify
    /// exactly like near-keyed ones. The verdict (structure + served bytes) is
    /// closeness-blind, so a "far/padding" shape can never produce a Fail.
    #[test]
    fn closeness_is_observe_only_far_keys_still_pass() {
        let nonce = [9u8; 32];

        let (built_far, proof_far, peer_far) = honest_far(400, &nonce);
        assert!(structure(&built_far, &proof_far, &nonce, &peer_far).is_ok());
        let sf = sample(&proof_far, &nonce, built_far.commitment().key_count);
        let v_far = verify_byte_response(&sf, &nonce, &peer_far, served_honest);

        let (built_near, proof_near, peer_near) = honest(400, &nonce);
        assert!(structure(&built_near, &proof_near, &nonce, &peer_near).is_ok());
        let sn = sample(&proof_near, &nonce, built_near.commitment().key_count);
        let v_near = verify_byte_response(&sn, &nonce, &peer_near, served_honest);

        match (&v_far, &v_near) {
            (AuditVerdict::Pass { checked: cf }, AuditVerdict::Pass { checked: cn }) => {
                assert!(*cf >= 1 && *cn >= 1);
            }
            other => panic!("both honest proofs must Pass regardless of closeness, got {other:?}"),
        }
        assert!(
            !matches!(v_far, AuditVerdict::Fail(_)),
            "far/padding-shaped honest proof must NEVER fail, got {v_far:?}"
        );
    }

    // Unused-leaf constructor guard: keep SubtreeLeaf import meaningful.
    #[test]
    fn subtree_leaf_is_constructible() {
        let _l = SubtreeLeaf {
            key: key(1),
            bytes_hash: [0u8; 32],
            nonced_hash: [0u8; 32],
        };
    }
}
