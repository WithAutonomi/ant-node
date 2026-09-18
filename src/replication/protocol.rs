//! Wire protocol messages for the replication subsystem.
//!
//! All messages use postcard serialization for compact, fast encoding.
//! Peer IDs are transmitted as raw `[u8; 32]` byte arrays.

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use saorsa_core::identity::PeerId;
use serde::{Deserialize, Serialize};

use crate::ant_protocol::XorName;

use super::types::AuditFailureReason;

pub use super::config::MAX_REPLICATION_MESSAGE_SIZE;
use super::config::MAX_SUBTREE_AUDIT_MESSAGE_SIZE;

/// Sentinel digest value indicating the challenged key is absent from storage.
///
/// Used in [`AuditResponse::Digests`] for keys the peer does not hold.
pub const ABSENT_KEY_DIGEST: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Top-level envelope
// ---------------------------------------------------------------------------

/// Top-level replication message envelope.
///
/// Every replication wire message carries a sender-assigned `request_id` so
/// that the receiver can correlate responses without relying on transport-layer
/// ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationMessage {
    /// Sender-assigned request ID for correlation.
    pub request_id: u64,
    /// The message body.
    pub body: ReplicationMessageBody,
}

impl ReplicationMessage {
    /// Encode the message to bytes using postcard.
    ///
    /// # Errors
    ///
    /// Returns [`ReplicationProtocolError::SerializationFailed`] if postcard
    /// serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, ReplicationProtocolError> {
        let bytes = postcard::to_stdvec(self)
            .map_err(|e| ReplicationProtocolError::SerializationFailed(e.to_string()))?;

        // The same family ceiling the decoder applies, from the same table and
        // with the same arms, including the unclassified case. Every receiver
        // drops a subtree-audit body over that ceiling before decoding it, so
        // encoding one and putting it on the wire produces a message nobody can
        // read, and the responder is then scored for the resulting silence.
        // Failing here turns that into a local, attributable error at the point
        // the oversized body was built.
        //
        // Matching `decode` exactly also means a body added later without a
        // family entry is measured against the same limit at both ends, so it
        // cannot become traffic that encodes here and is dropped there. It fails
        // loudly only if it exceeds the strict ceiling; a small unclassified body
        // still encodes, which is fine, because the receiver applies the same
        // ceiling and will accept it too. No legitimate body reaches the ceiling:
        // the largest is a round-1 proof at the commitment
        // key-count cap, pinned under it with headroom by
        // `max_round1_proof_fits_the_audit_family_ceiling`.
        let max_size = ceiling_for(family_of_variant(self.body.variant_index()));
        if bytes.len() > max_size {
            return Err(ReplicationProtocolError::MessageTooLarge {
                size: bytes.len(),
                max_size,
            });
        }

        // V2-623: cumulative per-variant tx accounting. Every replication send
        // funnels through here, so this is the single tx choke point.
        record_tx(&self.body, bytes.len());

        Ok(bytes)
    }

    /// Decode a message from bytes using postcard.
    ///
    /// Rejects payloads larger than [`MAX_REPLICATION_MESSAGE_SIZE`] before
    /// attempting deserialization.
    ///
    /// # Errors
    ///
    /// Returns [`ReplicationProtocolError::MessageTooLarge`] if the input
    /// exceeds the size limit, or
    /// [`ReplicationProtocolError::DeserializationFailed`] if postcard cannot
    /// parse the data.
    pub fn decode(data: &[u8]) -> Result<Self, ReplicationProtocolError> {
        // The ceiling follows the body's own family, read from its discriminant
        // before anything attacker-sized is touched. Putting it here rather than
        // only on the receive path is what makes it unskippable: a *response* is
        // decoded by whichever lane asked, and an audit lane asks a question a
        // few hundred bytes long, so without this a challenged peer could answer
        // with megabytes and be allocated all of it. Core bodies keep the core
        // allowance — a fetch response legitimately carries a whole chunk.
        // A prefix too malformed to classify takes the strict ceiling too: it
        // cannot be a legitimate message of any family, so it is not one to
        // decode generously.
        // `and_then`, not `map`: an index no variant declares classifies as
        // nothing, and `ceiling_for` gives nothing the strict ceiling exactly
        // like an unparseable prefix rather than the core allowance.
        let max_size = ceiling_for(peek_variant_index(data).and_then(family_of_variant));
        if data.len() > max_size {
            return Err(ReplicationProtocolError::MessageTooLarge {
                size: data.len(),
                max_size,
            });
        }
        let message: Self = postcard::from_bytes(data)
            .map_err(|e| ReplicationProtocolError::DeserializationFailed(e.to_string()))?;

        // V2-623: cumulative per-variant rx accounting. Every replication
        // receive funnels through here, so this is the single rx choke point.
        record_rx(&message.body, data.len());

        Ok(message)
    }

    /// Decode a reply to a subtree-audit challenge under the subtree-family ceiling.
    ///
    /// The pre-decode ceiling on the receive path bounds what an auditor can
    /// make a responder decode. This is that same bound in the other direction.
    /// A subtree challenge costs a few hundred bytes to send, so without it a challenged
    /// peer could answer with up to [`MAX_REPLICATION_MESSAGE_SIZE`] and make
    /// the auditor allocate and decode all of it — the cheap side of the
    /// exchange paying for the expensive one, which is the shape the responder
    /// ceiling exists to prevent. Subtree-audit bodies are ~110 KiB at worst (see
    /// [`MAX_SUBTREE_AUDIT_MESSAGE_SIZE`]), so this costs an honest responder nothing.
    ///
    /// No discriminant peek is needed here, unlike the receive path: the auditor
    /// asked the question, so it already knows the reply belongs to the subtree
    /// family, and a body that turns out not to be the expected one is rejected
    /// by the subtree lane's own matching afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`ReplicationProtocolError::MessageTooLarge`] above the subtree
    /// audit ceiling.
    pub fn decode_subtree_audit_response(data: &[u8]) -> Result<Self, ReplicationProtocolError> {
        if data.len() > MAX_SUBTREE_AUDIT_MESSAGE_SIZE {
            return Err(ReplicationProtocolError::MessageTooLarge {
                size: data.len(),
                max_size: MAX_SUBTREE_AUDIT_MESSAGE_SIZE,
            });
        }
        Self::decode(data)
    }
}

// ---------------------------------------------------------------------------
// Message body enum
// ---------------------------------------------------------------------------

/// All replication protocol message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationMessageBody {
    // === Fresh Replication (Section 6.1) ===
    /// Fresh replication offer with `PoP` (sent to close group members).
    FreshReplicationOffer(FreshReplicationOffer),
    /// Response to a fresh replication offer.
    FreshReplicationResponse(FreshReplicationResponse),

    /// Paid-list notification with `PoP` (sent to `PaidCloseGroup` members).
    PaidNotify(PaidNotify),

    // === Neighbor Sync (Section 6.2) ===
    /// Neighbor sync hint exchange (bidirectional).
    NeighborSyncRequest(NeighborSyncRequest),
    /// Response to neighbor sync with own hints.
    NeighborSyncResponse(NeighborSyncResponse),

    // === Verification (Section 9) ===
    /// Batched verification request (presence + paid-list queries).
    VerificationRequest(VerificationRequest),
    /// Response to verification request with per-key evidence.
    VerificationResponse(VerificationResponse),

    // === Fetch (record retrieval) ===
    /// Request to fetch a record by key.
    FetchRequest(FetchRequest),
    /// Response with the record data.
    FetchResponse(FetchResponse),

    // === Responsible-chunk audit (per-key digests) ===
    /// Per-key audit challenge: used by the responsible-chunk audit and the
    /// prune-confirmation path.
    AuditChallenge(AuditChallenge),
    /// Response to a per-key audit challenge.
    AuditResponse(AuditResponse),

    // === Storage-bound subtree audit (ADR-0002) ===
    /// Gossip-triggered contiguous-subtree storage audit challenge (round 1).
    SubtreeAuditChallenge(SubtreeAuditChallenge),
    /// Response to a contiguous-subtree storage audit challenge (round 1).
    SubtreeAuditResponse(SubtreeAuditResponse),
    /// Surprise slice challenge for the spot-checked leaves (round 2).
    SubtreeSliceChallenge(SubtreeSliceChallenge),
    /// Response carrying verified slices for the opened blocks (round 2).
    SubtreeSliceResponse(SubtreeSliceResponse),

    // === Commitment fetch by pin (ADR-0004) ===
    // APPENDED at the end so postcard variant discriminants of all the
    // pre-existing variants are unchanged — old nodes keep decoding every
    // message they already understood; only these two new indices are unknown
    // to them (and they never receive them, since old nodes never send the
    // matching request).
    /// Fetch a retained commitment by its pin (ADR-0004): used to resolve a
    /// quote's `commitment_pin` when the sidecar is absent and the gossip cache
    /// has no fresh copy.
    GetCommitmentByPin(GetCommitmentByPin),
    /// Response to [`Self::GetCommitmentByPin`].
    GetCommitmentByPinResponse(GetCommitmentByPinResponse),
}

// ---------------------------------------------------------------------------
// Cumulative per-variant traffic accounting (V2-623)
// ---------------------------------------------------------------------------
//
// Process-global relaxed-atomic counter table, indexed by variant. The
// encode/decode choke points bump these on every replication tx/rx; a periodic
// task in the replication engine emits them as `replication traffic summary
// (cumulative)` INFO lines. Values are monotonic since process start — rates
// are computed as deltas at query time, so a dropped/delayed log line cannot
// corrupt the data.
//
// A process-global static (rather than engine-owned state) is used because the
// encode/decode call sites are free functions scattered across the replication
// modules that do not carry any shared engine handle.

/// Number of [`ReplicationMessageBody`] variants (the counter-table width).
pub(crate) const N_REPLICATION_VARIANTS: usize = 17;

static REPL_TX_BYTES: [AtomicU64; N_REPLICATION_VARIANTS] =
    [const { AtomicU64::new(0) }; N_REPLICATION_VARIANTS];
static REPL_TX_COUNT: [AtomicU64; N_REPLICATION_VARIANTS] =
    [const { AtomicU64::new(0) }; N_REPLICATION_VARIANTS];
static REPL_RX_BYTES: [AtomicU64; N_REPLICATION_VARIANTS] =
    [const { AtomicU64::new(0) }; N_REPLICATION_VARIANTS];
static REPL_RX_COUNT: [AtomicU64; N_REPLICATION_VARIANTS] =
    [const { AtomicU64::new(0) }; N_REPLICATION_VARIANTS];

impl ReplicationMessageBody {
    /// Stable counter-table index for this variant.
    ///
    /// Matches declaration order. The last two variants were deliberately
    /// appended (see the enum comment) so this order is postcard-stable.
    pub(crate) fn variant_index(&self) -> usize {
        match self {
            Self::FreshReplicationOffer(_) => 0,
            Self::FreshReplicationResponse(_) => 1,
            Self::PaidNotify(_) => 2,
            Self::NeighborSyncRequest(_) => 3,
            Self::NeighborSyncResponse(_) => 4,
            Self::VerificationRequest(_) => 5,
            Self::VerificationResponse(_) => 6,
            Self::FetchRequest(_) => 7,
            Self::FetchResponse(_) => 8,
            Self::AuditChallenge(_) => 9,
            Self::AuditResponse(_) => 10,
            Self::SubtreeAuditChallenge(_) => 11,
            Self::SubtreeAuditResponse(_) => 12,
            Self::SubtreeSliceChallenge(_) => 13,
            Self::SubtreeSliceResponse(_) => 14,
            Self::GetCommitmentByPin(_) => 15,
            Self::GetCommitmentByPinResponse(_) => 16,
        }
    }

    /// Whether this body is a subtree storage-commitment audit message (both
    /// rounds). These ride [`SUBTREE_AUDIT_PROTOCOL_ID`], not the core
    /// [`REPLICATION_PROTOCOL_ID`]; the receive dispatch uses this to enforce
    /// that audit bodies only arrive on the audit id and core bodies only on the
    /// core id, so a mixed-version peer's message can never be honoured on the
    /// wrong handler even if postcard misdecodes it into a valid-looking value.
    ///
    /// [`SUBTREE_AUDIT_PROTOCOL_ID`]: crate::replication::config::SUBTREE_AUDIT_PROTOCOL_ID
    /// [`REPLICATION_PROTOCOL_ID`]: crate::replication::config::REPLICATION_PROTOCOL_ID
    #[must_use]
    pub fn is_subtree_audit(&self) -> bool {
        family_of_variant(self.variant_index()) == Some(BodyFamily::SubtreeAudit)
    }
}

/// Which protocol family a body belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFamily {
    /// Core replication, including digest-based responsible, possession, and
    /// prune-confirmation audits.
    Core,
    /// The four subtree storage-commitment audit bodies, both rounds.
    SubtreeAudit,
}

impl BodyFamily {
    /// Whether this family takes the tighter audit wire ceiling.
    #[must_use]
    pub(crate) fn is_audit(self) -> bool {
        matches!(self, Self::SubtreeAudit)
    }
}

/// The family of a body, keyed by its postcard discriminant.
///
/// Keyed by discriminant rather than by `&self` on purpose: the receive path has
/// to classify a message BEFORE decoding it, because the pre-decode size ceiling
/// is the only check that can run before an attacker-sized collection is
/// allocated. The discriminant is the one field reachable that early (see
/// [`peek_variant_index`]).
///
/// Everything that classifies a body reads this one table —
/// [`ReplicationMessageBody::is_subtree_audit`], outbound response routing, the
/// post-decode family guard, and the pre-decode ceiling — so the
/// pre- and post-decode views of "which family is this" cannot drift apart. A
/// drift is exactly what let an audit body sent on the core id skip the audit
/// ceiling and decode under the 10 MiB core allowance.
///
/// Indices match [`ReplicationMessageBody::variant_index`], which is declaration
/// order and postcard-stable.
///
/// `None` for an index that is not a variant of this enum. That is not the same
/// as "core": an index nothing declares cannot be a legitimate message of any
/// family, so callers selecting a wire ceiling must give it the strict audit one
/// rather than the generous core allowance. Postcard rejects an unknown outer
/// discriminant before decoding any trailing collection, so this is closing the
/// invariant rather than a demonstrated hole — but the rule "failing to classify
/// means do not decode generously" should hold everywhere, not just for a prefix
/// too malformed to parse.
#[must_use]
pub(crate) fn family_of_variant(index: usize) -> Option<BodyFamily> {
    match index {
        11..=14 => Some(BodyFamily::SubtreeAudit),
        0..=10 | 15 | 16 => Some(BodyFamily::Core),
        _ => None,
    }
}

/// The wire ceiling a body of this family takes.
///
/// One definition for both directions: `encode` measures what it produced
/// against it, `decode` measures what arrived before allocating anything. They
/// were duplicated matches that had to be kept in step by hand, which is the
/// kind of pair that silently drifts.
///
/// `None` — an index no declared variant uses — takes the STRICT ceiling.
/// Failing to classify must never mean "decode generously".
#[must_use]
pub(crate) fn ceiling_for(family: Option<BodyFamily>) -> usize {
    match family {
        Some(family) if !family.is_audit() => MAX_REPLICATION_MESSAGE_SIZE,
        _ => MAX_SUBTREE_AUDIT_MESSAGE_SIZE,
    }
}

/// Maximum bytes a postcard varint can occupy for a `u64`.
const MAX_VARINT_LEN: usize = 10;

/// Read one postcard varint (LEB128, little-endian base-128) from `bytes`.
///
/// Returns the value and how many bytes it consumed. Bounded by `max_bytes` and
/// by the 64-bit shift, so a hostile prefix cannot spin here.
fn read_varint(bytes: &[u8], max_bytes: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, byte) in bytes.iter().take(max_bytes).enumerate() {
        let payload = u64::from(byte & 0x7F);
        // A u64 LEB128 has only one payload bit left in byte ten. Rust's
        // shifts discard high bits rather than reporting value overflow, so
        // `checked_shl` alone would accept (and wrap) a terminal payload > 1.
        // Treat that malformed prefix as unclassifiable and apply the strict
        // audit ceiling.
        if shift == 63 && payload > 1 {
            return None;
        }
        value |= payload.checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift = shift.checked_add(7)?;
        if shift >= u64::BITS {
            return None;
        }
    }
    None
}

/// Read a message's body discriminant without decoding the body.
///
/// `ReplicationMessage` is `{ request_id: u64, body: ReplicationMessageBody }`,
/// and postcard writes struct fields in order with no length prefix: a varint
/// `request_id`, then the enum's varint discriminant. So the discriminant sits
/// behind at most [`MAX_VARINT_LEN`] bytes and costs two bounded varint reads to
/// reach — no allocation, and nothing attacker-sized is touched.
///
/// `None` means the prefix is not even well-formed enough to classify; the
/// caller treats that as "apply the strictest ceiling", since a message we
/// cannot classify is one we should not decode generously.
///
/// A test round-trips every variant through `encode` to prove this agrees with
/// [`ReplicationMessageBody::variant_index`] for real messages, rather than
/// trusting this reading of postcard's format.
#[must_use]
pub(crate) fn peek_variant_index(data: &[u8]) -> Option<usize> {
    let (_request_id, consumed) = read_varint(data, MAX_VARINT_LEN)?;
    let rest = data.get(consumed..)?;
    let (variant, _) = read_varint(rest, MAX_VARINT_LEN)?;
    usize::try_from(variant).ok()
}

// ---------------------------------------------------------------------------
// Cumulative audit outcome accounting (extends V2-623)
// ---------------------------------------------------------------------------
//
// The per-variant traffic counters above already give audit *volume* (challenge
// tx = launched, response tx = served). These tally the *outcomes*, which the
// traffic counters cannot express: auditor-side pass/fail per failure reason,
// and responder-side admission drops (challenges refused at the flood-fair
// caps). Same conventions: process-global relaxed atomics, monotonic since
// process start, emitted next to the traffic summary and diffed at query time.

/// Auditor-side audit kinds with pass/fail outcome tallies.
#[derive(Clone, Copy)]
pub(crate) enum AuditOutcomeKind {
    /// Responsible-chunk audit (audit #2, `AuditChallenge`).
    Responsible = 0,
    /// Storage-bound subtree audit (ADR-0002).
    Subtree = 1,
}

/// Responder-side challenge kinds dropped at the admission caps.
#[derive(Clone, Copy)]
pub(crate) enum AuditDropKind {
    /// Responsible-chunk / prune-confirmation `AuditChallenge`.
    Responsible = 0,
    /// Subtree audit round-1 challenge.
    Subtree = 1,
    /// Subtree audit round-2 slice challenge.
    ///
    /// The emitted counter is still named `audit_dropped_byte` (see
    /// `log_audit_outcome_summary`): round 2 no longer serves full chunk bytes,
    /// but keeping the wire-visible counter name fixed is what lets a v2 fleet
    /// and a v3 fleet be compared with no field mapping. The name is a metric
    /// identifier, not a description of the payload.
    Slice = 2,
}

/// One slot per [`AuditFailureReason`] variant, per [`AuditOutcomeKind`].
const N_FAIL_REASONS: usize = 5;
const N_OUTCOME_KINDS: usize = 2;
const N_DROP_KINDS: usize = 3;

static AUDIT_PASS: [AtomicU64; N_OUTCOME_KINDS] = [const { AtomicU64::new(0) }; N_OUTCOME_KINDS];
static AUDIT_FAIL: [AtomicU64; N_OUTCOME_KINDS * N_FAIL_REASONS] =
    [const { AtomicU64::new(0) }; N_OUTCOME_KINDS * N_FAIL_REASONS];
static AUDIT_DROPPED: [AtomicU64; N_DROP_KINDS] = [const { AtomicU64::new(0) }; N_DROP_KINDS];

/// Stable counter index for a failure reason. Matches declaration order of
/// [`AuditFailureReason`]; exhaustive so a new variant is a compile error here.
fn fail_reason_index(reason: &AuditFailureReason) -> usize {
    match reason {
        AuditFailureReason::Timeout => 0,
        AuditFailureReason::MalformedResponse => 1,
        AuditFailureReason::DigestMismatch => 2,
        AuditFailureReason::KeyAbsent => 3,
        AuditFailureReason::Rejected => 4,
    }
}

/// Record an auditor-side audit pass.
pub(crate) fn record_audit_pass(kind: AuditOutcomeKind) {
    AUDIT_PASS[kind as usize].fetch_add(1, Ordering::Relaxed);
}

/// Record an auditor-side audit failure with its reason.
pub(crate) fn record_audit_fail(kind: AuditOutcomeKind, reason: &AuditFailureReason) {
    AUDIT_FAIL[kind as usize * N_FAIL_REASONS + fail_reason_index(reason)]
        .fetch_add(1, Ordering::Relaxed);
}

/// Record a responder-side challenge dropped at the admission caps.
pub(crate) fn record_audit_drop(kind: AuditDropKind) {
    AUDIT_DROPPED[kind as usize].fetch_add(1, Ordering::Relaxed);
}

/// Emit the cumulative audit outcome tallies as one INFO summary line, same
/// target and cadence as [`log_traffic_summary`] (`group = 4`), so the
/// telegraf→Elasticsearch pipeline lifts each key into a `tail.*` field and
/// pass/fail/drop rates per hour fall out of max-per-hour deltas.
pub(crate) fn log_audit_outcome_summary() {
    let pass = |k: usize| AUDIT_PASS[k].load(Ordering::Relaxed);
    let fail = |k: usize, r: usize| AUDIT_FAIL[k * N_FAIL_REASONS + r].load(Ordering::Relaxed);
    let drop = |k: usize| AUDIT_DROPPED[k].load(Ordering::Relaxed);

    crate::logging::info!(
        target: "ant_node::replication::traffic",
        group = 4,
        responsible_audit_pass = pass(0),
        responsible_audit_fail_timeout = fail(0, 0),
        responsible_audit_fail_malformed = fail(0, 1),
        responsible_audit_fail_digest_mismatch = fail(0, 2),
        responsible_audit_fail_key_absent = fail(0, 3),
        responsible_audit_fail_rejected = fail(0, 4),
        subtree_audit_pass = pass(1),
        subtree_audit_fail_timeout = fail(1, 0),
        subtree_audit_fail_malformed = fail(1, 1),
        subtree_audit_fail_digest_mismatch = fail(1, 2),
        subtree_audit_fail_key_absent = fail(1, 3),
        subtree_audit_fail_rejected = fail(1, 4),
        audit_dropped_responsible = drop(0),
        audit_dropped_subtree = drop(1),
        audit_dropped_byte = drop(2),
        "audit outcome summary (cumulative)"
    );
}

/// Record an encoded (tx) replication message against its variant.
fn record_tx(body: &ReplicationMessageBody, bytes: usize) {
    let i = body.variant_index();
    REPL_TX_BYTES[i].fetch_add(bytes as u64, Ordering::Relaxed);
    REPL_TX_COUNT[i].fetch_add(1, Ordering::Relaxed);
}

/// Record a decoded (rx) replication message against its variant.
fn record_rx(body: &ReplicationMessageBody, bytes: usize) {
    let i = body.variant_index();
    REPL_RX_BYTES[i].fetch_add(bytes as u64, Ordering::Relaxed);
    REPL_RX_COUNT[i].fetch_add(1, Ordering::Relaxed);
}

/// Emit the cumulative per-variant replication traffic as INFO summary lines
/// (V2-623), target `ant_node::replication::traffic`.
///
/// The fields are flat snake-case keys (`<stem>_tx_bytes`, `<stem>_rx_count`,
/// …) so the telegraf→Elasticsearch pipeline lifts each into a first-class
/// `tail.*` field and the acceptance query (`max` per field per hour → delta)
/// yields per-variant MB/h directly.
///
/// 17 variants × 4 fields = 68 flat keys. `tracing` caps an event at 32 fields,
/// so the keys are split across three lines that share the same `target` and
/// message and are distinguished by a `group` field — telegraf still lifts
/// every key into its own ES field, so the split is transparent at query time.
pub(crate) fn log_traffic_summary() {
    // Relaxed loads — a slightly skewed read across counters is fine because
    // rates are computed as deltas over many intervals at query time.
    let tb = |i: usize| REPL_TX_BYTES[i].load(Ordering::Relaxed);
    let tc = |i: usize| REPL_TX_COUNT[i].load(Ordering::Relaxed);
    let rb = |i: usize| REPL_RX_BYTES[i].load(Ordering::Relaxed);
    let rc = |i: usize| REPL_RX_COUNT[i].load(Ordering::Relaxed);

    crate::logging::info!(
        target: "ant_node::replication::traffic",
        group = 1,
        fresh_offer_tx_bytes = tb(0), fresh_offer_tx_count = tc(0),
        fresh_offer_rx_bytes = rb(0), fresh_offer_rx_count = rc(0),
        fresh_response_tx_bytes = tb(1), fresh_response_tx_count = tc(1),
        fresh_response_rx_bytes = rb(1), fresh_response_rx_count = rc(1),
        paid_notify_tx_bytes = tb(2), paid_notify_tx_count = tc(2),
        paid_notify_rx_bytes = rb(2), paid_notify_rx_count = rc(2),
        neighbor_sync_request_tx_bytes = tb(3), neighbor_sync_request_tx_count = tc(3),
        neighbor_sync_request_rx_bytes = rb(3), neighbor_sync_request_rx_count = rc(3),
        neighbor_sync_response_tx_bytes = tb(4), neighbor_sync_response_tx_count = tc(4),
        neighbor_sync_response_rx_bytes = rb(4), neighbor_sync_response_rx_count = rc(4),
        verification_request_tx_bytes = tb(5), verification_request_tx_count = tc(5),
        verification_request_rx_bytes = rb(5), verification_request_rx_count = rc(5),
        "replication traffic summary (cumulative)"
    );
    crate::logging::info!(
        target: "ant_node::replication::traffic",
        group = 2,
        verification_response_tx_bytes = tb(6), verification_response_tx_count = tc(6),
        verification_response_rx_bytes = rb(6), verification_response_rx_count = rc(6),
        fetch_request_tx_bytes = tb(7), fetch_request_tx_count = tc(7),
        fetch_request_rx_bytes = rb(7), fetch_request_rx_count = rc(7),
        fetch_response_tx_bytes = tb(8), fetch_response_tx_count = tc(8),
        fetch_response_rx_bytes = rb(8), fetch_response_rx_count = rc(8),
        audit_challenge_tx_bytes = tb(9), audit_challenge_tx_count = tc(9),
        audit_challenge_rx_bytes = rb(9), audit_challenge_rx_count = rc(9),
        audit_response_tx_bytes = tb(10), audit_response_tx_count = tc(10),
        audit_response_rx_bytes = rb(10), audit_response_rx_count = rc(10),
        subtree_audit_challenge_tx_bytes = tb(11), subtree_audit_challenge_tx_count = tc(11),
        subtree_audit_challenge_rx_bytes = rb(11), subtree_audit_challenge_rx_count = rc(11),
        "replication traffic summary (cumulative)"
    );
    crate::logging::info!(
        target: "ant_node::replication::traffic",
        group = 3,
        subtree_audit_response_tx_bytes = tb(12), subtree_audit_response_tx_count = tc(12),
        subtree_audit_response_rx_bytes = rb(12), subtree_audit_response_rx_count = rc(12),
        // Indices 13/14 are the round-2 pair, renamed on the wire to
        // `SubtreeSliceChallenge`/`SubtreeSliceResponse`. The COUNTER names stay
        // `subtree_byte_*` on purpose: they are the field names an operator
        // queries, and holding them fixed is what let the V2-685 testnet compare
        // a 0.15.0 cohort against a slice-audit cohort with no field mapping
        // (6.19 MB vs 14.49 KB per response, same query). Renaming them would
        // silently zero every existing dashboard and alert. The variant index,
        // not the label, is the source of truth for what is being counted.
        subtree_byte_challenge_tx_bytes = tb(13), subtree_byte_challenge_tx_count = tc(13),
        subtree_byte_challenge_rx_bytes = rb(13), subtree_byte_challenge_rx_count = rc(13),
        subtree_byte_response_tx_bytes = tb(14), subtree_byte_response_tx_count = tc(14),
        subtree_byte_response_rx_bytes = rb(14), subtree_byte_response_rx_count = rc(14),
        get_commitment_by_pin_tx_bytes = tb(15), get_commitment_by_pin_tx_count = tc(15),
        get_commitment_by_pin_rx_bytes = rb(15), get_commitment_by_pin_rx_count = rc(15),
        get_commitment_by_pin_response_tx_bytes = tb(16),
        get_commitment_by_pin_response_tx_count = tc(16),
        get_commitment_by_pin_response_rx_bytes = rb(16),
        get_commitment_by_pin_response_rx_count = rc(16),
        "replication traffic summary (cumulative)"
    );
}

// ---------------------------------------------------------------------------
// Per-peer served-bytes accounting (V2-684)
// ---------------------------------------------------------------------------
//
// Follow-up to V2-623: the per-variant table above says how many bytes each
// message type served, but not WHICH peers pulled them. This adds per-peer
// attribution for the heavy serve paths (`FetchResponse`, `NeighborSyncResponse`
// — ~99% of served bytes), emitted as a top-10-by-bytes INFO line on the same
// cadence and target as `log_traffic_summary`.
//
// Design (mirrors V2-623's process-global-static choice for the same reason —
// the serve choke point is a free function with no engine handle):
//
//   * A bounded, sharded table caps memory at `SERVED_SHARDS * SERVED_SHARD_CAP`
//     peers total.
//   * The serve hot path takes only a shared read lock on one shard plus two
//     relaxed `fetch_add`s when the peer is already tracked — no global lock per
//     response. A previously-unseen peer takes a one-shard write lock (rare).
//   * Per-shard eviction of the smallest-bytes entry when a shard is full. The
//     peers that matter are the largest accumulators and are never the minimum,
//     so they cannot be evicted by transient noise.
//   * Values are cumulative/monotonic since process start, so a dropped or
//     delayed log line cannot corrupt query-time deltas.

/// Number of shards in the served-peers table. Peers are assigned by the low
/// nibble of their first ID byte; peer IDs are hash-random (BLAKE3), so the
/// distribution across shards is uniform. Must be a power of two.
const SERVED_SHARDS: usize = 16;

/// Max peers tracked per shard. `SERVED_SHARDS * SERVED_SHARD_CAP` = 256 total.
const SERVED_SHARD_CAP: usize = 16;

/// Cumulative served counters for a single peer.
struct PeerServeStats {
    bytes: AtomicU64,
    count: AtomicU64,
}

/// One shard of the served-peers table: a small, cap-bounded list of
/// `(peer, counters)`. A `Vec` linear-scanned over at most `SERVED_SHARD_CAP`
/// entries is cheaper than hashing and — unlike `HashMap` — is
/// const-constructible, so the whole table is a plain `static` with no lazy
/// initialisation.
struct ServedShard {
    entries: RwLock<Vec<(PeerId, PeerServeStats)>>,
}

impl ServedShard {
    const fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }
}

static SERVED_PEERS: [ServedShard; SERVED_SHARDS] = [const { ServedShard::new() }; SERVED_SHARDS];

/// Cumulative count of peers evicted from the table (bounded-map pressure
/// indicator; emitted as `evictions`).
static SERVED_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// Shard index for a peer: the low `log2(SERVED_SHARDS)` bits of the first ID
/// byte.
fn served_shard_index(peer: &PeerId) -> usize {
    (peer.to_bytes()[0] as usize) & (SERVED_SHARDS - 1)
}

/// Record `bytes` served to `peer` (V2-684), called from the replication serve
/// choke point for the heavy response variants.
///
/// Fast path (peer already tracked): a shared read lock on one shard plus two
/// relaxed `fetch_add`s. Slow path (new peer): a one-shard write lock that
/// inserts the peer and, if the shard is at capacity, first evicts its
/// smallest-bytes entry.
pub(crate) fn record_served(peer: &PeerId, bytes: usize) {
    let shard = &SERVED_PEERS[served_shard_index(peer)];
    let bytes = bytes as u64;

    // Fast path: peer already present — no structural change, shared lock only.
    {
        let guard = shard.entries.read();
        if let Some((_, stats)) = guard.iter().find(|(p, _)| p == peer) {
            stats.bytes.fetch_add(bytes, Ordering::Relaxed);
            stats.count.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    // Slow path: insert the new peer. Re-check under the write lock in case a
    // racing writer added it between our read and write.
    let mut guard = shard.entries.write();
    if let Some((_, stats)) = guard.iter().find(|(p, _)| p == peer) {
        stats.bytes.fetch_add(bytes, Ordering::Relaxed);
        stats.count.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if guard.len() >= SERVED_SHARD_CAP {
        // Evict the smallest-bytes entry; the peers we care about are the
        // largest accumulators and are never the per-shard minimum.
        if let Some((min_idx, _)) = guard
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, s))| s.bytes.load(Ordering::Relaxed))
        {
            guard.swap_remove(min_idx);
            SERVED_EVICTIONS.fetch_add(1, Ordering::Relaxed);
        }
    }
    guard.push((
        *peer,
        PeerServeStats {
            bytes: AtomicU64::new(bytes),
            count: AtomicU64::new(1),
        },
    ));
}

/// Emit the cumulative top-K per-peer served-bytes summary (V2-684) as one INFO
/// line, target `ant_node::replication::traffic`, on the same cadence as
/// [`log_traffic_summary`].
///
/// The top 10 peers × 3 fields + `tracked_peers` + `evictions` = 32 fields,
/// exactly the `tracing` per-event field cap, so it fits on one line. Peer IDs
/// are full hex ([`PeerId::to_hex`]), matching the `claiming bootstrap` /
/// `per-source pending cap` log lines so the two can be joined in Elasticsearch.
/// Empty slots (fewer than 10 tracked peers) emit an empty id and zero counters
/// to keep the ES field schema stable.
pub(crate) fn log_served_peers_summary() {
    // Snapshot every shard, then rank. Reads are relaxed and short-lived; a
    // slightly skewed snapshot is fine because values are cumulative and
    // compared as deltas at query time.
    let mut all: Vec<(PeerId, u64, u64)> = Vec::new();
    for shard in &SERVED_PEERS {
        let guard = shard.entries.read();
        for (peer, stats) in guard.iter() {
            all.push((
                *peer,
                stats.bytes.load(Ordering::Relaxed),
                stats.count.load(Ordering::Relaxed),
            ));
        }
    }
    let tracked_peers = all.len() as u64;
    let evictions = SERVED_EVICTIONS.load(Ordering::Relaxed);

    // Top-K by bytes served, descending.
    all.sort_unstable_by_key(|(_, bytes, _)| std::cmp::Reverse(*bytes));

    // Fixed slots keep the emitted field set stable regardless of how many peers
    // are currently tracked.
    let id = |n: usize| all.get(n).map(|(p, _, _)| p.to_hex()).unwrap_or_default();
    let by = |n: usize| all.get(n).map_or(0, |(_, b, _)| *b);
    let ct = |n: usize| all.get(n).map_or(0, |(_, _, c)| *c);

    crate::logging::info!(
        target: "ant_node::replication::traffic",
        peer_1_id = %id(0), peer_1_bytes = by(0), peer_1_count = ct(0),
        peer_2_id = %id(1), peer_2_bytes = by(1), peer_2_count = ct(1),
        peer_3_id = %id(2), peer_3_bytes = by(2), peer_3_count = ct(2),
        peer_4_id = %id(3), peer_4_bytes = by(3), peer_4_count = ct(3),
        peer_5_id = %id(4), peer_5_bytes = by(4), peer_5_count = ct(4),
        peer_6_id = %id(5), peer_6_bytes = by(5), peer_6_count = ct(5),
        peer_7_id = %id(6), peer_7_bytes = by(6), peer_7_count = ct(6),
        peer_8_id = %id(7), peer_8_bytes = by(7), peer_8_count = ct(7),
        peer_9_id = %id(8), peer_9_bytes = by(8), peer_9_count = ct(8),
        peer_10_id = %id(9), peer_10_bytes = by(9), peer_10_count = ct(9),
        tracked_peers = tracked_peers,
        evictions = evictions,
        "replication served-peers summary (cumulative)"
    );
}

// ---------------------------------------------------------------------------
// Fresh Replication Messages
// ---------------------------------------------------------------------------

/// Fresh replication offer (includes record + `PoP`).
///
/// Sent to close-group members when a node receives a new chunk via client PUT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshReplicationOffer {
    /// The record key.
    pub key: XorName,
    /// The record data.
    pub data: Vec<u8>,
    /// Proof of Payment (required, validated by receiver).
    pub proof_of_payment: Vec<u8>,
}

/// Response to a fresh replication offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FreshReplicationResponse {
    /// Record accepted and stored.
    Accepted {
        /// The accepted record key.
        key: XorName,
    },
    /// Record rejected (with reason).
    Rejected {
        /// The rejected record key.
        key: XorName,
        /// Human-readable rejection reason.
        reason: String,
    },
}

/// Paid-list notification carrying key + `PoP` (Section 7.3).
///
/// Sent to `PaidCloseGroup` members so they record the key in their
/// `PaidForList` without needing to hold the record data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaidNotify {
    /// The record key.
    pub key: XorName,
    /// Proof of Payment for receiver-side verification.
    pub proof_of_payment: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Neighbor Sync Messages
// ---------------------------------------------------------------------------

/// Neighbor sync request carrying hint sets (Section 6.2).
///
/// Exchanged between close neighbors to detect and repair missing replicas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborSyncRequest {
    /// Keys sender believes receiver should hold (replica hints).
    pub replica_hints: Vec<XorName>,
    /// Keys sender believes receiver should track in `PaidForList` (paid hints).
    pub paid_hints: Vec<XorName>,
    /// Whether sender is currently bootstrapping.
    pub bootstrapping: bool,
    /// Sender's signed storage commitment (optional, see
    /// [`crate::replication::commitment`]). `None` from old peers; from
    /// new peers this carries the Merkle-root commitment over the
    /// sender's claimed keys. Receivers that recognize it store it as
    /// the per-peer "last known commitment" used to pin commitment-bound
    /// audits.
    #[serde(default)]
    pub commitment: Option<crate::replication::commitment::StorageCommitment>,
}

/// Neighbor sync response carrying own hint sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborSyncResponse {
    /// Keys receiver believes sender should hold (replica hints).
    pub replica_hints: Vec<XorName>,
    /// Keys receiver believes sender should track in `PaidForList` (paid hints).
    pub paid_hints: Vec<XorName>,
    /// Whether receiver is currently bootstrapping.
    pub bootstrapping: bool,
    /// Keys that receiver rejected (optional feedback to sender).
    pub rejected_keys: Vec<XorName>,
    /// Receiver's signed storage commitment (optional, see
    /// [`NeighborSyncRequest::commitment`]).
    #[serde(default)]
    pub commitment: Option<crate::replication::commitment::StorageCommitment>,
}

// ---------------------------------------------------------------------------
// Verification Messages
// ---------------------------------------------------------------------------

/// Batched verification request for multiple keys (Section 9).
///
/// Sent to peers in `VerifyTargets` (union of `QuorumTargets` and
/// `PaidTargets`). Each peer returns per-key presence and optionally
/// paid-list status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// Keys to verify (batched).
    pub keys: Vec<XorName>,
    /// Which keys need paid-list status in addition to presence.
    /// Each value is an index into the `keys` vector.
    pub paid_list_check_indices: Vec<u32>,
}

/// Per-key verification result from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVerificationResult {
    /// The key being verified.
    pub key: XorName,
    /// Whether this peer holds the record.
    pub present: bool,
    /// Paid-list status (only set if peer was asked for paid-list check).
    ///
    /// - `Some(true)` -- key is in peer's `PaidForList`.
    /// - `Some(false)` -- key is NOT in peer's `PaidForList`.
    /// - `None` -- paid-list check was not requested for this key.
    pub paid: Option<bool>,
}

/// Batched verification response with per-key results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    /// Per-key results (one per requested key, in request order).
    pub results: Vec<KeyVerificationResult>,
}

// ---------------------------------------------------------------------------
// Fetch Messages
// ---------------------------------------------------------------------------

/// Request to fetch a specific record by key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    /// The key of the record to fetch.
    pub key: XorName,
}

/// Response to a fetch request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FetchResponse {
    /// Record found and returned.
    Success {
        /// The record key.
        key: XorName,
        /// The record data.
        data: Vec<u8>,
    },
    /// Record not found on this peer.
    NotFound {
        /// The requested key.
        key: XorName,
    },
    /// Error during fetch.
    Error {
        /// The requested key.
        key: XorName,
        /// Human-readable error description.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Commitment fetch by pin (ADR-0004)
// ---------------------------------------------------------------------------

/// Request a retained commitment by its pin (commitment hash).
///
/// ADR-0004: a storer cross-checking a quote whose `commitment_pin` it does not
/// already hold (no sidecar, no fresh gossip copy) fetches the signed
/// commitment so it can verify the binding and route the commitment into audit.
/// The responder answers only from its retained set, so this never forces a
/// node to reconstruct or re-sign anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCommitmentByPin {
    /// The commitment hash (pin) being resolved.
    pub pin: [u8; 32],
}

/// Response to [`GetCommitmentByPin`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GetCommitmentByPinResponse {
    /// The pin resolved to a retained, signed commitment.
    Found {
        /// The signed commitment matching the requested pin. The fetcher
        /// re-verifies its signature and peer binding before trusting it.
        commitment: crate::replication::commitment::StorageCommitment,
    },
    /// The pin is not among the responder's retained commitments (rotated/aged
    /// out, or never held). ADR-0004 treats this as graced, never confirmed:
    /// an unanswerable pin is indistinguishable from an honest crash-restart.
    NotRetained {
        /// Echo of the requested pin, for matching.
        pin: [u8; 32],
    },
}

// ---------------------------------------------------------------------------
// Audit Messages
// ---------------------------------------------------------------------------

/// Per-key audit challenge.
///
/// The challenger picks a random nonce and a set of keys the challenged peer
/// should hold, then sends this challenge. The challenged peer proves storage
/// by returning per-key BLAKE3 digests. Used by the responsible-chunk audit
/// (audit #2: a node samples keys a close peer should hold) and by the
/// prune-confirmation path (a node checks a peer still holds a key before
/// pruning its own copy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChallenge {
    /// Unique challenge identifier.
    pub challenge_id: u64,
    /// Random nonce for digest computation.
    pub nonce: [u8; 32],
    /// Challenged peer ID (included in digest computation).
    pub challenged_peer_id: [u8; 32],
    /// Ordered list of keys to prove storage of.
    pub keys: Vec<XorName>,
}

/// Response to a per-key audit challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResponse {
    /// Per-key digests proving storage.
    ///
    /// `digests[i]` corresponds to `challenge.keys[i]`.
    /// An [`ABSENT_KEY_DIGEST`] sentinel signals key absence.
    Digests {
        /// The challenge this response answers.
        challenge_id: u64,
        /// One 32-byte digest per challenged key, in challenge order.
        digests: Vec<[u8; 32]>,
    },
    /// Peer is still bootstrapping (not ready for audit).
    Bootstrapping {
        /// The challenge this response answers.
        challenge_id: u64,
    },
    /// Challenge rejected (wrong target peer or too many keys).
    ///
    /// Distinct from empty `Digests` so the challenger can distinguish a
    /// legitimate rejection from misbehavior.
    Rejected {
        /// The challenge this response answers.
        challenge_id: u64,
        /// Human-readable rejection reason.
        reason: String,
    },
}

/// Gossip-triggered contiguous-subtree storage audit challenge (ADR-0002).
///
/// The auditor pins the commitment a peer just gossiped and sends a fresh
/// random nonce. The nonce alone deterministically selects one contiguous
/// subtree of the peer's committed Merkle tree (see
/// [`crate::replication::subtree::select_subtree_path`]); the auditor does
/// **not** name keys. The responder must reply with a
/// [`SubtreeAuditResponse::Proof`] for that selected subtree against the pinned
/// commitment, or a [`SubtreeAuditResponse::Rejected`] if it genuinely cannot
/// (for a recently gossiped pinned commitment a rejection is a confirmed
/// failure, since the responder retains its recently gossiped commitments for a
/// bounded TTL window).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtreeAuditChallenge {
    /// Unique challenge identifier.
    pub challenge_id: u64,
    /// Random nonce. Selects the subtree AND freshens each leaf's possession
    /// hash, so a stored answer cannot be replayed.
    pub nonce: [u8; 32],
    /// Challenged peer ID. Bound into each leaf's possession hash.
    pub challenged_peer_id: [u8; 32],
    /// The auditor's pin: the [`crate::replication::commitment::commitment_hash`]
    /// of the commitment the peer just gossiped. The response's commitment must
    /// hash to exactly this value.
    pub expected_commitment_hash: [u8; 32],
}

/// Response to a contiguous-subtree storage audit challenge (ADR-0002).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubtreeAuditResponse {
    /// The single-contiguous-subtree proof.
    ///
    /// Carries the responder's signed commitment (so the auditor re-derives
    /// `key_count` and confirms the pin and signature) and the
    /// nonce-selected subtree expanded to its leaves plus the sibling
    /// cut-hashes on the path to the root. This is **round 1** of the
    /// two-round audit. The auditor:
    ///   1. confirms `commitment_hash(commitment) == expected_commitment_hash`
    ///      and the signature is valid;
    ///   2. re-derives the selected subtree from `(nonce, key_count)`, rebuilds
    ///      the root from the proof, and requires it to equal the commitment
    ///      root (structure).
    ///
    /// The leaves carry only hashes (`bytes_hash`, `nonced_root`), so this round
    /// proves the tree SHAPE is committed — not that the bytes are still held.
    /// Real possession is proven in **round 2**: the auditor picks a few of the
    /// just-verified leaves and sends a [`SubtreeSliceChallenge`] opening one
    /// random 1 KiB block of each against both the chunk address and the round-1
    /// `nonced_root` (see that type).
    Proof {
        /// The challenge this response answers.
        challenge_id: u64,
        /// The signed commitment whose root the proof is against.
        commitment: crate::replication::commitment::StorageCommitment,
        /// The nonce-selected contiguous subtree proof.
        proof: crate::replication::subtree::SubtreeProof,
    },
    /// Peer is still bootstrapping (not ready for audit).
    Bootstrapping {
        /// The challenge this response answers.
        challenge_id: u64,
    },
    /// Challenge rejected. `kind` drives the auditor's accounting (confirmed vs
    /// graced); `reason` is the human-readable detail for logs.
    Rejected {
        /// The challenge this response answers.
        challenge_id: u64,
        /// Machine-readable rejection class (accounting).
        kind: RejectKind,
        /// Human-readable rejection reason.
        reason: String,
    },
}

/// Why a responder rejected an audit challenge, in a form the auditor can act
/// on without string-matching.
///
/// ADR-0004 Amendment 1: audit **grace is removed**. Answerability is now
/// restart-durable (the responder persists and reloads its commitment retention)
/// and the auditor only pins roots inside the answerability window, so an honest
/// node can always answer a pin it could be challenged on. The auditor therefore
/// grades a responsive rejection purely by kind, with no grace:
/// - `UnknownCommitment` / `Protocol` → **confirmed failure**: repudiating a
///   pinned root the node published (and may have been paid for), or an explicit
///   protocol fault.
/// - `Transient` → routed to the **non-response/timeout lane** (no trust penalty,
///   but the holder credit for the pinned commitment IS revoked). The responder
///   retries reads before emitting `Transient`, so one that still reaches the
///   auditor means the node could not serve data it committed to. A
///   `Transient`-spammer thus gains no positive standing; deterministically
///   distinguishing malicious from genuine transient IO network-wide is the
///   out-of-scope distributed non-response problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectKind {
    /// The responder does not retain the pinned commitment. With restart-durable
    /// retention and in-window auditing this is provable repudiation of a root
    /// the node published → CONFIRMED failure.
    UnknownCommitment,
    /// A transient, recoverable local condition (e.g. a storage read error),
    /// emitted only after the responder's read retries failed. Routed to the
    /// timeout lane (holder credit revoked, no trust penalty).
    Transient,
    /// Any other rejection (wrong target peer, no commitment state, malformed
    /// proof plan, oversized slice challenge, …). CONFIRMED failure.
    Protocol,
}

/// A single block the round-2 slice challenge opens: which committed key, and
/// which 1 KiB block within it.
///
/// The `block_index` is drawn with FRESH auditor randomness after round 1 (never
/// nonce-derived), so the responder cannot have prepared only the opened block.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubtreeSliceOpening {
    /// The committed key whose block is opened.
    pub key: XorName,
    /// The 1 KiB block index within the chunk, in `0..block_count(content_len)`.
    pub block_index: u32,
}

/// Round 2 of the storage audit (ADR-0002 / V2-685): the **surprise slice
/// challenge**.
///
/// After structurally verifying a [`SubtreeAuditResponse::Proof`] the auditor
/// picks a small sample of the just-proven leaves with FRESH randomness (chosen
/// now, after the proof is committed — NOT derived from the round-1 nonce) and,
/// for each, a fresh-random 1 KiB block index. It asks the responder to open
/// exactly those blocks. For each opened block the responder returns a Bao
/// verified slice plus a nonced block-tree opening; the auditor checks, over the
/// same block bytes:
///   - the Bao slice against `leaf.bytes_hash` (the chunk's content address), AND
///   - the nonced opening against `leaf.nonced_root` (round-1 possession commit).
///
/// The pair binds the opened block to bytes that were held when round 1 was
/// answered, cheaply: the response is a few KB, not up to two 4 MiB chunks.
/// Whoever answered round 1 without the bytes cannot have committed a correct
/// `nonced_root`, and cannot fold an after-the-fact-fetched block to a foreign
/// root without a preimage break.
///
/// What it does NOT bind is *which* party held them. Every input is public, so
/// a backend holding one copy can answer for any number of front-end
/// identities; the proof is delegable, and cheaper to delegate than the
/// full-byte round 2 it replaces, which priced delegation by forcing the chunk
/// through the relay. ADR-0009 records that as a known gap. Anything in this
/// tree that reads as "non-delegable" or "a relay blows the deadline" is a
/// claim about the older design and is superseded there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtreeSliceChallenge {
    /// The same `challenge_id` as the round-1 [`SubtreeAuditChallenge`], so the
    /// responder/auditor correlate the two rounds.
    pub challenge_id: u64,
    /// The same nonce as round 1 — binds each nonced block opening to this audit.
    pub nonce: [u8; 32],
    /// The challenged peer ID (bound into every nonced block leaf).
    pub challenged_peer_id: [u8; 32],
    /// The pinned commitment hash from round 1, so the responder resolves the
    /// SAME tree it just proved and opens blocks only for keys it committed to.
    pub expected_commitment_hash: [u8; 32],
    /// The exact blocks to open: the auditor's freshly-randomised spot-check
    /// sample of the round-1 subtree (chosen after the proof was received; not
    /// nonce-derived), up to two blocks per sampled leaf (a fresh-random block
    /// plus the final block, for the content-length pin).
    pub openings: Vec<SubtreeSliceOpening>,
}

/// One opened block in a [`SubtreeSliceResponse`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubtreeSliceItem {
    /// The responder holds this committed key and opens the requested block.
    Present {
        /// The requested key.
        key: XorName,
        /// The 1 KiB block index that was opened.
        block_index: u32,
        /// Bao verified slice: the block bytes plus the BLAKE3 parent hashes that
        /// authenticate them against the chunk address. The auditor decodes this
        /// to recover the verified block bytes.
        bao_slice: Vec<u8>,
        /// Sibling hashes on the path from this block up to the committed
        /// `nonced_root`, bottom-up. The auditor folds the block leaf with these
        /// to prove the block was committed under round 1's fresh nonce.
        nonced_siblings: Vec<[u8; 32]>,
    },
    /// The responder committed to this key but cannot serve its block. This is a
    /// PROVABLE cheat (it published a commitment over a chunk it does not hold),
    /// so the auditor counts it as a confirmed failure — NOT a graced timeout.
    /// Distinguishing this explicit signal from silence is what separates a
    /// deleter (instant fail) from a dropped packet (timeout).
    Absent {
        /// The committed key the responder could not serve.
        key: XorName,
    },
}

/// Response to a [`SubtreeSliceChallenge`] (round 2).
///
/// The contract is **coalesced and order-independent**: the responder groups the
/// requested openings by key (reading and hashing each chunk once), so
/// - a `Present` item is unique per distinct `(key, block_index)`;
/// - an `Absent` item is at most one per key and covers ALL of that key's
///   requested openings (it has no `block_index`);
/// - duplicate requested openings do not multiply work or response items;
/// - item order is unspecified — the auditor matches by identity, not position.
///
/// The auditor rejects a response whose identities collide (a duplicate
/// `(key, block_index)`, or a key that is both `Present` and `Absent`) as
/// malformed, so first-match ambiguity cannot decide a verdict.
///
/// Each item is a few KB (a 1 KiB block plus O(log n) hashes on two short
/// chains), so even the worst-case sample fits far under
/// [`MAX_REPLICATION_MESSAGE_SIZE`] with no batching — the auditor bounds the
/// sample to [`MAX_SLICE_OPENINGS`](super::config::MAX_SLICE_OPENINGS) and the
/// responder rejects larger requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubtreeSliceResponse {
    /// The responder's per-opening answers (a verified slice or an absent signal).
    Items {
        /// The challenge this response answers.
        challenge_id: u64,
        /// One item per DISTINCT requested opening, coalesced and
        /// order-independent (see the type-level contract above): duplicate
        /// openings do not multiply items, and one `Absent` covers all of a
        /// key's openings.
        items: Vec<SubtreeSliceItem>,
    },
    /// Peer is still bootstrapping (should not happen mid-audit, but handled).
    Bootstrapping {
        /// The challenge this response answers.
        challenge_id: u64,
    },
    /// The responder rejects the slice challenge outright. `kind` drives the
    /// auditor's accounting (ADR-0004 A1: grace removed): [`RejectKind::Transient`]
    /// routes to the timeout lane (no trust penalty, holder credit revoked); every
    /// other kind is a confirmed failure, like round 1.
    Rejected {
        /// The challenge this response answers.
        challenge_id: u64,
        /// Machine-readable rejection class (accounting).
        kind: RejectKind,
        /// Human-readable rejection reason.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Audit digest helper
// ---------------------------------------------------------------------------

/// Compute `AuditKeyDigest(K_i) = BLAKE3(nonce || challenged_peer_id || K_i || record_bytes_i)`.
///
/// This is the existing digest construction used by the core responsible-chunk,
/// post-replication possession, and prune-confirmation audit lanes. The subtree
/// slice audit has its own proof-specific keyed construction in `slice.rs`.
#[must_use]
pub fn compute_audit_digest(
    nonce: &[u8; 32],
    challenged_peer_id: &[u8; 32],
    key: &XorName,
    record_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(nonce);
    hasher.update(challenged_peer_id);
    hasher.update(key);
    hasher.update(record_bytes);
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from replication protocol encode/decode operations.
#[derive(Debug, Clone)]
pub enum ReplicationProtocolError {
    /// Postcard serialization failed.
    SerializationFailed(String),
    /// Postcard deserialization failed.
    DeserializationFailed(String),
    /// Wire message exceeds the maximum allowed size.
    MessageTooLarge {
        /// Actual size of the message in bytes.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },
}

impl std::fmt::Display for ReplicationProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationFailed(msg) => {
                write!(f, "replication serialization failed: {msg}")
            }
            Self::DeserializationFailed(msg) => {
                write!(f, "replication deserialization failed: {msg}")
            }
            Self::MessageTooLarge { size, max_size } => {
                write!(
                    f,
                    "replication message size {size} exceeds maximum {max_size}"
                )
            }
        }
    }
}

impl std::error::Error for ReplicationProtocolError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // === Audit outcome counters ===

    /// No other test mutates the audit outcome counters, so per-slot deltas are
    /// stable even under parallel test execution.
    #[test]
    fn audit_outcome_counters_tally_by_kind_and_reason() {
        let pass_slot = AuditOutcomeKind::Subtree as usize;
        let before = AUDIT_PASS[pass_slot].load(Ordering::Relaxed);
        record_audit_pass(AuditOutcomeKind::Subtree);
        assert_eq!(AUDIT_PASS[pass_slot].load(Ordering::Relaxed), before + 1);

        let reasons = [
            AuditFailureReason::Timeout,
            AuditFailureReason::MalformedResponse,
            AuditFailureReason::DigestMismatch,
            AuditFailureReason::KeyAbsent,
            AuditFailureReason::Rejected,
        ];
        for (kind, kind_index) in [
            (AuditOutcomeKind::Responsible, 0usize),
            (AuditOutcomeKind::Subtree, 1usize),
        ] {
            for (reason_index, reason) in reasons.iter().enumerate() {
                let slot = kind_index * N_FAIL_REASONS + reason_index;
                let before = AUDIT_FAIL[slot].load(Ordering::Relaxed);
                record_audit_fail(kind, reason);
                assert_eq!(
                    AUDIT_FAIL[slot].load(Ordering::Relaxed),
                    before + 1,
                    "kind {kind_index} reason {reason:?} must land in its own slot",
                );
            }
        }

        for (kind, kind_index) in [
            (AuditDropKind::Responsible, 0usize),
            (AuditDropKind::Subtree, 1usize),
            (AuditDropKind::Slice, 2usize),
        ] {
            let before = AUDIT_DROPPED[kind_index].load(Ordering::Relaxed);
            record_audit_drop(kind);
            assert_eq!(
                AUDIT_DROPPED[kind_index].load(Ordering::Relaxed),
                before + 1
            );
        }
    }

    // === Round-2 slice response sizing ===

    #[test]
    fn max_slice_response_is_tiny_relative_to_wire_cap() {
        // A worst-case round-2 slice response is MAX_SLICE_OPENINGS openings, each
        // a 1 KiB block plus a Bao proof and a nonced sibling chain. For a 4 MiB
        // chunk that is ~4096 BLAKE3 chunks → ~12 parent hashes per chain. We
        // overestimate generously (16 KiB slice + 24 sibling hashes per opening)
        // and assert it encodes far under the wire cap — the whole point of the
        // change is that round 2 is now KB-scale, not up to 8 MiB.
        let items: Vec<SubtreeSliceItem> = (0..crate::replication::config::MAX_SLICE_OPENINGS)
            .map(|i| SubtreeSliceItem::Present {
                key: [u8::try_from(i).unwrap_or(u8::MAX); 32],
                block_index: u32::try_from(i).unwrap_or(u32::MAX),
                bao_slice: vec![0xAB; 16 * 1024],
                nonced_siblings: vec![[0x5A; 32]; 24],
            })
            .collect();
        let msg = ReplicationMessage {
            request_id: 7,
            body: ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Items {
                challenge_id: 7,
                items,
            }),
        };
        let encoded = msg
            .encode()
            .expect("worst-case slice response must fit the wire cap");
        // Comfortably under 1 MiB, itself a fraction of the 10 MiB wire cap.
        assert!(encoded.len() <= 1024 * 1024);
        assert!(encoded.len() <= MAX_REPLICATION_MESSAGE_SIZE);
        assert!(
            encoded.len() <= crate::replication::config::MAX_SUBTREE_AUDIT_MESSAGE_SIZE,
            "round 2 must fit the tighter audit-family ceiling"
        );
    }

    // The audit families take a much tighter wire ceiling than the 10 MiB core
    // one, checked before decoding so an unknown peer cannot make this node
    // allocate megabytes before any admission check has run. That ceiling is
    // only safe if it clears the largest body an honest audit can produce, which
    // is the round-1 proof at the commitment key-count cap: 1,024 leaves plus
    // the sibling cut hashes and the signed commitment. Build that worst case
    // and pin the headroom, so a later change to leaf size or commitment
    // encoding cannot quietly start dropping honest proofs.
    #[test]
    fn max_round1_proof_fits_the_audit_family_ceiling() {
        use crate::replication::commitment::{StorageCommitment, MAX_COMMITMENT_KEY_COUNT};
        use crate::replication::config::MAX_SUBTREE_AUDIT_MESSAGE_SIZE;
        use crate::replication::subtree::{max_subtree_leaves, SubtreeLeaf, SubtreeProof};

        let leaf_count = max_subtree_leaves(MAX_COMMITMENT_KEY_COUNT) as usize;
        let leaves: Vec<SubtreeLeaf> = (0..leaf_count)
            .map(|_| SubtreeLeaf {
                key: [0xAB; 32],
                bytes_hash: [0xCD; 32],
                content_len: u32::MAX,
                nonced_root: [0xEF; 32],
            })
            .collect();
        let msg = ReplicationMessage {
            request_id: 11,
            body: ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Proof {
                challenge_id: 11,
                commitment: StorageCommitment {
                    root: [0x01; 32],
                    key_count: MAX_COMMITMENT_KEY_COUNT,
                    sender_peer_id: [0x02; 32],
                    // Over-sized stand-ins for the ML-DSA-65 key and signature.
                    sender_public_key: vec![0x03; 4096],
                    signature: vec![0x04; 8192],
                },
                proof: SubtreeProof {
                    leaves,
                    // One per level down to the subtree root; 32 is far past the
                    // real depth at this key count.
                    sibling_cut_hashes: vec![[0x05; 32]; 32],
                },
            }),
        };
        // Measure without going through `encode`, which now enforces this very
        // ceiling: encoding first would turn a regression into an opaque
        // `MessageTooLarge` from the guard instead of the explicit, diagnosable
        // assertion below.
        let encoded = postcard::to_stdvec(&msg).expect("serialize");
        assert!(
            encoded.len() <= MAX_SUBTREE_AUDIT_MESSAGE_SIZE,
            "worst legitimate round-1 proof is {} bytes, over the audit ceiling of \
             {MAX_SUBTREE_AUDIT_MESSAGE_SIZE}",
            encoded.len()
        );
        // And it must genuinely pass the guard, not merely fit the number.
        assert!(
            msg.encode().is_ok(),
            "the worst legitimate round-1 proof must still be encodable"
        );
    }

    /// Every body variant, in declaration order, so a test can walk the whole
    /// enum rather than a hand-picked sample.
    fn all_bodies() -> Vec<ReplicationMessageBody> {
        let z = [0u8; 32];
        vec![
            ReplicationMessageBody::FreshReplicationOffer(FreshReplicationOffer {
                key: z,
                data: vec![],
                proof_of_payment: vec![],
            }),
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Accepted {
                key: z,
            }),
            ReplicationMessageBody::PaidNotify(PaidNotify {
                key: z,
                proof_of_payment: vec![],
            }),
            ReplicationMessageBody::NeighborSyncRequest(NeighborSyncRequest {
                replica_hints: vec![],
                paid_hints: vec![],
                bootstrapping: false,
                commitment: None,
            }),
            ReplicationMessageBody::NeighborSyncResponse(NeighborSyncResponse {
                replica_hints: vec![],
                paid_hints: vec![],
                bootstrapping: false,
                rejected_keys: vec![],
                commitment: None,
            }),
            ReplicationMessageBody::VerificationRequest(VerificationRequest {
                keys: vec![],
                paid_list_check_indices: vec![],
            }),
            ReplicationMessageBody::VerificationResponse(VerificationResponse { results: vec![] }),
            ReplicationMessageBody::FetchRequest(FetchRequest { key: z }),
            ReplicationMessageBody::FetchResponse(FetchResponse::NotFound { key: z }),
            ReplicationMessageBody::AuditChallenge(AuditChallenge {
                challenge_id: 1,
                nonce: z,
                challenged_peer_id: z,
                keys: vec![],
            }),
            ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
                challenge_id: 1,
                digests: vec![],
            }),
            ReplicationMessageBody::SubtreeAuditChallenge(SubtreeAuditChallenge {
                challenge_id: 1,
                nonce: z,
                challenged_peer_id: z,
                expected_commitment_hash: z,
            }),
            ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Bootstrapping {
                challenge_id: 1,
            }),
            ReplicationMessageBody::SubtreeSliceChallenge(SubtreeSliceChallenge {
                challenge_id: 1,
                nonce: z,
                challenged_peer_id: z,
                expected_commitment_hash: z,
                openings: vec![],
            }),
            ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Bootstrapping {
                challenge_id: 1,
            }),
            ReplicationMessageBody::GetCommitmentByPin(GetCommitmentByPin { pin: z }),
            ReplicationMessageBody::GetCommitmentByPinResponse(
                GetCommitmentByPinResponse::NotRetained { pin: z },
            ),
        ]
    }

    // The pre-decode ceiling reads the body's discriminant straight off the
    // wire, so `peek_variant_index` MUST agree with `variant_index()` for every
    // variant, at request ids that straddle postcard's varint width boundaries.
    // If it ever disagreed, a body would be sized against the wrong family's
    // ceiling — which is the bug this whole path exists to prevent.
    #[test]
    fn peeked_discriminant_matches_the_decoded_one_for_every_variant() {
        // 1-byte, 2-byte, 5-byte and 10-byte `request_id` varints.
        for request_id in [0u64, 1, 127, 128, 300, u64::from(u32::MAX), u64::MAX] {
            for body in all_bodies() {
                let expected = body.variant_index();
                let encoded = ReplicationMessage { request_id, body }
                    .encode()
                    .expect("encode");
                assert_eq!(
                    peek_variant_index(&encoded),
                    Some(expected),
                    "peek disagreed with variant_index at request_id {request_id}"
                );
            }
        }
    }

    // A truncated or nonsense prefix must not classify as `Core`, because Core
    // is the LENIENT ceiling. Failing to classify has to mean "apply the strict
    // one", never "let it through".
    #[test]
    fn unclassifiable_prefix_yields_no_family() {
        assert_eq!(peek_variant_index(&[]), None);
        // A varint that never terminates: all continuation bits set.
        assert_eq!(peek_variant_index(&[0xFF; 32]), None);
        // A well-formed request_id with nothing after it.
        assert_eq!(peek_variant_index(&[0x01]), None);
        // Ten-byte u64 varints have only one payload bit in the final byte.
        // Reject overflow in either prefix field instead of letting the shift
        // discard high bits and classify attacker-controlled trailing bytes.
        let mut overflowing_request_id = vec![0x80; 9];
        overflowing_request_id.extend([0x02, 0x0B]);
        assert_eq!(peek_variant_index(&overflowing_request_id), None);

        let mut overflowing_discriminant = vec![0x01];
        overflowing_discriminant.extend([0x80; 9]);
        overflowing_discriminant.push(0x02);
        assert_eq!(peek_variant_index(&overflowing_discriminant), None);
    }

    // Regression (dirvine, PR #181): the pre-decode ceiling used to be chosen
    // from the protocol id the message arrived on, so an audit body addressed to
    // the CORE id skipped the audit ceiling and was decoded under the 10 MiB core
    // allowance — its collections allocated — before the family guard dropped it.
    //
    // The reproduction from that review: a valid `SubtreeSliceChallenge` with
    // 200,000 openings encodes to ~6.6 MB, far past the 512 KiB audit ceiling.
    // Classifying by discriminant catches it wherever it is addressed.
    #[test]
    fn oversized_audit_body_is_classified_as_audit_wherever_it_is_addressed() {
        let z = [0u8; 32];
        let challenge = SubtreeSliceChallenge {
            challenge_id: 1,
            nonce: z,
            challenged_peer_id: z,
            expected_commitment_hash: z,
            openings: (0..200_000u32)
                .map(|i| SubtreeSliceOpening {
                    key: z,
                    block_index: i,
                })
                .collect(),
        };
        // Serialised directly rather than through `encode`, which now refuses to
        // emit an audit body over the audit ceiling. That guard protects honest
        // senders; it says nothing about what arrives, since a hostile peer does
        // not run our encoder. Building the bytes the way an attacker would is
        // what keeps this a test of the RECEIVE path.
        let encoded = postcard::to_stdvec(&ReplicationMessage {
            request_id: 1,
            body: ReplicationMessageBody::SubtreeSliceChallenge(challenge),
        })
        .expect("serialize");
        // Pin BOTH bounds. Going through `encode` used to imply the upper one;
        // asserting it keeps the reproduction meaningful, since a body over the
        // core ceiling would be refused by size alone and would no longer
        // demonstrate that classification is what catches it.
        assert!(
            encoded.len() < crate::replication::config::MAX_REPLICATION_MESSAGE_SIZE,
            "the reproduction must sit UNDER the core ceiling, or it proves \
             nothing about family classification; got {} bytes",
            encoded.len()
        );

        assert!(
            encoded.len() > crate::replication::config::MAX_SUBTREE_AUDIT_MESSAGE_SIZE,
            "the reproduction must exceed the audit ceiling to be meaningful; got {} bytes",
            encoded.len()
        );
        // The classification the receive path performs, before any decode.
        let family = peek_variant_index(&encoded).and_then(family_of_variant);
        assert_eq!(family, Some(BodyFamily::SubtreeAudit));
        assert!(
            family.map_or(true, BodyFamily::is_audit),
            "an audit body must take the audit ceiling regardless of the id it rode"
        );
    }

    // The family table is the single source of truth: the `&self` predicates,
    // the response routing and the pre-decode ceiling all read it, so they
    // cannot drift. Walk every variant and check both views agree.
    #[test]
    fn family_table_agrees_with_the_body_predicates() {
        for body in all_bodies() {
            let family = family_of_variant(body.variant_index());
            // Every DECLARED variant must classify. `None` is reserved for an
            // index no variant uses; a real body landing there would silently
            // take the strict ceiling on both encode and decode.
            let family = family.expect("every declared variant must have a family");
            assert_eq!(body.is_subtree_audit(), family == BodyFamily::SubtreeAudit);
            assert_eq!(family.is_audit(), body.is_subtree_audit());
        }
    }

    /// The encoder applies the same family ceiling the decoder does. Without
    /// this, an audit body that outgrew the audit ceiling would serialise
    /// happily and then be dropped pre-decode by every peer that received it —
    /// and since the drop is silent, the sender would be scored for the
    /// resulting non-answer rather than told its message was unsendable.
    ///
    /// No legitimate body reaches the ceiling today; this is about where the
    /// failure surfaces if one ever does.
    ///
    /// FLIPS IF: `encode` goes back to checking only the core ceiling.
    #[test]
    fn the_encoder_refuses_an_audit_body_over_the_audit_ceiling() {
        let z = [0u8; 32];
        let oversized = ReplicationMessage {
            request_id: 1,
            body: ReplicationMessageBody::SubtreeSliceChallenge(SubtreeSliceChallenge {
                challenge_id: 1,
                nonce: z,
                challenged_peer_id: z,
                expected_commitment_hash: z,
                openings: (0..200_000u32)
                    .map(|i| SubtreeSliceOpening {
                        key: z,
                        block_index: i,
                    })
                    .collect(),
            }),
        };
        // Sits under the core ceiling, so only the family-aware check can catch
        // it — this is the exact gap, not merely an enormous message.
        let raw = postcard::to_stdvec(&oversized).expect("serialize");
        assert!(raw.len() > MAX_SUBTREE_AUDIT_MESSAGE_SIZE);
        assert!(raw.len() < MAX_REPLICATION_MESSAGE_SIZE);

        match oversized.encode() {
            Err(ReplicationProtocolError::MessageTooLarge { max_size, .. }) => {
                assert_eq!(
                    max_size, MAX_SUBTREE_AUDIT_MESSAGE_SIZE,
                    "an audit body must be measured against the audit ceiling"
                );
            }
            // Report only the length on the success arm: debug-printing the body
            // would dump megabytes of payload into the failure output.
            other => panic!(
                "expected the audit ceiling to refuse this, got {:?}",
                other.map(|bytes| bytes.len())
            ),
        }

        // A core body of the same size still encodes: the tighter ceiling is
        // scoped to the audit families and must not shrink core traffic, which
        // legitimately carries a whole chunk.
        let core = ReplicationMessage {
            request_id: 1,
            body: ReplicationMessageBody::FetchResponse(FetchResponse::Success {
                key: z,
                data: vec![0u8; MAX_SUBTREE_AUDIT_MESSAGE_SIZE * 2],
            }),
        };
        assert!(core.encode().is_ok(), "core bodies keep the core allowance");
    }

    /// An index no variant declares classifies as nothing, and "nothing" takes
    /// the strict audit ceiling rather than the generous core allowance on both
    /// sides of the wire. Postcard rejects an unknown outer discriminant before
    /// decoding any trailing collection, so this closes the invariant rather than
    /// a demonstrated hole — but the rule has to hold uniformly, or a later
    /// variant added without a family entry would quietly inherit 10 MiB.
    ///
    /// FLIPS IF: the family table regains a catch-all that answers `Core`.
    #[test]
    fn an_undeclared_variant_index_classifies_as_nothing() {
        let declared = all_bodies().len();
        assert_eq!(
            declared, 17,
            "update this test's bounds when a variant is added or removed"
        );
        for index in [declared, declared + 1, 99, usize::MAX] {
            assert_eq!(
                family_of_variant(index),
                None,
                "index {index} is not a declared variant and must not classify"
            );
        }
        // Call the REAL selector both wire paths use. Restating its arms here, or
        // asserting a property that `None` satisfies vacuously, would pass no
        // matter how the production selection changed.
        assert_eq!(
            ceiling_for(family_of_variant(declared)),
            MAX_SUBTREE_AUDIT_MESSAGE_SIZE,
            "an unclassifiable variant must take the strict audit ceiling, not \
             the generous core allowance"
        );
        // And a declared core body still takes the generous one, so the
        // assertion above is about being unclassifiable rather than about the
        // selector returning one answer for everything.
        assert_eq!(
            ceiling_for(family_of_variant(0)),
            MAX_REPLICATION_MESSAGE_SIZE,
            "core bodies keep the core allowance"
        );
    }

    // `is_subtree_audit()` classifies exactly the four subtree-audit variants
    // (both rounds), and NOTHING else — crucially not the digest-based
    // `AuditChallenge`/`AuditResponse` pair, which remains on the core protocol.
    // The receive guard and response routing key off this predicate, so it must
    // be exact.
    #[test]
    fn is_subtree_audit_covers_both_rounds_only() {
        let z = [0u8; 32];
        let audit = [
            ReplicationMessageBody::SubtreeAuditChallenge(SubtreeAuditChallenge {
                challenge_id: 1,
                nonce: z,
                challenged_peer_id: z,
                expected_commitment_hash: z,
            }),
            ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Bootstrapping {
                challenge_id: 1,
            }),
            ReplicationMessageBody::SubtreeSliceChallenge(SubtreeSliceChallenge {
                challenge_id: 1,
                nonce: z,
                challenged_peer_id: z,
                expected_commitment_hash: z,
                openings: vec![],
            }),
            ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Bootstrapping {
                challenge_id: 1,
            }),
        ];
        for body in &audit {
            assert!(
                body.is_subtree_audit(),
                "variant {} must be subtree-audit",
                body.variant_index()
            );
        }
        let core = [
            ReplicationMessageBody::FreshReplicationOffer(FreshReplicationOffer {
                key: z,
                data: vec![],
                proof_of_payment: vec![],
            }),
            // Periodic possession audit — core replication, not subtree audit.
            ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping { challenge_id: 1 }),
        ];
        for body in &core {
            assert!(
                !body.is_subtree_audit(),
                "variant {} must be core, not subtree-audit",
                body.variant_index()
            );
        }
    }

    // === Fresh Replication roundtrip ===

    #[test]
    fn fresh_replication_offer_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 1,
            body: ReplicationMessageBody::FreshReplicationOffer(FreshReplicationOffer {
                key: [0xAA; 32],
                data: vec![1, 2, 3, 4, 5],
                proof_of_payment: vec![10, 20, 30],
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 1);
        if let ReplicationMessageBody::FreshReplicationOffer(offer) = decoded.body {
            assert_eq!(offer.key, [0xAA; 32]);
            assert_eq!(offer.data, vec![1, 2, 3, 4, 5]);
            assert_eq!(offer.proof_of_payment, vec![10, 20, 30]);
        } else {
            panic!("expected FreshReplicationOffer");
        }
    }

    #[test]
    fn fresh_replication_response_accepted_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 2,
            body: ReplicationMessageBody::FreshReplicationResponse(
                FreshReplicationResponse::Accepted { key: [0xBB; 32] },
            ),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 2);
        if let ReplicationMessageBody::FreshReplicationResponse(
            FreshReplicationResponse::Accepted { key },
        ) = decoded.body
        {
            assert_eq!(key, [0xBB; 32]);
        } else {
            panic!("expected FreshReplicationResponse::Accepted");
        }
    }

    #[test]
    fn fresh_replication_response_rejected_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 3,
            body: ReplicationMessageBody::FreshReplicationResponse(
                FreshReplicationResponse::Rejected {
                    key: [0xCC; 32],
                    reason: "out of range".to_string(),
                },
            ),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 3);
        if let ReplicationMessageBody::FreshReplicationResponse(
            FreshReplicationResponse::Rejected { key, reason },
        ) = decoded.body
        {
            assert_eq!(key, [0xCC; 32]);
            assert_eq!(reason, "out of range");
        } else {
            panic!("expected FreshReplicationResponse::Rejected");
        }
    }

    // === PaidNotify roundtrip ===

    #[test]
    fn paid_notify_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 4,
            body: ReplicationMessageBody::PaidNotify(PaidNotify {
                key: [0xDD; 32],
                proof_of_payment: vec![99, 100],
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 4);
        if let ReplicationMessageBody::PaidNotify(notify) = decoded.body {
            assert_eq!(notify.key, [0xDD; 32]);
            assert_eq!(notify.proof_of_payment, vec![99, 100]);
        } else {
            panic!("expected PaidNotify");
        }
    }

    // === Neighbor Sync roundtrips ===

    // -- backwards compat across the wire-type extension --------------------

    /// Backwards-compat: an old peer that has the v0 layout of
    /// `NeighborSyncRequest` (no `commitment` field) can still decode a
    /// message encoded by a new peer that emits `commitment: None`. This
    /// is the realistic mixed-version case during rollout: new peers
    /// gossip with the field; old peers must not crash.
    ///
    /// The check works because postcard's [`from_bytes`] is lenient on
    /// trailing bytes — the old decoder reads what it knows about and
    /// stops, the new fields are silently ignored. This test pins that
    /// invariant so any future codec/library swap that breaks it is
    /// caught immediately.
    #[test]
    fn old_decoder_tolerates_new_neighbor_sync_request() {
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct OldNeighborSyncRequest {
            #[allow(dead_code)]
            pub replica_hints: Vec<XorName>,
            #[allow(dead_code)]
            pub paid_hints: Vec<XorName>,
            #[allow(dead_code)]
            pub bootstrapping: bool,
        }

        let new_req = NeighborSyncRequest {
            replica_hints: vec![[0x01; 32], [0x02; 32]],
            paid_hints: vec![[0x03; 32]],
            bootstrapping: true,
            commitment: None,
        };
        let encoded = postcard::to_stdvec(&new_req).expect("encode");
        let old_decoded: OldNeighborSyncRequest =
            postcard::from_bytes(&encoded).expect("old decoder accepts");
        // Field-by-field check would fail if old peer misaligned on the
        // length prefix — passing decode is the structural check.
        assert_eq!(old_decoded.replica_hints.len(), 2);
        assert_eq!(old_decoded.paid_hints.len(), 1);
        assert!(old_decoded.bootstrapping);
    }

    /// Same property for `NeighborSyncResponse`.
    #[test]
    fn old_decoder_tolerates_new_neighbor_sync_response() {
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct OldNeighborSyncResponse {
            #[allow(dead_code)]
            pub replica_hints: Vec<XorName>,
            #[allow(dead_code)]
            pub paid_hints: Vec<XorName>,
            #[allow(dead_code)]
            pub bootstrapping: bool,
            #[allow(dead_code)]
            pub rejected_keys: Vec<XorName>,
        }

        let new_resp = NeighborSyncResponse {
            replica_hints: vec![[0x04; 32]],
            paid_hints: vec![],
            bootstrapping: false,
            rejected_keys: vec![[0x05; 32]],
            commitment: None,
        };
        let encoded = postcard::to_stdvec(&new_resp).expect("encode");
        let old_decoded: OldNeighborSyncResponse =
            postcard::from_bytes(&encoded).expect("old decoder accepts");
        assert_eq!(old_decoded.replica_hints.len(), 1);
        assert_eq!(old_decoded.rejected_keys.len(), 1);
    }

    /// Roundtrip: a new peer can decode its own message including the
    /// commitment field. Catches accidental serde annotation breakage
    /// (e.g. forgetting `#[serde(default)]` on the new field).
    #[test]
    fn new_peer_roundtrips_with_commitment_some() {
        use crate::replication::commitment::{sign_commitment, StorageCommitment};
        use saorsa_pqc::api::sig::ml_dsa_65;

        let (pk, sk) = ml_dsa_65().generate_keypair().expect("keygen");
        let root = [0x7Fu8; 32];
        let sender = [0xCCu8; 32];
        let pk_bytes = pk.to_bytes();
        let sig = sign_commitment(&sk, &root, 3, &sender, &pk_bytes).expect("sign");
        let commitment = StorageCommitment {
            root,
            key_count: 3,
            sender_peer_id: sender,
            sender_public_key: pk_bytes,
            signature: sig,
        };

        let req = NeighborSyncRequest {
            replica_hints: vec![[0x01; 32]],
            paid_hints: vec![],
            bootstrapping: false,
            commitment: Some(commitment.clone()),
        };
        let encoded = postcard::to_stdvec(&req).expect("encode");
        let decoded: NeighborSyncRequest = postcard::from_bytes(&encoded).expect("new decoder");
        assert_eq!(decoded.commitment, Some(commitment));
    }

    #[test]
    fn neighbor_sync_request_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 5,
            body: ReplicationMessageBody::NeighborSyncRequest(NeighborSyncRequest {
                replica_hints: vec![[0x01; 32], [0x02; 32]],
                paid_hints: vec![[0x03; 32]],
                bootstrapping: true,
                commitment: None,
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 5);
        if let ReplicationMessageBody::NeighborSyncRequest(req) = decoded.body {
            assert_eq!(req.replica_hints.len(), 2);
            assert_eq!(req.paid_hints.len(), 1);
            assert!(req.bootstrapping);
        } else {
            panic!("expected NeighborSyncRequest");
        }
    }

    #[test]
    fn neighbor_sync_response_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 6,
            body: ReplicationMessageBody::NeighborSyncResponse(NeighborSyncResponse {
                replica_hints: vec![[0x04; 32]],
                paid_hints: vec![],
                bootstrapping: false,
                rejected_keys: vec![[0x05; 32], [0x06; 32]],
                commitment: None,
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 6);
        if let ReplicationMessageBody::NeighborSyncResponse(resp) = decoded.body {
            assert_eq!(resp.replica_hints.len(), 1);
            assert!(resp.paid_hints.is_empty());
            assert!(!resp.bootstrapping);
            assert_eq!(resp.rejected_keys.len(), 2);
        } else {
            panic!("expected NeighborSyncResponse");
        }
    }

    // === Verification roundtrips ===

    #[test]
    fn verification_request_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 7,
            body: ReplicationMessageBody::VerificationRequest(VerificationRequest {
                keys: vec![[0x10; 32], [0x20; 32], [0x30; 32]],
                paid_list_check_indices: vec![0, 2],
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 7);
        if let ReplicationMessageBody::VerificationRequest(req) = decoded.body {
            assert_eq!(req.keys.len(), 3);
            assert_eq!(req.paid_list_check_indices, vec![0, 2]);
        } else {
            panic!("expected VerificationRequest");
        }
    }

    #[test]
    fn verification_response_roundtrip() {
        let results = vec![
            KeyVerificationResult {
                key: [0x10; 32],
                present: true,
                paid: Some(true),
            },
            KeyVerificationResult {
                key: [0x20; 32],
                present: false,
                paid: None,
            },
            KeyVerificationResult {
                key: [0x30; 32],
                present: true,
                paid: Some(false),
            },
        ];
        let msg = ReplicationMessage {
            request_id: 8,
            body: ReplicationMessageBody::VerificationResponse(VerificationResponse { results }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 8);
        if let ReplicationMessageBody::VerificationResponse(resp) = decoded.body {
            assert_eq!(resp.results.len(), 3);
            assert!(resp.results[0].present);
            assert_eq!(resp.results[0].paid, Some(true));
            assert!(!resp.results[1].present);
            assert_eq!(resp.results[1].paid, None);
            assert!(resp.results[2].present);
            assert_eq!(resp.results[2].paid, Some(false));
        } else {
            panic!("expected VerificationResponse");
        }
    }

    // === Fetch roundtrips ===

    #[test]
    fn fetch_request_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 9,
            body: ReplicationMessageBody::FetchRequest(FetchRequest { key: [0x40; 32] }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 9);
        if let ReplicationMessageBody::FetchRequest(req) = decoded.body {
            assert_eq!(req.key, [0x40; 32]);
        } else {
            panic!("expected FetchRequest");
        }
    }

    #[test]
    fn fetch_response_success_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 10,
            body: ReplicationMessageBody::FetchResponse(FetchResponse::Success {
                key: [0x50; 32],
                data: vec![7, 8, 9],
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 10);
        if let ReplicationMessageBody::FetchResponse(FetchResponse::Success { key, data }) =
            decoded.body
        {
            assert_eq!(key, [0x50; 32]);
            assert_eq!(data, vec![7, 8, 9]);
        } else {
            panic!("expected FetchResponse::Success");
        }
    }

    #[test]
    fn fetch_response_not_found_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 11,
            body: ReplicationMessageBody::FetchResponse(FetchResponse::NotFound {
                key: [0x60; 32],
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 11);
        if let ReplicationMessageBody::FetchResponse(FetchResponse::NotFound { key }) = decoded.body
        {
            assert_eq!(key, [0x60; 32]);
        } else {
            panic!("expected FetchResponse::NotFound");
        }
    }

    #[test]
    fn fetch_response_error_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 12,
            body: ReplicationMessageBody::FetchResponse(FetchResponse::Error {
                key: [0x70; 32],
                reason: "disk full".to_string(),
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 12);
        if let ReplicationMessageBody::FetchResponse(FetchResponse::Error { key, reason }) =
            decoded.body
        {
            assert_eq!(key, [0x70; 32]);
            assert_eq!(reason, "disk full");
        } else {
            panic!("expected FetchResponse::Error");
        }
    }

    // === Audit roundtrips ===

    #[test]
    fn audit_challenge_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 13,
            body: ReplicationMessageBody::AuditChallenge(AuditChallenge {
                challenge_id: 999,
                nonce: [0xAB; 32],
                challenged_peer_id: [0xCD; 32],
                keys: vec![[0x01; 32], [0x02; 32]],
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 13);
        if let ReplicationMessageBody::AuditChallenge(challenge) = decoded.body {
            assert_eq!(challenge.challenge_id, 999);
            assert_eq!(challenge.nonce, [0xAB; 32]);
            assert_eq!(challenge.challenged_peer_id, [0xCD; 32]);
            assert_eq!(challenge.keys.len(), 2);
        } else {
            panic!("expected AuditChallenge");
        }
    }

    #[test]
    fn audit_response_digests_roundtrip() {
        let digests = vec![[0x11; 32], ABSENT_KEY_DIGEST];
        let msg = ReplicationMessage {
            request_id: 14,
            body: ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
                challenge_id: 999,
                digests: digests.clone(),
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 14);
        if let ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
            challenge_id,
            digests: decoded_digests,
        }) = decoded.body
        {
            assert_eq!(challenge_id, 999);
            assert_eq!(decoded_digests, digests);
        } else {
            panic!("expected AuditResponse::Digests");
        }
    }

    #[test]
    fn audit_response_bootstrapping_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 15,
            body: ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping {
                challenge_id: 42,
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 15);
        if let ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping {
            challenge_id,
        }) = decoded.body
        {
            assert_eq!(challenge_id, 42);
        } else {
            panic!("expected AuditResponse::Bootstrapping");
        }
    }

    // === Oversized message rejection ===

    #[test]
    fn decode_rejects_oversized_payload() {
        let oversized = vec![0u8; MAX_REPLICATION_MESSAGE_SIZE + 1];
        let result = ReplicationMessage::decode(&oversized);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ReplicationProtocolError::MessageTooLarge { .. }),
            "expected MessageTooLarge, got {err:?}"
        );
    }

    // A challenge is a few hundred bytes; without the tighter ceiling the reply
    // to it could cost the auditor up to the full core allowance in allocation
    // and decode. The gap between the two ceilings is exactly what an audited
    // peer could spend the auditor's memory on, so pin that it is refused as an
    // audit reply while still being a legal core message.
    #[test]
    fn an_audit_reply_above_the_audit_ceiling_is_refused_before_decode() {
        let between_the_ceilings = vec![0u8; MAX_SUBTREE_AUDIT_MESSAGE_SIZE + 1];
        assert!(between_the_ceilings.len() < MAX_REPLICATION_MESSAGE_SIZE);

        let err = ReplicationMessage::decode_subtree_audit_response(&between_the_ceilings)
            .expect_err("an audit reply over the audit ceiling must not be decoded");
        assert!(
            matches!(
                err,
                ReplicationProtocolError::MessageTooLarge { max_size, .. }
                    if max_size == MAX_SUBTREE_AUDIT_MESSAGE_SIZE
            ),
            "expected the audit ceiling to be the one reported, got {err:?}"
        );
    }

    // The ceiling lives in `decode` itself, so it cannot be skipped by reaching
    // a decode site that forgot to ask. A core lane that gets answered with an
    // audit-discriminant body still gets the audit ceiling, even though the same
    // lane may legitimately receive a whole chunk when the body is a core one.
    #[test]
    fn the_family_ceiling_is_enforced_by_decode_itself() {
        let mut oversized_audit_body = ReplicationMessage {
            request_id: 1,
            body: ReplicationMessageBody::SubtreeSliceChallenge(SubtreeSliceChallenge {
                challenge_id: 1,
                nonce: [0u8; 32],
                challenged_peer_id: [0u8; 32],
                expected_commitment_hash: [0u8; 32],
                openings: vec![],
            }),
        }
        .encode()
        .expect("a small audit body encodes");
        // Postcard ignores trailing bytes, so padding keeps this a decodable
        // audit body while pushing it between the two ceilings.
        oversized_audit_body.resize(MAX_SUBTREE_AUDIT_MESSAGE_SIZE + 1, 0);
        assert!(oversized_audit_body.len() < MAX_REPLICATION_MESSAGE_SIZE);

        let err = ReplicationMessage::decode(&oversized_audit_body)
            .expect_err("an audit-family body over the audit ceiling must not be decoded");
        assert!(
            matches!(
                err,
                ReplicationProtocolError::MessageTooLarge { max_size, .. }
                    if max_size == MAX_SUBTREE_AUDIT_MESSAGE_SIZE
            ),
            "the audit ceiling must be the one applied, got {err:?}"
        );

        // A core body of the same size is still fine: that is the allowance a
        // fetched chunk needs.
        let mut core_body = ReplicationMessage {
            request_id: 1,
            body: ReplicationMessageBody::FetchRequest(FetchRequest { key: [0u8; 32] }),
        }
        .encode()
        .expect("a small core body encodes");
        core_body.resize(MAX_SUBTREE_AUDIT_MESSAGE_SIZE + 1, 0);
        assert!(
            ReplicationMessage::decode(&core_body).is_ok(),
            "a core body must keep the core allowance"
        );
    }

    // The tighter ceiling must not clip a legitimate subtree reply. Round 1's
    // `Proof` is the largest subtree-audit body, and `MAX_SUBTREE_AUDIT_MESSAGE_SIZE` is
    // sized against it; this checks the auditor accepts a small valid reply.
    #[test]
    fn a_legitimate_audit_reply_still_decodes_under_the_audit_ceiling() {
        let msg = ReplicationMessage {
            request_id: 7,
            body: ReplicationMessageBody::SubtreeAuditResponse(
                SubtreeAuditResponse::Bootstrapping { challenge_id: 42 },
            ),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode_subtree_audit_response(&encoded)
            .expect("a small audit reply must decode");
        assert_eq!(decoded.request_id, 7);
    }

    #[test]
    fn encode_rejects_oversized_message() {
        // Build a message whose serialized form exceeds the limit.
        let msg = ReplicationMessage {
            request_id: 0,
            body: ReplicationMessageBody::FreshReplicationOffer(FreshReplicationOffer {
                key: [0; 32],
                data: vec![0xFF; MAX_REPLICATION_MESSAGE_SIZE],
                proof_of_payment: vec![],
            }),
        };
        let result = msg.encode();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ReplicationProtocolError::MessageTooLarge { .. }),
            "expected MessageTooLarge, got {err:?}"
        );
    }

    // === Invalid data rejection ===

    #[test]
    fn decode_rejects_invalid_data() {
        let invalid = vec![0xFF, 0xFF, 0xFF];
        let result = ReplicationMessage::decode(&invalid);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ReplicationProtocolError::DeserializationFailed(_)),
            "expected DeserializationFailed, got {err:?}"
        );
    }

    // === Audit digest computation ===

    #[test]
    fn audit_digest_matches_core_replication_construction() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];
        let record_bytes = vec![0x5A; 8 * 1024];

        let mut expected = blake3::Hasher::new();
        expected.update(&nonce);
        expected.update(&peer_id);
        expected.update(&key);
        expected.update(&record_bytes);
        assert_eq!(
            compute_audit_digest(&nonce, &peer_id, &key, &record_bytes),
            *expected.finalize().as_bytes(),
            "digest must remain BLAKE3(nonce || peer || key || bytes)"
        );
    }

    #[test]
    fn audit_digest_is_deterministic() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];
        let record_bytes = b"hello world";

        let digest_a = compute_audit_digest(&nonce, &peer_id, &key, record_bytes);
        let digest_b = compute_audit_digest(&nonce, &peer_id, &key, record_bytes);

        assert_eq!(digest_a, digest_b, "same inputs must produce same digest");
    }

    #[test]
    fn audit_digest_differs_with_different_nonce() {
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];
        let record_bytes = b"hello world";

        let digest_a = compute_audit_digest(&[0x01; 32], &peer_id, &key, record_bytes);
        let digest_b = compute_audit_digest(&[0xFF; 32], &peer_id, &key, record_bytes);

        assert_ne!(
            digest_a, digest_b,
            "different nonces must produce different digests"
        );
    }

    #[test]
    fn audit_digest_differs_with_different_data() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];

        let digest_a = compute_audit_digest(&nonce, &peer_id, &key, b"data-A");
        let digest_b = compute_audit_digest(&nonce, &peer_id, &key, b"data-B");

        assert_ne!(
            digest_a, digest_b,
            "different data must produce different digests"
        );
    }

    #[test]
    fn audit_digest_differs_with_different_peer() {
        let nonce = [0x01; 32];
        let key: XorName = [0x03; 32];
        let record_bytes = b"hello";

        let digest_a = compute_audit_digest(&nonce, &[0x02; 32], &key, record_bytes);
        let digest_b = compute_audit_digest(&nonce, &[0xFF; 32], &key, record_bytes);

        assert_ne!(
            digest_a, digest_b,
            "different peer IDs must produce different digests"
        );
    }

    #[test]
    fn audit_digest_differs_with_different_key() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let record_bytes = b"hello";

        let digest_a = compute_audit_digest(&nonce, &peer_id, &[0x03; 32], record_bytes);
        let digest_b = compute_audit_digest(&nonce, &peer_id, &[0xFF; 32], record_bytes);

        assert_ne!(
            digest_a, digest_b,
            "different keys must produce different digests"
        );
    }

    // === Absent key digest sentinel ===

    #[test]
    fn absent_key_digest_is_all_zeros() {
        assert_eq!(ABSENT_KEY_DIGEST, [0u8; 32]);
    }

    #[test]
    fn real_digest_differs_from_absent_sentinel() {
        let nonce = [0x01; 32];
        let peer_id = [0x02; 32];
        let key: XorName = [0x03; 32];
        let record_bytes = b"non-empty data";

        let digest = compute_audit_digest(&nonce, &peer_id, &key, record_bytes);
        assert_ne!(
            digest, ABSENT_KEY_DIGEST,
            "a real digest should not collide with the all-zeros sentinel"
        );
    }

    // === Error Display ===

    #[test]
    fn error_display_serialization_failed() {
        let err = ReplicationProtocolError::SerializationFailed("boom".to_string());
        assert_eq!(err.to_string(), "replication serialization failed: boom");
    }

    #[test]
    fn error_display_deserialization_failed() {
        let err = ReplicationProtocolError::DeserializationFailed("bad data".to_string());
        assert_eq!(
            err.to_string(),
            "replication deserialization failed: bad data"
        );
    }

    #[test]
    fn error_display_message_too_large() {
        let err = ReplicationProtocolError::MessageTooLarge {
            size: 20_000_000,
            max_size: MAX_REPLICATION_MESSAGE_SIZE,
        };
        let display = err.to_string();
        assert!(display.contains("20000000"));
        assert!(display.contains(&MAX_REPLICATION_MESSAGE_SIZE.to_string()));
    }
}
