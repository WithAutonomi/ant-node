//! Wire protocol messages for the replication subsystem.
//!
//! All messages use postcard serialization for compact, fast encoding.
//! Peer IDs are transmitted as raw `[u8; 32]` byte arrays.

use serde::{Deserialize, Serialize};

use crate::ant_protocol::XorName;

pub use super::config::MAX_REPLICATION_MESSAGE_SIZE;

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

        if bytes.len() > MAX_REPLICATION_MESSAGE_SIZE {
            return Err(ReplicationProtocolError::MessageTooLarge {
                size: bytes.len(),
                max_size: MAX_REPLICATION_MESSAGE_SIZE,
            });
        }

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
        if data.len() > MAX_REPLICATION_MESSAGE_SIZE {
            return Err(ReplicationProtocolError::MessageTooLarge {
                size: data.len(),
                max_size: MAX_REPLICATION_MESSAGE_SIZE,
            });
        }
        postcard::from_bytes(data)
            .map_err(|e| ReplicationProtocolError::DeserializationFailed(e.to_string()))
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
    /// Surprise byte challenge for the spot-checked leaves (round 2).
    SubtreeByteChallenge(SubtreeByteChallenge),
    /// Response carrying the requested chunks' original bytes (round 2).
    SubtreeByteResponse(SubtreeByteResponse),
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
/// failure, since the responder retains its last two gossiped commitments).
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
    /// The leaves carry only hashes (`bytes_hash`, `nonced_hash`), so this round
    /// proves the tree SHAPE is committed — not that the bytes are still held.
    /// Real possession is proven in **round 2**: the auditor picks a few of the
    /// just-verified leaves and sends a [`SubtreeByteChallenge`] requesting their
    /// original chunk bytes FROM the responder (see that type).
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
/// The distinction matters for accounting: a responder that no longer RETAINS
/// the pinned commitment may simply have rotated past it legitimately — the
/// auditor can pin a root it gossiped a while ago, or one whose newer
/// replacements the auditor never observed (retention is capped at the last two
/// *gossiped* roots, so a peer that rotated several times within the
/// answerability window can honestly drop an older one). That is NOT provable
/// misbehaviour, so it is GRACED like a timeout. Every other rejection is a
/// genuine protocol fault the auditor confirms.
///
/// **Self-grace is bounded and does not preserve stale credit.** A Byzantine
/// peer can deliberately claim `UnknownCommitment`/`Transient` to dodge the
/// confirmed-failure *trust penalty*. But the auditor still REVOKES the holder
/// credit for the PINNED commitment on any graced rejection (it answered and
/// could not prove possession now — see the credit revocation in
/// `storage_commitment_audit`'s rejection handling). The revocation is scoped to
/// the pinned commitment hash, so it strips exactly the credit for the root the
/// peer would not prove without touching credit it legitimately re-earned for a
/// newer commitment. Lying therefore does not let a deleter keep "proven holder"
/// status for that root until the credit TTL — the loophole a plain timeout
/// would leave. It also accumulates a timeout strike, so a peer
/// that self-graces on every audit still crosses the strike threshold once
/// timeout-eviction is enabled. An honest peer that genuinely rotated simply
/// re-earns credit on the next audit of its current commitment, so the grace
/// strips no peer that is actually holding its responsible data. The grace
/// removes only the false TRUST PENALTY for the genuinely-ambiguous
/// rotated/transient case; it does not remove the possession requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectKind {
    /// The responder does not retain the pinned commitment (rotated past it).
    /// GRACED — indistinguishable from legitimate rotation the auditor missed.
    UnknownCommitment,
    /// A transient, recoverable condition on the responder (e.g. a storage read
    /// error) that is NOT evidence of missing data. GRACED like a timeout so a
    /// flaky disk never manufactures a confirmed possession failure.
    Transient,
    /// Any other rejection (wrong target peer, no commitment state, malformed
    /// proof plan, oversized byte challenge, …). CONFIRMED failure.
    Protocol,
}

impl RejectKind {
    /// Whether the auditor should GRACE this rejection (treat like a timeout —
    /// no confirmed penalty, no holder-credit revocation) rather than confirm
    /// it. Only genuine protocol faults are confirmed; rotation/transient
    /// conditions are graced because they are not provable misbehaviour.
    #[must_use]
    pub fn is_graced(self) -> bool {
        matches!(self, Self::UnknownCommitment | Self::Transient)
    }
}

/// Round 2 of the storage audit (ADR-0002): the **surprise byte challenge**.
///
/// After the auditor has structurally verified a [`SubtreeAuditResponse::Proof`]
/// it picks a small sample of that subtree's just-proven leaves with FRESH
/// randomness (chosen now, after the proof is committed — NOT derived from the
/// round-1 nonce, so the responder could not have predicted it at proof-build
/// time) and asks the responder to return the ORIGINAL chunk bytes for exactly
/// those keys. The auditor then checks each returned chunk against the committed
/// leaf:
///   - `BLAKE3(bytes) == leaf.bytes_hash` (the chunk's content address), AND
///   - `compute_audit_digest(nonce, peer, key, bytes) == leaf.nonced_hash`.
///
/// This makes possession non-delegable to the auditor: the auditor needs to
/// hold NONE of the responder's chunks. A responder that committed to a chunk it
/// no longer holds cannot fabricate bytes that hash to the committed address (a
/// preimage break), so it is caught regardless of who audits it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtreeByteChallenge {
    /// The same `challenge_id` as the round-1 [`SubtreeAuditChallenge`], so the
    /// responder/auditor correlate the two rounds.
    pub challenge_id: u64,
    /// The same nonce as round 1 — needed for the freshness (`nonced_hash`)
    /// check and to bind these bytes to this audit.
    pub nonce: [u8; 32],
    /// The challenged peer ID (bound into each leaf's possession hash).
    pub challenged_peer_id: [u8; 32],
    /// The pinned commitment hash from round 1, so the responder resolves the
    /// SAME tree it just proved and serves bytes only for keys it committed to.
    pub expected_commitment_hash: [u8; 32],
    /// The exact keys whose original bytes the responder must return. These are
    /// the auditor's freshly-randomised spot-check sample of the round-1 subtree
    /// (chosen after the proof was received; not nonce-derived).
    pub keys: Vec<XorName>,
}

/// One requested chunk in a [`SubtreeByteResponse`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubtreeByteItem {
    /// The responder holds this committed key and returns its original bytes.
    Present {
        /// The requested key.
        key: XorName,
        /// The original chunk bytes (the auditor re-hashes to verify).
        bytes: Vec<u8>,
    },
    /// The responder committed to this key but cannot serve its bytes. This is a
    /// PROVABLE cheat (it published a commitment over a chunk it does not hold),
    /// so the auditor counts it as a confirmed failure — NOT a graced timeout.
    /// Distinguishing this explicit signal from silence is what separates a
    /// deleter (instant fail) from a dropped packet (timeout).
    Absent {
        /// The committed key the responder could not serve.
        key: XorName,
    },
}

/// Response to a [`SubtreeByteChallenge`] (round 2). One item per requested key,
/// in the requested order.
///
/// Sizing rule: a challenge carries at most
/// [`MAX_BYTE_CHALLENGE_KEYS`](super::config::MAX_BYTE_CHALLENGE_KEYS) keys —
/// the auditor batches its sample, the responder rejects larger requests — so
/// the WORST-CASE `Items` response (every chunk at `MAX_CHUNK_SIZE`) always
/// encodes under [`MAX_REPLICATION_MESSAGE_SIZE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubtreeByteResponse {
    /// The responder's per-key answers (bytes or an explicit absent signal).
    Items {
        /// The challenge this response answers.
        challenge_id: u64,
        /// One entry per requested key.
        items: Vec<SubtreeByteItem>,
    },
    /// Peer is still bootstrapping (should not happen mid-audit, but handled).
    Bootstrapping {
        /// The challenge this response answers.
        challenge_id: u64,
    },
    /// The responder rejects the byte challenge outright. `kind` drives the
    /// auditor's accounting: [`RejectKind::UnknownCommitment`] (rotated past the
    /// pin) is graced; everything else is a confirmed failure, like round 1.
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
/// Returns the 32-byte BLAKE3 digest binding the nonce, peer identity, key,
/// and record content together so a peer cannot forge proofs without holding
/// the actual data.
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

    // === Round-2 byte response sizing ===

    #[test]
    fn max_batch_worst_case_byte_response_fits_wire_cap() {
        // The auditor batches its round-2 sample to MAX_BYTE_CHALLENGE_KEYS per
        // challenge precisely so this worst case — every requested chunk at
        // MAX_CHUNK_SIZE — still encodes. If this fails, honest responders
        // would hit encode errors and be penalized as timeouts.
        let items: Vec<SubtreeByteItem> = (0..crate::replication::config::MAX_BYTE_CHALLENGE_KEYS)
            .map(|i| SubtreeByteItem::Present {
                key: [u8::try_from(i).unwrap_or(u8::MAX); 32],
                bytes: vec![0xAB; crate::ant_protocol::MAX_CHUNK_SIZE],
            })
            .collect();
        let msg = ReplicationMessage {
            request_id: 7,
            body: ReplicationMessageBody::SubtreeByteResponse(SubtreeByteResponse::Items {
                challenge_id: 7,
                items,
            }),
        };
        let encoded = msg
            .encode()
            .expect("worst-case max-batch byte response must fit the wire cap");
        assert!(encoded.len() <= MAX_REPLICATION_MESSAGE_SIZE);
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
