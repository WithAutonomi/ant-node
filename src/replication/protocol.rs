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

    // === Audit (Section 15) ===
    /// Storage audit challenge.
    AuditChallenge(AuditChallenge),
    /// Response to audit challenge.
    AuditResponse(AuditResponse),

    // === Admission control ===
    /// Sent in place of a typed response when the receiver's inbound handler
    /// capacity is exhausted and a request type has no natural rejection
    /// response to carry the overload reason (currently `NeighborSyncRequest`).
    ///
    /// Added as the final variant so postcard keeps the discriminants of all
    /// existing variants byte-identical: a node that predates this variant
    /// simply fails to decode it and falls back to its neutral
    /// no-response-received path, rather than misreading another message.
    Overloaded(OverloadedNotice),
}

/// Notice that the receiver dropped a request because its inbound replication
/// handler capacity was exhausted. Carries the human-readable reason for
/// logging parity with the typed overload rejections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverloadedNotice {
    /// Human-readable overload reason (for logging only).
    pub reason: String,
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

/// Storage audit challenge (Section 15).
///
/// The challenger picks a random nonce and a set of keys the challenged peer
/// should hold, then sends this challenge. The challenged peer must prove
/// storage by returning per-key BLAKE3 digests.
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

/// Response to audit challenge.
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

    #[test]
    fn neighbor_sync_request_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 5,
            body: ReplicationMessageBody::NeighborSyncRequest(NeighborSyncRequest {
                replica_hints: vec![[0x01; 32], [0x02; 32]],
                paid_hints: vec![[0x03; 32]],
                bootstrapping: true,
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

    #[test]
    fn overloaded_notice_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 42,
            body: ReplicationMessageBody::Overloaded(OverloadedNotice {
                reason: "inbound replication handler capacity exceeded".to_string(),
            }),
        };
        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ReplicationMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 42);
        if let ReplicationMessageBody::Overloaded(notice) = decoded.body {
            assert_eq!(
                notice.reason,
                "inbound replication handler capacity exceeded"
            );
        } else {
            panic!("expected Overloaded");
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
