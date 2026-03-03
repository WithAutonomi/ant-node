//! Wire protocol for replication messages (Section 9, 15).
//!
//! All replication messages share a single protocol topic and use postcard
//! serialization, matching the existing `ChunkMessage` pattern.

use crate::client::XorName;
use serde::{Deserialize, Serialize};

/// Protocol identifier for replication messages.
pub const REPLICATION_PROTOCOL_ID: &str = "saorsa/replication/v1";

/// Maximum replication message size (5 MiB, matching chunk protocol).
const MAX_REPLICATION_MESSAGE_SIZE: usize = 5 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// Top-level replication message envelope.
///
/// Same pattern as `ChunkMessage`: sender-assigned `request_id` is echoed
/// in the response for correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationMessage {
    /// Sender-assigned request identifier, echoed in response.
    pub request_id: u64,
    /// Message body (discriminated by variant).
    pub body: ReplicationBody,
}

/// All replication message variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationBody {
    // ----- Fresh replication (Section 6.1) -----
    /// Offer a newly written record with proof-of-payment.
    FreshOffer(FreshOfferRequest),
    /// Response to a fresh offer.
    FreshOfferResponse(FreshOfferResponse),
    /// Paid-list notification (fire-and-forget).
    PaidNotify(PaidNotifyRequest),
    /// Acknowledgement for paid-list notification.
    PaidNotifyResponse(PaidNotifyResponse),

    // ----- Neighbor sync (Section 6.2) -----
    /// Hint exchange during neighbor sync.
    SyncHints(SyncHintsRequest),
    /// Response to sync hints.
    SyncHintsResponse(SyncHintsResponse),

    // ----- Verification (Section 9) -----
    /// Batched verification request (presence + paid-list).
    VerifyRequest(VerifyRequest),
    /// Batched verification response.
    VerifyResponse(VerifyResponse),

    // ----- Fetch (Section 12) -----
    /// Request to fetch a record.
    FetchRequest(FetchRequest),
    /// Response with record data.
    FetchResponse(FetchResponse),

    // ----- Audit (Section 15) -----
    /// Storage audit challenge.
    AuditChallenge(AuditChallengeRequest),
    /// Storage audit response.
    AuditResponse(AuditChallengeResponse),

    // ----- Standalone presence probe (Section 7.5) -----
    /// Presence probe request.
    PresenceRequest(PresenceRequest),
    /// Presence probe response.
    PresenceResponse(PresenceResponse),
}

// ---------------------------------------------------------------------------
// Fresh replication messages
// ---------------------------------------------------------------------------

/// Fresh offer: newly written record with `PoP` (Section 6.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshOfferRequest {
    /// Record key (content address).
    pub key: XorName,
    /// Record content bytes.
    pub content: Vec<u8>,
    /// Proof-of-payment (serialized, mandatory for fresh path).
    pub proof_of_payment: Vec<u8>,
}

/// Response to a fresh offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FreshOfferResponse {
    /// Accepted and stored.
    Accepted {
        /// Record key.
        key: XorName,
    },
    /// Rejected (not responsible, invalid `PoP`, etc.).
    Rejected {
        /// Record key.
        key: XorName,
        /// Rejection reason.
        reason: String,
    },
}

/// Paid-list notification carrying key + `PoP` (Section 7.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaidNotifyRequest {
    /// Record key.
    pub key: XorName,
    /// Proof-of-payment for receiver verification.
    pub proof_of_payment: Vec<u8>,
}

/// Acknowledgement for `PaidNotify` (fire-and-forget, minimal).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaidNotifyResponse {
    /// Key added to `PaidForList`.
    Accepted {
        /// Record key.
        key: XorName,
    },
    /// `PoP` invalid or not in `PaidCloseGroup`.
    Rejected {
        /// Record key.
        key: XorName,
    },
}

// ---------------------------------------------------------------------------
// Neighbor sync messages
// ---------------------------------------------------------------------------

/// Sync hints for neighbor repair (Section 6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHintsRequest {
    /// Keys the sender believes the receiver should hold as replicas.
    pub replica_hints: Vec<XorName>,
    /// Keys the sender believes the receiver should track in `PaidForList`.
    pub paid_hints: Vec<XorName>,
    /// Whether the sender is currently bootstrapping.
    pub bootstrapping: bool,
}

/// Response to sync hints (bidirectional).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHintsResponse {
    /// Hints from the receiver back to the sender.
    pub replica_hints: Vec<XorName>,
    /// Paid-list hints from the receiver.
    pub paid_hints: Vec<XorName>,
    /// Whether the receiver is currently bootstrapping.
    pub bootstrapping: bool,
}

// ---------------------------------------------------------------------------
// Verification messages
// ---------------------------------------------------------------------------

/// Batched verification request (Section 9).
///
/// Each peer receives one request carrying many keys. Responses include
/// per-key evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Keys to check for presence.
    pub presence_keys: Vec<XorName>,
    /// Keys to check for paid-list membership (subset or overlap with `presence_keys`).
    pub paid_list_keys: Vec<XorName>,
}

/// Per-key verification result from a single peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyKeyResult {
    /// The key.
    pub key: XorName,
    /// Whether the key is present locally.
    pub present: bool,
    /// Whether the key is in the peer's `PaidForList` (only set for paid-list queries).
    pub paid: Option<bool>,
}

/// Batched verification response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Per-key results.
    pub results: Vec<VerifyKeyResult>,
}

// ---------------------------------------------------------------------------
// Fetch messages
// ---------------------------------------------------------------------------

/// Request to fetch a specific record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    /// Record key to fetch.
    pub key: XorName,
}

/// Response with record data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FetchResponse {
    /// Record found and returned.
    Found {
        /// Record key.
        key: XorName,
        /// Record content bytes.
        content: Vec<u8>,
    },
    /// Record not found locally.
    NotFound {
        /// Record key.
        key: XorName,
    },
}

// ---------------------------------------------------------------------------
// Audit messages (Section 15)
// ---------------------------------------------------------------------------

/// Storage audit challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChallengeRequest {
    /// Unique challenge identifier.
    pub challenge_id: u64,
    /// Random nonce for digest computation.
    pub nonce: [u8; 32],
    /// Ordered set of keys to challenge.
    pub keys: Vec<XorName>,
}

/// Storage audit response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditChallengeResponse {
    /// Per-key digests in challenge order.
    Digests {
        /// Challenge identifier (echoed).
        challenge_id: u64,
        /// Per-key `AuditKeyDigest` values. Length must equal challenge key count.
        /// Empty digest (`[0; 32]`) signals absence for that position.
        digests: Vec<[u8; 32]>,
    },
    /// Peer is currently bootstrapping.
    Bootstrapping {
        /// Challenge identifier (echoed).
        challenge_id: u64,
    },
}

// ---------------------------------------------------------------------------
// Presence probe (Section 7.5)
// ---------------------------------------------------------------------------

/// Standalone presence probe for a single key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceRequest {
    /// Key to probe.
    pub key: XorName,
}

/// Presence probe response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PresenceResponse {
    /// Key exists locally.
    Present {
        /// Record key.
        key: XorName,
    },
    /// Key not found locally.
    Absent {
        /// Record key.
        key: XorName,
    },
}

// ---------------------------------------------------------------------------
// Encoding / Decoding
// ---------------------------------------------------------------------------

/// Protocol error for encoding/decoding failures.
#[derive(Debug, Clone)]
pub enum ReplicationProtocolError {
    /// Serialization failed.
    SerializationFailed(String),
    /// Deserialization failed.
    DeserializationFailed(String),
    /// Message exceeds size limit.
    MessageTooLarge {
        /// Actual message size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },
}

impl std::fmt::Display for ReplicationProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationFailed(e) => write!(f, "serialization failed: {e}"),
            Self::DeserializationFailed(e) => write!(f, "deserialization failed: {e}"),
            Self::MessageTooLarge { size, max } => {
                write!(f, "message too large: {size} bytes (max {max})")
            }
        }
    }
}

impl std::error::Error for ReplicationProtocolError {}

impl ReplicationMessage {
    /// Serialize to bytes using postcard.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the result exceeds the size limit.
    pub fn encode(&self) -> Result<Vec<u8>, ReplicationProtocolError> {
        let bytes = postcard::to_allocvec(self)
            .map_err(|e| ReplicationProtocolError::SerializationFailed(e.to_string()))?;

        if bytes.len() > MAX_REPLICATION_MESSAGE_SIZE {
            return Err(ReplicationProtocolError::MessageTooLarge {
                size: bytes.len(),
                max: MAX_REPLICATION_MESSAGE_SIZE,
            });
        }

        Ok(bytes)
    }

    /// Deserialize from bytes using postcard.
    ///
    /// # Errors
    ///
    /// Returns an error if the data exceeds the size limit or deserialization fails.
    pub fn decode(data: &[u8]) -> Result<Self, ReplicationProtocolError> {
        if data.len() > MAX_REPLICATION_MESSAGE_SIZE {
            return Err(ReplicationProtocolError::MessageTooLarge {
                size: data.len(),
                max: MAX_REPLICATION_MESSAGE_SIZE,
            });
        }

        postcard::from_bytes(data)
            .map_err(|e| ReplicationProtocolError::DeserializationFailed(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Helper to encode→decode round-trip and assert success.
    #[allow(clippy::needless_pass_by_value)]
    fn roundtrip(msg: ReplicationMessage) -> ReplicationMessage {
        let bytes = msg.encode().expect("encode");
        ReplicationMessage::decode(&bytes).expect("decode")
    }

    // ----- Fresh replication -----

    #[test]
    fn test_fresh_offer_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 1,
            body: ReplicationBody::FreshOffer(FreshOfferRequest {
                key: [0xAA; 32],
                content: vec![1, 2, 3, 4],
                proof_of_payment: vec![5, 6, 7],
            }),
        };
        let decoded = roundtrip(msg);
        assert_eq!(decoded.request_id, 1);
        if let ReplicationBody::FreshOffer(req) = decoded.body {
            assert_eq!(req.key, [0xAA; 32]);
            assert_eq!(req.content, vec![1, 2, 3, 4]);
            assert_eq!(req.proof_of_payment, vec![5, 6, 7]);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_fresh_offer_response_accepted() {
        let msg = ReplicationMessage {
            request_id: 2,
            body: ReplicationBody::FreshOfferResponse(FreshOfferResponse::Accepted {
                key: [0xBB; 32],
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::FreshOfferResponse(FreshOfferResponse::Accepted { key }) =
            decoded.body
        {
            assert_eq!(key, [0xBB; 32]);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_fresh_offer_response_rejected() {
        let msg = ReplicationMessage {
            request_id: 3,
            body: ReplicationBody::FreshOfferResponse(FreshOfferResponse::Rejected {
                key: [0xCC; 32],
                reason: "not responsible".to_string(),
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::FreshOfferResponse(FreshOfferResponse::Rejected { key, reason }) =
            decoded.body
        {
            assert_eq!(key, [0xCC; 32]);
            assert_eq!(reason, "not responsible");
        } else {
            panic!("wrong variant");
        }
    }

    // ----- PaidNotify -----

    #[test]
    fn test_paid_notify_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 10,
            body: ReplicationBody::PaidNotify(PaidNotifyRequest {
                key: [0x11; 32],
                proof_of_payment: vec![10, 20],
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::PaidNotify(req) = decoded.body {
            assert_eq!(req.key, [0x11; 32]);
            assert_eq!(req.proof_of_payment, vec![10, 20]);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_paid_notify_response() {
        let msg = ReplicationMessage {
            request_id: 11,
            body: ReplicationBody::PaidNotifyResponse(PaidNotifyResponse::Accepted {
                key: [0x22; 32],
            }),
        };
        let decoded = roundtrip(msg);
        assert_eq!(decoded.request_id, 11);
    }

    // ----- Sync hints -----

    #[test]
    fn test_sync_hints_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 20,
            body: ReplicationBody::SyncHints(SyncHintsRequest {
                replica_hints: vec![[0x01; 32], [0x02; 32]],
                paid_hints: vec![[0x03; 32]],
                bootstrapping: false,
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::SyncHints(req) = decoded.body {
            assert_eq!(req.replica_hints.len(), 2);
            assert_eq!(req.paid_hints.len(), 1);
            assert!(!req.bootstrapping);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_sync_hints_response_bootstrapping() {
        let msg = ReplicationMessage {
            request_id: 21,
            body: ReplicationBody::SyncHintsResponse(SyncHintsResponse {
                replica_hints: vec![],
                paid_hints: vec![],
                bootstrapping: true,
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::SyncHintsResponse(resp) = decoded.body {
            assert!(resp.bootstrapping);
        } else {
            panic!("wrong variant");
        }
    }

    // ----- Verification -----

    #[test]
    fn test_verify_request_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 30,
            body: ReplicationBody::VerifyRequest(VerifyRequest {
                presence_keys: vec![[0xAA; 32], [0xBB; 32]],
                paid_list_keys: vec![[0xAA; 32]],
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::VerifyRequest(req) = decoded.body {
            assert_eq!(req.presence_keys.len(), 2);
            assert_eq!(req.paid_list_keys.len(), 1);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_verify_response_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 31,
            body: ReplicationBody::VerifyResponse(VerifyResponse {
                results: vec![
                    VerifyKeyResult {
                        key: [0xAA; 32],
                        present: true,
                        paid: Some(true),
                    },
                    VerifyKeyResult {
                        key: [0xBB; 32],
                        present: false,
                        paid: None,
                    },
                ],
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::VerifyResponse(resp) = decoded.body {
            assert_eq!(resp.results.len(), 2);
            assert!(resp.results[0].present);
            assert_eq!(resp.results[0].paid, Some(true));
            assert!(!resp.results[1].present);
            assert_eq!(resp.results[1].paid, None);
        } else {
            panic!("wrong variant");
        }
    }

    // ----- Fetch -----

    #[test]
    fn test_fetch_request_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 40,
            body: ReplicationBody::FetchRequest(FetchRequest { key: [0xDD; 32] }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::FetchRequest(req) = decoded.body {
            assert_eq!(req.key, [0xDD; 32]);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_fetch_response_found() {
        let msg = ReplicationMessage {
            request_id: 41,
            body: ReplicationBody::FetchResponse(FetchResponse::Found {
                key: [0xEE; 32],
                content: vec![99; 100],
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::FetchResponse(FetchResponse::Found { key, content }) = decoded.body
        {
            assert_eq!(key, [0xEE; 32]);
            assert_eq!(content.len(), 100);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_fetch_response_not_found() {
        let msg = ReplicationMessage {
            request_id: 42,
            body: ReplicationBody::FetchResponse(FetchResponse::NotFound { key: [0xFF; 32] }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::FetchResponse(FetchResponse::NotFound { key }) = decoded.body {
            assert_eq!(key, [0xFF; 32]);
        } else {
            panic!("wrong variant");
        }
    }

    // ----- Audit -----

    #[test]
    fn test_audit_challenge_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 50,
            body: ReplicationBody::AuditChallenge(AuditChallengeRequest {
                challenge_id: 12345,
                nonce: [0x42; 32],
                keys: vec![[0x01; 32], [0x02; 32], [0x03; 32]],
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::AuditChallenge(req) = decoded.body {
            assert_eq!(req.challenge_id, 12345);
            assert_eq!(req.nonce, [0x42; 32]);
            assert_eq!(req.keys.len(), 3);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_audit_response_digests() {
        let msg = ReplicationMessage {
            request_id: 51,
            body: ReplicationBody::AuditResponse(AuditChallengeResponse::Digests {
                challenge_id: 12345,
                digests: vec![[0xAA; 32], [0xBB; 32]],
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::AuditResponse(AuditChallengeResponse::Digests {
            challenge_id,
            digests,
        }) = decoded.body
        {
            assert_eq!(challenge_id, 12345);
            assert_eq!(digests.len(), 2);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_audit_response_bootstrapping() {
        let msg = ReplicationMessage {
            request_id: 52,
            body: ReplicationBody::AuditResponse(AuditChallengeResponse::Bootstrapping {
                challenge_id: 99,
            }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::AuditResponse(AuditChallengeResponse::Bootstrapping {
            challenge_id,
        }) = decoded.body
        {
            assert_eq!(challenge_id, 99);
        } else {
            panic!("wrong variant");
        }
    }

    // ----- Presence -----

    #[test]
    fn test_presence_request_roundtrip() {
        let msg = ReplicationMessage {
            request_id: 60,
            body: ReplicationBody::PresenceRequest(PresenceRequest { key: [0x55; 32] }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::PresenceRequest(req) = decoded.body {
            assert_eq!(req.key, [0x55; 32]);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_presence_response_present() {
        let msg = ReplicationMessage {
            request_id: 61,
            body: ReplicationBody::PresenceResponse(PresenceResponse::Present { key: [0x66; 32] }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::PresenceResponse(PresenceResponse::Present { key }) = decoded.body {
            assert_eq!(key, [0x66; 32]);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_presence_response_absent() {
        let msg = ReplicationMessage {
            request_id: 62,
            body: ReplicationBody::PresenceResponse(PresenceResponse::Absent { key: [0x77; 32] }),
        };
        let decoded = roundtrip(msg);
        if let ReplicationBody::PresenceResponse(PresenceResponse::Absent { key }) = decoded.body {
            assert_eq!(key, [0x77; 32]);
        } else {
            panic!("wrong variant");
        }
    }

    // ----- Error cases -----

    #[test]
    fn test_decode_garbage() {
        let result = ReplicationMessage::decode(b"not valid postcard");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_empty() {
        let result = ReplicationMessage::decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_too_large_on_decode() {
        let oversized = vec![0u8; MAX_REPLICATION_MESSAGE_SIZE + 1];
        let result = ReplicationMessage::decode(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn test_request_id_preserved() {
        let msg = ReplicationMessage {
            request_id: u64::MAX,
            body: ReplicationBody::PresenceRequest(PresenceRequest { key: [0x00; 32] }),
        };
        let decoded = roundtrip(msg);
        assert_eq!(decoded.request_id, u64::MAX);
    }
}
