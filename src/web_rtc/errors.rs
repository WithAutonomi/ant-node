// Copyright 2026 Saorsa Labs Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error redaction at the browser boundary; native protocol errors are unchanged.

use super::ServerResult;
use crate::logging::warn;
use ant_protocol::{
    ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutResponse, ChunkQuoteResponse,
    MerkleCandidateQuoteResponse, ProtocolError,
};
use saorsa_transport::webrtc::BrowserResponse;
use std::fmt::Display;

pub(super) fn public_error(code: &str, detail: impl Display) -> String {
    warn!(code, detail = %detail, "Browser operation failed");
    match code {
        "storage_error" => "chunk storage operation failed",
        "quote_failed" | "invalid_quote" | "invalid_quote_response" => "storage quote unavailable",
        "put_failed" | "invalid_put_response" => "chunk storage request failed",
        _ => "node could not process the request",
    }
    .to_string()
}

pub(super) fn error_response(request_id: u64, code: &str, detail: impl Display) -> BrowserResponse {
    BrowserResponse::error(request_id, code, public_error(code, detail))
}

/// Consume the encoded buffer before callers re-encode the decoded message, so
/// sanitization retains at most two response-sized allocations at a time.
pub(super) fn decode_response(response: bytes::Bytes) -> ServerResult<ChunkMessage> {
    let mut message =
        ChunkMessage::decode(&response).map_err(|error| public_error("invalid_response", error))?;
    drop(response);
    sanitize_response(&mut message)?;
    Ok(message)
}

fn sanitize_response(message: &mut ChunkMessage) -> ServerResult<()> {
    match &mut message.body {
        ChunkMessageBody::PutResponse(ChunkPutResponse::Error(error))
        | ChunkMessageBody::GetResponse(ChunkGetResponse::Error(error))
        | ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(error))
        | ChunkMessageBody::MerkleCandidateQuoteResponse(MerkleCandidateQuoteResponse::Error(
            error,
        )) => {
            sanitize_protocol_error(error);
        }
        ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => {
            warn!(detail = %message, "Browser payment verification failed");
            *message = "valid payment is required".to_string();
        }
        ChunkMessageBody::PutResponse(
            ChunkPutResponse::Success { .. } | ChunkPutResponse::AlreadyExists { .. },
        )
        | ChunkMessageBody::GetResponse(
            ChunkGetResponse::Success { .. } | ChunkGetResponse::NotFound { .. },
        )
        | ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success { .. })
        | ChunkMessageBody::MerkleCandidateQuoteResponse(MerkleCandidateQuoteResponse::Success {
            ..
        }) => {}
        // New response variants must explicitly opt into the browser boundary.
        _ => {
            return Err(public_error(
                "invalid_response",
                "unexpected chunk response variant",
            ))
        }
    }
    Ok(())
}

fn sanitize_protocol_error(error: &mut ProtocolError) {
    let (detail, replacement) = match error {
        ProtocolError::SerializationFailed(detail) => (detail, "message encoding failed"),
        ProtocolError::DeserializationFailed(detail) => (detail, "invalid message encoding"),
        ProtocolError::StorageFailed(detail) => (detail, "chunk storage operation failed"),
        ProtocolError::PaymentFailed(detail) => (detail, "payment verification failed"),
        ProtocolError::QuoteFailed(detail) => (detail, "storage quote unavailable"),
        ProtocolError::Internal(detail) => (detail, "node could not process the request"),
        ProtocolError::MessageTooLarge { .. }
        | ProtocolError::ChunkTooLarge { .. }
        | ProtocolError::AddressMismatch { .. } => return,
        _ => {
            warn!(detail = %error, "Unrecognized browser protocol error");
            *error = ProtocolError::Internal("node could not process the request".to_string());
            return;
        }
    };
    warn!(detail = %detail, "Browser protocol operation failed");
    *detail = replacement.to_string();
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const PRIVATE_DETAIL: &str = "backend /private/node/chunks.mdb https://rpc.example/key-secret";

    #[test]
    fn binary_errors_keep_their_kinds_without_backenddetails() {
        let errors = [
            ProtocolError::SerializationFailed(PRIVATE_DETAIL.into()),
            ProtocolError::DeserializationFailed(PRIVATE_DETAIL.into()),
            ProtocolError::StorageFailed(PRIVATE_DETAIL.into()),
            ProtocolError::PaymentFailed(PRIVATE_DETAIL.into()),
            ProtocolError::QuoteFailed(PRIVATE_DETAIL.into()),
            ProtocolError::Internal(PRIVATE_DETAIL.into()),
        ];
        for error in errors {
            let responses = [
                ChunkMessageBody::GetResponse(ChunkGetResponse::Error(error.clone())),
                ChunkMessageBody::PutResponse(ChunkPutResponse::Error(error.clone())),
                ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(error.clone())),
                ChunkMessageBody::MerkleCandidateQuoteResponse(
                    MerkleCandidateQuoteResponse::Error(error.clone()),
                ),
            ];
            for body in responses {
                let original = ChunkMessage {
                    request_id: 42,
                    body,
                };
                let decoded =
                    decode_response(original.encode().expect("encode").into()).expect("redact");
                assert_eq!(decoded.request_id, original.request_id);
                assert_eq!(
                    std::mem::discriminant(&decoded.body),
                    std::mem::discriminant(&original.body)
                );
                let (ChunkMessageBody::GetResponse(ChunkGetResponse::Error(sanitized))
                | ChunkMessageBody::PutResponse(ChunkPutResponse::Error(sanitized))
                | ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(sanitized))
                | ChunkMessageBody::MerkleCandidateQuoteResponse(
                    MerkleCandidateQuoteResponse::Error(sanitized),
                )) = &decoded.body
                else {
                    unreachable!();
                };
                assert_eq!(
                    std::mem::discriminant(sanitized),
                    std::mem::discriminant(&error)
                );
                let wire = decoded.encode().expect("encode redacted");
                assert!(!String::from_utf8_lossy(&wire).contains(PRIVATE_DETAIL));
                assert!(!sanitized.to_string().contains("private"));
            }
        }
    }

    #[test]
    fn payment_required_and_json_errors_do_not_expose_backenddetails() {
        let original = ChunkMessage {
            request_id: 7,
            body: ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired {
                message: PRIVATE_DETAIL.into(),
            }),
        };
        let decoded = decode_response(original.encode().expect("encode").into()).expect("redact");
        assert!(
            matches!(decoded.body, ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { ref message }) if message == "valid payment is required")
        );
        for code in [
            "storage_error",
            "quote_failed",
            "invalid_quote",
            "put_failed",
            "invalid_put_response",
        ] {
            let json = serde_json::to_value(error_response(7, code, PRIVATE_DETAIL)).expect("JSON");
            assert_eq!(json["code"], code);
            assert!(!json.to_string().contains(PRIVATE_DETAIL));
        }
    }

    #[test]
    fn successful_chunk_and_structured_validation_errors_are_unchanged() {
        for body in [
            ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                address: [1; 32],
                content: vec![2; 128],
            }),
            ChunkMessageBody::PutResponse(ChunkPutResponse::Error(
                ProtocolError::AddressMismatch {
                    expected: [1; 32],
                    actual: [2; 32],
                },
            )),
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(
                ProtocolError::ChunkTooLarge {
                    size: 100,
                    max_size: 10,
                },
            )),
        ] {
            let original = ChunkMessage {
                request_id: 8,
                body,
            }
            .encode()
            .expect("encode");
            let decoded = decode_response(original.clone().into()).expect("decode");
            assert_eq!(decoded.encode().expect("encode"), original);
        }
    }
}
