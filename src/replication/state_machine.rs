//! Receiver verification state machine (Section 8).
//!
//! Defines all states and enforces valid transitions. Each transition method
//! returns `Result<Self, TransitionError>` to prevent invalid state changes.

use crate::client::XorName;
use crate::replication::types::HintPipeline;
use std::fmt;

/// Errors from invalid state transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    /// Current state name.
    pub from: &'static str,
    /// Attempted target state name.
    pub to: &'static str,
    /// Why the transition is invalid.
    pub reason: String,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid transition {} -> {}: {}",
            self.from, self.to, self.reason
        )
    }
}

impl std::error::Error for TransitionError {}

/// Verification state machine for a single key's replication lifecycle.
///
/// See Section 8 of `REPLICATION_DESIGN.md` for the full state diagram.
#[derive(Debug, Clone)]
pub enum VerificationState {
    /// Initial state — no offer received.
    Idle,

    /// Offer received, pending admission filtering.
    OfferReceived {
        /// The key being offered.
        key: XorName,
        /// Which pipeline the key will follow.
        pipeline: HintPipeline,
    },

    /// Offer rejected by admission filter.
    FilterRejected {
        /// The key that was rejected.
        key: XorName,
    },

    /// Awaiting quorum/paid-list verification results.
    PendingVerify {
        /// The key being verified.
        key: XorName,
        /// Which pipeline the key follows.
        pipeline: HintPipeline,
    },

    /// Quorum verification succeeded (presence positives >= `QuorumNeeded`).
    QuorumVerified {
        /// The key.
        key: XorName,
        /// Peers that responded `Present` (verified fetch sources).
        sources: Vec<String>,
    },

    /// Paid-list verification succeeded.
    PaidListVerified {
        /// The key.
        key: XorName,
        /// Which pipeline the key follows.
        pipeline: HintPipeline,
        /// Peers that responded `Present` (may be empty for paid-only).
        sources: Vec<String>,
    },

    /// Queued for record fetch.
    QueuedForFetch {
        /// The key.
        key: XorName,
        /// Verified fetch source peers.
        sources: Vec<String>,
        /// Sources already tried.
        tried: Vec<String>,
    },

    /// Actively fetching.
    Fetching {
        /// The key.
        key: XorName,
        /// Current source peer being fetched from.
        current_source: String,
        /// All verified source peers.
        sources: Vec<String>,
        /// Sources already tried.
        tried: Vec<String>,
    },

    /// Fetch succeeded and record stored.
    Stored {
        /// The key.
        key: XorName,
    },

    /// Fetch failed but can retry with alternate source.
    FetchRetryable {
        /// The key.
        key: XorName,
        /// Remaining verified source peers.
        sources: Vec<String>,
        /// Sources already tried (including the one that just failed).
        tried: Vec<String>,
    },

    /// Fetch abandoned (terminal failure or no alternate sources).
    FetchAbandoned {
        /// The key.
        key: XorName,
    },

    /// Quorum verification failed (both conditions impossible).
    QuorumFailed {
        /// The key.
        key: XorName,
    },

    /// Quorum verification inconclusive (deadline expired, still undecidable).
    QuorumInconclusive {
        /// The key.
        key: XorName,
    },

    /// Terminal state after quorum failure or inconclusive result.
    QuorumAbandoned {
        /// The key.
        key: XorName,
    },
}

impl VerificationState {
    /// Get the name of the current state.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::OfferReceived { .. } => "OfferReceived",
            Self::FilterRejected { .. } => "FilterRejected",
            Self::PendingVerify { .. } => "PendingVerify",
            Self::QuorumVerified { .. } => "QuorumVerified",
            Self::PaidListVerified { .. } => "PaidListVerified",
            Self::QueuedForFetch { .. } => "QueuedForFetch",
            Self::Fetching { .. } => "Fetching",
            Self::Stored { .. } => "Stored",
            Self::FetchRetryable { .. } => "FetchRetryable",
            Self::FetchAbandoned { .. } => "FetchAbandoned",
            Self::QuorumFailed { .. } => "QuorumFailed",
            Self::QuorumInconclusive { .. } => "QuorumInconclusive",
            Self::QuorumAbandoned { .. } => "QuorumAbandoned",
        }
    }

    /// Get the key associated with this state, if any.
    #[must_use]
    pub fn key(&self) -> Option<&XorName> {
        match self {
            Self::Idle => None,
            Self::OfferReceived { key, .. }
            | Self::FilterRejected { key }
            | Self::PendingVerify { key, .. }
            | Self::QuorumVerified { key, .. }
            | Self::PaidListVerified { key, .. }
            | Self::QueuedForFetch { key, .. }
            | Self::Fetching { key, .. }
            | Self::Stored { key }
            | Self::FetchRetryable { key, .. }
            | Self::FetchAbandoned { key }
            | Self::QuorumFailed { key }
            | Self::QuorumInconclusive { key }
            | Self::QuorumAbandoned { key } => Some(key),
        }
    }

    // ----- Transition methods -----

    /// `Idle -> OfferReceived`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `Idle` state.
    pub fn receive_offer(
        self,
        key: XorName,
        pipeline: HintPipeline,
    ) -> Result<Self, TransitionError> {
        match self {
            Self::Idle => Ok(Self::OfferReceived { key, pipeline }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "OfferReceived",
                reason: "can only receive offer from Idle".to_string(),
            }),
        }
    }

    /// `OfferReceived -> FilterRejected`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `OfferReceived` state.
    pub fn reject_filter(self) -> Result<Self, TransitionError> {
        match self {
            Self::OfferReceived { key, .. } => Ok(Self::FilterRejected { key }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "FilterRejected",
                reason: "can only reject from OfferReceived".to_string(),
            }),
        }
    }

    /// `OfferReceived -> PendingVerify`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `OfferReceived` state.
    pub fn accept_for_verify(self) -> Result<Self, TransitionError> {
        match self {
            Self::OfferReceived { key, pipeline } => Ok(Self::PendingVerify { key, pipeline }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "PendingVerify",
                reason: "can only accept from OfferReceived".to_string(),
            }),
        }
    }

    /// `PendingVerify -> QuorumVerified`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `PendingVerify` state or
    /// pipeline is not `Replica`.
    pub fn quorum_verified(self, sources: Vec<String>) -> Result<Self, TransitionError> {
        match self {
            Self::PendingVerify {
                key,
                pipeline: HintPipeline::Replica,
            } => Ok(Self::QuorumVerified { key, sources }),
            Self::PendingVerify {
                pipeline: HintPipeline::PaidOnly,
                ..
            } => Err(TransitionError {
                from: "PendingVerify",
                to: "QuorumVerified",
                reason: "QuorumVerified requires Replica pipeline".to_string(),
            }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "QuorumVerified",
                reason: "can only verify quorum from PendingVerify".to_string(),
            }),
        }
    }

    /// `PendingVerify -> PaidListVerified`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `PendingVerify` state.
    pub fn paid_list_verified(self, sources: Vec<String>) -> Result<Self, TransitionError> {
        match self {
            Self::PendingVerify { key, pipeline } => Ok(Self::PaidListVerified {
                key,
                pipeline,
                sources,
            }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "PaidListVerified",
                reason: "can only verify paid-list from PendingVerify".to_string(),
            }),
        }
    }

    /// `QuorumVerified -> QueuedForFetch`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `QuorumVerified` state.
    pub fn queue_for_fetch_from_quorum(self) -> Result<Self, TransitionError> {
        match self {
            Self::QuorumVerified { key, sources } => Ok(Self::QueuedForFetch {
                key,
                sources,
                tried: Vec::new(),
            }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "QueuedForFetch",
                reason: "can only queue from QuorumVerified".to_string(),
            }),
        }
    }

    /// `PaidListVerified -> QueuedForFetch` (replica pipeline, has sources)
    /// `PaidListVerified -> FetchAbandoned` (replica pipeline, no sources)
    /// `PaidListVerified -> Idle` (paid-only pipeline)
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `PaidListVerified` state.
    pub fn advance_from_paid_list(self) -> Result<Self, TransitionError> {
        match self {
            Self::PaidListVerified {
                key,
                pipeline: HintPipeline::Replica,
                sources,
            } => {
                if sources.is_empty() {
                    Ok(Self::FetchAbandoned { key })
                } else {
                    Ok(Self::QueuedForFetch {
                        key,
                        sources,
                        tried: Vec::new(),
                    })
                }
            }
            Self::PaidListVerified {
                pipeline: HintPipeline::PaidOnly,
                ..
            } => Ok(Self::Idle),
            _ => Err(TransitionError {
                from: self.name(),
                to: "QueuedForFetch/FetchAbandoned/Idle",
                reason: "can only advance from PaidListVerified".to_string(),
            }),
        }
    }

    /// `QueuedForFetch -> Fetching`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `QueuedForFetch` state.
    pub fn start_fetch(self, source: String) -> Result<Self, TransitionError> {
        match self {
            Self::QueuedForFetch {
                key,
                sources,
                tried,
            } => Ok(Self::Fetching {
                key,
                current_source: source,
                sources,
                tried,
            }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "Fetching",
                reason: "can only start fetch from QueuedForFetch".to_string(),
            }),
        }
    }

    /// `Fetching -> Stored`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `Fetching` state.
    pub fn store_success(self) -> Result<Self, TransitionError> {
        match self {
            Self::Fetching { key, .. } => Ok(Self::Stored { key }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "Stored",
                reason: "can only store from Fetching".to_string(),
            }),
        }
    }

    /// `Fetching -> FetchRetryable` (if alternate sources remain)
    /// `Fetching -> FetchAbandoned` (if no alternate sources)
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `Fetching` state.
    pub fn fetch_failed(self, is_terminal: bool) -> Result<Self, TransitionError> {
        match self {
            Self::Fetching {
                key,
                current_source,
                sources,
                mut tried,
            } => {
                tried.push(current_source);
                let has_untried = sources.iter().any(|s| !tried.contains(s));

                if is_terminal || !has_untried {
                    Ok(Self::FetchAbandoned { key })
                } else {
                    Ok(Self::FetchRetryable {
                        key,
                        sources,
                        tried,
                    })
                }
            }
            _ => Err(TransitionError {
                from: self.name(),
                to: "FetchRetryable/FetchAbandoned",
                reason: "can only fail fetch from Fetching".to_string(),
            }),
        }
    }

    /// `FetchRetryable -> QueuedForFetch`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `FetchRetryable` state.
    pub fn retry_fetch(self) -> Result<Self, TransitionError> {
        match self {
            Self::FetchRetryable {
                key,
                sources,
                tried,
            } => Ok(Self::QueuedForFetch {
                key,
                sources,
                tried,
            }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "QueuedForFetch",
                reason: "can only retry from FetchRetryable".to_string(),
            }),
        }
    }

    /// `QuorumFailed -> QuorumAbandoned`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `QuorumFailed` state.
    pub fn abandon_quorum_failed(self) -> Result<Self, TransitionError> {
        match self {
            Self::QuorumFailed { key } => Ok(Self::QuorumAbandoned { key }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "QuorumAbandoned",
                reason: "can only abandon from QuorumFailed".to_string(),
            }),
        }
    }

    /// `QuorumInconclusive -> QuorumAbandoned`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `QuorumInconclusive` state.
    pub fn abandon_quorum_inconclusive(self) -> Result<Self, TransitionError> {
        match self {
            Self::QuorumInconclusive { key } => Ok(Self::QuorumAbandoned { key }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "QuorumAbandoned",
                reason: "can only abandon from QuorumInconclusive".to_string(),
            }),
        }
    }

    /// `PendingVerify -> QuorumFailed`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `PendingVerify` state.
    pub fn quorum_failed(self) -> Result<Self, TransitionError> {
        match self {
            Self::PendingVerify { key, .. } => Ok(Self::QuorumFailed { key }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "QuorumFailed",
                reason: "can only fail quorum from PendingVerify".to_string(),
            }),
        }
    }

    /// `PendingVerify -> QuorumInconclusive`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in `PendingVerify` state.
    pub fn quorum_inconclusive(self) -> Result<Self, TransitionError> {
        match self {
            Self::PendingVerify { key, .. } => Ok(Self::QuorumInconclusive { key }),
            _ => Err(TransitionError {
                from: self.name(),
                to: "QuorumInconclusive",
                reason: "can only mark inconclusive from PendingVerify".to_string(),
            }),
        }
    }

    /// `FetchAbandoned -> Idle`
    /// `QuorumAbandoned -> Idle`
    /// `Stored -> Idle` (lifecycle complete)
    /// `FilterRejected -> Idle`
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] if not in a terminal-like state.
    pub fn reset_to_idle(self) -> Result<Self, TransitionError> {
        match self {
            Self::FetchAbandoned { .. }
            | Self::QuorumAbandoned { .. }
            | Self::Stored { .. }
            | Self::FilterRejected { .. } => Ok(Self::Idle),
            _ => Err(TransitionError {
                from: self.name(),
                to: "Idle",
                reason: "can only reset from terminal states".to_string(),
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_key() -> XorName {
        [0xAA; 32]
    }

    // ---- Happy paths ----

    #[test]
    fn test_replica_quorum_verified_to_stored() {
        let key = test_key();
        let state = VerificationState::Idle;

        let state = state
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer");
        assert_eq!(state.name(), "OfferReceived");

        let state = state.accept_for_verify().expect("accept");
        assert_eq!(state.name(), "PendingVerify");

        let state = state
            .quorum_verified(vec!["peer1".to_string()])
            .expect("quorum");
        assert_eq!(state.name(), "QuorumVerified");

        let state = state.queue_for_fetch_from_quorum().expect("queue");
        assert_eq!(state.name(), "QueuedForFetch");

        let state = state.start_fetch("peer1".to_string()).expect("fetch");
        assert_eq!(state.name(), "Fetching");

        let state = state.store_success().expect("store");
        assert_eq!(state.name(), "Stored");

        let state = state.reset_to_idle().expect("idle");
        assert_eq!(state.name(), "Idle");
    }

    #[test]
    fn test_paid_list_verified_replica_to_stored() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .accept_for_verify()
            .expect("accept")
            .paid_list_verified(vec!["peer1".to_string()])
            .expect("paid");

        assert_eq!(state.name(), "PaidListVerified");

        let state = state.advance_from_paid_list().expect("advance");
        assert_eq!(state.name(), "QueuedForFetch");
    }

    #[test]
    fn test_paid_only_pipeline_to_idle() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::PaidOnly)
            .expect("offer")
            .accept_for_verify()
            .expect("accept")
            .paid_list_verified(vec![])
            .expect("paid")
            .advance_from_paid_list()
            .expect("advance");

        assert_eq!(state.name(), "Idle");
    }

    #[test]
    fn test_paid_list_verified_replica_no_sources() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .accept_for_verify()
            .expect("accept")
            .paid_list_verified(vec![])
            .expect("paid")
            .advance_from_paid_list()
            .expect("advance");

        assert_eq!(state.name(), "FetchAbandoned");
    }

    // ---- Failure paths ----

    #[test]
    fn test_quorum_failed_to_abandoned() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .accept_for_verify()
            .expect("accept")
            .quorum_failed()
            .expect("failed");

        assert_eq!(state.name(), "QuorumFailed");

        let state = state.abandon_quorum_failed().expect("abandon");
        assert_eq!(state.name(), "QuorumAbandoned");

        let state = state.reset_to_idle().expect("idle");
        assert_eq!(state.name(), "Idle");
    }

    #[test]
    fn test_quorum_inconclusive_to_abandoned() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .accept_for_verify()
            .expect("accept")
            .quorum_inconclusive()
            .expect("inconclusive");

        assert_eq!(state.name(), "QuorumInconclusive");

        let state = state.abandon_quorum_inconclusive().expect("abandon");
        assert_eq!(state.name(), "QuorumAbandoned");
    }

    #[test]
    fn test_filter_rejected_to_idle() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .reject_filter()
            .expect("reject");

        assert_eq!(state.name(), "FilterRejected");

        let state = state.reset_to_idle().expect("idle");
        assert_eq!(state.name(), "Idle");
    }

    // ---- Fetch retry ----

    #[test]
    fn test_fetch_retry_then_success() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .accept_for_verify()
            .expect("accept")
            .quorum_verified(vec!["peer1".to_string(), "peer2".to_string()])
            .expect("quorum")
            .queue_for_fetch_from_quorum()
            .expect("queue")
            .start_fetch("peer1".to_string())
            .expect("fetch");

        // peer1 fails, retryable
        let state = state.fetch_failed(false).expect("failed");
        assert_eq!(state.name(), "FetchRetryable");

        let state = state.retry_fetch().expect("retry");
        assert_eq!(state.name(), "QueuedForFetch");

        // Try peer2
        let state = state
            .start_fetch("peer2".to_string())
            .expect("fetch2")
            .store_success()
            .expect("stored");
        assert_eq!(state.name(), "Stored");
    }

    #[test]
    fn test_fetch_all_sources_exhausted() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .accept_for_verify()
            .expect("accept")
            .quorum_verified(vec!["peer1".to_string()])
            .expect("quorum")
            .queue_for_fetch_from_quorum()
            .expect("queue")
            .start_fetch("peer1".to_string())
            .expect("fetch");

        // Only source fails -> abandoned
        let state = state.fetch_failed(false).expect("failed");
        assert_eq!(state.name(), "FetchAbandoned");
    }

    #[test]
    fn test_fetch_terminal_failure() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .accept_for_verify()
            .expect("accept")
            .quorum_verified(vec!["peer1".to_string(), "peer2".to_string()])
            .expect("quorum")
            .queue_for_fetch_from_quorum()
            .expect("queue")
            .start_fetch("peer1".to_string())
            .expect("fetch");

        // Terminal failure -> abandoned even with remaining sources
        let state = state.fetch_failed(true).expect("terminal");
        assert_eq!(state.name(), "FetchAbandoned");
    }

    // ---- Invalid transitions ----

    #[test]
    fn test_cannot_receive_offer_from_non_idle() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer");

        let result = state.receive_offer(key, HintPipeline::Replica);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_verify_quorum_from_idle() {
        let result = VerificationState::Idle.quorum_verified(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_quorum_verify_paid_only_pipeline() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::PaidOnly)
            .expect("offer")
            .accept_for_verify()
            .expect("accept");

        let result = state.quorum_verified(vec!["peer1".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_reset_from_pending_verify() {
        let key = test_key();
        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer")
            .accept_for_verify()
            .expect("accept");

        let result = state.reset_to_idle();
        assert!(result.is_err());
    }

    #[test]
    fn test_key_accessor() {
        let key = test_key();
        assert!(VerificationState::Idle.key().is_none());

        let state = VerificationState::Idle
            .receive_offer(key, HintPipeline::Replica)
            .expect("offer");
        assert_eq!(state.key(), Some(&key));
    }
}
