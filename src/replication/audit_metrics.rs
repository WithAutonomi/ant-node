//! Lightweight node-local counters and labels for audit observability.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// In-scope audit issuer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditType {
    /// Periodic responsible-chunk audit.
    ResponsibleChunk,
    /// Prune-confirmation audit.
    Prune,
    /// ADR-0003 fresh-replication possession check.
    Possession,
}

/// Node-local class for no-response audit verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFailureClass {
    /// The request was delivered but no response arrived before the deadline.
    Timeout,
    /// The request could not be delivered to the target peer.
    Unreachable,
}

/// Responder-side admission class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResponderClass {
    /// Digest-only `AuditChallenge`.
    Digest,
    /// Subtree proof challenge.
    Subtree,
    /// Subtree byte-serving challenge.
    Byte,
}

static RESPONSIBLE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static RESPONSIBLE_UNREACHABLE: AtomicU64 = AtomicU64::new(0);
static PRUNE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static PRUNE_UNREACHABLE: AtomicU64 = AtomicU64::new(0);
static POSSESSION_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static POSSESSION_UNREACHABLE: AtomicU64 = AtomicU64::new(0);

static REPLICATION_EVENT_LAGGED: AtomicU64 = AtomicU64::new(0);
static DIGEST_ADMISSION_DROPS: AtomicU64 = AtomicU64::new(0);
static SUBTREE_ADMISSION_DROPS: AtomicU64 = AtomicU64::new(0);
static BYTE_ADMISSION_DROPS: AtomicU64 = AtomicU64::new(0);

static DIGEST_DISPATCH_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
static DIGEST_DISPATCH_LATENCY_TOTAL_MS: AtomicU64 = AtomicU64::new(0);
static DIGEST_DISPATCH_LATENCY_MAX_MS: AtomicU64 = AtomicU64::new(0);

impl AuditType {
    /// Stable structured-log label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResponsibleChunk => "responsible_chunk",
            Self::Prune => "prune",
            Self::Possession => "possession",
        }
    }
}

impl AuditFailureClass {
    /// Stable structured-log label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
        }
    }
}

impl AuditResponderClass {
    /// Stable structured-log label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Subtree => "subtree",
            Self::Byte => "byte",
        }
    }
}

/// Best-effort coarse class for the transport/request error returned by
/// `P2PNode::send_request`.
///
/// The current core networking layer exposes request-response delivery failure
/// and response-deadline expiry through display strings. Keep this bounded and
/// local to observability: trust evidence still uses the existing
/// `AuditFailureReason::Timeout` wire-compatible reason.
#[must_use]
pub fn classify_audit_send_error(error: &str) -> (&'static str, AuditFailureClass) {
    let lower = error.to_ascii_lowercase();
    if lower.contains("request to") && lower.contains("timed out") {
        ("response_timeout", AuditFailureClass::Timeout)
    } else if lower.contains("peer not found") || lower.contains("no channel") {
        ("peer_unavailable", AuditFailureClass::Unreachable)
    } else if lower.contains("connection") || lower.contains("connect") || lower.contains("dial") {
        ("connection_failed", AuditFailureClass::Unreachable)
    } else if lower.contains("closed") || lower.contains("dropped") {
        ("connection_closed", AuditFailureClass::Unreachable)
    } else if lower.contains("transport") {
        ("transport_error", AuditFailureClass::Unreachable)
    } else if lower.contains("timed out") || lower.contains("timeout") {
        ("transport_timeout", AuditFailureClass::Unreachable)
    } else {
        ("other", AuditFailureClass::Unreachable)
    }
}

pub fn record_audit_no_response(audit_type: AuditType, class: AuditFailureClass) {
    match (audit_type, class) {
        (AuditType::ResponsibleChunk, AuditFailureClass::Timeout) => {
            RESPONSIBLE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        }
        (AuditType::ResponsibleChunk, AuditFailureClass::Unreachable) => {
            RESPONSIBLE_UNREACHABLE.fetch_add(1, Ordering::Relaxed);
        }
        (AuditType::Prune, AuditFailureClass::Timeout) => {
            PRUNE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        }
        (AuditType::Prune, AuditFailureClass::Unreachable) => {
            PRUNE_UNREACHABLE.fetch_add(1, Ordering::Relaxed);
        }
        (AuditType::Possession, AuditFailureClass::Timeout) => {
            POSSESSION_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        }
        (AuditType::Possession, AuditFailureClass::Unreachable) => {
            POSSESSION_UNREACHABLE.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn record_replication_event_lagged(missed: u64) {
    REPLICATION_EVENT_LAGGED.fetch_add(missed, Ordering::Relaxed);
}

pub fn record_admission_drop(class: AuditResponderClass) {
    match class {
        AuditResponderClass::Digest => {
            DIGEST_ADMISSION_DROPS.fetch_add(1, Ordering::Relaxed);
        }
        AuditResponderClass::Subtree => {
            SUBTREE_ADMISSION_DROPS.fetch_add(1, Ordering::Relaxed);
        }
        AuditResponderClass::Byte => {
            BYTE_ADMISSION_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn record_digest_dispatch_latency(latency: Duration) {
    let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
    DIGEST_DISPATCH_LATENCY_COUNT.fetch_add(1, Ordering::Relaxed);
    DIGEST_DISPATCH_LATENCY_TOTAL_MS.fetch_add(latency_ms, Ordering::Relaxed);
    update_max(&DIGEST_DISPATCH_LATENCY_MAX_MS, latency_ms);
}

#[cfg(test)]
pub fn replication_event_lagged_total() -> u64 {
    REPLICATION_EVENT_LAGGED.load(Ordering::Relaxed)
}

fn update_max(max: &AtomicU64, value: u64) {
    let mut current = max.load(Ordering::Relaxed);
    while value > current {
        match max.compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_error_classification_splits_timeout_from_unreachable() {
        assert_eq!(
            classify_audit_send_error("Request to peer on /replication timed out after 4s"),
            ("response_timeout", AuditFailureClass::Timeout)
        );
        assert_eq!(
            classify_audit_send_error("peer not found in active channels"),
            ("peer_unavailable", AuditFailureClass::Unreachable)
        );
        assert_eq!(
            classify_audit_send_error("dial failed for all candidate addresses"),
            ("connection_failed", AuditFailureClass::Unreachable)
        );
        assert_eq!(
            classify_audit_send_error("operation timed out after 10s"),
            ("transport_timeout", AuditFailureClass::Unreachable)
        );
    }
}
