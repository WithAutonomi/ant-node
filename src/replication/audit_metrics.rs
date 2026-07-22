//! Lightweight node-local counters and labels for audit observability.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use saorsa_core::identity::PeerId;

use super::protocol::{self, ReplicationMessageBody};

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
    /// Commitment-pin lookup sharing the audit responder capacity pool.
    CommitmentPin,
}

impl AuditResponderClass {
    const COUNT: usize = 4;

    #[cfg(any(feature = "logging", test))]
    const fn index(self) -> usize {
        match self {
            Self::Digest => 0,
            Self::Subtree => 1,
            Self::Byte => 2,
            Self::CommitmentPin => 3,
        }
    }
}

/// Capacity ceiling responsible for dropping an inbound audit-pool request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResponderDropReason {
    /// The node-wide responder pool was full.
    GlobalPoolFull,
    /// This source peer was already at its class-specific share.
    PerPeerCapFull,
}

/// One origin's activity during an audit-responder summary window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditOriginSnapshot {
    /// Source peer.
    pub source: Option<PeerId>,
    /// Received requests, indexed by [`AuditResponderClass`].
    pub received_by_class: [u64; AuditResponderClass::COUNT],
    /// Successfully admitted requests.
    pub admitted: u64,
    /// Requests dropped because the global pool was full.
    pub global_pool_drops: u64,
    /// Requests dropped because the source hit its per-peer cap.
    pub per_peer_cap_drops: u64,
    /// Requests dropped before dispatch because the serial replication queue
    /// was full or closed.
    pub serial_queue_drops: u64,
    /// Responses whose processing and send attempt completed.
    pub completed: u64,
    /// Completed response send attempts that failed.
    pub send_failures: u64,
    /// Sum of handler-only processing durations.
    pub processing_total_ms: u64,
    /// Slowest handler-only processing duration.
    pub processing_max_ms: u64,
    /// Sum of end-to-end durations from network receipt through send attempt.
    pub total_total_ms: u64,
    /// Slowest end-to-end duration.
    pub total_max_ms: u64,
    /// Highest node-wide in-flight value observed at this source's admission.
    pub peak_global_inflight: usize,
    /// Highest per-source in-flight value observed at admission.
    pub peak_peer_inflight: u32,
}

impl AuditOriginSnapshot {
    /// Total received requests across all audit-pool classes.
    #[must_use]
    #[cfg(any(feature = "logging", test))]
    pub fn received(&self) -> u64 {
        self.received_by_class.iter().sum()
    }

    /// Mean handler-only processing duration for completed requests.
    #[must_use]
    #[cfg(any(feature = "logging", test))]
    pub fn processing_avg_ms(&self) -> u64 {
        self.processing_total_ms
            .checked_div(self.completed)
            .unwrap_or(0)
    }

    /// Mean end-to-end duration for completed requests.
    #[must_use]
    #[cfg(any(feature = "logging", test))]
    pub fn total_avg_ms(&self) -> u64 {
        self.total_total_ms.checked_div(self.completed).unwrap_or(0)
    }

    #[cfg(any(feature = "logging", test))]
    fn merge(&mut self, other: &Self) {
        for (total, value) in self
            .received_by_class
            .iter_mut()
            .zip(other.received_by_class)
        {
            *total = total.saturating_add(value);
        }
        self.admitted = self.admitted.saturating_add(other.admitted);
        self.global_pool_drops = self
            .global_pool_drops
            .saturating_add(other.global_pool_drops);
        self.per_peer_cap_drops = self
            .per_peer_cap_drops
            .saturating_add(other.per_peer_cap_drops);
        self.serial_queue_drops = self
            .serial_queue_drops
            .saturating_add(other.serial_queue_drops);
        self.completed = self.completed.saturating_add(other.completed);
        self.send_failures = self.send_failures.saturating_add(other.send_failures);
        self.processing_total_ms = self
            .processing_total_ms
            .saturating_add(other.processing_total_ms);
        self.processing_max_ms = self.processing_max_ms.max(other.processing_max_ms);
        self.total_total_ms = self.total_total_ms.saturating_add(other.total_total_ms);
        self.total_max_ms = self.total_max_ms.max(other.total_max_ms);
        self.peak_global_inflight = self.peak_global_inflight.max(other.peak_global_inflight);
        self.peak_peer_inflight = self.peak_peer_inflight.max(other.peak_peer_inflight);
    }
}

/// A completed audit-responder summary window.
#[cfg(any(feature = "logging", test))]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AuditResponderSnapshot {
    /// Totals across all sources seen during the window.
    pub total: AuditOriginSnapshot,
    /// Sources ordered by descending request count.
    pub origins: Vec<AuditOriginSnapshot>,
}

#[derive(Debug, Default)]
#[cfg_attr(not(any(feature = "logging", test)), allow(dead_code))]
struct AuditResponderWindow {
    by_source: HashMap<PeerId, AuditOriginSnapshot>,
}

/// Windowed responder metrics used to identify dominant remote origins and
/// distinguish capacity pressure from slow disk/proof work.
#[derive(Debug, Default)]
pub struct AuditResponderMetrics {
    #[cfg_attr(not(any(feature = "logging", test)), allow(dead_code))]
    window: Mutex<AuditResponderWindow>,
}

impl AuditResponderMetrics {
    /// Record a request as soon as it reaches the replication handler.
    #[cfg(any(feature = "logging", test))]
    pub fn record_received(&self, source: PeerId, class: AuditResponderClass) {
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = window.by_source.entry(source).or_default();
        stats.source = Some(source);
        stats.received_by_class[class.index()] =
            stats.received_by_class[class.index()].saturating_add(1);
    }

    /// No-op when responder logging is compiled out.
    #[cfg(not(any(feature = "logging", test)))]
    pub fn record_received(&self, _source: PeerId, _class: AuditResponderClass) {}

    /// Record a successful capacity admission and its decision-time occupancy.
    #[cfg(any(feature = "logging", test))]
    pub fn record_admitted(&self, source: PeerId, global_inflight: usize, peer_inflight: u32) {
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = window.by_source.entry(source).or_default();
        stats.source = Some(source);
        stats.admitted = stats.admitted.saturating_add(1);
        stats.peak_global_inflight = stats.peak_global_inflight.max(global_inflight);
        stats.peak_peer_inflight = stats.peak_peer_inflight.max(peer_inflight);
    }

    /// No-op when responder logging is compiled out.
    #[cfg(not(any(feature = "logging", test)))]
    pub fn record_admitted(&self, _source: PeerId, _global_inflight: usize, _peer_inflight: u32) {}

    /// Record a rejected capacity admission.
    #[cfg(any(feature = "logging", test))]
    pub fn record_drop(&self, source: PeerId, reason: AuditResponderDropReason) {
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = window.by_source.entry(source).or_default();
        stats.source = Some(source);
        match reason {
            AuditResponderDropReason::GlobalPoolFull => {
                stats.global_pool_drops = stats.global_pool_drops.saturating_add(1);
            }
            AuditResponderDropReason::PerPeerCapFull => {
                stats.per_peer_cap_drops = stats.per_peer_cap_drops.saturating_add(1);
            }
        }
    }

    /// No-op when responder logging is compiled out.
    #[cfg(not(any(feature = "logging", test)))]
    pub fn record_drop(&self, _source: PeerId, _reason: AuditResponderDropReason) {}

    /// Record a request lost before handler dispatch in the serial queue.
    #[cfg(any(feature = "logging", test))]
    pub fn record_serial_queue_drop(&self, source: PeerId) {
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = window.by_source.entry(source).or_default();
        stats.source = Some(source);
        stats.serial_queue_drops = stats.serial_queue_drops.saturating_add(1);
    }

    /// No-op when responder logging is compiled out.
    #[cfg(not(any(feature = "logging", test)))]
    pub fn record_serial_queue_drop(&self, _source: PeerId) {}

    /// Record handler and end-to-end latency after the response send attempt.
    #[cfg(any(feature = "logging", test))]
    pub fn record_completed(
        &self,
        source: PeerId,
        processing: Duration,
        total: Duration,
        sent: bool,
    ) {
        let processing_ms = duration_ms(processing);
        let total_ms = duration_ms(total);
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = window.by_source.entry(source).or_default();
        stats.source = Some(source);
        stats.completed = stats.completed.saturating_add(1);
        if !sent {
            stats.send_failures = stats.send_failures.saturating_add(1);
        }
        stats.processing_total_ms = stats.processing_total_ms.saturating_add(processing_ms);
        stats.processing_max_ms = stats.processing_max_ms.max(processing_ms);
        stats.total_total_ms = stats.total_total_ms.saturating_add(total_ms);
        stats.total_max_ms = stats.total_max_ms.max(total_ms);
    }

    /// No-op when responder logging is compiled out.
    #[cfg(not(any(feature = "logging", test)))]
    pub fn record_completed(
        &self,
        _source: PeerId,
        _processing: Duration,
        _total: Duration,
        _sent: bool,
    ) {
    }

    /// Close the current window and return totals plus origins ordered by load.
    #[cfg(any(feature = "logging", test))]
    pub fn take_snapshot(&self) -> AuditResponderSnapshot {
        let by_source = {
            let mut window = self
                .window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut window.by_source)
        };
        let mut origins: Vec<_> = by_source.into_values().collect();
        origins.sort_unstable_by_key(|origin| std::cmp::Reverse(origin.received()));
        let mut total = AuditOriginSnapshot::default();
        for origin in &origins {
            total.merge(origin);
        }
        AuditResponderSnapshot { total, origins }
    }
}

#[cfg(any(feature = "logging", test))]
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Bulk replication responder class isolated from the serial lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationResponderClass {
    /// Chunk fetch responder.
    Fetch,
    /// Batched presence and paid-list verification responder.
    Verification,
    /// Neighbor-sync responder.
    NeighborSync,
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
static COMMITMENT_PIN_ADMISSION_DROPS: AtomicU64 = AtomicU64::new(0);
static FETCH_RESPONDER_ADMISSION_DROPS: AtomicU64 = AtomicU64::new(0);
static VERIFICATION_RESPONDER_ADMISSION_DROPS: AtomicU64 = AtomicU64::new(0);
static NEIGHBOR_SYNC_RESPONDER_ADMISSION_DROPS: AtomicU64 = AtomicU64::new(0);

static FETCH_RESPONDER_STALENESS_SHEDS: AtomicU64 = AtomicU64::new(0);
static VERIFICATION_RESPONDER_STALENESS_SHEDS: AtomicU64 = AtomicU64::new(0);
static NEIGHBOR_SYNC_RESPONDER_STALENESS_SHEDS: AtomicU64 = AtomicU64::new(0);

static SERIAL_QUEUE_OVERFLOW_DROPS: [AtomicU64; protocol::N_REPLICATION_VARIANTS] =
    [const { AtomicU64::new(0) }; protocol::N_REPLICATION_VARIANTS];

static DIGEST_DISPATCH_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
static DIGEST_DISPATCH_LATENCY_TOTAL_MS: AtomicU64 = AtomicU64::new(0);
static DIGEST_DISPATCH_LATENCY_MAX_MS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "logging")]
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

#[cfg(feature = "logging")]
impl AuditResponderClass {
    /// Stable structured-log label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Subtree => "subtree",
            Self::Byte => "byte",
            Self::CommitmentPin => "commitment_pin",
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
        AuditResponderClass::CommitmentPin => {
            COMMITMENT_PIN_ADMISSION_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn record_responder_admission_drop(class: ReplicationResponderClass) {
    match class {
        ReplicationResponderClass::Fetch => {
            FETCH_RESPONDER_ADMISSION_DROPS.fetch_add(1, Ordering::Relaxed);
        }
        ReplicationResponderClass::Verification => {
            VERIFICATION_RESPONDER_ADMISSION_DROPS.fetch_add(1, Ordering::Relaxed);
        }
        ReplicationResponderClass::NeighborSync => {
            NEIGHBOR_SYNC_RESPONDER_ADMISSION_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn record_responder_staleness_shed(class: ReplicationResponderClass) {
    match class {
        ReplicationResponderClass::Fetch => {
            FETCH_RESPONDER_STALENESS_SHEDS.fetch_add(1, Ordering::Relaxed);
        }
        ReplicationResponderClass::Verification => {
            VERIFICATION_RESPONDER_STALENESS_SHEDS.fetch_add(1, Ordering::Relaxed);
        }
        ReplicationResponderClass::NeighborSync => {
            NEIGHBOR_SYNC_RESPONDER_STALENESS_SHEDS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn record_serial_queue_overflow_drop(body: &ReplicationMessageBody) {
    if let Some(counter) = SERIAL_QUEUE_OVERFLOW_DROPS.get(body.variant_index()) {
        counter.fetch_add(1, Ordering::Relaxed);
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

#[cfg(test)]
pub fn responder_admission_drops_total(class: ReplicationResponderClass) -> u64 {
    match class {
        ReplicationResponderClass::Fetch => FETCH_RESPONDER_ADMISSION_DROPS.load(Ordering::Relaxed),
        ReplicationResponderClass::Verification => {
            VERIFICATION_RESPONDER_ADMISSION_DROPS.load(Ordering::Relaxed)
        }
        ReplicationResponderClass::NeighborSync => {
            NEIGHBOR_SYNC_RESPONDER_ADMISSION_DROPS.load(Ordering::Relaxed)
        }
    }
}

#[cfg(test)]
pub fn responder_staleness_sheds_total(class: ReplicationResponderClass) -> u64 {
    match class {
        ReplicationResponderClass::Fetch => FETCH_RESPONDER_STALENESS_SHEDS.load(Ordering::Relaxed),
        ReplicationResponderClass::Verification => {
            VERIFICATION_RESPONDER_STALENESS_SHEDS.load(Ordering::Relaxed)
        }
        ReplicationResponderClass::NeighborSync => {
            NEIGHBOR_SYNC_RESPONDER_STALENESS_SHEDS.load(Ordering::Relaxed)
        }
    }
}

#[cfg(test)]
pub fn serial_queue_overflow_drops_total(body: &ReplicationMessageBody) -> u64 {
    SERIAL_QUEUE_OVERFLOW_DROPS
        .get(body.variant_index())
        .map_or(0, |counter| counter.load(Ordering::Relaxed))
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

    #[test]
    fn bulk_responder_counters_are_split_by_class_and_outcome() {
        let class = ReplicationResponderClass::Fetch;
        let admission_before = responder_admission_drops_total(class);
        let staleness_before = responder_staleness_sheds_total(class);
        let verification_before =
            responder_admission_drops_total(ReplicationResponderClass::Verification);

        record_responder_admission_drop(class);
        record_responder_staleness_shed(class);

        assert_eq!(
            responder_admission_drops_total(class).saturating_sub(admission_before),
            1
        );
        assert_eq!(
            responder_staleness_sheds_total(class).saturating_sub(staleness_before),
            1
        );
        assert_eq!(
            responder_admission_drops_total(ReplicationResponderClass::Verification),
            verification_before
        );
    }

    #[test]
    fn responder_snapshot_orders_origins_and_keeps_stage_timings() {
        let metrics = AuditResponderMetrics::default();
        let busy = PeerId::from_bytes([1; 32]);
        let quiet = PeerId::from_bytes([2; 32]);

        for _ in 0..3 {
            metrics.record_received(busy, AuditResponderClass::Digest);
        }
        metrics.record_admitted(busy, 31, 3);
        metrics.record_completed(
            busy,
            Duration::from_millis(40),
            Duration::from_millis(55),
            true,
        );
        metrics.record_received(quiet, AuditResponderClass::Subtree);
        metrics.record_drop(quiet, AuditResponderDropReason::GlobalPoolFull);

        let snapshot = metrics.take_snapshot();
        assert_eq!(snapshot.total.received(), 4);
        assert_eq!(snapshot.origins[0].source, Some(busy));
        assert_eq!(snapshot.origins[0].processing_avg_ms(), 40);
        assert_eq!(snapshot.origins[0].total_avg_ms(), 55);
        assert_eq!(snapshot.origins[0].peak_global_inflight, 31);
        assert_eq!(snapshot.total.global_pool_drops, 1);
        assert!(metrics.take_snapshot().origins.is_empty());
    }
}
