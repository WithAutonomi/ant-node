//! Cumulative upgrade-download traffic accounting (V2-834 Part D.2).
//!
//! Binary/archive downloads are tens of megabytes and bursty; manifest polls
//! are small but periodic. All are plain HTTPS GETs whose only meaningful
//! byte figure is the response body, counted here once the body has been
//! read in full. Process-global relaxed atomics, same style as the
//! replication and chunk-RPC tables.

use std::sync::atomic::{AtomicU64, Ordering};

/// What an upgrade HTTP fetch was for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeFetch {
    /// Release archive (auto-apply path).
    Archive,
    /// Raw binary (legacy path).
    Binary,
    /// Detached signature file.
    Signature,
    /// GitHub releases / manifest poll.
    Manifest,
}

impl UpgradeFetch {
    const N: usize = 4;

    const fn index(self) -> usize {
        match self {
            Self::Archive => 0,
            Self::Binary => 1,
            Self::Signature => 2,
            Self::Manifest => 3,
        }
    }
}

static RX_BYTES: [AtomicU64; UpgradeFetch::N] = [const { AtomicU64::new(0) }; UpgradeFetch::N];
static RX_COUNT: [AtomicU64; UpgradeFetch::N] = [const { AtomicU64::new(0) }; UpgradeFetch::N];
/// Fetches that failed before a body was fully read (network error, non-2xx,
/// body read error). No bytes are attributed to these.
static ERROR_COUNT: [AtomicU64; UpgradeFetch::N] = [const { AtomicU64::new(0) }; UpgradeFetch::N];

/// Record a fully-read response body.
pub fn record_rx(kind: UpgradeFetch, bytes: usize) {
    let i = kind.index();
    RX_BYTES[i].fetch_add(bytes as u64, Ordering::Relaxed);
    RX_COUNT[i].fetch_add(1, Ordering::Relaxed);
}

/// Record a fetch that did not yield a full body.
pub fn record_error(kind: UpgradeFetch) {
    ERROR_COUNT[kind.index()].fetch_add(1, Ordering::Relaxed);
}

/// Emit the cumulative upgrade fetch figures as one INFO line, target
/// `ant_node::upgrade::traffic`.
pub fn log_upgrade_traffic_summary() {
    use UpgradeFetch as U;

    let rb = |k: U| RX_BYTES[k.index()].load(Ordering::Relaxed);
    let rc = |k: U| RX_COUNT[k.index()].load(Ordering::Relaxed);
    let ec = |k: U| ERROR_COUNT[k.index()].load(Ordering::Relaxed);

    crate::logging::info!(
        target: "ant_node::upgrade::traffic",
        archive_rx_bytes = rb(U::Archive), archive_rx_count = rc(U::Archive),
        archive_error_count = ec(U::Archive),
        binary_rx_bytes = rb(U::Binary), binary_rx_count = rc(U::Binary),
        binary_error_count = ec(U::Binary),
        signature_rx_bytes = rb(U::Signature), signature_rx_count = rc(U::Signature),
        signature_error_count = ec(U::Signature),
        manifest_rx_bytes = rb(U::Manifest), manifest_rx_count = rc(U::Manifest),
        manifest_error_count = ec(U::Manifest),
        "upgrade traffic summary (cumulative)"
    );
}
