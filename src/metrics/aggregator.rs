//! Event-driven metrics aggregator.
//!
//! Accumulates high-frequency [`MetricEvent`]s from saorsa-core's dedicated
//! channel into atomic counters and bounded sliding windows. Also tracks
//! peer connections (from [`P2PEvent`]) and storage operations (from
//! saorsa-node's own storage layer).

use saorsa_core::{MetricEvent, StreamClass};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

/// Maximum number of samples retained in each sliding window.
const WINDOW_SIZE: usize = 1000;

/// Counters for a single storage operation type (read / write / delete).
pub(crate) struct OperationCounter {
    pub total: AtomicU64,
    pub errors: AtomicU64,
    pub durations: RwLock<VecDeque<u64>>,
}

impl OperationCounter {
    fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            durations: RwLock::new(VecDeque::with_capacity(WINDOW_SIZE)),
        }
    }

    async fn record(&self, duration: Duration, success: bool) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        let mut window = self.durations.write().await;
        if window.len() >= WINDOW_SIZE {
            window.pop_front();
        }
        window.push_back(micros);
    }
}

/// Aggregates event-driven metrics into counters and sliding windows.
pub struct MetricsAggregator {
    // --- Peer connections (from P2PEvent) ---
    pub(crate) connected_peers: AtomicU64,

    // --- Lookup metrics (from MetricEvent) ---
    pub(crate) lookup_latencies: RwLock<VecDeque<u64>>, // microseconds
    pub(crate) lookup_hops: RwLock<VecDeque<u8>>,
    pub(crate) lookup_count: AtomicU64,
    pub(crate) lookup_timeouts: AtomicU64,

    // --- DHT operation counters ---
    pub(crate) dht_puts_total: AtomicU64,
    pub(crate) dht_puts_success: AtomicU64,
    pub(crate) dht_gets_total: AtomicU64,
    pub(crate) dht_gets_success: AtomicU64,

    // --- Auth ---
    pub(crate) auth_failures_total: AtomicU64,

    // --- Stream metrics ---
    pub(crate) stream_bandwidth: RwLock<HashMap<StreamClass, VecDeque<u64>>>,
    pub(crate) stream_rtt: RwLock<HashMap<StreamClass, VecDeque<u64>>>, // microseconds

    // --- Storage operations (saorsa-node's own layer) ---
    pub(crate) storage_reads: OperationCounter,
    pub(crate) storage_writes: OperationCounter,
    pub(crate) storage_deletes: OperationCounter,
}

impl MetricsAggregator {
    /// Create a new, empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connected_peers: AtomicU64::new(0),

            lookup_latencies: RwLock::new(VecDeque::with_capacity(WINDOW_SIZE)),
            lookup_hops: RwLock::new(VecDeque::with_capacity(WINDOW_SIZE)),
            lookup_count: AtomicU64::new(0),
            lookup_timeouts: AtomicU64::new(0),

            dht_puts_total: AtomicU64::new(0),
            dht_puts_success: AtomicU64::new(0),
            dht_gets_total: AtomicU64::new(0),
            dht_gets_success: AtomicU64::new(0),

            auth_failures_total: AtomicU64::new(0),

            stream_bandwidth: RwLock::new(HashMap::new()),
            stream_rtt: RwLock::new(HashMap::new()),

            storage_reads: OperationCounter::new(),
            storage_writes: OperationCounter::new(),
            storage_deletes: OperationCounter::new(),
        }
    }

    // ---- Event handling ----

    /// Process a metric event from saorsa-core's dedicated channel.
    pub async fn handle_metric_event(&self, event: MetricEvent) {
        match event {
            MetricEvent::LookupCompleted { duration, hops } => {
                self.lookup_count.fetch_add(1, Ordering::Relaxed);
                let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
                {
                    let mut w = self.lookup_latencies.write().await;
                    if w.len() >= WINDOW_SIZE {
                        w.pop_front();
                    }
                    w.push_back(micros);
                }
                {
                    let mut w = self.lookup_hops.write().await;
                    if w.len() >= WINDOW_SIZE {
                        w.pop_front();
                    }
                    w.push_back(hops);
                }
            }
            MetricEvent::LookupTimedOut => {
                self.lookup_count.fetch_add(1, Ordering::Relaxed);
                self.lookup_timeouts.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::DhtPutCompleted { success, .. } => {
                self.dht_puts_total.fetch_add(1, Ordering::Relaxed);
                if success {
                    self.dht_puts_success.fetch_add(1, Ordering::Relaxed);
                }
            }
            MetricEvent::DhtGetCompleted { success, .. } => {
                self.dht_gets_total.fetch_add(1, Ordering::Relaxed);
                if success {
                    self.dht_gets_success.fetch_add(1, Ordering::Relaxed);
                }
            }
            MetricEvent::AuthFailure => {
                self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::StreamBandwidth {
                class,
                bytes_per_sec,
            } => {
                let mut map = self.stream_bandwidth.write().await;
                let window = map
                    .entry(class)
                    .or_insert_with(|| VecDeque::with_capacity(WINDOW_SIZE));
                if window.len() >= WINDOW_SIZE {
                    window.pop_front();
                }
                window.push_back(bytes_per_sec);
            }
            MetricEvent::StreamRtt { class, rtt } => {
                let micros = rtt.as_micros().min(u128::from(u64::MAX)) as u64;
                let mut map = self.stream_rtt.write().await;
                let window = map
                    .entry(class)
                    .or_insert_with(|| VecDeque::with_capacity(WINDOW_SIZE));
                if window.len() >= WINDOW_SIZE {
                    window.pop_front();
                }
                window.push_back(micros);
            }
        }
    }

    // ---- Peer connection tracking (from P2PEvent) ----

    /// Record a new peer connection.
    pub fn record_peer_connected(&self) {
        self.connected_peers.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a peer disconnection.
    pub fn record_peer_disconnected(&self) {
        // Saturating subtract to avoid underflow if events arrive out of order.
        let prev = self.connected_peers.load(Ordering::Relaxed);
        if prev > 0 {
            self.connected_peers
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    if v > 0 {
                        Some(v - 1)
                    } else {
                        None
                    }
                })
                .ok();
        }
    }

    // ---- Storage operation recording ----

    /// Record a storage read operation.
    pub async fn record_storage_read(&self, duration: Duration, success: bool) {
        self.storage_reads.record(duration, success).await;
    }

    /// Record a storage write operation.
    pub async fn record_storage_write(&self, duration: Duration, success: bool) {
        self.storage_writes.record(duration, success).await;
    }

    /// Record a storage delete operation.
    pub async fn record_storage_delete(&self, duration: Duration, success: bool) {
        self.storage_deletes.record(duration, success).await;
    }

    // ---- Accessors for PrometheusFormatter ----

    /// Current number of connected peers.
    pub fn connected_peers(&self) -> u64 {
        self.connected_peers.load(Ordering::Relaxed)
    }

    /// Total lookup count.
    pub fn lookup_count(&self) -> u64 {
        self.lookup_count.load(Ordering::Relaxed)
    }

    /// Total lookup timeouts.
    pub fn lookup_timeouts(&self) -> u64 {
        self.lookup_timeouts.load(Ordering::Relaxed)
    }

    /// Lookup timeout rate (timeouts / total lookups).
    pub fn lookup_timeout_rate(&self) -> f64 {
        let total = self.lookup_count.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.lookup_timeouts.load(Ordering::Relaxed) as f64 / total as f64
    }

    /// DHT success rate across all puts and gets.
    pub fn dht_success_rate(&self) -> f64 {
        let total = self.dht_puts_total.load(Ordering::Relaxed)
            + self.dht_gets_total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let success = self.dht_puts_success.load(Ordering::Relaxed)
            + self.dht_gets_success.load(Ordering::Relaxed);
        success as f64 / total as f64
    }
}

impl Default for MetricsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Percentile helpers ----

/// Compute a percentile (0–100) from a sorted slice of u64 values.
/// Returns 0 if the slice is empty.
pub(crate) fn percentile_u64(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round().max(0.0) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Compute a percentile (0–100) from a sorted slice of u8 values.
/// Returns 0 if the slice is empty.
pub(crate) fn percentile_u8(sorted: &[u8], p: f64) -> u8 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round().max(0.0) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn percentile_empty() {
        assert_eq!(percentile_u64(&[], 50.0), 0);
        assert_eq!(percentile_u8(&[], 95.0), 0);
    }

    #[test]
    fn percentile_single_element() {
        assert_eq!(percentile_u64(&[42], 50.0), 42);
        assert_eq!(percentile_u64(&[42], 99.0), 42);
    }

    #[test]
    fn percentile_multiple() {
        let data: Vec<u64> = (1..=100).collect();
        // With 100 elements (indices 0-99), p50 rounds to index 50 → value 51
        assert_eq!(percentile_u64(&data, 50.0), 51);
        assert_eq!(percentile_u64(&data, 95.0), 95);
        assert_eq!(percentile_u64(&data, 99.0), 99);
    }

    #[tokio::test]
    async fn handle_lookup_completed() {
        let agg = MetricsAggregator::new();
        agg.handle_metric_event(MetricEvent::LookupCompleted {
            duration: Duration::from_millis(42),
            hops: 3,
        })
        .await;

        assert_eq!(agg.lookup_count(), 1);
        assert_eq!(agg.lookup_timeouts(), 0);
        assert_eq!(agg.lookup_latencies.read().await.len(), 1);
        assert_eq!(agg.lookup_hops.read().await.len(), 1);
    }

    #[tokio::test]
    async fn handle_lookup_timeout() {
        let agg = MetricsAggregator::new();
        agg.handle_metric_event(MetricEvent::LookupTimedOut).await;

        assert_eq!(agg.lookup_count(), 1);
        assert_eq!(agg.lookup_timeouts(), 1);
    }

    #[tokio::test]
    async fn handle_dht_ops() {
        let agg = MetricsAggregator::new();
        agg.handle_metric_event(MetricEvent::DhtPutCompleted {
            duration: Duration::from_millis(10),
            success: true,
        })
        .await;
        agg.handle_metric_event(MetricEvent::DhtPutCompleted {
            duration: Duration::from_millis(10),
            success: false,
        })
        .await;
        agg.handle_metric_event(MetricEvent::DhtGetCompleted {
            duration: Duration::from_millis(10),
            success: true,
        })
        .await;

        assert_eq!(agg.dht_puts_total.load(Ordering::Relaxed), 2);
        assert_eq!(agg.dht_puts_success.load(Ordering::Relaxed), 1);
        assert_eq!(agg.dht_gets_total.load(Ordering::Relaxed), 1);
        assert_eq!(agg.dht_gets_success.load(Ordering::Relaxed), 1);
        // 2 successes out of 3 total
        let rate = agg.dht_success_rate();
        assert!((rate - 2.0 / 3.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn peer_connect_disconnect() {
        let agg = MetricsAggregator::new();
        agg.record_peer_connected();
        agg.record_peer_connected();
        assert_eq!(agg.connected_peers(), 2);

        agg.record_peer_disconnected();
        assert_eq!(agg.connected_peers(), 1);

        // Saturating: can't go below 0
        agg.record_peer_disconnected();
        agg.record_peer_disconnected();
        assert_eq!(agg.connected_peers(), 0);
    }

    #[tokio::test]
    async fn storage_operations() {
        let agg = MetricsAggregator::new();
        agg.record_storage_write(Duration::from_millis(5), true)
            .await;
        agg.record_storage_write(Duration::from_millis(10), false)
            .await;

        assert_eq!(agg.storage_writes.total.load(Ordering::Relaxed), 2);
        assert_eq!(agg.storage_writes.errors.load(Ordering::Relaxed), 1);
        assert_eq!(agg.storage_writes.durations.read().await.len(), 2);
    }

    #[tokio::test]
    async fn stream_bandwidth_and_rtt() {
        let agg = MetricsAggregator::new();
        agg.handle_metric_event(MetricEvent::StreamBandwidth {
            class: StreamClass::File,
            bytes_per_sec: 1024,
        })
        .await;
        agg.handle_metric_event(MetricEvent::StreamRtt {
            class: StreamClass::Control,
            rtt: Duration::from_millis(15),
        })
        .await;

        let bw = agg.stream_bandwidth.read().await;
        assert_eq!(bw.get(&StreamClass::File).map(VecDeque::len), Some(1));

        let rtt = agg.stream_rtt.read().await;
        assert_eq!(rtt.get(&StreamClass::Control).map(VecDeque::len), Some(1));
    }

    #[tokio::test]
    async fn window_bounded() {
        let agg = MetricsAggregator::new();
        for i in 0..WINDOW_SIZE + 50 {
            agg.handle_metric_event(MetricEvent::LookupCompleted {
                duration: Duration::from_micros(i as u64),
                hops: 1,
            })
            .await;
        }
        assert_eq!(agg.lookup_latencies.read().await.len(), WINDOW_SIZE);
        assert_eq!(agg.lookup_hops.read().await.len(), WINDOW_SIZE);
    }
}
