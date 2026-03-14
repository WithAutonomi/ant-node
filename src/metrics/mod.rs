//! Metrics aggregation and Prometheus export for saorsa-node.
//!
//! Two data paths feed the `/metrics` endpoint:
//! - **Event-driven** ([`MetricsAggregator`]): processes `MetricEvent`s and `P2PEvent`s
//!   into counters and sliding windows, always up-to-date.
//! - **Pull-based** ([`SnapshotCollector`]): reads state snapshots from saorsa-core
//!   accessor methods on each scrape.
//!
//! [`PrometheusFormatter`] merges both into Prometheus text exposition format.

mod aggregator;
mod prometheus;
mod snapshot;

pub use aggregator::MetricsAggregator;
pub use prometheus::PrometheusFormatter;
pub use snapshot::{MetricsSnapshot, SnapshotCollector};
