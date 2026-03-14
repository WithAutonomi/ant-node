//! Prometheus text exposition formatter.
//!
//! Merges event-driven data from [`MetricsAggregator`] with pull-based
//! snapshots from [`MetricsSnapshot`] into a single Prometheus-compatible
//! text block.
//!
//! Follows the Prometheus text exposition spec:
//! - HELP/TYPE lines are emitted only when samples exist
//! - All samples for a metric family are contiguous
//! - Duration metrics use sub-millisecond precision (f64 ms)

use super::aggregator::{percentile_u64, percentile_u8, MetricsAggregator};
use super::snapshot::MetricsSnapshot;
use saorsa_core::dht::metrics::{
    DhtHealthMetrics, PlacementMetrics, SecurityMetrics, TrustMetrics,
};
use saorsa_core::identity::PeerId;
use saorsa_core::{StrategyStats, StreamClass, TransportStats};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write;
use std::sync::atomic::Ordering;

/// Formats aggregated + snapshot metrics into Prometheus text exposition format.
pub struct PrometheusFormatter;

impl PrometheusFormatter {
    /// Produce the full Prometheus text output.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on `fmt::Write` failure (should not happen with `String`).
    pub async fn format(
        aggregator: &MetricsAggregator,
        snapshot: &MetricsSnapshot,
    ) -> std::result::Result<String, std::fmt::Error> {
        let mut out = String::with_capacity(8192);

        Self::format_connection_metrics(&mut out, aggregator)?;
        Self::format_lookup_metrics(&mut out, aggregator).await?;
        Self::format_dht_op_metrics(&mut out, aggregator)?;
        Self::format_auth_metrics(&mut out, aggregator)?;
        Self::format_stream_metrics(&mut out, aggregator).await?;
        Self::format_storage_metrics(&mut out, aggregator).await?;
        Self::format_routing_table_metrics(&mut out, &snapshot.dht_health)?;
        Self::format_replication_metrics(&mut out, &snapshot.dht_health)?;
        Self::format_security_metrics(&mut out, &snapshot.security)?;
        Self::format_trust_metrics(&mut out, &snapshot.trust, &snapshot.trust_scores)?;
        Self::format_placement_metrics(&mut out, &snapshot.placement)?;
        Self::format_transport_metrics(&mut out, &snapshot.transport)?;
        Self::format_strategy_metrics(&mut out, &snapshot.strategy_stats)?;

        Ok(out)
    }

    // ---- Event-driven metrics ----

    fn format_connection_metrics(out: &mut String, agg: &MetricsAggregator) -> std::fmt::Result {
        let peers = agg.connected_peers();
        writeln!(
            out,
            "# HELP p2p_connected_peers Number of currently connected peers"
        )?;
        writeln!(out, "# TYPE p2p_connected_peers gauge")?;
        writeln!(out, "p2p_connected_peers {peers}")?;
        Ok(())
    }

    async fn format_lookup_metrics(out: &mut String, agg: &MetricsAggregator) -> std::fmt::Result {
        let total = agg.lookup_count();
        let timeouts = agg.lookup_timeouts();

        writeln!(out, "# HELP p2p_lookup_total Total lookup operations")?;
        writeln!(out, "# TYPE p2p_lookup_total counter")?;
        writeln!(out, "p2p_lookup_total {total}")?;

        // Latency percentiles
        {
            let window = agg.lookup_latencies.read().await;
            let mut sorted: Vec<u64> = window.iter().copied().collect();
            sorted.sort_unstable();
            let p50 = percentile_u64(&sorted, 50.0) as f64 / 1000.0;
            let p95 = percentile_u64(&sorted, 95.0) as f64 / 1000.0;
            let p99 = percentile_u64(&sorted, 99.0) as f64 / 1000.0;

            writeln!(
                out,
                "# HELP p2p_lookup_latency_p50_ms Lookup latency p50 in milliseconds"
            )?;
            writeln!(out, "# TYPE p2p_lookup_latency_p50_ms gauge")?;
            writeln!(out, "p2p_lookup_latency_p50_ms {p50:.3}")?;

            writeln!(
                out,
                "# HELP p2p_lookup_latency_p95_ms Lookup latency p95 in milliseconds"
            )?;
            writeln!(out, "# TYPE p2p_lookup_latency_p95_ms gauge")?;
            writeln!(out, "p2p_lookup_latency_p95_ms {p95:.3}")?;

            writeln!(
                out,
                "# HELP p2p_lookup_latency_p99_ms Lookup latency p99 in milliseconds"
            )?;
            writeln!(out, "# TYPE p2p_lookup_latency_p99_ms gauge")?;
            writeln!(out, "p2p_lookup_latency_p99_ms {p99:.3}")?;
        }

        // Hop count percentiles
        {
            let window = agg.lookup_hops.read().await;
            let mut sorted: Vec<u8> = window.iter().copied().collect();
            sorted.sort_unstable();
            let p50 = percentile_u8(&sorted, 50.0);
            let p95 = percentile_u8(&sorted, 95.0);

            writeln!(out, "# HELP p2p_lookup_hop_count_p50 Lookup hop count p50")?;
            writeln!(out, "# TYPE p2p_lookup_hop_count_p50 gauge")?;
            writeln!(out, "p2p_lookup_hop_count_p50 {p50}")?;

            writeln!(out, "# HELP p2p_lookup_hop_count_p95 Lookup hop count p95")?;
            writeln!(out, "# TYPE p2p_lookup_hop_count_p95 gauge")?;
            writeln!(out, "p2p_lookup_hop_count_p95 {p95}")?;
        }

        writeln!(out, "# HELP p2p_lookup_timeout_total Total lookup timeouts")?;
        writeln!(out, "# TYPE p2p_lookup_timeout_total counter")?;
        writeln!(out, "p2p_lookup_timeout_total {timeouts}")?;

        let rate = agg.lookup_timeout_rate();
        writeln!(out, "# HELP p2p_lookup_timeout_rate Lookup timeout rate")?;
        writeln!(out, "# TYPE p2p_lookup_timeout_rate gauge")?;
        writeln!(out, "p2p_lookup_timeout_rate {rate:.6}")?;

        Ok(())
    }

    fn format_dht_op_metrics(out: &mut String, agg: &MetricsAggregator) -> std::fmt::Result {
        let puts = agg.dht_puts_total.load(Ordering::Relaxed);
        let puts_ok = agg.dht_puts_success.load(Ordering::Relaxed);
        let gets = agg.dht_gets_total.load(Ordering::Relaxed);
        let gets_ok = agg.dht_gets_success.load(Ordering::Relaxed);

        writeln!(out, "# HELP p2p_dht_puts_total Total DHT put operations")?;
        writeln!(out, "# TYPE p2p_dht_puts_total counter")?;
        writeln!(out, "p2p_dht_puts_total {puts}")?;

        writeln!(
            out,
            "# HELP p2p_dht_puts_success_total Successful DHT put operations"
        )?;
        writeln!(out, "# TYPE p2p_dht_puts_success_total counter")?;
        writeln!(out, "p2p_dht_puts_success_total {puts_ok}")?;

        writeln!(out, "# HELP p2p_dht_gets_total Total DHT get operations")?;
        writeln!(out, "# TYPE p2p_dht_gets_total counter")?;
        writeln!(out, "p2p_dht_gets_total {gets}")?;

        writeln!(
            out,
            "# HELP p2p_dht_gets_success_total Successful DHT get operations"
        )?;
        writeln!(out, "# TYPE p2p_dht_gets_success_total counter")?;
        writeln!(out, "p2p_dht_gets_success_total {gets_ok}")?;

        let rate = agg.dht_success_rate();
        writeln!(
            out,
            "# HELP p2p_dht_success_rate DHT operation success rate"
        )?;
        writeln!(out, "# TYPE p2p_dht_success_rate gauge")?;
        writeln!(out, "p2p_dht_success_rate {rate:.6}")?;

        Ok(())
    }

    fn format_auth_metrics(out: &mut String, agg: &MetricsAggregator) -> std::fmt::Result {
        let failures = agg.auth_failures_total.load(Ordering::Relaxed);
        writeln!(
            out,
            "# HELP p2p_auth_failures_total Total authentication failures"
        )?;
        writeln!(out, "# TYPE p2p_auth_failures_total counter")?;
        writeln!(out, "p2p_auth_failures_total {failures}")?;
        Ok(())
    }

    async fn format_stream_metrics(out: &mut String, agg: &MetricsAggregator) -> std::fmt::Result {
        // Bandwidth
        {
            let guard = agg.stream_bandwidth.read().await;
            let map: &HashMap<StreamClass, VecDeque<u64>> = &guard;
            if !map.is_empty() {
                writeln!(
                    out,
                    "# HELP p2p_stream_bandwidth_p50_bytes_per_sec Stream bandwidth p50"
                )?;
                writeln!(out, "# TYPE p2p_stream_bandwidth_p50_bytes_per_sec gauge")?;
                for (class, window) in map {
                    let label = stream_class_label(class);
                    let mut sorted: Vec<u64> = window.iter().copied().collect();
                    sorted.sort_unstable();
                    let p50 = percentile_u64(&sorted, 50.0);
                    writeln!(
                        out,
                        "p2p_stream_bandwidth_p50_bytes_per_sec{{class=\"{label}\"}} {p50}"
                    )?;
                }
                writeln!(
                    out,
                    "# HELP p2p_stream_bandwidth_p95_bytes_per_sec Stream bandwidth p95"
                )?;
                writeln!(out, "# TYPE p2p_stream_bandwidth_p95_bytes_per_sec gauge")?;
                for (class, window) in map {
                    let label = stream_class_label(class);
                    let mut sorted: Vec<u64> = window.iter().copied().collect();
                    sorted.sort_unstable();
                    let p95 = percentile_u64(&sorted, 95.0);
                    writeln!(
                        out,
                        "p2p_stream_bandwidth_p95_bytes_per_sec{{class=\"{label}\"}} {p95}"
                    )?;
                }
            }
        }

        // RTT
        {
            let guard = agg.stream_rtt.read().await;
            let map: &HashMap<StreamClass, VecDeque<u64>> = &guard;
            if !map.is_empty() {
                writeln!(
                    out,
                    "# HELP p2p_stream_rtt_p50_ms Stream RTT p50 in milliseconds"
                )?;
                writeln!(out, "# TYPE p2p_stream_rtt_p50_ms gauge")?;
                for (class, window) in map {
                    let label = stream_class_label(class);
                    let mut sorted: Vec<u64> = window.iter().copied().collect();
                    sorted.sort_unstable();
                    let p50 = percentile_u64(&sorted, 50.0) as f64 / 1000.0;
                    writeln!(out, "p2p_stream_rtt_p50_ms{{class=\"{label}\"}} {p50:.3}")?;
                }
                writeln!(
                    out,
                    "# HELP p2p_stream_rtt_p95_ms Stream RTT p95 in milliseconds"
                )?;
                writeln!(out, "# TYPE p2p_stream_rtt_p95_ms gauge")?;
                for (class, window) in map {
                    let label = stream_class_label(class);
                    let mut sorted: Vec<u64> = window.iter().copied().collect();
                    sorted.sort_unstable();
                    let p95 = percentile_u64(&sorted, 95.0) as f64 / 1000.0;
                    writeln!(out, "p2p_stream_rtt_p95_ms{{class=\"{label}\"}} {p95:.3}")?;
                }
            }
        }

        Ok(())
    }

    async fn format_storage_metrics(out: &mut String, agg: &MetricsAggregator) -> std::fmt::Result {
        for (op, counter) in [
            ("read", &agg.storage_reads),
            ("write", &agg.storage_writes),
            ("delete", &agg.storage_deletes),
        ] {
            let total = counter.total.load(Ordering::Relaxed);
            let errors = counter.errors.load(Ordering::Relaxed);

            writeln!(
                out,
                "# HELP p2p_storage_{op}_total Total storage {op} operations"
            )?;
            writeln!(out, "# TYPE p2p_storage_{op}_total counter")?;
            writeln!(out, "p2p_storage_{op}_total {total}")?;

            writeln!(
                out,
                "# HELP p2p_storage_{op}_errors_total Failed storage {op} operations"
            )?;
            writeln!(out, "# TYPE p2p_storage_{op}_errors_total counter")?;
            writeln!(out, "p2p_storage_{op}_errors_total {errors}")?;

            let window = counter.durations.read().await;
            if window.is_empty() {
                writeln!(
                    out,
                    "# HELP p2p_storage_{op}_avg_duration_ms Average {op} duration in ms"
                )?;
                writeln!(out, "# TYPE p2p_storage_{op}_avg_duration_ms gauge")?;
                writeln!(out, "p2p_storage_{op}_avg_duration_ms 0")?;
                writeln!(
                    out,
                    "# HELP p2p_storage_{op}_min_duration_ms Minimum {op} duration in ms"
                )?;
                writeln!(out, "# TYPE p2p_storage_{op}_min_duration_ms gauge")?;
                writeln!(out, "p2p_storage_{op}_min_duration_ms 0")?;
                writeln!(
                    out,
                    "# HELP p2p_storage_{op}_max_duration_ms Maximum {op} duration in ms"
                )?;
                writeln!(out, "# TYPE p2p_storage_{op}_max_duration_ms gauge")?;
                writeln!(out, "p2p_storage_{op}_max_duration_ms 0")?;
            } else {
                let sum: u64 = window.iter().sum();
                let avg_ms = (sum as f64 / window.len() as f64) / 1000.0;
                let min_ms = window.iter().copied().min().unwrap_or(0) as f64 / 1000.0;
                let max_ms = window.iter().copied().max().unwrap_or(0) as f64 / 1000.0;

                writeln!(
                    out,
                    "# HELP p2p_storage_{op}_avg_duration_ms Average {op} duration in ms"
                )?;
                writeln!(out, "# TYPE p2p_storage_{op}_avg_duration_ms gauge")?;
                writeln!(out, "p2p_storage_{op}_avg_duration_ms {avg_ms:.3}")?;
                writeln!(
                    out,
                    "# HELP p2p_storage_{op}_min_duration_ms Minimum {op} duration in ms"
                )?;
                writeln!(out, "# TYPE p2p_storage_{op}_min_duration_ms gauge")?;
                writeln!(out, "p2p_storage_{op}_min_duration_ms {min_ms:.3}")?;
                writeln!(
                    out,
                    "# HELP p2p_storage_{op}_max_duration_ms Maximum {op} duration in ms"
                )?;
                writeln!(out, "# TYPE p2p_storage_{op}_max_duration_ms gauge")?;
                writeln!(out, "p2p_storage_{op}_max_duration_ms {max_ms:.3}")?;
            }
        }
        Ok(())
    }

    // ---- Snapshot-based metrics ----

    fn format_routing_table_metrics(out: &mut String, m: &DhtHealthMetrics) -> std::fmt::Result {
        writeln!(
            out,
            "# HELP p2p_routing_table_size Number of peers in routing table"
        )?;
        writeln!(out, "# TYPE p2p_routing_table_size gauge")?;
        writeln!(out, "p2p_routing_table_size {}", m.routing_table_size)?;

        writeln!(
            out,
            "# HELP p2p_routing_buckets_filled Number of non-empty k-buckets"
        )?;
        writeln!(out, "# TYPE p2p_routing_buckets_filled gauge")?;
        writeln!(out, "p2p_routing_buckets_filled {}", m.buckets_filled)?;

        writeln!(
            out,
            "# HELP p2p_routing_bucket_fullness Average bucket fullness ratio"
        )?;
        writeln!(out, "# TYPE p2p_routing_bucket_fullness gauge")?;
        writeln!(out, "p2p_routing_bucket_fullness {:.6}", m.bucket_fullness)?;

        writeln!(
            out,
            "# HELP p2p_dht_operations_total Total DHT operations from routing layer"
        )?;
        writeln!(out, "# TYPE p2p_dht_operations_total counter")?;
        writeln!(out, "p2p_dht_operations_total {}", m.operations_total)?;

        writeln!(
            out,
            "# HELP p2p_dht_operations_success_total Successful DHT operations"
        )?;
        writeln!(out, "# TYPE p2p_dht_operations_success_total counter")?;
        writeln!(
            out,
            "p2p_dht_operations_success_total {}",
            m.operations_success_total
        )?;

        writeln!(
            out,
            "# HELP p2p_dht_operations_failed_total Failed DHT operations"
        )?;
        writeln!(out, "# TYPE p2p_dht_operations_failed_total counter")?;
        writeln!(
            out,
            "p2p_dht_operations_failed_total {}",
            m.operations_failed_total
        )?;

        writeln!(
            out,
            "# HELP p2p_dht_liveness_checks_total Total liveness checks"
        )?;
        writeln!(out, "# TYPE p2p_dht_liveness_checks_total counter")?;
        writeln!(
            out,
            "p2p_dht_liveness_checks_total {}",
            m.liveness_checks_total
        )?;

        writeln!(
            out,
            "# HELP p2p_dht_liveness_failures_total Failed liveness checks"
        )?;
        writeln!(out, "# TYPE p2p_dht_liveness_failures_total counter")?;
        writeln!(
            out,
            "p2p_dht_liveness_failures_total {}",
            m.liveness_failures_total
        )?;

        Ok(())
    }

    fn format_replication_metrics(out: &mut String, m: &DhtHealthMetrics) -> std::fmt::Result {
        writeln!(
            out,
            "# HELP p2p_replication_factor Current replication factor"
        )?;
        writeln!(out, "# TYPE p2p_replication_factor gauge")?;
        writeln!(out, "p2p_replication_factor {}", m.replication_factor)?;

        writeln!(
            out,
            "# HELP p2p_replication_health Replication health score"
        )?;
        writeln!(out, "# TYPE p2p_replication_health gauge")?;
        writeln!(out, "p2p_replication_health {:.6}", m.replication_health)?;

        writeln!(
            out,
            "# HELP p2p_under_replicated_keys Number of under-replicated keys"
        )?;
        writeln!(out, "# TYPE p2p_under_replicated_keys gauge")?;
        writeln!(out, "p2p_under_replicated_keys {}", m.under_replicated_keys)?;

        Ok(())
    }

    fn format_security_metrics(out: &mut String, m: &SecurityMetrics) -> std::fmt::Result {
        writeln!(
            out,
            "# HELP p2p_security_eclipse_score Eclipse attack risk score"
        )?;
        writeln!(out, "# TYPE p2p_security_eclipse_score gauge")?;
        writeln!(out, "p2p_security_eclipse_score {:.6}", m.eclipse_score)?;

        writeln!(
            out,
            "# HELP p2p_security_sybil_score Sybil attack risk score"
        )?;
        writeln!(out, "# TYPE p2p_security_sybil_score gauge")?;
        writeln!(out, "p2p_security_sybil_score {:.6}", m.sybil_score)?;

        writeln!(
            out,
            "# HELP p2p_security_collusion_score Collusion risk score"
        )?;
        writeln!(out, "# TYPE p2p_security_collusion_score gauge")?;
        writeln!(out, "p2p_security_collusion_score {:.6}", m.collusion_score)?;

        writeln!(
            out,
            "# HELP p2p_security_eclipse_attempts_total Total eclipse attack attempts"
        )?;
        writeln!(out, "# TYPE p2p_security_eclipse_attempts_total counter")?;
        writeln!(
            out,
            "p2p_security_eclipse_attempts_total {}",
            m.eclipse_attempts_total
        )?;

        writeln!(
            out,
            "# HELP p2p_security_sybil_nodes_detected_total Total Sybil nodes detected"
        )?;
        writeln!(
            out,
            "# TYPE p2p_security_sybil_nodes_detected_total counter"
        )?;
        writeln!(
            out,
            "p2p_security_sybil_nodes_detected_total {}",
            m.sybil_nodes_detected_total
        )?;

        writeln!(
            out,
            "# HELP p2p_security_collusion_groups_detected_total Total collusion groups detected"
        )?;
        writeln!(
            out,
            "# TYPE p2p_security_collusion_groups_detected_total counter"
        )?;
        writeln!(
            out,
            "p2p_security_collusion_groups_detected_total {}",
            m.collusion_groups_detected_total
        )?;

        writeln!(
            out,
            "# HELP p2p_security_bft_mode_active BFT consensus mode active"
        )?;
        writeln!(out, "# TYPE p2p_security_bft_mode_active gauge")?;
        writeln!(
            out,
            "p2p_security_bft_mode_active {}",
            u8::from(m.bft_mode_active)
        )?;

        writeln!(
            out,
            "# HELP p2p_security_churn_rate_5m Node churn rate over 5 minutes"
        )?;
        writeln!(out, "# TYPE p2p_security_churn_rate_5m gauge")?;
        writeln!(out, "p2p_security_churn_rate_5m {:.6}", m.churn_rate_5m)?;

        writeln!(
            out,
            "# HELP p2p_security_ip_diversity_rejections_total IP diversity rejections"
        )?;
        writeln!(
            out,
            "# TYPE p2p_security_ip_diversity_rejections_total counter"
        )?;
        writeln!(
            out,
            "p2p_security_ip_diversity_rejections_total {}",
            m.ip_diversity_rejections_total
        )?;

        writeln!(out, "# HELP p2p_security_geographic_diversity_rejections_total Geographic diversity rejections")?;
        writeln!(
            out,
            "# TYPE p2p_security_geographic_diversity_rejections_total counter"
        )?;
        writeln!(
            out,
            "p2p_security_geographic_diversity_rejections_total {}",
            m.geographic_diversity_rejections_total
        )?;

        writeln!(
            out,
            "# HELP p2p_security_nodes_evicted_total Total nodes evicted"
        )?;
        writeln!(out, "# TYPE p2p_security_nodes_evicted_total counter")?;
        writeln!(
            out,
            "p2p_security_nodes_evicted_total {}",
            m.nodes_evicted_total
        )?;

        writeln!(
            out,
            "# HELP p2p_security_witness_validations_total Total witness validations"
        )?;
        writeln!(out, "# TYPE p2p_security_witness_validations_total counter")?;
        writeln!(
            out,
            "p2p_security_witness_validations_total {}",
            m.witness_validations_total
        )?;

        writeln!(
            out,
            "# HELP p2p_security_witness_failures_total Total witness validation failures"
        )?;
        writeln!(out, "# TYPE p2p_security_witness_failures_total counter")?;
        writeln!(
            out,
            "p2p_security_witness_failures_total {}",
            m.witness_failures_total
        )?;

        writeln!(
            out,
            "# HELP p2p_security_close_group_validations_total Total close group validations"
        )?;
        writeln!(
            out,
            "# TYPE p2p_security_close_group_validations_total counter"
        )?;
        writeln!(
            out,
            "p2p_security_close_group_validations_total {}",
            m.close_group_validations_total
        )?;

        writeln!(out, "# HELP p2p_security_close_group_consensus_failures_total Close group consensus failures")?;
        writeln!(
            out,
            "# TYPE p2p_security_close_group_consensus_failures_total counter"
        )?;
        writeln!(
            out,
            "p2p_security_close_group_consensus_failures_total {}",
            m.close_group_consensus_failures_total
        )?;

        writeln!(
            out,
            "# HELP p2p_security_low_trust_nodes_current Current low trust nodes"
        )?;
        writeln!(out, "# TYPE p2p_security_low_trust_nodes_current gauge")?;
        writeln!(
            out,
            "p2p_security_low_trust_nodes_current {}",
            m.low_trust_nodes_current
        )?;

        Ok(())
    }

    fn format_trust_metrics(
        out: &mut String,
        m: &TrustMetrics,
        trust_scores: &Option<HashMap<PeerId, f64>>,
    ) -> std::fmt::Result {
        writeln!(
            out,
            "# HELP p2p_trust_eigentrust_avg Average EigenTrust score"
        )?;
        writeln!(out, "# TYPE p2p_trust_eigentrust_avg gauge")?;
        writeln!(out, "p2p_trust_eigentrust_avg {:.6}", m.eigentrust_avg)?;

        writeln!(
            out,
            "# HELP p2p_trust_eigentrust_min Minimum EigenTrust score"
        )?;
        writeln!(out, "# TYPE p2p_trust_eigentrust_min gauge")?;
        writeln!(out, "p2p_trust_eigentrust_min {:.6}", m.eigentrust_min)?;

        writeln!(
            out,
            "# HELP p2p_trust_eigentrust_max Maximum EigenTrust score"
        )?;
        writeln!(out, "# TYPE p2p_trust_eigentrust_max gauge")?;
        writeln!(out, "p2p_trust_eigentrust_max {:.6}", m.eigentrust_max)?;

        writeln!(
            out,
            "# HELP p2p_trust_eigentrust_epochs_total Total EigenTrust epochs"
        )?;
        writeln!(out, "# TYPE p2p_trust_eigentrust_epochs_total counter")?;
        writeln!(
            out,
            "p2p_trust_eigentrust_epochs_total {}",
            m.eigentrust_epochs_total
        )?;

        writeln!(
            out,
            "# HELP p2p_trust_low_trust_nodes Nodes below trust threshold"
        )?;
        writeln!(out, "# TYPE p2p_trust_low_trust_nodes gauge")?;
        writeln!(out, "p2p_trust_low_trust_nodes {}", m.low_trust_nodes)?;

        writeln!(
            out,
            "# HELP p2p_trust_interactions_total Total peer interactions"
        )?;
        writeln!(out, "# TYPE p2p_trust_interactions_total counter")?;
        writeln!(
            out,
            "p2p_trust_interactions_total {}",
            m.interactions_recorded_total
        )?;

        writeln!(
            out,
            "# HELP p2p_trust_positive_interactions_total Total positive interactions"
        )?;
        writeln!(out, "# TYPE p2p_trust_positive_interactions_total counter")?;
        writeln!(
            out,
            "p2p_trust_positive_interactions_total {}",
            m.positive_interactions_total
        )?;

        writeln!(
            out,
            "# HELP p2p_trust_negative_interactions_total Total negative interactions"
        )?;
        writeln!(out, "# TYPE p2p_trust_negative_interactions_total counter")?;
        writeln!(
            out,
            "p2p_trust_negative_interactions_total {}",
            m.negative_interactions_total
        )?;

        writeln!(
            out,
            "# HELP p2p_trust_witness_receipts_issued_total Witness receipts issued"
        )?;
        writeln!(
            out,
            "# TYPE p2p_trust_witness_receipts_issued_total counter"
        )?;
        writeln!(
            out,
            "p2p_trust_witness_receipts_issued_total {}",
            m.witness_receipts_issued_total
        )?;

        writeln!(
            out,
            "# HELP p2p_trust_witness_receipts_verified_total Witness receipts verified"
        )?;
        writeln!(
            out,
            "# TYPE p2p_trust_witness_receipts_verified_total counter"
        )?;
        writeln!(
            out,
            "p2p_trust_witness_receipts_verified_total {}",
            m.witness_receipts_verified_total
        )?;

        writeln!(
            out,
            "# HELP p2p_trust_witness_receipts_rejected_total Witness receipts rejected"
        )?;
        writeln!(
            out,
            "# TYPE p2p_trust_witness_receipts_rejected_total counter"
        )?;
        writeln!(
            out,
            "p2p_trust_witness_receipts_rejected_total {}",
            m.witness_receipts_rejected_total
        )?;

        // Trust score distribution from cached global trust
        if let Some(scores) = trust_scores {
            if !scores.is_empty() {
                let mut buckets = [0u64; 10];
                for score in scores.values() {
                    let idx = (score * 10.0).floor().min(9.0).max(0.0) as usize;
                    buckets[idx] += 1;
                }
                writeln!(
                    out,
                    "# HELP p2p_trust_score_distribution Trust score distribution"
                )?;
                writeln!(out, "# TYPE p2p_trust_score_distribution gauge")?;
                for (i, count) in buckets.iter().enumerate() {
                    let lo = i as f64 / 10.0;
                    let hi = (i + 1) as f64 / 10.0;
                    writeln!(
                        out,
                        "p2p_trust_score_distribution{{bucket=\"{lo:.1}-{hi:.1}\"}} {count}"
                    )?;
                }
            }
        }

        // Trust distribution from TrustMetrics (bucket-based from collector)
        if !m.trust_distribution.is_empty() {
            // Already emitted distribution above from cached scores if available;
            // only emit the collector's distribution if we didn't have live scores.
            if trust_scores.is_none() {
                writeln!(
                    out,
                    "# HELP p2p_trust_score_distribution Trust score distribution"
                )?;
                writeln!(out, "# TYPE p2p_trust_score_distribution gauge")?;
                for (bucket, count) in &m.trust_distribution {
                    writeln!(
                        out,
                        "p2p_trust_score_distribution{{bucket=\"{bucket}\"}} {count}"
                    )?;
                }
            }
        }

        Ok(())
    }

    fn format_placement_metrics(out: &mut String, m: &PlacementMetrics) -> std::fmt::Result {
        writeln!(
            out,
            "# HELP p2p_placement_total_stored_bytes Total bytes stored"
        )?;
        writeln!(out, "# TYPE p2p_placement_total_stored_bytes gauge")?;
        writeln!(
            out,
            "p2p_placement_total_stored_bytes {}",
            m.total_stored_bytes
        )?;

        writeln!(
            out,
            "# HELP p2p_placement_total_records Total records stored"
        )?;
        writeln!(out, "# TYPE p2p_placement_total_records gauge")?;
        writeln!(out, "p2p_placement_total_records {}", m.total_records)?;

        writeln!(
            out,
            "# HELP p2p_placement_storage_nodes Number of storage nodes"
        )?;
        writeln!(out, "# TYPE p2p_placement_storage_nodes gauge")?;
        writeln!(out, "p2p_placement_storage_nodes {}", m.storage_nodes)?;

        writeln!(
            out,
            "# HELP p2p_placement_geographic_diversity Geographic diversity score"
        )?;
        writeln!(out, "# TYPE p2p_placement_geographic_diversity gauge")?;
        writeln!(
            out,
            "p2p_placement_geographic_diversity {:.6}",
            m.geographic_diversity
        )?;

        writeln!(
            out,
            "# HELP p2p_placement_regions_covered Number of regions covered"
        )?;
        writeln!(out, "# TYPE p2p_placement_regions_covered gauge")?;
        writeln!(out, "p2p_placement_regions_covered {}", m.regions_covered)?;

        writeln!(
            out,
            "# HELP p2p_placement_total_capacity_bytes Total storage capacity"
        )?;
        writeln!(out, "# TYPE p2p_placement_total_capacity_bytes gauge")?;
        writeln!(
            out,
            "p2p_placement_total_capacity_bytes {}",
            m.total_capacity_bytes
        )?;

        writeln!(
            out,
            "# HELP p2p_placement_used_capacity_ratio Used capacity ratio"
        )?;
        writeln!(out, "# TYPE p2p_placement_used_capacity_ratio gauge")?;
        writeln!(
            out,
            "p2p_placement_used_capacity_ratio {:.6}",
            m.used_capacity_ratio
        )?;

        writeln!(
            out,
            "# HELP p2p_placement_load_balance_score Load balance score"
        )?;
        writeln!(out, "# TYPE p2p_placement_load_balance_score gauge")?;
        writeln!(
            out,
            "p2p_placement_load_balance_score {:.6}",
            m.load_balance_score
        )?;

        writeln!(
            out,
            "# HELP p2p_placement_overloaded_nodes Number of overloaded nodes"
        )?;
        writeln!(out, "# TYPE p2p_placement_overloaded_nodes gauge")?;
        writeln!(out, "p2p_placement_overloaded_nodes {}", m.overloaded_nodes)?;

        writeln!(
            out,
            "# HELP p2p_placement_rebalance_operations_total Total rebalance operations"
        )?;
        writeln!(
            out,
            "# TYPE p2p_placement_rebalance_operations_total counter"
        )?;
        writeln!(
            out,
            "p2p_placement_rebalance_operations_total {}",
            m.rebalance_operations_total
        )?;

        writeln!(
            out,
            "# HELP p2p_placement_audits_total Total storage audits"
        )?;
        writeln!(out, "# TYPE p2p_placement_audits_total counter")?;
        writeln!(out, "p2p_placement_audits_total {}", m.audits_total)?;

        writeln!(
            out,
            "# HELP p2p_placement_audit_failures_total Total audit failures"
        )?;
        writeln!(out, "# TYPE p2p_placement_audit_failures_total counter")?;
        writeln!(
            out,
            "p2p_placement_audit_failures_total {}",
            m.audit_failures_total
        )?;

        Ok(())
    }

    fn format_transport_metrics(out: &mut String, m: &TransportStats) -> std::fmt::Result {
        writeln!(
            out,
            "# HELP p2p_transport_active_connections Active transport connections"
        )?;
        writeln!(out, "# TYPE p2p_transport_active_connections gauge")?;
        writeln!(
            out,
            "p2p_transport_active_connections {}",
            m.active_connections
        )?;

        writeln!(
            out,
            "# HELP p2p_transport_ipv4_connections IPv4 connections"
        )?;
        writeln!(out, "# TYPE p2p_transport_ipv4_connections gauge")?;
        writeln!(out, "p2p_transport_ipv4_connections {}", m.ipv4_connections)?;

        writeln!(
            out,
            "# HELP p2p_transport_ipv6_connections IPv6 connections"
        )?;
        writeln!(out, "# TYPE p2p_transport_ipv6_connections gauge")?;
        writeln!(out, "p2p_transport_ipv6_connections {}", m.ipv6_connections)?;

        Ok(())
    }

    fn format_strategy_metrics(out: &mut String, stats: &[StrategyStats]) -> std::fmt::Result {
        if stats.is_empty() {
            return Ok(());
        }

        writeln!(
            out,
            "# HELP p2p_strategy_selections_total Strategy selection count"
        )?;
        writeln!(out, "# TYPE p2p_strategy_selections_total counter")?;
        for s in stats {
            writeln!(
                out,
                "p2p_strategy_selections_total{{strategy=\"{}\"}} {}",
                s.name, s.selections
            )?;
        }

        writeln!(
            out,
            "# HELP p2p_strategy_successes_total Strategy success count"
        )?;
        writeln!(out, "# TYPE p2p_strategy_successes_total counter")?;
        for s in stats {
            writeln!(
                out,
                "p2p_strategy_successes_total{{strategy=\"{}\"}} {}",
                s.name, s.successes
            )?;
        }

        writeln!(
            out,
            "# HELP p2p_strategy_estimated_success_rate Estimated success rate"
        )?;
        writeln!(out, "# TYPE p2p_strategy_estimated_success_rate gauge")?;
        for s in stats {
            writeln!(
                out,
                "p2p_strategy_estimated_success_rate{{strategy=\"{}\"}} {:.6}",
                s.name, s.estimated_success_rate
            )?;
        }

        writeln!(
            out,
            "# HELP p2p_strategy_alpha Thompson sampling alpha parameter"
        )?;
        writeln!(out, "# TYPE p2p_strategy_alpha gauge")?;
        for s in stats {
            writeln!(
                out,
                "p2p_strategy_alpha{{strategy=\"{}\"}} {:.6}",
                s.name, s.alpha
            )?;
        }

        writeln!(
            out,
            "# HELP p2p_strategy_beta Thompson sampling beta parameter"
        )?;
        writeln!(out, "# TYPE p2p_strategy_beta gauge")?;
        for s in stats {
            writeln!(
                out,
                "p2p_strategy_beta{{strategy=\"{}\"}} {:.6}",
                s.name, s.beta
            )?;
        }

        Ok(())
    }
}

/// Map [`StreamClass`] to a Prometheus label value.
fn stream_class_label(class: &StreamClass) -> &'static str {
    match class {
        StreamClass::Control => "control",
        StreamClass::Mls => "mls",
        StreamClass::File => "file",
        StreamClass::Media => "media",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::metrics::aggregator::MetricsAggregator;
    use saorsa_core::dht::metrics::{
        DhtHealthMetrics, PlacementMetrics, SecurityMetrics, TrustMetrics,
    };
    use saorsa_core::{MetricEvent, TransportStats};
    use std::time::Duration;

    fn default_snapshot() -> MetricsSnapshot {
        MetricsSnapshot {
            dht_health: DhtHealthMetrics::default(),
            security: SecurityMetrics::default(),
            trust: TrustMetrics::default(),
            placement: PlacementMetrics::default(),
            transport: TransportStats::default(),
            strategy_stats: vec![],
            trust_scores: None,
        }
    }

    #[tokio::test]
    async fn format_contains_expected_metrics() {
        let agg = MetricsAggregator::new();
        agg.handle_metric_event(MetricEvent::LookupCompleted {
            duration: Duration::from_millis(42),
            hops: 3,
        })
        .await;
        agg.record_peer_connected();

        let snapshot = default_snapshot();
        let output = PrometheusFormatter::format(&agg, &snapshot).await.unwrap();

        assert!(output.contains("p2p_connected_peers 1"));
        assert!(output.contains("p2p_lookup_total 1"));
        assert!(output.contains("p2p_lookup_latency_p50_ms"));
        assert!(output.contains("p2p_routing_table_size"));
        assert!(output.contains("p2p_security_eclipse_score"));
        assert!(output.contains("p2p_trust_eigentrust_avg"));
        assert!(output.contains("p2p_placement_total_records"));
        assert!(output.contains("p2p_transport_active_connections"));
    }

    #[tokio::test]
    async fn format_no_orphaned_headers() {
        let agg = MetricsAggregator::new();
        let snapshot = default_snapshot();
        let output = PrometheusFormatter::format(&agg, &snapshot).await.unwrap();

        // Every HELP line should have a corresponding TYPE line
        for line in output.lines() {
            if line.starts_with("# HELP ") {
                let metric_name = line
                    .strip_prefix("# HELP ")
                    .and_then(|s| s.split_whitespace().next())
                    .unwrap();
                let type_line = format!("# TYPE {metric_name}");
                assert!(
                    output.contains(&type_line),
                    "HELP without TYPE for {metric_name}"
                );
            }
        }
    }

    #[tokio::test]
    async fn strategy_metrics_grouped() {
        let agg = MetricsAggregator::new();
        let mut snapshot = default_snapshot();
        snapshot.strategy_stats = vec![
            StrategyStats {
                name: "kademlia".to_string(),
                selections: 100,
                successes: 90,
                alpha: 91.0,
                beta: 11.0,
                estimated_success_rate: 0.9,
            },
            StrategyStats {
                name: "hyperbolic".to_string(),
                selections: 50,
                successes: 45,
                alpha: 46.0,
                beta: 6.0,
                estimated_success_rate: 0.9,
            },
        ];

        let output = PrometheusFormatter::format(&agg, &snapshot).await.unwrap();

        // Verify contiguous grouping: all selections_total lines together
        assert!(output.contains("p2p_strategy_selections_total{strategy=\"kademlia\"} 100"));
        assert!(output.contains("p2p_strategy_selections_total{strategy=\"hyperbolic\"} 50"));
    }

    #[tokio::test]
    async fn empty_strategy_no_output() {
        let agg = MetricsAggregator::new();
        let snapshot = default_snapshot();
        let output = PrometheusFormatter::format(&agg, &snapshot).await.unwrap();
        assert!(!output.contains("p2p_strategy_"));
    }

    #[tokio::test]
    async fn stream_metrics_with_data() {
        let agg = MetricsAggregator::new();
        agg.handle_metric_event(MetricEvent::StreamBandwidth {
            class: StreamClass::File,
            bytes_per_sec: 1_000_000,
        })
        .await;

        let snapshot = default_snapshot();
        let output = PrometheusFormatter::format(&agg, &snapshot).await.unwrap();
        assert!(output.contains("p2p_stream_bandwidth_p50_bytes_per_sec{class=\"file\"}"));
    }
}
