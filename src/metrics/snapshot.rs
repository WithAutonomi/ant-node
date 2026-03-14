//! Pull-based snapshot collector.
//!
//! On each `/metrics` scrape, [`SnapshotCollector::collect`] reads state
//! snapshots from saorsa-core's accessor methods. This gives a consistent
//! point-in-time view without requiring continuous event processing.

use saorsa_core::dht::metrics::{
    DhtHealthMetrics, DhtMetricsCollector, PlacementMetrics, PlacementMetricsCollector,
    SecurityMetrics, SecurityMetricsCollector, TrustMetrics, TrustMetricsCollector,
};
use saorsa_core::identity::PeerId;
use saorsa_core::{EigenTrustEngine, P2PNode, StrategyStats, TransportStats};
use std::collections::HashMap;
use std::sync::Arc;

/// Point-in-time snapshot of all pull-based metrics from saorsa-core.
pub struct MetricsSnapshot {
    /// DHT routing table, replication, and operation metrics.
    pub dht_health: DhtHealthMetrics,
    /// Security attack scores and event counters.
    pub security: SecurityMetrics,
    /// `EigenTrust` scores, witness validation, and interaction tracking.
    pub trust: TrustMetrics,
    /// Storage distribution, capacity, and audit metrics.
    pub placement: PlacementMetrics,
    /// Transport layer connection stats.
    pub transport: TransportStats,
    /// Per-strategy selection and success stats (from multi-armed bandit).
    pub strategy_stats: Vec<StrategyStats>,
    /// Cached global trust scores keyed by peer ID.
    pub trust_scores: Option<HashMap<PeerId, f64>>,
}

/// Holds `Arc` references to saorsa-core components and pulls snapshots on demand.
pub struct SnapshotCollector {
    dht_health: Arc<DhtMetricsCollector>,
    security: Arc<SecurityMetricsCollector>,
    trust: Arc<TrustMetricsCollector>,
    placement: Arc<PlacementMetricsCollector>,
    p2p_node: Arc<P2PNode>,
    eigentrust: Option<Arc<EigenTrustEngine>>,
}

impl SnapshotCollector {
    /// Create a new collector.
    ///
    /// The individual metrics collectors should be the *same* instances used
    /// by saorsa-core internally so that the snapshots reflect live data.
    /// When that isn't possible (e.g. the collector isn't exposed), fresh
    /// instances are acceptable — they'll report defaults until populated.
    #[must_use]
    pub fn new(
        dht_health: Arc<DhtMetricsCollector>,
        security: Arc<SecurityMetricsCollector>,
        trust: Arc<TrustMetricsCollector>,
        placement: Arc<PlacementMetricsCollector>,
        p2p_node: Arc<P2PNode>,
        eigentrust: Option<Arc<EigenTrustEngine>>,
    ) -> Self {
        Self {
            dht_health,
            security,
            trust,
            placement,
            p2p_node,
            eigentrust,
        }
    }

    /// Pull a complete snapshot from all saorsa-core accessors.
    ///
    /// Called once per `/metrics` scrape.
    pub async fn collect(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            dht_health: self.dht_health.get_metrics().await,
            security: self.security.get_metrics().await,
            trust: self.trust.get_metrics().await,
            placement: self.placement.get_metrics().await,
            transport: self.p2p_node.transport_stats().await,
            // MultiArmedBandit is not currently exposed from P2PNode,
            // so strategy stats are empty until an accessor is added.
            strategy_stats: vec![],
            trust_scores: match &self.eigentrust {
                Some(engine) => engine.cached_global_trust().await,
                None => None,
            },
        }
    }
}
