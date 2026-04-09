# Integrating Trust Signals in saorsa-node

This guide shows how saorsa-node (and other consumers) should integrate with
saorsa-core's EigenTrust reputation system to report data availability outcomes.

## Prerequisites

Add saorsa-core dependency in your `Cargo.toml` with the `adaptive-ml` feature enabled:

```toml
[dependencies]
saorsa-core = { version = "0.11.0", features = ["adaptive-ml"] }
```

Note: The `adaptive-ml` feature is required for trust API methods (`report_peer_success`,
`report_peer_failure`, `peer_trust`, `trust_engine`).

## Basic Integration

### Step 1: Initialize P2PNode

The trust engine is automatically initialized when you create a P2PNode:

```rust
use saorsa_core::{P2PNode, NodeConfig};

pub struct SaorsaNode {
    p2p: P2PNode,
    // ... other fields
}

impl SaorsaNode {
    pub async fn new(config: SaorsaNodeConfig) -> Result<Self, Error> {
        // P2PNode automatically initializes EigenTrust with bootstrap peers as pre-trusted
        let node_config = NodeConfig::builder()
            .port(config.port)
            .bootstrap_peer(config.bootstrap_addr)
            .build()?;

        let p2p = P2PNode::new(node_config).await?;

        Ok(Self { p2p })
    }
}
```

### Step 2: Report Outcomes for Data Operations

#### Chunk Retrieval

```rust
impl SaorsaNode {
    pub async fn get_chunk(&self, address: &ChunkAddress) -> Result<Chunk, Error> {
        // Find providers via DHT
        let providers = self.find_chunk_providers(address).await?;

        // Sort by trust score (highest first)
        let mut scored_providers: Vec<_> = providers
            .iter()
            .map(|p| (p.clone(), self.p2p.peer_trust(p)))
            .collect();
        scored_providers.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Try providers in trust order
        for (provider, trust_score) in scored_providers {
            // Skip very low trust peers
            if trust_score < 0.1 {
                tracing::debug!("Skipping low-trust provider {provider} (trust={trust_score:.2})");
                continue;
            }

            match self.fetch_chunk_from(&provider, address).await {
                Ok(chunk) => {
                    // Verify chunk hash matches address
                    if chunk.verify(address) {
                        // SUCCESS: Report to trust system
                        self.p2p.report_peer_success(&provider).await.ok();
                        return Ok(chunk);
                    } else {
                        // FAILURE: Corrupted data - severe trust penalty
                        tracing::warn!(
                            "Peer {provider} returned corrupted chunk for {address}"
                        );
                        self.p2p.report_peer_failure(&provider).await.ok();
                    }
                }
                Err(e) => {
                    // FAILURE: Request failed
                    tracing::warn!("Fetch from {provider} failed: {e}");
                    self.p2p.report_peer_failure(&provider).await.ok();
                }
            }
        }

        Err(Error::ChunkNotFound)
    }
}
```

#### Chunk Storage

```rust
impl SaorsaNode {
    pub async fn store_chunk(&self, chunk: &Chunk) -> Result<Vec<String>, Error> {
        // Select storage nodes (placement system can use trust scores)
        let targets = self.select_storage_nodes(chunk.address()).await?;

        let mut successful = Vec::new();

        for target in targets {
            match self.send_store_request(&target, chunk).await {
                Ok(()) => {
                    // SUCCESS: Report to trust system
                    self.p2p.report_peer_success(&target).await.ok();
                    successful.push(target);
                }
                Err(e) => {
                    // FAILURE: Store failed
                    tracing::warn!("Store to {target} failed: {e}");
                    self.p2p.report_peer_failure(&target).await.ok();
                }
            }
        }

        if successful.len() >= self.config.min_replicas {
            Ok(successful)
        } else {
            Err(Error::InsufficientReplicas)
        }
    }
}
```

## Advanced Integration

### Periodic Storage Auditing

Regular audits help maintain accurate trust scores and trigger re-replication:

```rust
impl SaorsaNode {
    pub fn start_audit_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;
                if let Err(e) = self.audit_stored_chunks().await {
                    tracing::error!("Audit failed: {e}");
                }
            }
        });
    }

    async fn audit_stored_chunks(&self) -> Result<(), Error> {
        let chunks_to_audit = self.select_chunks_for_audit().await;

        for (chunk_addr, expected_holders) in chunks_to_audit {
            for holder in expected_holders {
                match self.probe_chunk(&holder, &chunk_addr).await {
                    Ok(true) => {
                        // Still has the data - report success
                        self.p2p.report_peer_success(&holder).await.ok();
                    }
                    Ok(false) => {
                        // Lost the data - report failure and schedule re-replication
                        tracing::warn!("Node {holder} lost chunk {chunk_addr}");
                        self.p2p.report_peer_failure(&holder).await.ok();
                        self.schedule_replication(&chunk_addr).await;
                    }
                    Err(_) => {
                        // Unreachable - report failure
                        self.p2p.report_peer_failure(&holder).await.ok();
                    }
                }
            }
        }

        Ok(())
    }
}
```

### Direct EigenTrust Engine Access

For advanced use cases, access the engine directly:

```rust
use saorsa_core::{EigenTrustEngine, NodeStatisticsUpdate};

impl SaorsaNode {
    /// Report bandwidth contribution after large transfers
    pub async fn report_bandwidth(&self, peer_id: &str, bytes: u64) {
        if let Some(engine) = self.p2p.trust_engine() {
            let node_id = self.peer_id_to_node_id(peer_id);
            engine
                .update_node_stats(&node_id, NodeStatisticsUpdate::BandwidthContributed(bytes))
                .await;
        }
    }

    /// Report storage contribution
    pub async fn report_storage(&self, peer_id: &str, bytes: u64) {
        if let Some(engine) = self.p2p.trust_engine() {
            let node_id = self.peer_id_to_node_id(peer_id);
            engine
                .update_node_stats(&node_id, NodeStatisticsUpdate::StorageContributed(bytes))
                .await;
        }
    }

    /// Get global network trust metrics
    pub async fn trust_metrics(&self) -> TrustMetrics {
        let Some(engine) = self.p2p.trust_engine() else {
            return TrustMetrics::default();
        };

        let all_trust = engine.compute_global_trust().await;
        let scores: Vec<f64> = all_trust.values().copied().collect();

        TrustMetrics {
            total_nodes: scores.len(),
            avg_trust: scores.iter().sum::<f64>() / scores.len().max(1) as f64,
            low_trust_nodes: scores.iter().filter(|&&t| t < 0.3).count(),
            high_trust_nodes: scores.iter().filter(|&&t| t > 0.7).count(),
        }
    }

    // Helper to convert peer ID string to NodeId
    fn peer_id_to_node_id(&self, peer_id: &str) -> saorsa_core::adaptive::NodeId {
        let hash = blake3::hash(peer_id.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        saorsa_core::adaptive::NodeId::from_bytes(bytes)
    }
}

#[derive(Debug, Default)]
pub struct TrustMetrics {
    pub total_nodes: usize,
    pub avg_trust: f64,
    pub low_trust_nodes: usize,
    pub high_trust_nodes: usize,
}
```

### Trust-Weighted Provider Selection

Use trust scores to improve provider selection:

```rust
impl SaorsaNode {
    /// Select storage nodes with trust-weighted probability
    pub async fn select_storage_nodes(&self, address: &ChunkAddress) -> Result<Vec<String>, Error> {
        let candidates = self.find_candidate_nodes(address).await?;
        let required = self.config.replication_factor;

        // Filter out very low trust nodes
        let viable: Vec<_> = candidates
            .into_iter()
            .filter(|p| self.p2p.peer_trust(p) > 0.15)
            .collect();

        if viable.len() < required {
            return Err(Error::InsufficientNodes);
        }

        // Weight selection by trust score
        let mut weighted: Vec<_> = viable
            .iter()
            .map(|p| {
                let trust = self.p2p.peer_trust(p);
                // Add some randomness to avoid always picking the same nodes
                let weight = trust * (0.8 + rand::random::<f64>() * 0.4);
                (p.clone(), weight)
            })
            .collect();

        weighted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        Ok(weighted.into_iter().take(required).map(|(p, _)| p).collect())
    }
}
```

## Complete Example: Message Handler

Here's a complete message handler that integrates trust reporting:

```rust
use saorsa_core::{P2PNode, P2PEvent};

impl SaorsaNode {
    pub async fn run_message_loop(&self) -> Result<(), Error> {
        let mut events = self.p2p.subscribe_events();

        loop {
            match events.recv().await {
                Ok(P2PEvent::Message { source, topic, data }) => {
                    match self.handle_message(&source, &topic, &data).await {
                        Ok(()) => {
                            // Message handled successfully
                            self.p2p.report_peer_success(&source).await.ok();
                        }
                        Err(e) => {
                            tracing::warn!("Message from {source} failed: {e}");
                            // Only report failure for protocol violations, not application errors
                            if e.is_protocol_error() {
                                self.p2p.report_peer_failure(&source).await.ok();
                            }
                        }
                    }
                }
                Ok(P2PEvent::PeerConnected(peer_id)) => {
                    tracing::info!("Peer connected: {peer_id}");
                }
                Ok(P2PEvent::PeerDisconnected(peer_id)) => {
                    tracing::info!("Peer disconnected: {peer_id}");
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("Dropped {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_message(
        &self,
        source: &str,
        topic: &str,
        data: &[u8],
    ) -> Result<(), Error> {
        match topic {
            "chunk/get" => self.handle_chunk_get(source, data).await,
            "chunk/store" => self.handle_chunk_store(source, data).await,
            "chunk/probe" => self.handle_chunk_probe(source, data).await,
            _ => Err(Error::UnknownTopic(topic.to_string())),
        }
    }
}
```

## Testing Trust Integration

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_trust_updates() {
        let node = create_test_node().await;
        let peer_id = "test_peer_123";

        // Initial trust should be low/neutral
        let initial_trust = node.p2p.peer_trust(peer_id);
        assert!(initial_trust <= 0.5);

        // Report multiple successes
        for _ in 0..10 {
            node.p2p.report_peer_success(peer_id).await.unwrap();
        }

        // Force trust recomputation (normally happens in background)
        if let Some(engine) = node.p2p.trust_engine() {
            engine.compute_global_trust().await;
        }

        // Trust should have increased
        let final_trust = node.p2p.peer_trust(peer_id);
        assert!(final_trust > initial_trust);
    }

    #[tokio::test]
    async fn test_trust_decreases_on_failure() {
        let node = create_test_node().await;
        let peer_id = "bad_peer_456";

        // Build up some trust first
        for _ in 0..5 {
            node.p2p.report_peer_success(peer_id).await.unwrap();
        }

        if let Some(engine) = node.p2p.trust_engine() {
            engine.compute_global_trust().await;
        }
        let trust_before = node.p2p.peer_trust(peer_id);

        // Report failures
        for _ in 0..10 {
            node.p2p.report_peer_failure(peer_id).await.unwrap();
        }

        if let Some(engine) = node.p2p.trust_engine() {
            engine.compute_global_trust().await;
        }
        let trust_after = node.p2p.peer_trust(peer_id);

        assert!(trust_after < trust_before);
    }
}
```

## Best Practices

1. **Always report outcomes**: Every data operation should report success or failure
2. **Report promptly**: Update trust immediately after operations complete
3. **Handle errors gracefully**: Trust updates are best-effort, don't let them block operations
4. **Use trust for routing**: Sort providers by trust when fetching data
5. **Set minimum thresholds**: Skip peers with very low trust (< 0.1)
6. **Implement auditing**: Periodic verification helps maintain accurate scores
7. **Monitor metrics**: Track trust distribution to detect network issues

## Troubleshooting

### Trust not updating

- Ensure you're calling `report_peer_success`/`report_peer_failure`
- Background computation runs every 5 minutes
- Check if `trust_engine()` returns `Some`

### All peers have same trust

- Normal for new networks with few interactions
- Trust differentiates as more operations occur
- Pre-trusted (bootstrap) nodes start with 0.9

### Trust scores too low

- Verify you're reporting successes, not just failures
- Check for network issues causing false failures
- Review minimum trust thresholds

## Related Documentation

- [Trust Signals API Reference](../trust-signals-api.md) - Complete API documentation
- [ADR-006: EigenTrust Reputation](../adr/ADR-006-eigentrust-reputation.md) - Architecture decision
