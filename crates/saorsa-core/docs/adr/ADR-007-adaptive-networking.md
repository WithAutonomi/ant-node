# ADR-007: Adaptive Networking with Machine Learning

## Status

Accepted

## Context

P2P networks operate in highly dynamic environments:

- **Churn**: Nodes join and leave continuously
- **Heterogeneity**: Nodes have varying capabilities (bandwidth, storage, uptime)
- **Topology changes**: Network structure evolves over time
- **Load variations**: Traffic patterns change hourly, daily, weekly
- **Adversarial conditions**: Attacks require adaptive responses

Static routing and placement strategies cannot optimize for all these conditions. We needed a system that:

1. Learns from network behavior
2. Adapts strategies in real-time
3. Balances exploration vs. exploitation
4. Predicts failures before they occur
5. Optimizes multiple objectives simultaneously

## Decision

We implement an **adaptive networking layer** using machine learning techniques for dynamic optimization:

### Core ML Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Adaptive Networking Layer                     │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                Multi-Armed Bandit (MAB)                   │   │
│  │  • Thompson Sampling for strategy selection               │   │
│  │  • Balances exploration/exploitation                      │   │
│  │  • Adapts to changing reward distributions                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────┬─────────────────────────┬─────────────────┐    │
│  │   Kademlia  │   Hyperbolic Routing   │  Trust-Based    │    │
│  │   Strategy  │      Strategy          │   Strategy      │    │
│  └─────────────┴─────────────────────────┴─────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                Q-Learning Cache Optimization              │   │
│  │  • State: cache fullness, hit rate, peer popularity      │   │
│  │  • Actions: evict, retain, prefetch                      │   │
│  │  • Reward: hit rate improvement, latency reduction       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                Churn Prediction                           │   │
│  │  • Features: uptime history, activity patterns, session  │   │
│  │  • Model: Gradient boosted trees / logistic regression   │   │
│  │  • Output: probability of departure in next T minutes    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Thompson Sampling for Strategy Selection

```rust
// src/adaptive/multi_armed_bandit.rs

/// Multi-Armed Bandit with Thompson Sampling
pub struct ThompsonSampling {
    /// Beta distribution parameters for each strategy
    /// (alpha = successes + 1, beta = failures + 1)
    strategies: HashMap<RoutingStrategy, BetaParams>,
}

#[derive(Clone)]
pub struct BetaParams {
    alpha: f64,  // Prior successes + observed successes
    beta: f64,   // Prior failures + observed failures
}

impl ThompsonSampling {
    /// Select a strategy by sampling from posterior distributions
    pub fn select_strategy(&self, rng: &mut impl Rng) -> RoutingStrategy {
        let mut best_strategy = RoutingStrategy::Kademlia;
        let mut best_sample = 0.0;

        for (strategy, params) in &self.strategies {
            // Sample from Beta(alpha, beta) distribution
            let beta_dist = Beta::new(params.alpha, params.beta).unwrap();
            let sample = beta_dist.sample(rng);

            if sample > best_sample {
                best_sample = sample;
                best_strategy = *strategy;
            }
        }

        best_strategy
    }

    /// Update strategy performance after observation
    pub fn update(&mut self, strategy: RoutingStrategy, success: bool) {
        let params = self.strategies.entry(strategy).or_insert(BetaParams {
            alpha: 1.0,
            beta: 1.0,
        });

        if success {
            params.alpha += 1.0;
        } else {
            params.beta += 1.0;
        }
    }
}
```

### Available Routing Strategies

```rust
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum RoutingStrategy {
    /// Standard Kademlia XOR-distance routing
    Kademlia,

    /// Hyperbolic geometry-based routing for hierarchical networks
    Hyperbolic,

    /// Route through high-trust peers only
    TrustBased,

    /// Route through geographically close peers
    Geographic,

    /// Hybrid combining multiple strategies
    Hybrid,
}
```

### Q-Learning for Cache Optimization

```rust
// src/adaptive/q_learning_cache.rs

pub struct QLearningCache {
    /// Q-values: Q(state, action) → expected reward
    q_table: HashMap<(CacheState, CacheAction), f64>,

    /// Learning rate
    alpha: f64,  // Default: 0.1

    /// Discount factor
    gamma: f64,  // Default: 0.95

    /// Exploration rate
    epsilon: f64,  // Default: 0.1, decays over time
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub struct CacheState {
    /// Cache fullness bucket (0-10)
    fullness: u8,

    /// Recent hit rate bucket (0-10)
    hit_rate: u8,

    /// Request frequency bucket (0-10)
    request_freq: u8,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub enum CacheAction {
    /// Keep item in cache
    Retain,

    /// Evict item from cache
    Evict,

    /// Prefetch related items
    Prefetch,

    /// Promote item priority
    Promote,
}

impl QLearningCache {
    /// Select action using ε-greedy policy
    pub fn select_action(&self, state: &CacheState, rng: &mut impl Rng) -> CacheAction {
        if rng.gen::<f64>() < self.epsilon {
            // Explore: random action
            self.random_action(rng)
        } else {
            // Exploit: best known action
            self.best_action(state)
        }
    }

    /// Update Q-value after observing reward
    pub fn update(
        &mut self,
        state: CacheState,
        action: CacheAction,
        reward: f64,
        next_state: CacheState,
    ) {
        let current_q = self.q_table.get(&(state.clone(), action)).copied().unwrap_or(0.0);
        let max_next_q = self.max_q_value(&next_state);

        // Q-learning update: Q(s,a) ← Q(s,a) + α[r + γ·max_a'(Q(s',a')) - Q(s,a)]
        let new_q = current_q + self.alpha * (reward + self.gamma * max_next_q - current_q);

        self.q_table.insert((state, action), new_q);
    }
}
```

### Churn Prediction

```rust
// src/adaptive/churn_predictor.rs

pub struct ChurnPredictor {
    /// Feature weights (logistic regression)
    weights: ChurnFeatureWeights,

    /// Historical accuracy for calibration
    calibration: CalibrationCurve,
}

pub struct ChurnFeatureWeights {
    pub uptime_hours: f64,
    pub session_count: f64,
    pub time_since_activity: f64,
    pub avg_session_length: f64,
    pub time_of_day: f64,
    pub day_of_week: f64,
    pub is_weekend: f64,
    pub connection_stability: f64,
}

impl ChurnPredictor {
    /// Predict probability of churn in next window
    pub fn predict_churn(&self, peer: &PeerInfo, window: Duration) -> f64 {
        let features = self.extract_features(peer);
        let logit = self.compute_logit(&features);
        let probability = 1.0 / (1.0 + (-logit).exp());  // Sigmoid

        // Apply calibration
        self.calibration.calibrate(probability)
    }

    /// Get high-risk peers for proactive replication
    pub fn get_at_risk_peers(&self, peers: &[PeerInfo], threshold: f64) -> Vec<PeerId> {
        peers
            .iter()
            .filter(|p| self.predict_churn(p, Duration::from_secs(300)) > threshold)
            .map(|p| p.id.clone())
            .collect()
    }
}
```

### Proactive Replication

When churn prediction identifies at-risk nodes, the system proactively replicates:

```rust
// src/adaptive/proactive_replication.rs

pub struct ProactiveReplicator {
    churn_predictor: ChurnPredictor,
    placement_engine: PlacementEngine,
}

impl ProactiveReplicator {
    /// Check for at-risk data and replicate proactively
    pub async fn check_and_replicate(&self) -> Result<ReplicationStats> {
        let at_risk = self.churn_predictor.get_at_risk_peers(
            &self.get_all_peers().await,
            0.7,  // 70% churn probability threshold
        );

        let mut replicated = 0;

        for peer_id in at_risk {
            // Find all data stored on this peer
            let stored_keys = self.get_keys_on_peer(&peer_id).await;

            for key in stored_keys {
                // Check current replica count
                let replicas = self.count_replicas(&key).await;

                if replicas <= self.config.min_replicas {
                    // Need to replicate before peer leaves
                    let target = self.placement_engine.select_replica_target(&key).await?;
                    self.replicate_to(&key, &target).await?;
                    replicated += 1;
                }
            }
        }

        Ok(ReplicationStats { replicated })
    }
}
```

### Performance Metrics Collection

```rust
// src/adaptive/metrics.rs

#[derive(Default)]
pub struct AdaptiveMetrics {
    /// Strategy selection outcomes
    pub strategy_outcomes: HashMap<RoutingStrategy, StrategyOutcome>,

    /// Cache performance
    pub cache_hits: u64,
    pub cache_misses: u64,

    /// Churn prediction accuracy
    pub churn_true_positives: u64,
    pub churn_false_positives: u64,
    pub churn_false_negatives: u64,

    /// Routing latencies by strategy
    pub latencies: HashMap<RoutingStrategy, LatencyHistogram>,
}
```

## Consequences

### Positive

1. **Adaptation**: System learns optimal strategies for current conditions
2. **Self-tuning**: No manual parameter adjustment needed
3. **Failure prediction**: Proactive replication prevents data loss
4. **Performance optimization**: ML-driven caching improves hit rates
5. **Resilience**: Multiple strategies provide fallback options

### Negative

1. **Complexity**: ML components add implementation complexity
2. **Cold start**: Initial period with suboptimal decisions
3. **Overhead**: ML inference has CPU cost
4. **Explainability**: Harder to debug why system made decisions
5. **Training data**: Needs sufficient observations to learn

### Neutral

1. **Memory usage**: Model parameters and observations stored in memory
2. **Convergence time**: Depends on network activity level

## Algorithm Selection Rationale

### Why Thompson Sampling (not UCB)?

**Upper Confidence Bound (UCB)** is a common alternative:
- UCB: Deterministic selection based on confidence intervals
- Thompson Sampling: Probabilistic selection via posterior sampling

We chose Thompson Sampling because:
1. **Better empirical performance** in non-stationary environments
2. **Natural exploration** without explicit exploration parameter
3. **Handles uncertainty** more gracefully
4. **Parallelizable** (can sample independently for concurrent requests)

### Why Q-Learning (not Deep RL)?

Deep Reinforcement Learning (DQN, PPO, etc.) would provide:
- Function approximation for continuous states
- Better generalization

We chose tabular Q-Learning because:
1. **Simplicity**: Easier to implement and debug
2. **Sample efficiency**: Converges faster with limited data
3. **Interpretability**: Can inspect Q-table directly
4. **State space**: Cache states naturally discretize well
5. **No training infrastructure**: No GPU or training pipeline needed

## Alternatives Considered

### Static Strategies

Use fixed routing/caching strategies.

**Rejected because**:
- Cannot adapt to changing conditions
- Suboptimal for diverse network environments
- No learning from experience

### Expert Systems

Use hand-crafted rules.

**Rejected because**:
- Rules become complex and brittle
- Cannot capture subtle patterns
- Requires constant manual tuning

### Centralized ML

Run ML models on central servers.

**Rejected because**:
- Single point of failure
- Privacy concerns (sending data to central server)
- Latency for real-time decisions
- Conflicts with P2P philosophy

### Neural Networks

Use deep learning for all decisions.

**Rejected because**:
- Training complexity
- Compute requirements
- Sample inefficiency
- Harder to verify correctness

## References

- [Thompson Sampling Tutorial](https://web.stanford.edu/~bvr/pubs/TS_Tutorial.pdf)
- [Reinforcement Learning: An Introduction (Sutton & Barto)](http://incompleteideas.net/book/the-book.html)
- [Multi-Armed Bandit Algorithms](https://banditalgs.com/)
- [Adaptive Caching in P2P Systems](https://ieeexplore.ieee.org/document/1354680)
- [Churn Prediction in P2P Networks](https://dl.acm.org/doi/10.1145/1217299.1217311)
