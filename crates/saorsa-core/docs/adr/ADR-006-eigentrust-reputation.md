# ADR-006: EigenTrust Reputation System

## Status

Accepted

## Context

Decentralized networks face the fundamental challenge of establishing trust without central authorities. Nodes must make decisions about:

- Which peers to connect to
- Which nodes to store data on
- Which witnesses to accept attestations from
- How to weight routing decisions

Without a reputation system:
- Sybil attacks become trivial (create many identities, gain influence)
- Malicious nodes are indistinguishable from honest ones
- No accountability for bad behavior
- No incentive for good behavior

We needed a reputation system that:
1. Resists Sybil attacks (many fake identities cannot gain trust easily)
2. Converges to stable values
3. Distributes computation across the network
4. Adapts to changing behavior

## Decision

We implement **EigenTrust**, a distributed reputation algorithm that computes global trust scores from local observations.

### Algorithm Overview

EigenTrust works by iteratively propagating trust through a peer-to-peer network until convergence:

```
Trust(i) = Σ (Trust(j) × LocalTrust(j→i))
           j∈peers

Where:
- Trust(i) is the global trust score of node i
- LocalTrust(j→i) is node j's direct observation of node i
- The sum is weighted by the trust in each recommending node
```

This is equivalent to finding the principal eigenvector of the normalized trust matrix—hence the name "EigenTrust."

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Local Observation Layer                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Record direct interactions:                               │   │
│  │ • Successful data transfers (+)                          │   │
│  │ • Failed requests (-)                                    │   │
│  │ • Correct witness attestations (+)                       │   │
│  │ • Invalid signatures (-)                                 │   │
│  │ • Uptime/availability (+)                                │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┬───────────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Local Trust Computation                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ c_ij = max(s_ij, 0) / Σ max(s_ik, 0)                     │   │
│  │                       k                                   │   │
│  │ Where s_ij = sat(i,j) - unsat(i,j)                       │   │
│  │ Normalized so Σ c_ij = 1 for each i                      │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┬───────────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Distributed Iteration                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ t(k+1) = (1-α) × C^T × t(k) + α × p                      │   │
│  │                                                           │   │
│  │ Where:                                                    │   │
│  │ • t(k) is the trust vector at iteration k                │   │
│  │ • C is the normalized local trust matrix                 │   │
│  │ • p is the pre-trusted peer distribution                 │   │
│  │ • α is the pre-trust weight (default 0.1)                │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┬───────────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Global Trust Scores                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Node A: 0.85 (highly trusted)                            │   │
│  │ Node B: 0.72 (trusted)                                   │   │
│  │ Node C: 0.45 (moderate)                                  │   │
│  │ Node D: 0.12 (low trust, possibly malicious)             │   │
│  │ Node E: 0.03 (very low, likely Sybil)                    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

```rust
// src/security/eigentrust.rs
pub struct EigenTrustManager {
    /// Local trust observations (peer_id → (satisfactory, unsatisfactory))
    local_trust: HashMap<PeerId, (u64, u64)>,

    /// Current global trust vector
    global_trust: HashMap<PeerId, f64>,

    /// Pre-trusted peers (bootstrap nodes, etc.)
    pre_trusted: Vec<PeerId>,

    /// Configuration
    config: EigenTrustConfig,
}

#[derive(Clone)]
pub struct EigenTrustConfig {
    /// Weight given to pre-trusted peers (α)
    pub pre_trust_weight: f64,  // Default: 0.1

    /// Convergence threshold
    pub epsilon: f64,  // Default: 0.001

    /// Maximum iterations
    pub max_iterations: usize,  // Default: 100

    /// Minimum interactions before trust is valid
    pub min_interactions: u64,  // Default: 5
}

impl EigenTrustManager {
    /// Record a satisfactory interaction
    pub fn record_success(&mut self, peer: &PeerId) {
        let entry = self.local_trust.entry(peer.clone()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
    }

    /// Record an unsatisfactory interaction
    pub fn record_failure(&mut self, peer: &PeerId) {
        let entry = self.local_trust.entry(peer.clone()).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);
    }

    /// Compute normalized local trust
    fn compute_local_trust(&self, peer: &PeerId) -> f64 {
        let (sat, unsat) = self.local_trust.get(peer).copied().unwrap_or((0, 0));
        let score = sat.saturating_sub(unsat) as f64;
        score.max(0.0)
    }

    /// Run one iteration of distributed EigenTrust
    pub async fn iterate(&mut self) -> f64 {
        let mut new_trust = HashMap::new();
        let mut max_change = 0.0f64;

        for (peer_id, _) in &self.global_trust {
            let mut trust = 0.0;

            // Sum weighted trust from all peers
            for (recommender, rec_trust) in &self.global_trust {
                let local = self.get_remote_local_trust(recommender, peer_id).await;
                trust += rec_trust * local;
            }

            // Apply pre-trust dampening
            let pre_trust = if self.pre_trusted.contains(peer_id) {
                1.0 / self.pre_trusted.len() as f64
            } else {
                0.0
            };

            trust = (1.0 - self.config.pre_trust_weight) * trust
                  + self.config.pre_trust_weight * pre_trust;

            let old_trust = self.global_trust.get(peer_id).copied().unwrap_or(0.0);
            max_change = max_change.max((trust - old_trust).abs());

            new_trust.insert(peer_id.clone(), trust);
        }

        self.global_trust = new_trust;
        max_change
    }

    /// Run EigenTrust to convergence
    pub async fn compute(&mut self) -> Result<()> {
        for _ in 0..self.config.max_iterations {
            let change = self.iterate().await;
            if change < self.config.epsilon {
                return Ok(());
            }
        }
        // Didn't converge, but results are still usable
        Ok(())
    }

    /// Get trust score for a peer
    pub fn get_score(&self, peer: &PeerId) -> f64 {
        self.global_trust.get(peer).copied().unwrap_or(0.0)
    }
}
```

### Integration with Placement

EigenTrust scores feed into the weighted placement formula:

```rust
// src/placement/weighted_strategy.rs

/// Weighted node selection formula
/// w_i = (τ_i^α) * (p_i^β) * (c_i^γ) * d_i
///
/// Where:
/// - τ_i: EigenTrust reputation score [0,1]
/// - p_i: Performance score [0,1]
/// - c_i: Capacity score [0,1]
/// - d_i: Diversity bonus multiplier [1,2]
/// - α, β, γ: Tunable exponents

pub fn compute_weight(
    trust_score: f64,      // τ_i from EigenTrust
    performance: f64,      // p_i from latency/uptime
    capacity: f64,         // c_i from available storage
    diversity_bonus: f64,  // d_i from geographic diversity
    config: &WeightConfig,
) -> f64 {
    trust_score.powf(config.trust_exponent)         // α = 2.0 (default)
        * performance.powf(config.perf_exponent)    // β = 1.0 (default)
        * capacity.powf(config.capacity_exponent)   // γ = 0.5 (default)
        * diversity_bonus
}
```

### Sybil Resistance

EigenTrust resists Sybil attacks through:

1. **Pre-trusted peers**: Bootstrap nodes provide anchor trust
2. **Transitivity**: New nodes must earn trust from existing trusted nodes
3. **Interaction requirement**: Minimum interactions before trust is valid
4. **Slow propagation**: Trust builds gradually, not instantly

```
Sybil Attack Scenario:
Attacker creates 1000 fake identities → All start at trust = 0
                                         ↓
                                 Need interactions with trusted nodes
                                         ↓
                                 Trusted nodes are vigilant, limit interactions
                                         ↓
                                 Takes months to build any meaningful trust
```

### Trust Decay

Trust decays over time to handle changing behavior:

```rust
impl EigenTrustManager {
    /// Apply time-based decay to local trust
    pub fn apply_decay(&mut self, decay_factor: f64) {
        for (_, (sat, unsat)) in &mut self.local_trust {
            // Decay old observations
            *sat = ((*sat as f64) * decay_factor) as u64;
            *unsat = ((*unsat as f64) * decay_factor) as u64;
        }
    }
}
```

## Consequences

### Positive

1. **Sybil resistance**: Fake identities cannot instantly gain trust
2. **Decentralized**: No central authority needed
3. **Adaptive**: Trust adjusts to changing behavior
4. **Convergent**: Algorithm reaches stable state
5. **Composable**: Integrates with placement and witness selection

### Negative

1. **Bootstrap problem**: New nodes start with zero trust
2. **Computation overhead**: Iterative algorithm requires CPU
3. **Network overhead**: Must query peers for their local trust
4. **Collusion risk**: Groups of malicious nodes can boost each other

### Neutral

1. **Tuning required**: Parameters (α, ε, iterations) need adjustment
2. **Storage overhead**: Must persist trust observations

## Collusion Mitigation

To mitigate collusion attacks:

1. **Pre-trust anchoring**: Sufficient pre-trusted peers dilute collusion impact
2. **Interaction verification**: Random audits of claimed interactions
3. **Geographic diversity**: Colluders often co-located
4. **Behavioral analysis**: Sudden trust spikes trigger investigation

## Alternatives Considered

### Simple Voting

Each peer votes on others' trustworthiness.

**Rejected because**:
- Trivially Sybil-attackable
- No weighting by voter reliability
- Doesn't converge to stable values

### Blockchain-Based Reputation

Store reputation on a blockchain.

**Rejected because**:
- Slow updates
- Consensus overhead
- Doesn't leverage local observations

### PageRank

Use PageRank-style algorithm.

**Rejected because**:
- Designed for link graphs, not trust
- No negative feedback mechanism
- Less studied for Sybil resistance

### Subjective Logic

Bayesian trust with uncertainty.

**Rejected because**:
- More complex to implement
- Less proven in P2P systems
- EigenTrust more widely studied

## References

- [EigenTrust: Reputation Management in P2P Networks](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf)
- [The Sybil Attack](https://www.microsoft.com/en-us/research/wp-content/uploads/2002/01/IPTPS2002.pdf)
- [PowerTrust: Leveraging Hierarchy](https://ieeexplore.ieee.org/document/4268195)
- [PeerTrust: Supporting Reputation-Based Trust](https://www.cs.purdue.edu/homes/ninghui/papers/peertrust_tkde.pdf)
- [ADR-005: S/Kademlia Witness Protocol](./ADR-005-skademlia-witness-protocol.md)
- [ADR-009: Sybil Protection Mechanisms](./ADR-009-sybil-protection.md)
