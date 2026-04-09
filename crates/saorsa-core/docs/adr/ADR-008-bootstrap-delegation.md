# ADR-008: Bootstrap Cache Delegation

## Status

Accepted

## Context

When a node joins a P2P network, it faces the **bootstrap problem**:

1. How does it find initial peers to connect to?
2. How does it discover the network topology?
3. How does it avoid connecting only to malicious nodes?

Traditional approaches include:
- **Hardcoded bootstrap nodes**: Simple but centralized, single point of failure
- **DNS seeds**: Requires DNS infrastructure, can be censored
- **DHT bootstrap**: Chicken-and-egg problem (need DHT to find DHT)

A **bootstrap cache** solves this by persisting known peers locally:
- Nodes remember peers from previous sessions
- Cache updates as network is explored
- Fresh installations use seed nodes, then cache good peers

Building a robust bootstrap cache requires:
- Efficient storage format
- Quality scoring for peers
- Merging caches from different sources
- Protection against cache poisoning

The MaidSafe ecosystem has already solved these problems in `saorsa-transport`, which provides:
- Persistent peer cache with quality metrics
- Automatic cache merging
- Connection history tracking
- QUIC-native peer information

## Decision

We **delegate bootstrap cache management to saorsa-transport**, adding a thin wrapper that provides Sybil protection specific to saorsa-core.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    saorsa-core Bootstrap Layer                   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                BootstrapManager                           │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │ Sybil Protection (saorsa-core specific)             │ │   │
│  │  │ • JoinRateLimiter: Rate limit by IP/subnet          │ │   │
│  │  │ • IPDiversityEnforcer: Geographic diversity         │ │   │
│  │  │ • Quality filtering: Minimum trust threshold        │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │                          │                               │   │
│  │                          ▼                               │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │            saorsa-transport BootstrapCache                  │ │   │
│  │  │ • Persistent storage (JSON/binary)                 │ │   │
│  │  │ • Quality metrics per contact                      │ │   │
│  │  │ • Connection history                               │ │   │
│  │  │ • Automatic cleanup                                │ │   │
│  │  │ • Cache merging                                    │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

```rust
// src/bootstrap/manager.rs

use saorsa_transport::BootstrapCache as AntBootstrapCache;

pub struct BootstrapManager {
    /// Delegated cache (saorsa-transport handles persistence, merging)
    cache: Arc<AntBootstrapCache>,

    /// Sybil protection: rate limiting per IP/subnet
    rate_limiter: JoinRateLimiter,

    /// Sybil protection: geographic diversity
    diversity_enforcer: Mutex<IPDiversityEnforcer>,

    /// Stored configuration for diversity checks
    diversity_config: IPDiversityConfig,

    /// Background maintenance task
    maintenance_handle: Option<JoinHandle<()>>,
}

impl BootstrapManager {
    /// Create with default configuration
    pub async fn new(cache_dir: PathBuf) -> Result<Self> {
        Self::with_full_config(
            CacheConfig { cache_dir, ..Default::default() },
            JoinRateLimiterConfig::default(),
            IPDiversityConfig::default(),
        ).await
    }

    /// Create with full configuration
    pub async fn with_full_config(
        cache_config: CacheConfig,
        rate_limit_config: JoinRateLimiterConfig,
        diversity_config: IPDiversityConfig,
    ) -> Result<Self> {
        // Create saorsa-transport cache (handles persistence internally)
        let ant_config = cache_config.to_ant_config()?;
        let cache = AntBootstrapCache::new(ant_config).await?;

        Ok(Self {
            cache: Arc::new(cache),
            rate_limiter: JoinRateLimiter::new(rate_limit_config),
            diversity_enforcer: Mutex::new(IPDiversityEnforcer::new(diversity_config.clone())),
            diversity_config,
            maintenance_handle: None,
        })
    }

    /// Add contact with Sybil protection
    pub async fn add_contact(&self, addr: SocketAddr) -> Result<()> {
        // 1. Check rate limits
        self.rate_limiter.check_rate(addr.ip())
            .map_err(|e| P2PError::Bootstrap(BootstrapError::RateLimited(e.to_string())))?;

        // 2. Check diversity requirements
        {
            let enforcer = self.diversity_enforcer.lock()
                .map_err(|_| P2PError::Bootstrap(BootstrapError::LockError))?;

            if !enforcer.check_diversity(addr.ip()) {
                return Err(P2PError::Bootstrap(
                    BootstrapError::DiversityViolation(addr.ip().to_string())
                ));
            }
        }

        // 3. Delegate to saorsa-transport (handles storage, quality metrics)
        self.cache.add_contact(addr.into()).await?;

        Ok(())
    }

    /// Get bootstrap contacts, filtered by quality
    pub async fn get_contacts(&self, count: usize) -> Vec<SocketAddr> {
        self.cache
            .get_contacts(count)
            .await
            .into_iter()
            .map(|c| c.addr)
            .collect()
    }

    /// Update quality metrics after connection attempt
    pub async fn record_connection_result(
        &self,
        addr: SocketAddr,
        success: bool,
        latency: Option<Duration>,
    ) {
        // Delegate to saorsa-transport
        self.cache.record_connection(addr.into(), success, latency).await;
    }
}
```

### What We Delegate

| Responsibility | Handler | Rationale |
|---------------|---------|-----------|
| Persistent storage | saorsa-transport | Battle-tested, efficient format |
| Quality scoring | saorsa-transport | Complex metrics already implemented |
| Cache merging | saorsa-transport | Handles conflicts correctly |
| Connection history | saorsa-transport | Tracks success/failure patterns |
| Stale contact cleanup | saorsa-transport | Time-based expiration logic |

### What We Add

| Responsibility | Handler | Rationale |
|---------------|---------|-----------|
| IP rate limiting | saorsa-core | Sybil-specific protection |
| Geographic diversity | saorsa-core | Ensures global distribution |
| Subnet limiting | saorsa-core | Prevents /24 flood attacks |
| Trust integration | saorsa-core | Links to EigenTrust system |

### Rate Limiting Configuration

```rust
// src/rate_limit.rs

pub struct JoinRateLimiterConfig {
    /// Maximum joins per IP per minute
    pub per_ip_per_minute: u32,  // Default: 5

    /// Maximum joins per /24 subnet per minute
    pub per_subnet24_per_minute: u32,  // Default: 20

    /// Maximum joins per /16 subnet per hour
    pub per_subnet16_per_hour: u32,  // Default: 100

    /// Window sizes for rate limiting
    pub window_size: Duration,  // Default: 60 seconds
}

impl JoinRateLimiter {
    pub fn check_rate(&self, ip: IpAddr) -> Result<(), JoinRateLimitError> {
        // Check per-IP limit
        if self.ip_counter.count(ip) >= self.config.per_ip_per_minute {
            return Err(JoinRateLimitError::IpRateExceeded);
        }

        // Check /24 subnet limit
        let subnet24 = extract_ipv4_subnet_24(ip);
        if self.subnet24_counter.count(subnet24) >= self.config.per_subnet24_per_minute {
            return Err(JoinRateLimitError::SubnetRateExceeded);
        }

        // Record this attempt
        self.ip_counter.increment(ip);
        self.subnet24_counter.increment(subnet24);

        Ok(())
    }
}
```

### Diversity Enforcement

```rust
// src/security/ip_diversity.rs

pub struct IPDiversityConfig {
    /// Maximum percentage from any single /8 subnet
    pub max_per_slash8: f64,  // Default: 0.25 (25%)

    /// Maximum percentage from any single /16 subnet
    pub max_per_slash16: f64,  // Default: 0.10 (10%)

    /// Minimum number of distinct /16 subnets
    pub min_distinct_slash16: usize,  // Default: 5
}

impl IPDiversityEnforcer {
    pub fn check_diversity(&self, ip: IpAddr) -> bool {
        let subnet8 = extract_ipv4_subnet_8(ip);
        let subnet16 = extract_ipv4_subnet_16(ip);

        let current_count = self.get_total_count();
        let subnet8_count = self.get_subnet8_count(subnet8);
        let subnet16_count = self.get_subnet16_count(subnet16);

        // Check /8 concentration
        if current_count > 0 {
            let ratio = subnet8_count as f64 / current_count as f64;
            if ratio > self.config.max_per_slash8 {
                return false;
            }
        }

        // Check /16 concentration
        if current_count > 0 {
            let ratio = subnet16_count as f64 / current_count as f64;
            if ratio > self.config.max_per_slash16 {
                return false;
            }
        }

        true
    }
}
```

## Consequences

### Positive

1. **Reduced maintenance**: saorsa-transport handles complex cache logic
2. **Proven reliability**: Cache code battle-tested in MaidSafe networks
3. **Sybil protection**: Saorsa-specific protections layer on top
4. **Consistent behavior**: Transport and bootstrap use same peer format
5. **Automatic updates**: saorsa-transport improvements benefit us

### Negative

1. **Version coupling**: Must track saorsa-transport releases
2. **Less control**: Cannot modify cache internals directly
3. **Feature limitations**: Constrained to saorsa-transport's capabilities

### Neutral

1. **Debugging**: Must understand both layers for troubleshooting
2. **Testing**: Integration tests needed for wrapper behavior

## Migration from Previous Implementation

The previous saorsa-core bootstrap (pre-0.4.0) had:
- Custom cache format (incompatible with saorsa-transport)
- Separate merge/discovery modules
- Duplicated quality metrics

Migration steps:
1. Remove old `cache.rs`, `merge.rs`, `discovery.rs`
2. Update `manager.rs` to wrap saorsa-transport
3. Keep `contact.rs` for ContactEntry types
4. Update exports in `lib.rs`

Old caches are not migrated (acceptable since network not yet launched).

## Alternatives Considered

### Build from Scratch

Implement all bootstrap cache logic in saorsa-core.

**Rejected because**:
- Duplicates 5000+ lines of tested code
- Divergence from upstream fixes
- Maintenance burden

### Fork saorsa-transport Cache

Copy saorsa-transport cache code and modify.

**Rejected because**:
- Loses upstream improvements
- Maintenance burden
- No benefit over delegation

### Use Different Library

Use a generic caching library.

**Rejected because**:
- P2P-specific features needed
- Integration with QUIC transport
- Would still need wrapper

## References

- [saorsa-transport BootstrapCache](https://github.com/maidsafe/saorsa-transport)
- [ADR-002: Delegated Transport via saorsa-transport](./ADR-002-delegated-transport.md)
- [ADR-009: Sybil Protection Mechanisms](./ADR-009-sybil-protection.md)
- [Bootstrap Problems in P2P Networks](https://ieeexplore.ieee.org/document/4146944)
