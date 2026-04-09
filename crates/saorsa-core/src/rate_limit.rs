use lru::LruCache;
use parking_lot::RwLock;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum rate limit keys before evicting oldest (prevents memory DoS from many IPs)
const MAX_RATE_LIMIT_KEYS: usize = 100_000;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub window: Duration,
    pub max_requests: u32,
    pub burst_size: u32,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_update: Instant,
    requests_in_window: u32,
    window_start: Instant,
}

impl Bucket {
    fn new(initial_tokens: f64) -> Self {
        let now = Instant::now();
        Self {
            tokens: initial_tokens,
            last_update: now,
            requests_in_window: 0,
            window_start: now,
        }
    }

    fn try_consume(&mut self, cfg: &EngineConfig) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) > cfg.window {
            self.window_start = now;
            self.requests_in_window = 0;
        }
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let refill_rate = cfg.max_requests as f64 / cfg.window.as_secs_f64();
        self.tokens += elapsed * refill_rate;
        self.tokens = self.tokens.min(cfg.burst_size as f64);
        self.last_update = now;
        if self.tokens >= 1.0 && self.requests_in_window < cfg.max_requests {
            self.tokens -= 1.0;
            self.requests_in_window += 1;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct Engine<K: Eq + Hash + Clone + ToString> {
    cfg: EngineConfig,
    global: Mutex<Bucket>,
    /// LRU cache with max 100k entries to prevent memory DoS from many IPs
    keyed: RwLock<LruCache<K, Bucket>>,
}

impl<K: Eq + Hash + Clone + ToString> Engine<K> {
    pub fn new(cfg: EngineConfig) -> Self {
        let burst_size = cfg.burst_size as f64;
        // Safety: MAX_RATE_LIMIT_KEYS is a const > 0, so unwrap_or with MIN (=1) is safe
        let cache_size = NonZeroUsize::new(MAX_RATE_LIMIT_KEYS).unwrap_or(NonZeroUsize::MIN);
        Self {
            cfg,
            global: Mutex::new(Bucket::new(burst_size)),
            keyed: RwLock::new(LruCache::new(cache_size)),
        }
    }

    pub fn try_consume_global(&self) -> bool {
        match self.global.lock() {
            Ok(mut guard) => guard.try_consume(&self.cfg),
            Err(_poisoned) => {
                // Treat poisoned mutex as a denial to maintain safety
                // and avoid panicking in production code.
                false
            }
        }
    }

    pub fn try_consume_key(&self, key: &K) -> bool {
        let mut map = self.keyed.write();
        // Get or insert with LRU cache (automatically evicts oldest if at capacity)
        if let Some(bucket) = map.get_mut(key) {
            bucket.try_consume(&self.cfg)
        } else {
            let mut bucket = Bucket::new(self.cfg.burst_size as f64);
            let result = bucket.try_consume(&self.cfg);
            map.put(key.clone(), bucket);
            result
        }
    }
}

pub type SharedEngine<K> = Arc<Engine<K>>;

// ============================================================================
// Join Rate Limiting for Sybil Protection
// ============================================================================

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Error types for join rate limiting
#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum JoinRateLimitError {
    /// Global join limit exceeded (network is under high load)
    #[error("global join rate limit exceeded: max {max_per_minute} joins per minute")]
    GlobalLimitExceeded { max_per_minute: u32 },

    /// Per-subnet /64 limit exceeded (potential Sybil attack)
    #[error("subnet /64 join rate limit exceeded: max {max_per_hour} joins per hour from this /64")]
    Subnet64LimitExceeded { max_per_hour: u32 },

    /// Per-subnet /48 limit exceeded (potential coordinated attack)
    #[error("subnet /48 join rate limit exceeded: max {max_per_hour} joins per hour from this /48")]
    Subnet48LimitExceeded { max_per_hour: u32 },

    /// Per-subnet /24 limit exceeded (IPv4 Sybil attack)
    #[error("subnet /24 join rate limit exceeded: max {max_per_hour} joins per hour from this /24")]
    Subnet24LimitExceeded { max_per_hour: u32 },
}

/// Configuration for join rate limiting
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinRateLimiterConfig {
    /// Maximum joins per /64 subnet per hour (default: 1)
    /// This is the strictest limit to prevent Sybil attacks
    pub max_joins_per_64_per_hour: u32,

    /// Maximum joins per /48 subnet per hour (default: 5)
    pub max_joins_per_48_per_hour: u32,

    /// Maximum joins per /24 subnet per hour for IPv4 (default: 3)
    pub max_joins_per_24_per_hour: u32,

    /// Maximum global joins per minute (default: 100)
    /// This protects against network-wide flooding
    pub max_global_joins_per_minute: u32,

    /// Burst allowance for global limit (default: 10)
    pub global_burst_size: u32,
}

impl Default for JoinRateLimiterConfig {
    fn default() -> Self {
        Self {
            max_joins_per_64_per_hour: 10_000,
            max_joins_per_48_per_hour: 10_000,
            max_joins_per_24_per_hour: 10_000,
            max_global_joins_per_minute: 10_000,
            global_burst_size: 10_000,
        }
    }
}

/// Join rate limiter for Sybil attack protection
///
/// Implements multi-level rate limiting to prevent attackers from flooding
/// the network with Sybil identities:
///
/// - **Global limit**: Protects against network-wide flooding attacks
/// - **Per-subnet /64 limit**: Prevents single residential/small org Sybil attacks
/// - **Per-subnet /48 limit**: Prevents coordinated attacks from larger organizations
/// - **Per-subnet /24 limit**: IPv4-specific protection
///
/// # Example
///
/// ```rust,ignore
/// use saorsa_core::rate_limit::{JoinRateLimiter, JoinRateLimiterConfig};
/// use std::net::IpAddr;
///
/// let limiter = JoinRateLimiter::new(JoinRateLimiterConfig::default());
///
/// let ip: IpAddr = "2001:db8::1".parse().unwrap();
/// match limiter.check_join_allowed(&ip) {
///     Ok(()) => println!("Join allowed"),
///     Err(e) => println!("Join denied: {}", e),
/// }
/// ```
#[derive(Debug)]
pub struct JoinRateLimiter {
    config: JoinRateLimiterConfig,
    /// Per /64 subnet rate limiter (1 hour window)
    per_subnet_64: Engine<Ipv6Addr>,
    /// Per /48 subnet rate limiter (1 hour window)
    per_subnet_48: Engine<Ipv6Addr>,
    /// Per /24 subnet rate limiter for IPv4 (1 hour window)
    per_subnet_24: Engine<Ipv4Addr>,
    /// Global rate limiter (1 minute window) - uses u8 key with constant 0
    global: Engine<u8>,
}

impl JoinRateLimiter {
    /// Create a new join rate limiter with the given configuration
    pub fn new(config: JoinRateLimiterConfig) -> Self {
        // /64 subnet limiter: max_joins_per_64_per_hour over 1 hour
        let subnet_64_config = EngineConfig {
            window: Duration::from_secs(3600), // 1 hour
            max_requests: config.max_joins_per_64_per_hour,
            burst_size: config.max_joins_per_64_per_hour, // Allow configured limit as burst
        };

        // /48 subnet limiter: max_joins_per_48_per_hour over 1 hour
        let subnet_48_config = EngineConfig {
            window: Duration::from_secs(3600), // 1 hour
            max_requests: config.max_joins_per_48_per_hour,
            burst_size: config.max_joins_per_48_per_hour, // Allow configured limit as burst
        };

        // /24 subnet limiter for IPv4
        let subnet_24_config = EngineConfig {
            window: Duration::from_secs(3600), // 1 hour
            max_requests: config.max_joins_per_24_per_hour,
            burst_size: config.max_joins_per_24_per_hour, // Allow full burst up to limit
        };

        // Global limiter: max_global_joins_per_minute over 1 minute
        let global_config = EngineConfig {
            window: Duration::from_secs(60), // 1 minute
            max_requests: config.max_global_joins_per_minute,
            burst_size: config.global_burst_size,
        };

        Self {
            config,
            per_subnet_64: Engine::new(subnet_64_config),
            per_subnet_48: Engine::new(subnet_48_config),
            per_subnet_24: Engine::new(subnet_24_config),
            global: Engine::new(global_config),
        }
    }

    /// Check if a join request from the given IP is allowed
    ///
    /// Returns `Ok(())` if the join is allowed, or `Err(JoinRateLimitError)`
    /// if any rate limit is exceeded.
    ///
    /// # Rate Limit Checks (in order)
    ///
    /// 1. Global rate limit (protects against network flooding)
    /// 2. Per-subnet limits based on IP version:
    ///    - IPv6: /64 and /48 subnet limits
    ///    - IPv4: /24 subnet limit
    pub fn check_join_allowed(&self, ip: &IpAddr) -> Result<(), JoinRateLimitError> {
        // 1. Check global limit first (uses constant key 0)
        if !self.global.try_consume_key(&0u8) {
            return Err(JoinRateLimitError::GlobalLimitExceeded {
                max_per_minute: self.config.max_global_joins_per_minute,
            });
        }

        // 2. Check per-subnet limits based on IP version
        match ip {
            IpAddr::V6(ipv6) => {
                // Check /64 subnet limit (strictest for Sybil protection)
                let subnet_64 = extract_ipv6_subnet_64(ipv6);
                if !self.per_subnet_64.try_consume_key(&subnet_64) {
                    return Err(JoinRateLimitError::Subnet64LimitExceeded {
                        max_per_hour: self.config.max_joins_per_64_per_hour,
                    });
                }

                // Check /48 subnet limit
                let subnet_48 = extract_ipv6_subnet_48(ipv6);
                if !self.per_subnet_48.try_consume_key(&subnet_48) {
                    return Err(JoinRateLimitError::Subnet48LimitExceeded {
                        max_per_hour: self.config.max_joins_per_48_per_hour,
                    });
                }
            }
            IpAddr::V4(ipv4) => {
                // Check /24 subnet limit for IPv4
                let subnet_24 = extract_ipv4_subnet_24(ipv4);
                if !self.per_subnet_24.try_consume_key(&subnet_24) {
                    return Err(JoinRateLimitError::Subnet24LimitExceeded {
                        max_per_hour: self.config.max_joins_per_24_per_hour,
                    });
                }
            }
        }

        Ok(())
    }
}

/// Extract /64 subnet prefix from an IPv6 address
///
/// Returns an IPv6 address with only the first 64 bits preserved (network portion),
/// with the remaining 64 bits zeroed (interface identifier).
#[inline]
pub fn extract_ipv6_subnet_64(addr: &Ipv6Addr) -> Ipv6Addr {
    let octets = addr.octets();
    let mut subnet = [0u8; 16];
    subnet[..8].copy_from_slice(&octets[..8]); // Keep first 64 bits
    Ipv6Addr::from(subnet)
}

/// Extract /48 subnet prefix from an IPv6 address
///
/// Returns an IPv6 address with only the first 48 bits preserved.
#[inline]
pub fn extract_ipv6_subnet_48(addr: &Ipv6Addr) -> Ipv6Addr {
    let octets = addr.octets();
    let mut subnet = [0u8; 16];
    subnet[..6].copy_from_slice(&octets[..6]); // Keep first 48 bits
    Ipv6Addr::from(subnet)
}

/// Extract /24 subnet prefix from an IPv4 address
///
/// Returns an IPv4 address with only the first 24 bits preserved.
#[inline]
pub fn extract_ipv4_subnet_24(addr: &Ipv4Addr) -> Ipv4Addr {
    let octets = addr.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ipv6_subnet_64() {
        let addr: Ipv6Addr = "2001:db8:85a3:1234:8a2e:370:7334:1234".parse().unwrap();
        let subnet = extract_ipv6_subnet_64(&addr);
        assert_eq!(subnet.to_string(), "2001:db8:85a3:1234::");
    }

    #[test]
    fn test_extract_ipv6_subnet_48() {
        let addr: Ipv6Addr = "2001:db8:85a3:1234:8a2e:370:7334:1234".parse().unwrap();
        let subnet = extract_ipv6_subnet_48(&addr);
        assert_eq!(subnet.to_string(), "2001:db8:85a3::");
    }

    #[test]
    fn test_extract_ipv4_subnet_24() {
        let addr: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let subnet = extract_ipv4_subnet_24(&addr);
        assert_eq!(subnet.to_string(), "192.168.1.0");
    }

    #[test]
    fn test_join_rate_limiter_allows_first_join() {
        let limiter = JoinRateLimiter::new(JoinRateLimiterConfig::default());
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(limiter.check_join_allowed(&ip).is_ok());
    }

    #[test]
    fn test_join_rate_limiter_blocks_second_from_same_64() {
        let config = JoinRateLimiterConfig {
            max_joins_per_64_per_hour: 1,
            ..Default::default()
        };
        let limiter = JoinRateLimiter::new(config);

        // First join should succeed
        let ip1: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(limiter.check_join_allowed(&ip1).is_ok());

        // Second join from same /64 should fail
        let ip2: IpAddr = "2001:db8::2".parse().unwrap();
        let result = limiter.check_join_allowed(&ip2);
        assert!(matches!(
            result,
            Err(JoinRateLimitError::Subnet64LimitExceeded { .. })
        ));
    }

    #[test]
    fn test_join_rate_limiter_allows_different_subnets() {
        let config = JoinRateLimiterConfig {
            max_joins_per_64_per_hour: 1,
            ..Default::default()
        };
        let limiter = JoinRateLimiter::new(config);

        // First join from one /64
        let ip1: IpAddr = "2001:db8:1::1".parse().unwrap();
        assert!(limiter.check_join_allowed(&ip1).is_ok());

        // Second join from different /64 should succeed
        let ip2: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert!(limiter.check_join_allowed(&ip2).is_ok());
    }

    #[test]
    fn test_join_rate_limiter_ipv4() {
        let config = JoinRateLimiterConfig {
            max_joins_per_24_per_hour: 2,
            ..Default::default()
        };
        let limiter = JoinRateLimiter::new(config);

        // First two joins should succeed
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(limiter.check_join_allowed(&ip1).is_ok());
        assert!(limiter.check_join_allowed(&ip2).is_ok());

        // Third join from same /24 should fail
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();
        let result = limiter.check_join_allowed(&ip3);
        assert!(matches!(
            result,
            Err(JoinRateLimitError::Subnet24LimitExceeded { .. })
        ));
    }
}
