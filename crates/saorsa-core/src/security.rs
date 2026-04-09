// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Security module
//!
//! This module provides Sybil protection for the P2P network via IP diversity
//! enforcement to prevent large-scale Sybil attacks while maintaining network
//! openness.

use anyhow::{Result, anyhow};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;

/// Maximum subnet tracking entries before evicting oldest (prevents memory DoS)
const BOOTSTRAP_MAX_TRACKED_SUBNETS: usize = 50_000;

/// Max nodes sharing an exact IP address per bucket/close-group.
/// Used by both `DhtCoreEngine` and `BootstrapIpLimiter` when
/// `IPDiversityConfig::max_per_ip` is `None`.
pub const IP_EXACT_LIMIT: usize = 2;

/// Default K value for `BootstrapIpLimiter` when the actual K is not known
/// (e.g. standalone test construction). Matches `DHTConfig::DEFAULT_K_VALUE`.
#[cfg(test)]
const DEFAULT_K_VALUE: usize = 20;

/// Canonicalize an IP address: map IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to
/// its IPv4 equivalent so that diversity limits are enforced uniformly
/// regardless of which address family the transport layer reports.
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// Compute the subnet diversity limit from the active K value.
/// At least 1 node per subnet is always permitted.
pub const fn ip_subnet_limit(k: usize) -> usize {
    if k / 4 > 0 { k / 4 } else { 1 }
}

/// Configuration for IP diversity enforcement at two tiers: exact IP and subnet.
///
/// Limits are applied **per-bucket** and **per-close-group** (the K closest
/// nodes to self), matching how geographic diversity is enforced.  When a
/// candidate would exceed a limit, it may still be admitted via swap-closer
/// logic: if the candidate is closer (XOR distance) to self than the
/// farthest same-subnet peer in the scope, that farther peer is evicted.
///
/// By default every limit is `None`, meaning the K-based defaults from
/// `DhtCoreEngine` apply (fractions of the bucket size K).  Setting an
/// explicit `Some(n)` overrides the K-based default for that tier.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IPDiversityConfig {
    /// Override for max nodes sharing an exact IP address per bucket/close-group.
    /// When `None`, uses the default of 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_ip: Option<usize>,

    /// Override for max nodes in the same subnet (/24 IPv4, /48 IPv6).
    /// When `None`, uses the K-based default (~25% of bucket size).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_subnet: Option<usize>,
}

impl IPDiversityConfig {
    /// Create a testnet configuration with relaxed diversity requirements.
    ///
    /// This is useful for testing environments like Digital Ocean where all nodes
    /// share the same ASN (AS14061). The relaxed limits allow many nodes from the
    /// same provider while still maintaining some diversity tracking.
    ///
    /// Currently identical to [`permissive`](Self::permissive) but kept as a
    /// separate constructor so testnet limits can diverge independently (e.g.
    /// allowing same-subnet but limiting per-IP) without changing local-dev
    /// callers.
    ///
    /// # Warning
    ///
    /// This configuration should NEVER be used in production as it significantly
    /// weakens Sybil attack protection.
    #[must_use]
    pub fn testnet() -> Self {
        Self::permissive()
    }

    /// Create a permissive configuration that effectively disables diversity checks.
    ///
    /// This is useful for local development and unit testing where all nodes
    /// run on localhost or the same machine.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            max_per_ip: Some(usize::MAX),
            max_per_subnet: Some(usize::MAX),
        }
    }

    /// Validate IP diversity parameter safety constraints (Section 4 points 1-2).
    ///
    /// Returns `Err` if any explicit limit is less than 1.
    pub fn validate(&self) -> Result<()> {
        if let Some(limit) = self.max_per_ip
            && limit < 1
        {
            anyhow::bail!("max_per_ip must be >= 1 (got {limit})");
        }
        if let Some(limit) = self.max_per_subnet
            && limit < 1
        {
            anyhow::bail!("max_per_subnet must be >= 1 (got {limit})");
        }
        Ok(())
    }
}

/// IP diversity enforcement system
///
/// Tracks per-IP and per-subnet counts to prevent Sybil attacks.
/// Uses simple 2-tier limits: exact IP and subnet (/24 IPv4, /48 IPv6).
#[derive(Debug)]
pub struct BootstrapIpLimiter {
    config: IPDiversityConfig,
    /// Allow loopback addresses (127.0.0.1, ::1) to bypass diversity checks.
    ///
    /// This flag is intentionally separate from `IPDiversityConfig` so that it
    /// has a single source of truth in the owning component (`NodeConfig`,
    /// `BootstrapManager`, etc.) rather than being copied into every config.
    allow_loopback: bool,
    /// K value from DHT config, used to derive subnet limits consistent with
    /// the routing table's `ip_subnet_limit(k)`.
    k_value: usize,
    /// Count of nodes per exact IP address
    ip_counts: LruCache<IpAddr, usize>,
    /// Count of nodes per subnet (/24 IPv4, /48 IPv6)
    subnet_counts: LruCache<IpAddr, usize>,
}

impl BootstrapIpLimiter {
    /// Create a new IP diversity enforcer with loopback disabled and default K.
    ///
    /// Uses [`DEFAULT_K_VALUE`] — production code should prefer
    /// [`with_loopback_and_k`](Self::with_loopback_and_k) to stay consistent
    /// with the configured bucket size.
    #[cfg(test)]
    pub fn new(config: IPDiversityConfig) -> Self {
        Self::with_loopback(config, false)
    }

    /// Create a new IP diversity enforcer with explicit loopback setting and
    /// default K value.
    ///
    /// Uses [`DEFAULT_K_VALUE`] — production code should prefer
    /// [`with_loopback_and_k`](Self::with_loopback_and_k) to stay consistent
    /// with the configured bucket size.
    #[cfg(test)]
    pub fn with_loopback(config: IPDiversityConfig, allow_loopback: bool) -> Self {
        Self::with_loopback_and_k(config, allow_loopback, DEFAULT_K_VALUE)
    }

    /// Create a new IP diversity enforcer with explicit loopback setting and K value.
    ///
    /// The `k_value` is used to derive the subnet limit (`k/4`) so that bootstrap
    /// and routing table diversity limits stay consistent.
    pub fn with_loopback_and_k(
        config: IPDiversityConfig,
        allow_loopback: bool,
        k_value: usize,
    ) -> Self {
        let cache_size =
            NonZeroUsize::new(BOOTSTRAP_MAX_TRACKED_SUBNETS).unwrap_or(NonZeroUsize::MIN);
        Self {
            config,
            allow_loopback,
            k_value,
            ip_counts: LruCache::new(cache_size),
            subnet_counts: LruCache::new(cache_size),
        }
    }

    /// Mask an IP to its subnet prefix (/24 for IPv4, /48 for IPv6).
    fn subnet_key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
            }
            IpAddr::V6(v6) => {
                let mut o = v6.octets();
                // Zero out bytes 6-15 (host portion of /48)
                for b in &mut o[6..] {
                    *b = 0;
                }
                IpAddr::V6(Ipv6Addr::from(o))
            }
        }
    }

    /// Check if a new node with the given IP can be accepted under diversity limits.
    pub fn can_accept(&self, ip: IpAddr) -> bool {
        let ip = canonicalize_ip(ip);

        // Loopback: bypass all checks when allowed, reject outright when not.
        if ip.is_loopback() {
            return self.allow_loopback;
        }

        // Reject addresses that are never valid peer endpoints.
        if ip.is_unspecified() || ip.is_multicast() {
            return false;
        }

        let ip_limit = self.config.max_per_ip.unwrap_or(IP_EXACT_LIMIT);
        let subnet_limit = self
            .config
            .max_per_subnet
            .unwrap_or(ip_subnet_limit(self.k_value));

        // Check exact IP limit
        if let Some(&count) = self.ip_counts.peek(&ip)
            && count >= ip_limit
        {
            return false;
        }

        // Check subnet limit
        let subnet = Self::subnet_key(ip);
        if let Some(&count) = self.subnet_counts.peek(&subnet)
            && count >= subnet_limit
        {
            return false;
        }

        true
    }

    /// Track a new node's IP address in the diversity enforcer.
    ///
    /// Returns an error if the IP would exceed diversity limits.
    pub fn track(&mut self, ip: IpAddr) -> Result<()> {
        let ip = canonicalize_ip(ip);
        if !self.can_accept(ip) {
            return Err(anyhow!("IP diversity limits exceeded"));
        }

        let count = self.ip_counts.get(&ip).copied().unwrap_or(0) + 1;
        self.ip_counts.put(ip, count);

        let subnet = Self::subnet_key(ip);
        let count = self.subnet_counts.get(&subnet).copied().unwrap_or(0) + 1;
        self.subnet_counts.put(subnet, count);

        Ok(())
    }

    /// Remove a tracked IP address from the diversity enforcer.
    #[allow(dead_code)]
    pub fn untrack(&mut self, ip: IpAddr) {
        let ip = canonicalize_ip(ip);
        if let Some(count) = self.ip_counts.peek_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.ip_counts.pop(&ip);
            }
        }

        let subnet = Self::subnet_key(ip);
        if let Some(count) = self.subnet_counts.peek_mut(&subnet) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.subnet_counts.pop(&subnet);
            }
        }
    }
}

#[cfg(test)]
impl BootstrapIpLimiter {
    #[allow(dead_code)]
    pub fn config(&self) -> &IPDiversityConfig {
        &self.config
    }
}

/// GeoIP/ASN provider trait.
///
/// Used by `BgpGeoProvider` in the transport layer; kept here so it can be
/// shared across crates without a circular dependency.
#[allow(dead_code)]
pub trait GeoProvider: std::fmt::Debug {
    /// Look up geo/ASN information for an IP address.
    fn lookup(&self, ip: Ipv6Addr) -> GeoInfo;
}

/// Geo information for a peer's IP address.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GeoInfo {
    /// Autonomous System Number
    pub asn: Option<u32>,
    /// Country code
    pub country: Option<String>,
    /// Whether the IP belongs to a known hosting provider
    pub is_hosting_provider: bool,
    /// Whether the IP belongs to a known VPN provider
    pub is_vpn_provider: bool,
}

// Ed25519 compatibility removed

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_diversity_config_default() {
        let config = IPDiversityConfig::default();

        assert!(config.max_per_ip.is_none());
        assert!(config.max_per_subnet.is_none());
    }

    #[test]
    fn test_bootstrap_ip_limiter_creation() {
        let config = IPDiversityConfig {
            max_per_ip: None,
            max_per_subnet: Some(1),
        };
        let enforcer = BootstrapIpLimiter::with_loopback(config.clone(), true);

        assert_eq!(enforcer.config.max_per_subnet, config.max_per_subnet);
    }

    #[test]
    fn test_can_accept_basic() {
        let config = IPDiversityConfig::default();
        let enforcer = BootstrapIpLimiter::new(config);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(enforcer.can_accept(ip));
    }

    #[test]
    fn test_ip_limit_enforcement() {
        let config = IPDiversityConfig {
            max_per_ip: Some(1),
            max_per_subnet: Some(usize::MAX),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // First node should be accepted
        assert!(enforcer.can_accept(ip));
        enforcer.track(ip).unwrap();

        // Second node with same IP should be rejected
        assert!(!enforcer.can_accept(ip));
        assert!(enforcer.track(ip).is_err());
    }

    #[test]
    fn test_subnet_limit_enforcement_ipv4() {
        let config = IPDiversityConfig {
            max_per_ip: Some(usize::MAX),
            max_per_subnet: Some(2),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        // Two IPs in same /24 subnet
        let ip1: IpAddr = "10.0.1.1".parse().unwrap();
        let ip2: IpAddr = "10.0.1.2".parse().unwrap();
        let ip3: IpAddr = "10.0.1.3".parse().unwrap();

        enforcer.track(ip1).unwrap();
        enforcer.track(ip2).unwrap();

        // Third in same /24 should be rejected
        assert!(!enforcer.can_accept(ip3));
        assert!(enforcer.track(ip3).is_err());

        // Different /24 should still be accepted
        let ip_other: IpAddr = "10.0.2.1".parse().unwrap();
        assert!(enforcer.can_accept(ip_other));
    }

    #[test]
    fn test_subnet_limit_enforcement_ipv6() {
        let config = IPDiversityConfig {
            max_per_ip: Some(usize::MAX),
            max_per_subnet: Some(1),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        // Two IPs in same /48 subnet
        let ip1: IpAddr = "2001:db8:85a3:1234::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:85a3:5678::2".parse().unwrap();

        enforcer.track(ip1).unwrap();

        // Second in same /48 should be rejected
        assert!(!enforcer.can_accept(ip2));

        // Different /48 should be accepted
        let ip_other: IpAddr = "2001:db8:aaaa::1".parse().unwrap();
        assert!(enforcer.can_accept(ip_other));
    }

    #[test]
    fn test_track_and_untrack() {
        let config = IPDiversityConfig {
            max_per_ip: Some(1),
            max_per_subnet: Some(usize::MAX),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Track
        enforcer.track(ip).unwrap();
        assert!(!enforcer.can_accept(ip));

        // Untrack
        enforcer.untrack(ip);
        assert!(enforcer.can_accept(ip));

        // Can track again after untrack
        enforcer.track(ip).unwrap();
        assert!(!enforcer.can_accept(ip));
    }

    #[test]
    fn test_loopback_bypass() {
        let config = IPDiversityConfig {
            max_per_ip: Some(1),
            max_per_subnet: Some(1),
        };

        // With loopback enabled
        let enforcer = BootstrapIpLimiter::with_loopback(config.clone(), true);
        let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
        let loopback_v6: IpAddr = "::1".parse().unwrap();
        assert!(enforcer.can_accept(loopback_v4));
        assert!(enforcer.can_accept(loopback_v6));

        // With loopback disabled (default) — rejected outright, not tracked
        let enforcer_no_lb = BootstrapIpLimiter::new(config);
        assert!(
            !enforcer_no_lb.can_accept(loopback_v4),
            "loopback should be rejected when allow_loopback=false"
        );
        assert!(
            !enforcer_no_lb.can_accept(loopback_v6),
            "loopback IPv6 should be rejected when allow_loopback=false"
        );
    }

    #[test]
    fn test_subnet_key_ipv4() {
        let ip: IpAddr = "192.168.42.100".parse().unwrap();
        let subnet = BootstrapIpLimiter::subnet_key(ip);
        let expected: IpAddr = "192.168.42.0".parse().unwrap();
        assert_eq!(subnet, expected);
    }

    #[test]
    fn test_subnet_key_ipv6() {
        let ip: IpAddr = "2001:db8:85a3:1234:5678:8a2e:0370:7334".parse().unwrap();
        let subnet = BootstrapIpLimiter::subnet_key(ip);
        let expected: IpAddr = "2001:db8:85a3::".parse().unwrap();
        assert_eq!(subnet, expected);
    }

    #[test]
    fn test_default_ip_limit_is_two() {
        let config = IPDiversityConfig::default();
        let mut enforcer = BootstrapIpLimiter::new(config);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();

        // Default IP limit is 2, so two tracks should succeed
        enforcer.track(ip1).unwrap();
        enforcer.track(ip1).unwrap();

        // Third should fail
        assert!(!enforcer.can_accept(ip1));
    }

    #[test]
    fn test_default_subnet_limit_matches_k() {
        // With default K=20, subnet limit should be K/4 = 5
        let config = IPDiversityConfig::default();
        let mut enforcer = BootstrapIpLimiter::new(config);

        // Track 5 IPs in the same /24 subnet — all should succeed
        for i in 1..=5 {
            let ip: IpAddr = format!("10.0.1.{i}").parse().unwrap();
            enforcer.track(ip).unwrap();
        }

        // 6th in same subnet should be rejected
        let ip6: IpAddr = "10.0.1.6".parse().unwrap();
        assert!(
            !enforcer.can_accept(ip6),
            "6th peer in same /24 should exceed K/4=5 subnet limit"
        );
    }

    #[test]
    fn test_ipv4_mapped_ipv6_counts_as_ipv4() {
        let config = IPDiversityConfig {
            max_per_ip: Some(1),
            max_per_subnet: Some(usize::MAX),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        // Track using native IPv4
        let ipv4: IpAddr = "10.0.0.1".parse().unwrap();
        enforcer.track(ipv4).unwrap();

        // IPv4-mapped IPv6 form of the same address should be rejected
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(
            !enforcer.can_accept(mapped),
            "IPv4-mapped IPv6 should be canonicalized and hit the IPv4 limit"
        );
    }

    #[test]
    fn test_multicast_rejected() {
        let config = IPDiversityConfig::default();
        let enforcer = BootstrapIpLimiter::new(config);

        let multicast_v4: IpAddr = "224.0.0.1".parse().unwrap();
        assert!(!enforcer.can_accept(multicast_v4));

        let multicast_v6: IpAddr = "ff02::1".parse().unwrap();
        assert!(!enforcer.can_accept(multicast_v6));
    }

    #[test]
    fn test_unspecified_rejected() {
        let config = IPDiversityConfig::default();
        let enforcer = BootstrapIpLimiter::new(config);

        let unspec_v4: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(!enforcer.can_accept(unspec_v4));

        let unspec_v6: IpAddr = "::".parse().unwrap();
        assert!(!enforcer.can_accept(unspec_v6));
    }

    #[test]
    fn test_untrack_ipv4_mapped_ipv6() {
        let config = IPDiversityConfig {
            max_per_ip: Some(1),
            max_per_subnet: Some(usize::MAX),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        // Track using native IPv4
        let ipv4: IpAddr = "10.0.0.1".parse().unwrap();
        enforcer.track(ipv4).unwrap();
        assert!(!enforcer.can_accept(ipv4));

        // Untrack using the IPv4-mapped IPv6 form — should still decrement
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        enforcer.untrack(mapped);
        assert!(
            enforcer.can_accept(ipv4),
            "untrack via mapped form should decrement the IPv4 counter"
        );
    }
}
