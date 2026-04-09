// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! BGP-based GeoIP Provider
//!
//! This module provides IP-to-ASN and IP-to-country mappings using open-source
//! BGP routing data. Unlike proprietary GeoIP databases, this uses:
//!
//! - BGP prefix-to-ASN mappings from public route collectors (RIPE RIS, RouteViews)
//! - ASN-to-country mappings from RIR delegations (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
//! - Curated list of known hosting/VPN provider ASNs
//!
//! Data sources (all open/free):
//! - RIPE RIS: <https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris>
//! - RouteViews: <http://www.routeviews.org/>
//! - RIR delegation files: <https://www.nro.net/statistics>
//! - PeeringDB (for hosting provider identification): <https://www.peeringdb.com/>

use crate::security::{GeoInfo, GeoProvider};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// BGP-based GeoIP provider using open-source routing data
#[derive(Debug)]
pub struct BgpGeoProvider {
    /// IPv4 prefix-to-ASN mappings (uses a simple prefix table)
    ipv4_prefixes: Arc<RwLock<Vec<Ipv4Prefix>>>,
    /// IPv6 prefix-to-ASN mappings
    ipv6_prefixes: Arc<RwLock<Vec<Ipv6Prefix>>>,
    /// ASN-to-organization info
    asn_info: Arc<RwLock<HashMap<u32, AsnInfo>>>,
    /// Known hosting provider ASNs
    hosting_asns: Arc<RwLock<std::collections::HashSet<u32>>>,
    /// Known VPN provider ASNs
    vpn_asns: Arc<RwLock<std::collections::HashSet<u32>>>,
}

/// IPv4 prefix entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Prefix {
    /// Network address
    pub network: u32,
    /// Prefix length (CIDR notation)
    pub prefix_len: u8,
    /// Netmask derived from prefix_len
    pub mask: u32,
    /// Origin ASN
    pub asn: u32,
}

/// IPv6 prefix entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Prefix {
    /// Network address (high 64 bits)
    pub network_high: u64,
    /// Network address (low 64 bits)
    pub network_low: u64,
    /// Prefix length
    pub prefix_len: u8,
    /// Origin ASN
    pub asn: u32,
}

/// ASN information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    /// ASN number
    pub asn: u32,
    /// Organization name
    pub org_name: String,
    /// Country code (ISO 3166-1 alpha-2)
    pub country: String,
    /// RIR that allocated this ASN
    pub rir: String,
}

impl BgpGeoProvider {
    /// Create a new BgpGeoProvider with default embedded data
    pub fn new() -> Self {
        let mut provider = Self {
            ipv4_prefixes: Arc::new(RwLock::new(Vec::new())),
            ipv6_prefixes: Arc::new(RwLock::new(Vec::new())),
            asn_info: Arc::new(RwLock::new(HashMap::new())),
            hosting_asns: Arc::new(RwLock::new(std::collections::HashSet::new())),
            vpn_asns: Arc::new(RwLock::new(std::collections::HashSet::new())),
        };

        // Load embedded data
        provider.load_embedded_data();
        provider
    }

    /// Load embedded BGP data (curated list of major networks)
    fn load_embedded_data(&mut self) {
        // Load known hosting provider ASNs
        self.load_hosting_asns();
        // Load known VPN provider ASNs
        self.load_vpn_asns();
        // Load major ASN info
        self.load_asn_info();
        // Load some well-known prefixes
        self.load_common_prefixes();
    }

    /// Load known hosting/cloud provider ASNs
    fn load_hosting_asns(&mut self) {
        let mut hosting = self.hosting_asns.write();

        // Major cloud providers
        hosting.insert(16509); // Amazon AWS
        hosting.insert(14618); // Amazon AWS
        hosting.insert(8075); // Microsoft Azure
        hosting.insert(15169); // Google Cloud
        hosting.insert(396982); // Google Cloud
        hosting.insert(13335); // Cloudflare
        hosting.insert(20940); // Akamai
        hosting.insert(14061); // DigitalOcean
        hosting.insert(63949); // Linode/Akamai
        hosting.insert(20473); // Vultr/Choopa
        hosting.insert(36351); // SoftLayer/IBM
        hosting.insert(19871); // Network Solutions
        hosting.insert(46606); // Unified Layer
        hosting.insert(16276); // OVH
        hosting.insert(24940); // Hetzner
        hosting.insert(51167); // Contabo
        hosting.insert(12876); // Scaleway
        hosting.insert(9009); // M247
        hosting.insert(60781); // LeaseWeb
        hosting.insert(202018); // Hostwinds
        hosting.insert(62567); // DigitalOcean (additional)
        hosting.insert(39572); // DataCamp
        hosting.insert(174); // Cogent (large transit, often used by hosting)
        hosting.insert(3356); // Level3/Lumen
        hosting.insert(6939); // Hurricane Electric
        hosting.insert(4766); // Korea Telecom (IDC operations)
        hosting.insert(45102); // Alibaba Cloud
        hosting.insert(37963); // Alibaba Cloud
        hosting.insert(132203); // Tencent Cloud
        hosting.insert(45090); // Tencent Cloud
        hosting.insert(55967); // Oracle Cloud
        hosting.insert(31898); // Oracle Cloud
    }

    /// Load known VPN provider ASNs
    fn load_vpn_asns(&mut self) {
        let mut vpn = self.vpn_asns.write();

        // Known VPN providers
        vpn.insert(9009); // M247 (NordVPN, ExpressVPN infrastructure)
        vpn.insert(212238); // Datacamp (VPN infrastructure)
        vpn.insert(60068); // CDN77 (VPN infrastructure)
        vpn.insert(200651); // Flokinet (privacy focused)
        vpn.insert(51852); // Private Layer
        vpn.insert(60729); // ZeroTier (P2P VPN)
        vpn.insert(395954); // Mullvad VPN
        vpn.insert(39351); // 31173 Services (VPN)
        vpn.insert(44066); // LLC First Colo
        vpn.insert(9312); // xTom (VPN hosting)
        vpn.insert(34549); // meerfarbig (VPN hosting)
        vpn.insert(210277); // TrafficTransit
        vpn.insert(204957); // Green Floid
        vpn.insert(44592); // SkyLink (VPN services)
        vpn.insert(34927); // iFog (privacy)
        vpn.insert(197540); // Netcup (popular VPN hosting)
    }

    /// Load ASN-to-country mappings for major networks
    fn load_asn_info(&mut self) {
        let mut info = self.asn_info.write();

        // Major networks with country info
        let asns = [
            (16509, "Amazon.com, Inc.", "US", "ARIN"),
            (14618, "Amazon.com, Inc.", "US", "ARIN"),
            (8075, "Microsoft Corporation", "US", "ARIN"),
            (15169, "Google LLC", "US", "ARIN"),
            (396982, "Google LLC", "US", "ARIN"),
            (13335, "Cloudflare, Inc.", "US", "ARIN"),
            (20940, "Akamai Technologies", "US", "ARIN"),
            (14061, "DigitalOcean, LLC", "US", "ARIN"),
            (63949, "Linode, LLC", "US", "ARIN"),
            (20473, "The Constant Company, LLC", "US", "ARIN"),
            (36351, "SoftLayer Technologies", "US", "ARIN"),
            (16276, "OVH SAS", "FR", "RIPE"),
            (24940, "Hetzner Online GmbH", "DE", "RIPE"),
            (51167, "Contabo GmbH", "DE", "RIPE"),
            (12876, "Scaleway S.A.S.", "FR", "RIPE"),
            (9009, "M247 Ltd", "GB", "RIPE"),
            (60781, "LeaseWeb Netherlands B.V.", "NL", "RIPE"),
            (174, "Cogent Communications", "US", "ARIN"),
            (3356, "Lumen Technologies", "US", "ARIN"),
            (6939, "Hurricane Electric LLC", "US", "ARIN"),
            (4766, "Korea Telecom", "KR", "APNIC"),
            (45102, "Alibaba (US) Technology Co.", "CN", "APNIC"),
            (37963, "Hangzhou Alibaba Advertising", "CN", "APNIC"),
            (132203, "Tencent Building", "CN", "APNIC"),
            (45090, "Shenzhen Tencent", "CN", "APNIC"),
            (55967, "Oracle Corporation", "US", "ARIN"),
            (31898, "Oracle Corporation", "US", "ARIN"),
            (7922, "Comcast Cable Communications", "US", "ARIN"),
            (701, "Verizon Business", "US", "ARIN"),
            (209, "CenturyLink", "US", "ARIN"),
            (3320, "Deutsche Telekom AG", "DE", "RIPE"),
            (5089, "Virgin Media Limited", "GB", "RIPE"),
            (12322, "Free SAS", "FR", "RIPE"),
            (3215, "Orange S.A.", "FR", "RIPE"),
            (6830, "Liberty Global Operations", "NL", "RIPE"),
            (2856, "British Telecommunications", "GB", "RIPE"),
            (6805, "Telefonica Germany", "DE", "RIPE"),
            (3269, "Telecom Italia S.p.A.", "IT", "RIPE"),
            (6739, "Vodafone Ono, S.A.", "ES", "RIPE"),
            (12389, "PJSC Rostelecom", "RU", "RIPE"),
            (9498, "Bharti Airtel Ltd.", "IN", "APNIC"),
            (4134, "Chinanet", "CN", "APNIC"),
            (4837, "China Unicom", "CN", "APNIC"),
            (17676, "SoftBank Corp.", "JP", "APNIC"),
            (2914, "NTT America, Inc.", "US", "ARIN"),
            (7018, "AT&T Services, Inc.", "US", "ARIN"),
            (1299, "Telia Company AB", "SE", "RIPE"),
            (6453, "TATA Communications", "IN", "APNIC"),
            (3257, "GTT Communications Inc.", "US", "ARIN"),
        ];

        for (asn, org, country, rir) in asns {
            info.insert(
                asn,
                AsnInfo {
                    asn,
                    org_name: org.to_string(),
                    country: country.to_string(),
                    rir: rir.to_string(),
                },
            );
        }
    }

    /// Load some common IP prefixes (major allocations)
    fn load_common_prefixes(&mut self) {
        let mut prefixes = self.ipv4_prefixes.write();

        // Amazon AWS ranges (selected)
        prefixes.push(Ipv4Prefix::new([52, 0, 0, 0], 10, 16509));
        prefixes.push(Ipv4Prefix::new([54, 0, 0, 0], 8, 16509));
        prefixes.push(Ipv4Prefix::new([3, 0, 0, 0], 8, 16509));

        // Google ranges
        prefixes.push(Ipv4Prefix::new([35, 192, 0, 0], 12, 15169));
        prefixes.push(Ipv4Prefix::new([34, 64, 0, 0], 10, 15169));

        // Microsoft Azure
        prefixes.push(Ipv4Prefix::new([40, 64, 0, 0], 10, 8075));
        prefixes.push(Ipv4Prefix::new([20, 0, 0, 0], 8, 8075));

        // Cloudflare
        prefixes.push(Ipv4Prefix::new([104, 16, 0, 0], 12, 13335));
        prefixes.push(Ipv4Prefix::new([172, 64, 0, 0], 13, 13335));
        prefixes.push(Ipv4Prefix::new([1, 1, 1, 0], 24, 13335));

        // DigitalOcean
        prefixes.push(Ipv4Prefix::new([167, 99, 0, 0], 16, 14061));
        prefixes.push(Ipv4Prefix::new([206, 189, 0, 0], 16, 14061));

        // Hetzner
        prefixes.push(Ipv4Prefix::new([88, 198, 0, 0], 16, 24940));
        prefixes.push(Ipv4Prefix::new([78, 46, 0, 0], 15, 24940));

        // OVH
        prefixes.push(Ipv4Prefix::new([51, 68, 0, 0], 16, 16276));
        prefixes.push(Ipv4Prefix::new([51, 77, 0, 0], 16, 16276));

        // Sort by prefix length (longest first for most-specific match)
        prefixes.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    /// Look up ASN for an IPv4 address
    #[allow(dead_code)]
    pub fn lookup_ipv4_asn(&self, ip: Ipv4Addr) -> Option<u32> {
        let ip_u32 = u32::from(ip);
        let prefixes = self.ipv4_prefixes.read();

        // Find the most specific matching prefix
        for prefix in prefixes.iter() {
            if (ip_u32 & prefix.mask) == prefix.network {
                return Some(prefix.asn);
            }
        }
        None
    }

    /// Look up ASN for an IPv6 address
    #[allow(dead_code)]
    pub fn lookup_ipv6_asn(&self, ip: Ipv6Addr) -> Option<u32> {
        // Check if this is an IPv4-mapped address
        if let Some(ipv4) = ip.to_ipv4_mapped() {
            return self.lookup_ipv4_asn(ipv4);
        }

        let segments = ip.segments();
        let high = ((segments[0] as u64) << 48)
            | ((segments[1] as u64) << 32)
            | ((segments[2] as u64) << 16)
            | (segments[3] as u64);
        let low = ((segments[4] as u64) << 48)
            | ((segments[5] as u64) << 32)
            | ((segments[6] as u64) << 16)
            | (segments[7] as u64);

        let prefixes = self.ipv6_prefixes.read();
        for prefix in prefixes.iter() {
            if prefix.matches(high, low) {
                return Some(prefix.asn);
            }
        }
        None
    }

    /// Get country for an ASN
    #[allow(dead_code)]
    pub fn get_asn_country(&self, asn: u32) -> Option<String> {
        self.asn_info
            .read()
            .get(&asn)
            .map(|info| info.country.clone())
    }

    /// Check if ASN is a known hosting provider
    #[allow(dead_code)]
    pub fn is_hosting_asn(&self, asn: u32) -> bool {
        self.hosting_asns.read().contains(&asn)
    }

    /// Check if ASN is a known VPN provider
    #[allow(dead_code)]
    pub fn is_vpn_asn(&self, asn: u32) -> bool {
        self.vpn_asns.read().contains(&asn)
    }

    /// Add a custom IPv4 prefix
    #[allow(dead_code)]
    pub fn add_ipv4_prefix(&self, network: [u8; 4], prefix_len: u8, asn: u32) {
        let mut prefixes = self.ipv4_prefixes.write();
        prefixes.push(Ipv4Prefix::new(network, prefix_len, asn));
        prefixes.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    /// Add a custom hosting ASN
    #[allow(dead_code)]
    pub fn add_hosting_asn(&self, asn: u32) {
        self.hosting_asns.write().insert(asn);
    }

    /// Add a custom VPN ASN
    #[allow(dead_code)]
    pub fn add_vpn_asn(&self, asn: u32) {
        self.vpn_asns.write().insert(asn);
    }

    /// Add ASN info
    #[allow(dead_code)]
    pub fn add_asn_info(&self, asn: u32, org_name: &str, country: &str, rir: &str) {
        self.asn_info.write().insert(
            asn,
            AsnInfo {
                asn,
                org_name: org_name.to_string(),
                country: country.to_string(),
                rir: rir.to_string(),
            },
        );
    }

    /// Get statistics about loaded data
    #[allow(dead_code)]
    pub fn stats(&self) -> BgpGeoStats {
        BgpGeoStats {
            ipv4_prefix_count: self.ipv4_prefixes.read().len(),
            ipv6_prefix_count: self.ipv6_prefixes.read().len(),
            asn_info_count: self.asn_info.read().len(),
            hosting_asn_count: self.hosting_asns.read().len(),
            vpn_asn_count: self.vpn_asns.read().len(),
        }
    }
}

impl Default for BgpGeoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoProvider for BgpGeoProvider {
    fn lookup(&self, ip: Ipv6Addr) -> GeoInfo {
        // Try to find ASN
        let asn = self.lookup_ipv6_asn(ip);

        // Get country from ASN if available
        let country = asn.and_then(|a| self.get_asn_country(a));

        // Check hosting/VPN status
        let is_hosting_provider = asn.map(|a| self.is_hosting_asn(a)).unwrap_or(false);
        let is_vpn_provider = asn.map(|a| self.is_vpn_asn(a)).unwrap_or(false);

        GeoInfo {
            asn,
            country,
            is_hosting_provider,
            is_vpn_provider,
        }
    }
}

impl Ipv4Prefix {
    /// Create a new IPv4 prefix
    pub fn new(network: [u8; 4], prefix_len: u8, asn: u32) -> Self {
        let network_u32 = u32::from_be_bytes(network);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };

        Self {
            network: network_u32 & mask,
            prefix_len,
            mask,
            asn,
        }
    }
}

impl Ipv6Prefix {
    /// Check if an IPv6 address matches this prefix
    #[allow(dead_code)]
    pub fn matches(&self, high: u64, low: u64) -> bool {
        if self.prefix_len == 0 {
            return true;
        }

        if self.prefix_len <= 64 {
            let mask = !0u64 << (64 - self.prefix_len);
            (high & mask) == self.network_high
        } else {
            if high != self.network_high {
                return false;
            }
            let low_bits = self.prefix_len - 64;
            let mask = !0u64 << (64 - low_bits);
            (low & mask) == self.network_low
        }
    }
}

/// Statistics about loaded BGP data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct BgpGeoStats {
    pub ipv4_prefix_count: usize,
    pub ipv6_prefix_count: usize,
    pub asn_info_count: usize,
    pub hosting_asn_count: usize,
    pub vpn_asn_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_geo_provider_creation() {
        let provider = BgpGeoProvider::new();
        let stats = provider.stats();

        assert!(stats.ipv4_prefix_count > 0);
        assert!(stats.hosting_asn_count > 0);
        assert!(stats.vpn_asn_count > 0);
        assert!(stats.asn_info_count > 0);
    }

    #[test]
    fn test_ipv4_prefix_matching() {
        let prefix = Ipv4Prefix::new([192, 168, 0, 0], 16, 12345);

        assert_eq!(prefix.network, u32::from_be_bytes([192, 168, 0, 0]));
        assert_eq!(prefix.mask, 0xFFFF0000);
        assert_eq!(prefix.asn, 12345);
    }

    #[test]
    fn test_cloudflare_lookup() {
        let provider = BgpGeoProvider::new();

        // Cloudflare's 1.1.1.1
        let cloudflare_ip = Ipv6Addr::from([0, 0, 0, 0, 0, 0xFFFF, 0x0101, 0x0101]);
        let info = provider.lookup(cloudflare_ip);

        assert_eq!(info.asn, Some(13335));
        assert_eq!(info.country, Some("US".to_string()));
        assert!(!info.is_vpn_provider);
    }

    #[test]
    fn test_hosting_provider_detection() {
        let provider = BgpGeoProvider::new();

        // AWS IP (54.x.x.x range)
        let aws_ip = Ipv6Addr::from([0, 0, 0, 0, 0, 0xFFFF, 0x3600, 0x0001]);
        let info = provider.lookup(aws_ip);

        assert_eq!(info.asn, Some(16509));
        assert!(info.is_hosting_provider);
    }

    #[test]
    fn test_vpn_provider_detection() {
        let provider = BgpGeoProvider::new();

        // M247 is known for VPN infrastructure
        assert!(provider.is_vpn_asn(9009));
        // Mullvad VPN
        assert!(provider.is_vpn_asn(395954));
    }

    #[test]
    fn test_unknown_ip() {
        let provider = BgpGeoProvider::new();

        // Random private IP - should return None for ASN
        let private_ip = Ipv6Addr::from([0, 0, 0, 0, 0, 0xFFFF, 0xC0A8, 0x0101]);
        let info = provider.lookup(private_ip);

        assert!(info.asn.is_none());
        assert!(info.country.is_none());
        assert!(!info.is_hosting_provider);
        assert!(!info.is_vpn_provider);
    }

    #[test]
    fn test_add_custom_prefix() {
        let provider = BgpGeoProvider::new();

        // Add a custom prefix
        provider.add_ipv4_prefix([10, 0, 0, 0], 8, 99999);
        provider.add_asn_info(99999, "Test Corp", "XX", "TEST");

        // Now lookup should work
        let test_ip = Ipv6Addr::from([0, 0, 0, 0, 0, 0xFFFF, 0x0A01, 0x0101]);
        let info = provider.lookup(test_ip);

        assert_eq!(info.asn, Some(99999));
        assert_eq!(info.country, Some("XX".to_string()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        let provider = BgpGeoProvider::new();

        // Test IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
        let ipv4_mapped = Ipv4Addr::new(1, 1, 1, 1).to_ipv6_mapped();
        let info = provider.lookup(ipv4_mapped);

        assert_eq!(info.asn, Some(13335)); // Cloudflare
    }

    #[test]
    fn test_stats() {
        let provider = BgpGeoProvider::new();
        let stats = provider.stats();

        // Should have reasonable amounts of data loaded
        assert!(
            stats.hosting_asn_count >= 20,
            "Expected at least 20 hosting ASNs"
        );
        assert!(stats.vpn_asn_count >= 10, "Expected at least 10 VPN ASNs");
        assert!(
            stats.asn_info_count >= 40,
            "Expected at least 40 ASN info entries"
        );
    }

    #[test]
    fn test_geo_provider_trait_impl() {
        // Ensure we implement the GeoProvider trait correctly
        let provider: Box<dyn GeoProvider> = Box::new(BgpGeoProvider::new());

        let info = provider.lookup(Ipv6Addr::from([0, 0, 0, 0, 0, 0xFFFF, 0x0101, 0x0101]));
        assert!(info.asn.is_some());
    }

    #[test]
    fn test_prefix_length_ordering() {
        let provider = BgpGeoProvider::new();

        // Add overlapping prefixes
        provider.add_ipv4_prefix([192, 0, 0, 0], 8, 1000); // Broad
        provider.add_ipv4_prefix([192, 168, 0, 0], 16, 2000); // More specific
        provider.add_ipv4_prefix([192, 168, 1, 0], 24, 3000); // Most specific

        // The most specific should match
        let test_ip = Ipv6Addr::from([0, 0, 0, 0, 0, 0xFFFF, 0xC0A8, 0x0101]); // 192.168.1.1
        let asn = provider.lookup_ipv6_asn(test_ip);

        assert_eq!(asn, Some(3000), "Should match most specific prefix");
    }
}
