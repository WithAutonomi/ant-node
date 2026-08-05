//! Shared browser-client discovery types.
//!
//! These types deliberately describe only public read capabilities. Native
//! node addresses and payment/write APIs remain outside the browser surface.

use saorsa_core::{
    MultiAddr, PeerId, WebTransportAddr, WebTransportCertificateHash, WebTransportHost,
};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// Version of the local browser bootstrap manifest.
pub const BROWSER_MANIFEST_VERSION: u16 = 3;

/// Fixed HTTPS path represented by an Autonomi `/webtransport` multiaddress.
pub const BROWSER_WEBTRANSPORT_PATH: &str = "/autonomi/webtransport/v1";

/// A self-contained browser-compatible transport endpoint.
///
/// The multiaddress embeds the WebTransport certificate hash or overlapping
/// current/next hashes. Callers never supply a separate certificate pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserEndpoint {
    /// Canonical WebTransport multiaddress, including certificate hashes and peer ID.
    pub multiaddr: MultiAddr,
}

/// Validated components extracted from a [`BrowserEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBrowserEndpoint {
    /// HTTPS URL passed to the browser or native WebTransport implementation.
    pub url: String,
    /// Persistent ANT peer ID from the `/p2p` suffix.
    pub peer_id: PeerId,
    /// SHA-256 hashes of the accepted leaf certificates.
    pub certificate_hashes: Vec<[u8; 32]>,
}

impl BrowserEndpoint {
    /// Construct a canonical endpoint from an advertised HTTPS URL, ANT peer ID,
    /// and one or two leaf-certificate SHA-256 hashes.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-HTTPS URL, a non-standard session path,
    /// malformed peer ID, or an invalid certificate-hash count.
    pub fn new(
        advertised_url: &str,
        peer_id: &PeerId,
        certificate_hashes: &[[u8; 32]],
    ) -> Result<Self, String> {
        let url = parse_advertised_url(advertised_url)?;
        let host = match url.host() {
            Some(Host::Ipv4(ip)) => WebTransportHost::Ip4(ip),
            Some(Host::Ipv6(ip)) => WebTransportHost::Ip6(ip),
            Some(Host::Domain(domain)) => WebTransportHost::Dns(domain.to_ascii_lowercase()),
            None => return Err("WebTransport advertised URL has no host".to_string()),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "WebTransport advertised URL has no port".to_string())?;

        let certificate_hashes = certificate_hashes
            .iter()
            .copied()
            .map(WebTransportCertificateHash::new)
            .collect();
        let transport = WebTransportAddr::new(host, port, certificate_hashes)
            .map_err(|error| error.to_string())?;
        let multiaddr = MultiAddr::webtransport(transport).with_peer_id(*peer_id);
        Ok(Self { multiaddr })
    }

    /// Parse and validate this endpoint's transport, hashes, and peer identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the multiaddress is malformed, uses an unsupported
    /// transport or hash encoding, or omits its peer identity.
    pub fn parse(&self) -> Result<ParsedBrowserEndpoint, String> {
        let peer_id = self
            .multiaddr
            .peer_id()
            .copied()
            .ok_or_else(|| "WebTransport multiaddress has no peer ID".to_string())?;
        let address = self
            .multiaddr
            .webtransport_addr()
            .ok_or_else(|| "multiaddress does not use WebTransport".to_string())?;
        let url = format!(
            "https://{}:{}{}",
            address.host().url_host(),
            address.port(),
            BROWSER_WEBTRANSPORT_PATH
        );
        parse_advertised_url(&url)?;
        let certificate_hashes = address
            .certificate_hashes()
            .iter()
            .map(|hash| *hash.as_bytes())
            .collect();
        Ok(ParsedBrowserEndpoint {
            url,
            peer_id,
            certificate_hashes,
        })
    }
}

/// A bootstrap node that a browser can authenticate and contact directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserBootstrapNode {
    /// Self-contained browser endpoint for this node.
    #[serde(flatten)]
    pub endpoint: BrowserEndpoint,
}

/// Metadata for immutable content published into a browser-enabled devnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserPublicFile {
    /// Human-readable filename suggested to the browser.
    pub name: String,
    /// Address of the publicly stored `MessagePack` `DataMap`.
    pub address: String,
    /// Plaintext content length in bytes.
    pub size: usize,
    /// MIME type used by the browser when saving the content.
    pub content_type: String,
    /// BLAKE3 hash of the fully reconstructed plaintext file.
    pub blake3: String,
    /// Size of the publicly stored `MessagePack` `DataMap` chunk.
    pub data_map_size: usize,
    /// Resolved root `DataMap` used to reconstruct the file.
    pub chunks: Vec<BrowserChunkInfo>,
    /// Minimum number of devnet nodes that admitted every required record.
    pub replicas: usize,
}

/// One resolved self-encryption chunk descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserChunkInfo {
    /// Zero-based plaintext order.
    pub index: usize,
    /// Address of the encrypted chunk stored by nodes.
    pub dst_hash: String,
    /// BLAKE3 hash of the plaintext chunk and self-encryption key input.
    pub src_hash: String,
    /// Expected plaintext chunk size.
    pub src_size: usize,
}

/// Local-devnet handoff consumed by the browser application.
///
/// This manifest is intentionally a local testnet bootstrap artifact. The
/// production design replaces it with the ML-DSA-signed endpoint records from
/// ADR-0009.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserDevnetManifest {
    /// Manifest schema version.
    pub version: u16,
    /// Opaque identifier that distinguishes concurrent local devnets.
    pub network_id: String,
    /// Creation time in RFC 3339 form.
    pub created_at: String,
    /// Direct node endpoints available as initial browser contacts.
    pub endpoints: Vec<BrowserBootstrapNode>,
    /// Immutable files published when the devnet started.
    pub files: Vec<BrowserPublicFile>,
}

impl BrowserDevnetManifest {
    /// Construct a versioned local browser manifest.
    #[must_use]
    pub fn new(
        network_id: String,
        created_at: String,
        endpoints: Vec<BrowserBootstrapNode>,
        files: Vec<BrowserPublicFile>,
    ) -> Self {
        Self {
            version: BROWSER_MANIFEST_VERSION,
            network_id,
            created_at,
            endpoints,
            files,
        }
    }
}

fn parse_advertised_url(advertised_url: &str) -> Result<Url, String> {
    let url = Url::parse(advertised_url)
        .map_err(|error| format!("invalid WebTransport advertised URL: {error}"))?;
    if url.scheme() != "https" {
        return Err("WebTransport advertised URL must use https".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("WebTransport advertised URL must not contain credentials".to_string());
    }
    if url.path() != BROWSER_WEBTRANSPORT_PATH {
        return Err(format!(
            "WebTransport advertised URL path must be {BROWSER_WEBTRANSPORT_PATH}"
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("WebTransport advertised URL must not contain a query or fragment".to_string());
    }
    Ok(url)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn browser_endpoint_round_trips_current_and_next_hashes() {
        let peer_id = PeerId::from_bytes([0xab; 32]);
        let endpoint = BrowserEndpoint::new(
            "https://127.0.0.1:24000/autonomi/webtransport/v1",
            &peer_id,
            &[[0x11; 32], [0x22; 32]],
        )
        .expect("valid endpoint");

        assert!(endpoint
            .multiaddr
            .to_string()
            .starts_with("/ip4/127.0.0.1/udp/24000/quic-v1/webtransport/certhash/u"));
        assert_eq!(
            endpoint.multiaddr.to_string().matches("/certhash/").count(),
            2
        );
        let parsed = endpoint.parse().expect("round-trip endpoint");
        assert_eq!(
            parsed.url,
            "https://127.0.0.1:24000/autonomi/webtransport/v1"
        );
        assert_eq!(parsed.peer_id, peer_id);
        assert_eq!(parsed.certificate_hashes, vec![[0x11; 32], [0x22; 32]]);
    }

    #[test]
    fn browser_endpoint_round_trips_ipv6() {
        let peer_id = PeerId::from_bytes([0xcd; 32]);
        let endpoint = BrowserEndpoint::new(
            "https://[::1]:24000/autonomi/webtransport/v1",
            &peer_id,
            &[[0x33; 32]],
        )
        .expect("valid endpoint");
        let parsed = endpoint.parse().expect("round-trip endpoint");
        assert_eq!(parsed.url, "https://[::1]:24000/autonomi/webtransport/v1");
    }

    #[test]
    fn browser_endpoint_rejects_unpinned_or_malformed_addresses() {
        let peer_id = PeerId::from_bytes([0xab; 32]).to_hex();
        let unpinned = format!(
            r#"{{"multiaddr":"/ip4/127.0.0.1/udp/24000/quic-v1/webtransport/p2p/{peer_id}"}}"#
        );
        assert!(serde_json::from_str::<BrowserEndpoint>(&unpinned).is_err());

        let malformed = format!(
            r#"{{"multiaddr":"/ip4/127.0.0.1/udp/24000/quic-v1/webtransport/certhash/uAA/p2p/{peer_id}"}}"#
        );
        assert!(serde_json::from_str::<BrowserEndpoint>(&malformed).is_err());
    }

    #[test]
    fn browser_endpoint_requires_the_standard_path() {
        let peer_id = PeerId::from_bytes([0xab; 32]);
        let error = BrowserEndpoint::new("https://127.0.0.1:24000/custom", &peer_id, &[[0x11; 32]])
            .expect_err("custom path must fail");
        assert!(error.contains(BROWSER_WEBTRANSPORT_PATH));
    }
}
