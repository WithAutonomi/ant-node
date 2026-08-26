//! Shared browser-client discovery types.
//!
//! These types describe the public read and paid immutable-write capabilities
//! exposed by browser-enabled nodes. Wallet secrets never form part of these
//! records: browsers sign EVM transactions locally and send only payment
//! receipts to nodes.

use saorsa_core::{MultiAddr, PeerId, WebRtcCertificateHash, WebRtcDirectAddr};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Version of the local browser bootstrap manifest.
pub const BROWSER_MANIFEST_VERSION: u16 = 5;

/// A self-contained browser-compatible transport endpoint.
///
/// The multiaddress embeds the node's stable DTLS certificate hash. Callers
/// never supply a separate certificate pin or resolve a DNS name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserEndpoint {
    /// Canonical WebRTC Direct multiaddress, including certificate hash and peer ID.
    pub multiaddr: MultiAddr,
}

/// Validated components extracted from a [`BrowserEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBrowserEndpoint {
    /// Literal UDP socket address passed to the WebRTC Direct dialer.
    pub socket_addr: SocketAddr,
    /// Persistent ANT peer ID from the `/p2p` suffix.
    pub peer_id: PeerId,
    /// Stable SHA-256 hash of the node's DTLS certificate.
    pub certificate_hash: [u8; 32],
}

impl BrowserEndpoint {
    /// Construct a canonical endpoint from a literal socket address, ANT peer ID,
    /// and the stable DTLS certificate's SHA-256 hash.
    ///
    /// # Errors
    ///
    /// Returns an error for port zero.
    pub fn new(
        advertised_addr: SocketAddr,
        peer_id: &PeerId,
        certificate_hash: [u8; 32],
    ) -> Result<Self, String> {
        let transport = WebRtcDirectAddr::new(
            advertised_addr,
            WebRtcCertificateHash::new(certificate_hash),
        )
        .map_err(|error| error.to_string())?;
        let multiaddr = MultiAddr::webrtc_direct(transport).with_peer_id(*peer_id);
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
            .ok_or_else(|| "WebRtcDirect multiaddress has no peer ID".to_string())?;
        let address = self
            .multiaddr
            .webrtc_direct_addr()
            .ok_or_else(|| "multiaddress does not use WebRtcDirect".to_string())?;
        Ok(ParsedBrowserEndpoint {
            socket_addr: address.socket_addr(),
            peer_id,
            certificate_hash: *address.certificate_hash().as_bytes(),
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

/// Public EVM configuration required to pay for immutable browser uploads.
///
/// This deliberately excludes wallet keys. A browser obtains a key from its
/// user at runtime and must never transmit it to a storage node or manifest
/// server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserPaymentNetwork {
    /// HTTP JSON-RPC endpoint used to submit and inspect transactions.
    pub rpc_url: String,
    /// ERC-20 ANT token contract address.
    pub payment_token_address: String,
    /// Payment vault contract that accepts quote payments.
    pub payment_vault_address: String,
}

impl BrowserPaymentNetwork {
    /// Convert the node's concrete EVM network into browser-safe public data.
    #[must_use]
    pub fn from_evm_network(network: &evmlib::Network) -> Self {
        Self {
            rpc_url: network.rpc_url().to_string(),
            payment_token_address: format!("{:?}", network.payment_token_address()),
            payment_vault_address: format!("{:?}", network.payment_vault_address()),
        }
    }
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
    /// Public payment contracts and RPC used by browser uploads.
    pub payment: BrowserPaymentNetwork,
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
        payment: BrowserPaymentNetwork,
        files: Vec<BrowserPublicFile>,
    ) -> Self {
        Self {
            version: BROWSER_MANIFEST_VERSION,
            network_id,
            created_at,
            endpoints,
            payment,
            files,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn browser_endpoint_round_trips_stable_hash() {
        let peer_id = PeerId::from_bytes([0xab; 32]);
        let endpoint = BrowserEndpoint::new(
            "127.0.0.1:24000".parse().expect("valid socket address"),
            &peer_id,
            [0x11; 32],
        )
        .expect("valid endpoint");

        assert!(endpoint
            .multiaddr
            .to_string()
            .starts_with("/ip4/127.0.0.1/udp/24000/webrtc-direct/certhash/u"));
        assert_eq!(
            endpoint.multiaddr.to_string().matches("/certhash/").count(),
            1
        );
        let parsed = endpoint.parse().expect("round-trip endpoint");
        assert_eq!(parsed.socket_addr, "127.0.0.1:24000".parse().unwrap());
        assert_eq!(parsed.peer_id, peer_id);
        assert_eq!(parsed.certificate_hash, [0x11; 32]);
    }

    #[test]
    fn browser_endpoint_round_trips_ipv6() {
        let peer_id = PeerId::from_bytes([0xcd; 32]);
        let endpoint = BrowserEndpoint::new(
            "[::1]:24000".parse().expect("valid socket address"),
            &peer_id,
            [0x33; 32],
        )
        .expect("valid endpoint");
        let parsed = endpoint.parse().expect("round-trip endpoint");
        assert_eq!(parsed.socket_addr, "[::1]:24000".parse().unwrap());
    }

    #[test]
    fn browser_endpoint_rejects_unpinned_or_malformed_addresses() {
        let peer_id = PeerId::from_bytes([0xab; 32]).to_hex();
        let unpinned =
            format!(r#"{{"multiaddr":"/ip4/127.0.0.1/udp/24000/webrtc-direct/p2p/{peer_id}"}}"#);
        assert!(serde_json::from_str::<BrowserEndpoint>(&unpinned).is_err());

        let malformed = format!(
            r#"{{"multiaddr":"/ip4/127.0.0.1/udp/24000/webrtc-direct/certhash/uAA/p2p/{peer_id}"}}"#
        );
        assert!(serde_json::from_str::<BrowserEndpoint>(&malformed).is_err());
    }

    #[test]
    fn browser_endpoint_rejects_port_zero() {
        let peer_id = PeerId::from_bytes([0xab; 32]);
        let error = BrowserEndpoint::new("127.0.0.1:0".parse().unwrap(), &peer_id, [0x11; 32])
            .expect_err("port zero must fail");
        assert!(error.contains("must not be zero"));
    }
}
