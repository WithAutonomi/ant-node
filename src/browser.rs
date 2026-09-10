//! Shared browser-client discovery types.
//!
//! These types describe the public read and paid immutable-write capabilities
//! exposed by browser-enabled nodes. Wallet secrets never form part of these
//! records: browsers sign EVM transactions locally and send only payment
//! receipts to nodes.

pub use saorsa_transport::webrtc::{BrowserEndpoint, BrowserPaymentNetwork, WebRtcDirectEndpoint};
use serde::{Deserialize, Serialize};

/// Version of the local browser bootstrap manifest.
pub const BROWSER_MANIFEST_VERSION: u16 = 6;

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

/// Resolve the public payment identity without exposing the verifier's RPC URL.
#[cfg(any(feature = "webrtc-direct", test))]
pub(crate) async fn browser_payment_network(
    network: &evmlib::Network,
) -> crate::Result<BrowserPaymentNetwork> {
    let chain_id = match network {
        evmlib::Network::ArbitrumOne => 42_161,
        evmlib::Network::ArbitrumSepoliaTest => 421_614,
        evmlib::Network::Custom(_) => payment_chain_id(network.rpc_url()).await?,
    };
    Ok(BrowserPaymentNetwork {
        chain_id,
        payment_token_address: format!("{:?}", network.payment_token_address()),
        payment_vault_address: format!("{:?}", network.payment_vault_address()),
    })
}

#[cfg(any(feature = "webrtc-direct", test))]
async fn payment_chain_id(rpc_url: &reqwest::Url) -> crate::Result<u64> {
    // Neither provider errors nor response bodies may escape into errors: they
    // can contain the operator's credentials, API keys, or internal addresses.
    let unavailable = || {
        crate::Error::Config(
            "could not resolve the custom EVM chain ID for browser payment metadata".to_string(),
        )
    };
    let invalid = || {
        crate::Error::Config("custom EVM RPC returned an invalid eth_chainId response".to_string())
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| unavailable())?;
    let mut response = client
        .post(rpc_url.clone())
        .json(
            &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}),
        )
        .send()
        .await
        .map_err(|_| unavailable())?
        .error_for_status()
        .map_err(|_| unavailable())?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if body.len() + chunk.len() > 4096 {
            return Err(invalid());
        }
        body.extend_from_slice(&chunk);
    }
    let response: serde_json::Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
    if response["jsonrpc"] != "2.0" || response["id"] != 1 || response.get("error").is_some() {
        return Err(invalid());
    }
    let hex = response["result"]
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .filter(|hex| {
            !hex.is_empty()
                && (hex.len() == 1 || !hex.starts_with('0'))
                && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or_else(invalid)?;
    u64::from_str_radix(hex, 16).map_err(|_| invalid())
}

/// Local-devnet handoff consumed by the browser application.
///
/// This manifest is intentionally a local testnet bootstrap artifact. The
/// production design replaces it with the ML-DSA-signed endpoint records from
/// ADR-0013.
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
    /// Public payment chain and contracts used by browser uploads.
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
mod tests {
    use super::browser_payment_network;

    #[tokio::test]
    async fn builtin_payment_identity_contains_only_chain_and_contracts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (network, chain_id) in [
            (evmlib::Network::ArbitrumOne, 42_161),
            (evmlib::Network::ArbitrumSepoliaTest, 421_614),
        ] {
            let identity = browser_payment_network(&network).await?;
            assert_eq!(identity.chain_id, chain_id);
            assert_eq!(
                serde_json::to_value(identity)?,
                serde_json::json!({
                    "chain_id": chain_id,
                    "payment_token_address": format!("{:?}", network.payment_token_address()),
                    "payment_vault_address": format!("{:?}", network.payment_vault_address()),
                })
            );
        }
        Ok(())
    }
}
