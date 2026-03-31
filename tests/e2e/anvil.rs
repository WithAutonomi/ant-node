//! Anvil EVM testnet wrapper for payment verification tests.
//!
//! This module wraps `evmlib::testnet::Testnet` to provide a local
//! Anvil blockchain for testing payment verification.

use evmlib::testnet::Testnet;
use evmlib::wallet::Wallet;
use evmlib::Network as EvmNetwork;
use tracing::{debug, info};

/// Error type for Anvil operations.
#[derive(Debug, thiserror::Error)]
pub enum AnvilError {
    /// Failed to start Anvil
    #[error("Failed to start Anvil: {0}")]
    Startup(String),

    /// Anvil health check failed
    #[error("Anvil health check failed: {0}")]
    HealthCheck(String),

    /// Contract deployment failed
    #[error("Contract deployment failed: {0}")]
    ContractDeployment(String),
}

/// Result type for Anvil operations.
pub type Result<T> = std::result::Result<T, AnvilError>;

/// Wrapper around a real `evmlib::testnet::Testnet`.
///
/// Spawns a local Anvil instance with deployed contracts. The Anvil
/// process is kept alive for the lifetime of this struct.
///
/// ## Usage
///
/// ```rust,ignore
/// let anvil = TestAnvil::new().await?;
/// let network = anvil.to_network();
/// let wallet = anvil.create_funded_wallet()?;
/// anvil.shutdown().await;
/// ```
pub struct TestAnvil {
    /// The underlying evmlib testnet (owns the Anvil process).
    testnet: Testnet,
}

impl TestAnvil {
    /// Start a new Anvil EVM testnet.
    ///
    /// Spawns an Anvil process, deploys payment contracts, and returns
    /// a fully-configured testnet ready for payment verification tests.
    ///
    /// # Errors
    ///
    /// Returns an error if Anvil fails to start or contracts fail to deploy.
    pub async fn new() -> Result<Self> {
        info!("Starting Anvil EVM testnet");

        let testnet = Testnet::new()
            .await
            .map_err(|e| AnvilError::Startup(format!("Failed to start Anvil testnet: {e}")))?;

        info!("Anvil testnet started");

        Ok(Self { testnet })
    }

    /// Get the EVM network configuration for this testnet.
    ///
    /// Use this to configure `PaymentVerifier` or `Wallet` instances.
    #[must_use]
    pub fn to_network(&self) -> EvmNetwork {
        self.testnet.to_network()
    }

    /// Get a reference to the underlying `Testnet`.
    #[must_use]
    pub fn testnet(&self) -> &Testnet {
        &self.testnet
    }

    /// Get the default wallet private key (pre-funded Anvil account).
    ///
    /// # Errors
    ///
    /// Returns an error if the wallet key cannot be retrieved.
    pub fn default_wallet_key(&self) -> Result<String> {
        self.testnet
            .default_wallet_private_key()
            .map_err(|e| AnvilError::Startup(format!("Failed to get wallet key: {e}")))
    }

    /// Create a wallet funded with test tokens.
    ///
    /// Uses the default Anvil account (pre-funded).
    ///
    /// # Errors
    ///
    /// Returns an error if wallet creation fails.
    pub fn create_funded_wallet(&self) -> Result<Wallet> {
        let network = self.testnet.to_network();
        let private_key = self
            .testnet
            .default_wallet_private_key()
            .map_err(|e| AnvilError::Startup(format!("Failed to get wallet key: {e}")))?;

        let wallet = Wallet::new_from_private_key(network, &private_key)
            .map_err(|e| AnvilError::Startup(format!("Failed to create funded wallet: {e}")))?;

        debug!("Created funded wallet with address: {}", wallet.address());
        Ok(wallet)
    }

    /// Create an empty wallet (for testing insufficient funds).
    ///
    /// # Errors
    ///
    /// Returns an error if wallet creation fails.
    pub fn create_empty_wallet(&self) -> Result<Wallet> {
        let network = self.testnet.to_network();
        let random_key = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));

        let wallet = Wallet::new_from_private_key(network, &random_key)
            .map_err(|e| AnvilError::Startup(format!("Failed to create empty wallet: {e}")))?;

        debug!(
            "Created empty wallet (no funds) with address: {}",
            wallet.address()
        );
        Ok(wallet)
    }

    /// Consume `TestAnvil` and return the inner `Testnet`.
    #[must_use]
    pub fn into_testnet(self) -> Testnet {
        self.testnet
    }

    /// Shutdown the Anvil testnet.
    pub async fn shutdown(&mut self) {
        info!("Shutting down Anvil testnet");
        // Testnet is dropped when self is dropped, which kills the Anvil process.
    }
}

/// Create a funded wallet using an explicit EVM network and private key.
///
/// Use this when multiple test components share a single Anvil testnet
/// to ensure all wallets point at the same deployed contracts.
#[allow(dead_code)]
pub fn create_funded_wallet_for_network(network: &EvmNetwork, private_key: &str) -> Result<Wallet> {
    let wallet = Wallet::new_from_private_key(network.clone(), private_key)
        .map_err(|e| AnvilError::Startup(format!("Failed to create funded wallet: {e}")))?;
    debug!(
        "Created funded wallet for explicit network: {}",
        wallet.address()
    );
    Ok(wallet)
}

/// Pre-funded test accounts from Anvil.
///
/// These accounts are available by default in Anvil with the standard mnemonic:
/// "test test test test test test test test test test test junk"
pub mod test_accounts {
    /// Account #0 address
    pub const ACCOUNT_0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    /// Account #0 private key
    pub const ACCOUNT_0_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    /// Account #1 address
    #[allow(dead_code)]
    pub const ACCOUNT_1: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    /// Account #1 private key
    #[allow(dead_code)]
    pub const ACCOUNT_1_KEY: &str =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    /// Account #2 address
    #[allow(dead_code)]
    pub const ACCOUNT_2: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
    /// Account #2 private key
    #[allow(dead_code)]
    pub const ACCOUNT_2_KEY: &str =
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_anvil_creation() {
        let anvil = TestAnvil::new().await.unwrap();
        let _network = anvil.to_network();
        assert!(!anvil.default_wallet_key().unwrap().is_empty());
    }

    #[test]
    fn test_account_constants() {
        assert!(test_accounts::ACCOUNT_0.starts_with("0x"));
        assert!(test_accounts::ACCOUNT_0_KEY.starts_with("0x"));
    }
}
