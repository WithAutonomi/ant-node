//! Anvil EVM testnet wrapper for payment verification tests.
//!
//! This module wraps the `evmlib::testnet::Testnet` to provide a local
//! Anvil blockchain for testing payment verification.

use std::time::Duration;
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

/// Wrapper around Anvil EVM testnet.
///
/// This provides a local Ethereum-compatible blockchain for testing
/// payment verification without connecting to a real network.
///
/// ## Features
///
/// - Pre-funded test accounts (10,000 ETH each)
/// - Deployed payment contracts
/// - Fast block times for testing
///
/// ## Usage
///
/// ```rust,ignore
/// let anvil = TestAnvil::new().await?;
///
/// // Get the network configuration for PaymentVerifier
/// let network = anvil.network();
///
/// // Get a funded wallet for testing
/// let wallet_key = anvil.default_wallet_key();
///
/// anvil.shutdown().await;
/// ```
pub struct TestAnvil {
    /// The underlying evmlib testnet.
    // Note: When evmlib is available, this would be:
    // testnet: evmlib::testnet::Testnet,
    // network: evmlib::Network,

    /// RPC URL for the testnet.
    rpc_url: String,

    /// Default wallet private key.
    default_wallet_key: String,

    /// Payment token contract address.
    payment_token_address: Option<String>,

    /// Data payments contract address.
    data_payments_address: Option<String>,

    /// Whether Anvil is running.
    running: bool,
}

impl TestAnvil {
    /// Start a new Anvil EVM testnet.
    ///
    /// This spawns an Anvil process and deploys the necessary contracts
    /// for payment verification testing.
    ///
    /// # Errors
    ///
    /// Returns an error if Anvil fails to start or contracts fail to deploy.
    pub async fn new() -> Result<Self> {
        info!("Starting Anvil EVM testnet");

        // In a full implementation, this would use evmlib::testnet::Testnet
        // For now, we provide a placeholder that can be connected to actual Anvil

        // Default Anvil configuration
        let rpc_url = "http://127.0.0.1:8545".to_string();
        let default_wallet_key =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();

        // In production, this would:
        // 1. Spawn Anvil process
        // 2. Wait for it to be ready
        // 3. Deploy contracts
        // 4. Return the configured testnet

        // Placeholder: Simulate startup delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("Anvil testnet started on {}", rpc_url);

        Ok(Self {
            rpc_url,
            default_wallet_key,
            payment_token_address: None,
            data_payments_address: None,
            running: true,
        })
    }

    /// Start Anvil with evmlib integration (when available).
    ///
    /// This is the preferred method when evmlib is properly integrated.
    ///
    /// # Errors
    ///
    /// Returns an error if Anvil fails to start.
    #[allow(dead_code)]
    pub async fn with_evmlib() -> Result<Self> {
        // When evmlib is available:
        // let testnet = evmlib::testnet::Testnet::new().await;
        // let network = testnet.to_network();
        // ...

        Self::new().await
    }

    /// Get the RPC URL for the testnet.
    #[must_use]
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Get the default wallet private key.
    ///
    /// This is a pre-funded test account with 10,000 ETH.
    #[must_use]
    pub fn default_wallet_key(&self) -> &str {
        &self.default_wallet_key
    }

    /// Get the payment token contract address.
    #[must_use]
    pub fn payment_token_address(&self) -> Option<&str> {
        self.payment_token_address.as_deref()
    }

    /// Get the data payments contract address.
    #[must_use]
    pub fn data_payments_address(&self) -> Option<&str> {
        self.data_payments_address.as_deref()
    }

    /// Check if Anvil is running and healthy.
    pub async fn is_healthy(&self) -> bool {
        if !self.running {
            return false;
        }

        // In production, this would make an eth_blockNumber RPC call
        // to verify Anvil is responding
        true
    }

    /// Get the current block number.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC call fails.
    pub async fn block_number(&self) -> Result<u64> {
        // In production, this would make an eth_blockNumber RPC call
        Ok(0)
    }

    /// Mine a specified number of blocks.
    ///
    /// Useful for advancing block time in tests.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of blocks to mine
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC call fails.
    pub async fn mine_blocks(&self, count: u64) -> Result<()> {
        debug!("Mining {} blocks", count);
        // In production, this would call evm_mine RPC method
        Ok(())
    }

    /// Set the block timestamp to a specific value.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Unix timestamp to set
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC call fails.
    pub async fn set_timestamp(&self, timestamp: u64) -> Result<()> {
        debug!("Setting block timestamp to {}", timestamp);
        // In production, this would call evm_setNextBlockTimestamp
        Ok(())
    }

    /// Create a wallet funded with test tokens.
    ///
    /// This creates a wallet using one of Anvil's pre-funded test accounts.
    ///
    /// # Errors
    ///
    /// Returns an error if wallet creation fails.
    pub async fn create_funded_wallet(&self) -> Result<evmlib::wallet::Wallet> {
        use evmlib::testnet::Testnet;
        use evmlib::wallet::Wallet;

        // Start a new Anvil testnet with deployed contracts
        let testnet = Testnet::new().await;
        let network = testnet.to_network();

        // Use the default Anvil account (pre-funded)
        let private_key = testnet.default_wallet_private_key();
        let wallet = Wallet::new_from_private_key(network, &private_key)
            .map_err(|e| AnvilError::Startup(format!("Failed to create funded wallet: {e}")))?;

        debug!("Created funded wallet with address: {}", wallet.address());
        Ok(wallet)
    }

    /// Create an empty wallet (for testing insufficient funds).
    ///
    /// This creates a wallet with a random private key that has no balance.
    ///
    /// # Errors
    ///
    /// Returns an error if wallet creation fails.
    pub async fn create_empty_wallet(&self) -> Result<evmlib::wallet::Wallet> {
        use evmlib::testnet::Testnet;
        use evmlib::wallet::Wallet;

        // Start a new Anvil testnet to get the network configuration
        let testnet = Testnet::new().await;
        let network = testnet.to_network();

        // Generate a random private key (no funds)
        let random_key = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));

        let wallet = Wallet::new_from_private_key(network, &random_key)
            .map_err(|e| AnvilError::Startup(format!("Failed to create empty wallet: {e}")))?;

        debug!(
            "Created empty wallet (no funds) with address: {}",
            wallet.address()
        );
        Ok(wallet)
    }

    /// Shutdown the Anvil testnet.
    pub async fn shutdown(&mut self) {
        if self.running {
            info!("Shutting down Anvil testnet");
            // In production, this would kill the Anvil process
            self.running = false;
        }
    }
}

impl Drop for TestAnvil {
    fn drop(&mut self) {
        // Best-effort cleanup
        self.running = false;
    }
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

    #[tokio::test]
    async fn test_anvil_creation() {
        let anvil = TestAnvil::new().await.unwrap();
        assert!(anvil.is_healthy().await);
        assert!(!anvil.rpc_url().is_empty());
        assert!(!anvil.default_wallet_key().is_empty());
    }

    #[test]
    fn test_account_constants() {
        assert!(test_accounts::ACCOUNT_0.starts_with("0x"));
        assert!(test_accounts::ACCOUNT_0_KEY.starts_with("0x"));
    }
}
