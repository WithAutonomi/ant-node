//! E2E tests for payment-enabled chunk storage across multiple nodes.
//!
//! These tests validate the full payment workflow for chunk storage:
//!
//! **Payment Workflow**:
//! 1. Client requests quotes from 5 network nodes via DHT
//! 2. Client sorts quotes by price and selects median
//! 3. Client pays median node 3x on Arbitrum (`SingleNode` payment strategy)
//! 4. Client sends 0 atto to the other 4 nodes for verification
//! 5. Client sends chunk with `ProofOfPayment` to storage nodes
//! 6. Nodes verify payment on-chain before storing (when EVM verification enabled)
//! 7. Chunk is retrievable from the network
//!
//! **Test Coverage**:
//! - Network setup with 10-node test network and Anvil EVM testnet
//! - Wallet creation and funding
//! - Quote collection from DHT peers
//! - Median price calculation and `SingleNode` payment
//! - On-chain payment verification
//! - Payment cache preventing duplicate payments
//! - Network resilience with node failures
//!
//! **Network Setup**: Uses a 10-node test network (need 8+ for `CLOSE_GROUP_SIZE`).

use super::harness::TestHarness;
use evmlib::testnet::Testnet;
use evmlib::wallet::Wallet;
use serial_test::serial;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

/// Test environment containing both the test network and EVM testnet.
struct PaymentTestEnv {
    /// Test harness managing the ant node network
    harness: TestHarness,
    /// Anvil EVM testnet for payment testing
    testnet: Testnet,
}

impl PaymentTestEnv {
    /// Teardown the test environment.
    async fn teardown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.harness.teardown().await?;
        Ok(())
    }

    /// Create a funded wallet from the Anvil testnet.
    fn create_funded_wallet(&self) -> Result<Wallet, Box<dyn std::error::Error>> {
        let network = self.testnet.to_network();
        let private_key = self.testnet.default_wallet_private_key()?;

        let wallet = Wallet::new_from_private_key(network, &private_key)?;
        info!("Created funded wallet: {}", wallet.address());

        Ok(wallet)
    }
}

/// Initialize test network and EVM testnet for payment E2E tests.
///
/// This sets up:
/// - Anvil EVM testnet FIRST (so nodes can verify on the same chain)
/// - 10-node ant test network with `payment_enforcement: true`
/// - Network stabilization wait (5 seconds for 10 nodes)
///
/// All nodes share the SAME Anvil instance as the client wallet,
/// so on-chain verification is real, not bypassed.
///
/// # Returns
///
/// A `PaymentTestEnv` containing both the network harness and EVM testnet.
async fn init_testnet_and_evm() -> Result<PaymentTestEnv, Box<dyn std::error::Error>> {
    info!("Initializing payment test environment");

    // Start Anvil EVM testnet FIRST so we can wire it to nodes
    let testnet = Testnet::new().await?;
    let network = testnet.to_network();
    info!("Anvil testnet started");

    // Setup 10-node network with payment enforcement ON and the
    // SAME Anvil network so nodes verify on the same chain the client pays on.
    let config = super::testnet::TestNetworkConfig::small()
        .with_payment_enforcement()
        .with_evm_network(network);

    // Use setup_with_config (NOT setup_with_evm_and_config) because we already
    // created our own Testnet above — creating another would double-bind the port.
    let harness = TestHarness::setup_with_config(config).await?;

    info!("10-node test network started with payment enforcement ENABLED");

    // Wait for network to stabilize (10 nodes need more time)
    sleep(Duration::from_secs(10)).await;

    let total_connections = harness.total_connections().await;
    info!("Network stabilized with {total_connections} total connections");

    // Warm up DHT routing tables (essential for quote collection and chunk routing)
    harness.warmup_dht().await?;
    sleep(Duration::from_secs(5)).await;
    info!("Payment test environment ready");

    Ok(PaymentTestEnv { harness, testnet })
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    /// Test initialization helper.
    #[tokio::test]
    #[serial]
    async fn test_init_testnet_and_evm() -> Result<(), Box<dyn std::error::Error>> {
        let env = init_testnet_and_evm().await?;

        // Verify we can create wallets
        let wallet = env.create_funded_wallet()?;
        assert!(!wallet.address().to_string().is_empty());

        // Verify harness is accessible
        assert!(env.harness.node(0).is_some(), "Node 0 should exist");

        env.teardown().await?;
        Ok(())
    }
}
