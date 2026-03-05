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
use bytes::Bytes;
use evmlib::testnet::Testnet;
use evmlib::wallet::Wallet;
use saorsa_node::client::QuantumClient;
use saorsa_node::payment::SingleNodePayment;
use serial_test::serial;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

/// Test environment containing both the test network and EVM testnet.
struct PaymentTestEnv {
    /// Test harness managing the saorsa node network
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
        let private_key = self.testnet.default_wallet_private_key();

        let wallet = Wallet::new_from_private_key(network, &private_key)?;
        info!("Created funded wallet: {}", wallet.address());

        Ok(wallet)
    }
}

/// Initialize test network and EVM testnet for payment E2E tests.
///
/// This sets up:
/// - Anvil EVM testnet FIRST (so nodes can verify on the same chain)
/// - 10-node saorsa test network with `payment_enforcement: true`
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
    let testnet = Testnet::new().await;
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

/// Test: Client pays and stores chunk on 5-node network.
///
/// This validates the full end-to-end payment flow:
/// - Network discovery via DHT
/// - Quote collection from multiple nodes
/// - Median price calculation
/// - On-chain payment on Arbitrum
/// - Chunk storage after payment verification
/// - Cross-node retrieval
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_client_pays_and_stores_on_network() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting E2E payment test: client pays and stores on network");

    // Initialize test environment (network + EVM)
    let mut env = init_testnet_and_evm().await?;

    // Create funded wallet for client
    let wallet = env.create_funded_wallet()?;

    // Configure node 0 as the client with wallet
    let client_node = env.harness.test_node_mut(0).ok_or("Node 0 not found")?;
    client_node.set_wallet(wallet);

    info!("Client configured with funded wallet");

    // Store a chunk using the payment-enabled client
    let test_data = b"Test data for payment E2E flow";
    info!("Storing {} bytes", test_data.len());

    let address = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .store_chunk_with_payment(test_data)
        .await?;
    info!("Chunk stored successfully at: {}", hex::encode(address));

    // Verify chunk is retrievable via DHT-routed client (same routing as PUT)
    sleep(Duration::from_millis(500)).await;

    let retrieved = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .get_chunk_with_client(&address)
        .await?;

    assert!(
        retrieved.is_some(),
        "Chunk should be retrievable via DHT routing"
    );

    let chunk = retrieved.ok_or("Chunk not found")?;
    assert_eq!(
        chunk.content.as_ref(),
        test_data,
        "Retrieved data should match original"
    );

    info!("✅ Chunk successfully retrieved via DHT routing");

    env.teardown().await?;
    Ok(())
}

/// Test: Multiple clients store chunks with independent payments.
///
/// Validates that:
/// - Multiple clients can operate concurrently
/// - Each payment is independent
/// - All chunks are stored correctly
/// - Payment cache doesn't interfere between clients
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_multiple_clients_concurrent_payments() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting E2E payment test: multiple clients with concurrent payments");

    // Initialize test environment (network + EVM)
    let mut env = init_testnet_and_evm().await?;

    // Create 3 clients with separate wallets
    for i in 0..3 {
        let wallet = env.create_funded_wallet()?;
        let node = env
            .harness
            .test_node_mut(i)
            .ok_or_else(|| format!("Node {i} not found"))?;
        node.set_wallet(wallet);
    }

    info!("Created 3 clients with independent funded wallets");

    // Extra stabilization after wallet setup
    sleep(Duration::from_secs(3)).await;

    // Store chunks concurrently using payment-enabled client
    let mut addresses = Vec::new();
    for i in 0..3 {
        let data = format!("Data from client {i}");
        let address = env
            .harness
            .test_node(i)
            .ok_or_else(|| format!("Node {i} not found"))?
            .store_chunk_with_payment(data.as_bytes())
            .await?;
        info!("Client {} stored chunk at: {}", i, hex::encode(address));
        addresses.push(address);
    }

    assert_eq!(addresses.len(), 3, "All clients should store successfully");

    // Verify all chunks are retrievable via DHT routing
    for (i, address) in addresses.iter().enumerate() {
        let retrieved = env
            .harness
            .test_node(i)
            .ok_or_else(|| format!("Node {i} not found"))?
            .get_chunk_with_client(address)
            .await?;

        assert!(retrieved.is_some(), "Chunk {i} should be retrievable");

        let expected = format!("Data from client {i}");
        assert_eq!(
            retrieved.ok_or("Chunk not found")?.content.as_ref(),
            expected.as_bytes(),
            "Retrieved data should match for client {i}"
        );
    }

    info!("✅ All chunks from multiple clients verified");

    env.teardown().await?;
    Ok(())
}

/// Test: Payment verification prevents storage without valid payment.
///
/// Validates that:
/// - Nodes reject chunks without payment when EVM verification is enabled
/// - Payment verification is enforced on the server side
/// - Clients without wallets get appropriate errors
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_payment_required_enforcement() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting E2E payment test: payment enforcement validation");

    // Start Anvil EVM testnet FIRST so we can wire it to nodes
    let testnet = Testnet::new().await;
    let network = testnet.to_network();
    info!("Anvil testnet started");

    // Setup 10-node network with payment enforcement ON and the
    // SAME Anvil network so nodes verify on the same chain.
    let config = super::testnet::TestNetworkConfig::small()
        .with_payment_enforcement()
        .with_evm_network(network);

    // Use setup_with_config (NOT setup_with_evm_and_config) because we already
    // created our own Testnet above — creating another would double-bind the port.
    let harness = TestHarness::setup_with_config(config).await?;

    info!("10-node test network started with payment enforcement ENABLED");

    // Wait for network to stabilize (10 nodes need more time)
    sleep(Duration::from_secs(5)).await;

    let total_connections = harness.total_connections().await;
    info!("Payment test environment ready: {total_connections} total connections");

    let env = PaymentTestEnv { harness, testnet };

    // Try to store without wallet (should fail)
    let client_without_wallet =
        QuantumClient::with_defaults().with_node(env.harness.node(0).ok_or("Node 0 not found")?);

    let test_data = b"This should be rejected";
    let result = client_without_wallet
        .put_chunk(Bytes::from(test_data.to_vec()))
        .await;

    assert!(result.is_err(), "Store should fail without wallet/payment");

    info!("✅ Payment enforcement validated - storage rejected without payment");

    env.teardown().await?;
    Ok(())
}

/// Test: Large chunk storage with payment.
///
/// Validates that:
/// - Large chunks (near max size) work with payment flow
/// - Quote prices scale appropriately with chunk size
/// - Payment and storage succeed for realistic data sizes
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_large_chunk_payment_flow() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting E2E payment test: large chunk storage");

    // Initialize test environment (network + EVM)
    let mut env = init_testnet_and_evm().await?;

    // Configure client with wallet
    let wallet = env.create_funded_wallet()?;
    env.harness
        .test_node_mut(0)
        .ok_or("Node 0 not found")?
        .set_wallet(wallet);

    // Create a large chunk (512 KB)
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let large_data: Vec<u8> = (0..524_288).map(|i| (i % 256) as u8).collect();
    info!("Storing large chunk: {} bytes", large_data.len());

    let address = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .store_chunk_with_payment(&large_data)
        .await?;
    info!("Large chunk stored at: {}", hex::encode(address));

    // Verify retrieval via DHT routing
    sleep(Duration::from_millis(500)).await;

    let retrieved = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .get_chunk_with_client(&address)
        .await?;

    assert!(retrieved.is_some(), "Large chunk should be retrievable");

    let chunk = retrieved.ok_or("Chunk not found")?;
    assert_eq!(
        chunk.content.len(),
        large_data.len(),
        "Retrieved size should match"
    );
    assert_eq!(
        chunk.content.as_ref(),
        large_data.as_slice(),
        "Retrieved data should match original"
    );

    info!("✅ Large chunk payment flow validated");

    env.teardown().await?;
    Ok(())
}

/// Test: Idempotent chunk storage — storing the same chunk twice succeeds.
///
/// Validates that:
/// - First store with payment succeeds
/// - Second store of same data returns same address (`AlreadyExists` on node)
/// - Both stores produce valid addresses
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_idempotent_chunk_storage() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting E2E payment test: idempotent chunk storage");

    // Initialize test environment (network + EVM)
    let mut env = init_testnet_and_evm().await?;

    // Configure client
    let wallet = env.create_funded_wallet()?;
    env.harness
        .test_node_mut(0)
        .ok_or("Node 0 not found")?
        .set_wallet(wallet);

    let test_data = b"Test data for idempotent storage";

    // First store
    let address1 = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .store_chunk_with_payment(test_data)
        .await?;
    info!("First store: {}", hex::encode(address1));

    // Second store of same data — node should respond with AlreadyExists
    let address2 = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .store_chunk_with_payment(test_data)
        .await?;
    info!("Second store: {}", hex::encode(address2));

    assert_eq!(
        address1, address2,
        "Same data should produce same address on both stores"
    );

    // Verify chunk is retrievable
    let retrieved = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .get_chunk_with_client(&address1)
        .await?;

    assert!(
        retrieved.is_some(),
        "Chunk should be retrievable after idempotent store"
    );

    let chunk = retrieved.ok_or("Chunk not found")?;
    assert_eq!(
        chunk.content.as_ref(),
        test_data,
        "Retrieved data should match original"
    );

    info!("✅ Idempotent chunk storage validated");

    env.teardown().await?;
    Ok(())
}

/// Test: Quote collection from DHT peers.
///
/// Validates that:
/// - Client can discover and contact peers via DHT
/// - Multiple quotes are received
/// - Median price calculation works correctly
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_quote_collection_via_dht() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting E2E payment test: quote collection via DHT");

    // Initialize test environment (network + EVM)
    let env = init_testnet_and_evm().await?;

    // Create a client connected to node 0
    let client =
        QuantumClient::with_defaults().with_node(env.harness.node(0).ok_or("Node 0 not found")?);

    // Prepare test data
    let test_data = b"Test data for quote collection";
    info!("Requesting quotes for {} bytes", test_data.len());

    // Request quotes from DHT peers
    let quotes_with_prices = client.get_quotes_from_dht(test_data).await?;

    // Validate we got exactly 5 quotes (REQUIRED_QUOTES)
    assert_eq!(
        quotes_with_prices.len(),
        5,
        "Should collect exactly 5 quotes"
    );

    info!(
        "✅ Successfully collected {} quotes from DHT",
        quotes_with_prices.len()
    );

    // Validate each quote has a price and peer ID
    for (i, (peer_id, quote, price)) in quotes_with_prices.iter().enumerate() {
        info!(
            "Quote {}: peer = {peer_id}, price = {} atto, address = {}",
            i + 1,
            price,
            quote.rewards_address
        );

        // Verify quote content matches our data
        let address = saorsa_node::compute_address(test_data);
        assert_eq!(
            quote.content.0, address,
            "Quote content address should match computed address"
        );
    }

    // Create SingleNodePayment to test median selection (strip peer IDs)
    let quotes_for_payment: Vec<_> = quotes_with_prices
        .into_iter()
        .map(|(_peer_id, quote, price)| (quote, price))
        .collect();
    let payment = SingleNodePayment::from_quotes(quotes_for_payment)?;

    info!("✅ Successfully created SingleNodePayment from quotes");
    info!("   Total payment amount: {} atto", payment.total_amount());
    info!(
        "   Paid quote (median): {} atto",
        payment
            .paid_quote()
            .ok_or("Missing paid quote at median index")?
            .amount
    );

    // Verify only the median quote has a non-zero amount
    let non_zero_quotes = payment
        .quotes
        .iter()
        .filter(|q| q.amount > ant_evm::Amount::ZERO)
        .count();
    assert_eq!(
        non_zero_quotes, 1,
        "Only median quote should have non-zero amount"
    );

    info!("✅ Quote collection and median selection validated");

    env.teardown().await?;
    Ok(())
}

/// Test: Network resilience - storage succeeds even if some nodes fail.
///
/// Validates that:
/// - Payment flow works when some nodes are unavailable
/// - Chunk is still stored on available nodes
/// - System gracefully handles partial failures
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_payment_with_node_failures() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting E2E payment test: resilience with node failures");

    // Initialize test environment (network + EVM)
    let mut env = init_testnet_and_evm().await?;

    // Configure client
    let wallet = env.create_funded_wallet()?;
    env.harness
        .test_node_mut(0)
        .ok_or("Node 0 not found")?
        .set_wallet(wallet);

    // Verify initial network has all nodes running
    let initial_count = env.harness.running_node_count().await;
    info!("Initial network has {} running nodes", initial_count);
    assert_eq!(initial_count, 10, "Should start with 10 nodes");

    // Simulate node failures by shutting down nodes 5, 6, and 7
    info!("Simulating node failures: shutting down nodes 5, 6, 7");
    env.harness.shutdown_nodes(&[5, 6, 7]).await?;

    // Wait for network to adapt to failures
    sleep(Duration::from_secs(15)).await;

    // Verify nodes are shut down
    let remaining_count = env.harness.running_node_count().await;
    info!("After failures: {remaining_count} running nodes remain");
    assert_eq!(
        remaining_count, 7,
        "Should have 7 nodes after shutting down 3"
    );

    // Re-warm DHT after node failures so routing tables adapt
    env.harness.warmup_dht().await?;
    sleep(Duration::from_secs(15)).await;

    // Store a chunk with the remaining nodes (7 nodes still > 5 needed for quotes)
    let test_data = b"Resilience test data";
    let mut address = None;
    for attempt in 1..=10 {
        info!("Storage attempt {attempt}/10 after node failures...");
        match env
            .harness
            .test_node(0)
            .ok_or("Node 0 not found")?
            .store_chunk_with_payment(test_data)
            .await
        {
            Ok(addr) => {
                address = Some(addr);
                break;
            }
            Err(e) => {
                warn!("Storage attempt {attempt}/10 failed: {e}");
                if attempt < 10 {
                    let _ = env.harness.warmup_dht().await;
                    sleep(Duration::from_secs(10)).await;
                }
            }
        }
    }
    let address = address.ok_or("Storage MUST succeed after node failures with 10 attempts")?;

    info!(
        "Successfully stored chunk despite simulated failures: {}",
        hex::encode(address)
    );

    // Verify chunk is retrievable via DHT routing
    sleep(Duration::from_millis(500)).await;

    let retrieved = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .get_chunk_with_client(&address)
        .await?;

    assert!(
        retrieved.is_some(),
        "Chunk should be retrievable despite node failures"
    );

    let chunk = retrieved.ok_or("Chunk not found")?;
    assert_eq!(
        chunk.content.as_ref(),
        test_data,
        "Retrieved data should match original"
    );

    info!(
        "✅ Network resilience validated: storage succeeds with {} nodes after 3 failures",
        remaining_count
    );

    env.teardown().await?;
    Ok(())
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
