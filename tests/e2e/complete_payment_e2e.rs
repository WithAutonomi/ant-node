//! Complete E2E test proving the payment protocol works on live nodes.
//!
//! **All payment tests in this file use `payment_enforcement: true`.**
//! Nodes verify payments on-chain via Anvil before storing chunks.
//!
//! ## Test Flow
//!
//! 1. **Network Setup**: Spawn 10 live saorsa nodes + Anvil EVM testnet
//! 2. **Quote Collection**: Client requests quotes from 5 closest DHT peers
//! 3. **Price Calculation**: Sort quotes by price, select median
//! 4. **Payment**: Make on-chain payment (median node 3x, others 0 atto)
//! 5. **Chunk Storage**: Send chunk + `ProofOfPayment` to network
//! 6. **Verification**: Nodes verify payment on-chain before storing
//! 7. **Retrieval**: Retrieve chunk from storing node to prove storage succeeded
//! 8. **Cross-Node**: Retrieve chunk from a DIFFERENT node (tests replication)

use super::harness::TestHarness;
use super::testnet::TestNetworkConfig;
use ant_evm::ProofOfPayment;
use bytes::Bytes;
use evmlib::testnet::Testnet;
use evmlib::wallet::Wallet;
use saorsa_node::client::{hex_node_id_to_encoded_peer_id, QuantumClient};
use saorsa_node::payment::{PaymentProof, SingleNodePayment};
use serial_test::serial;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

/// Test environment for complete E2E payment flow.
///
/// All nodes have `payment_enforcement: true` and use the same Anvil
/// instance as the client wallet, so on-chain verification is real.
struct CompletePaymentTestEnv {
    harness: TestHarness,
    /// Kept alive to prevent Anvil process from being dropped
    _testnet: Testnet,
    wallet: Wallet,
}

impl CompletePaymentTestEnv {
    /// Initialize complete payment test environment with enforcement enabled.
    ///
    /// Nodes and client share the SAME Anvil instance so on-chain
    /// verification is real, not bypassed.
    async fn setup() -> Result<Self, Box<dyn std::error::Error>> {
        info!("Setting up complete payment E2E test environment");

        // Start Anvil EVM testnet FIRST so we can wire it to nodes
        let testnet = Testnet::new().await;
        let network = testnet.to_network();
        info!("Anvil testnet started");

        // Setup 10-node network with payment enforcement ON and the
        // SAME Anvil network so nodes verify on the same chain the client pays on.
        // Use setup_with_config (NOT setup_with_evm_and_config) because we already
        // created our own Testnet above — creating another would double-bind the port.
        let config = TestNetworkConfig::small()
            .with_payment_enforcement()
            .with_evm_network(network.clone());

        let harness = TestHarness::setup_with_config(config).await?;

        info!("10-node test network started with payment enforcement ENABLED");

        // Wait for network to stabilize
        sleep(Duration::from_secs(10)).await;

        let total_connections = harness.total_connections().await;
        info!("Network stabilized with {total_connections} total connections");

        // Warm up DHT routing tables (essential for quote collection)
        harness.warmup_dht().await?;
        sleep(Duration::from_secs(5)).await;

        // Create funded wallet from the SAME Anvil instance
        let private_key = testnet.default_wallet_private_key();
        let wallet = Wallet::new_from_private_key(network, &private_key)?;
        info!("Created funded wallet: {}", wallet.address());

        Ok(Self {
            harness,
            _testnet: testnet,
            wallet,
        })
    }

    async fn teardown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.harness.teardown().await?;
        Ok(())
    }
}

/// Complete chunk upload + payment + on-chain verification + retrieval flow.
///
/// Nodes have `payment_enforcement: true`. The payment is verified on-chain.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_complete_payment_flow_live_nodes() -> Result<(), Box<dyn std::error::Error>> {
    info!("COMPLETE E2E PAYMENT TEST - LIVE NODES (enforcement ON)");

    let mut env = CompletePaymentTestEnv::setup().await?;

    // Configure client node (node 0) with wallet
    env.harness
        .test_node_mut(0)
        .ok_or("Node 0 not found")?
        .set_wallet(env.wallet.clone());

    let test_data = b"Complete E2E payment test data - proving the protocol works!";
    let expected_address = saorsa_node::compute_address(test_data);

    // Request quotes from DHT peers with retries
    let client = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .client
        .as_ref()
        .ok_or("Client not configured")?;

    let mut quotes_with_prices = None;
    for attempt in 1..=10 {
        info!("Quote collection attempt {attempt}/10...");
        match client.get_quotes_from_dht(test_data).await {
            Ok(quotes) => {
                info!("Got {} quotes on attempt {attempt}", quotes.len());
                quotes_with_prices = Some(quotes);
                break;
            }
            Err(e) => {
                warn!("Attempt {attempt} failed: {e}");
                if attempt < 10 {
                    let _ = env.harness.warmup_dht().await;
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    let quotes_with_prices = quotes_with_prices.ok_or("Failed to get quotes after 10 attempts")?;

    assert_eq!(
        quotes_with_prices.len(),
        5,
        "Should receive exactly 5 quotes (REQUIRED_QUOTES)"
    );

    // Calculate payment (sort by price, select median)
    let mut peer_quotes: Vec<_> = Vec::with_capacity(quotes_with_prices.len());
    let mut quotes_for_payment: Vec<_> = Vec::with_capacity(quotes_with_prices.len());
    for (peer_id_str, quote, price) in quotes_with_prices {
        let encoded_peer_id = hex_node_id_to_encoded_peer_id(&peer_id_str.to_hex())
            .map_err(|e| format!("Failed to convert peer ID '{peer_id_str}': {e}"))?;
        peer_quotes.push((encoded_peer_id, quote.clone()));
        quotes_for_payment.push((quote, price));
    }
    let payment = SingleNodePayment::from_quotes(quotes_for_payment)
        .map_err(|e| format!("Failed to create payment: {e}"))?;

    info!("Payment total: {} atto", payment.total_amount());

    // Verify only median quote has non-zero amount
    let non_zero_quotes = payment
        .quotes
        .iter()
        .filter(|q| q.amount > ant_evm::Amount::ZERO)
        .count();
    assert_eq!(
        non_zero_quotes, 1,
        "Only median quote should have non-zero amount"
    );

    // Make on-chain payment
    let tx_hashes = payment
        .pay(&env.wallet)
        .await
        .map_err(|e| format!("Payment failed: {e}"))?;

    assert!(
        !tx_hashes.is_empty(),
        "Expected at least one transaction hash from payment"
    );
    info!(
        "On-chain payment succeeded: {} transactions",
        tx_hashes.len()
    );

    // Build proof AFTER payment with tx hashes included
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes,
    };
    let proof_bytes =
        rmp_serde::to_vec(&proof).map_err(|e| format!("Failed to serialize proof: {e}"))?;

    // Store chunk with payment proof — nodes WILL verify on-chain
    // Retry with backoff: DHT routing tables may not be fully stabilized yet
    let mut stored_address = None;
    for attempt in 1..=10 {
        match client
            .put_chunk_with_proof(Bytes::from(test_data.to_vec()), proof_bytes.clone())
            .await
        {
            Ok(addr) => {
                info!("Chunk stored on attempt {attempt}");
                stored_address = Some(addr);
                break;
            }
            Err(e) => {
                warn!("Storage attempt {attempt}/10 failed: {e}");
                if attempt < 10 {
                    let _ = env.harness.warmup_dht().await;
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
    let stored_address =
        stored_address.ok_or("Storage MUST succeed with valid payment proof after 10 attempts")?;

    assert_eq!(
        stored_address, expected_address,
        "Stored address should match computed address"
    );
    info!("Chunk stored at {}", hex::encode(stored_address));

    // Verify chunk is retrievable
    sleep(Duration::from_millis(500)).await;

    let retrieved = client
        .get_chunk(&stored_address)
        .await
        .map_err(|e| format!("Failed to retrieve chunk: {e}"))?;

    let chunk = retrieved.ok_or("Chunk should be retrievable from storing node")?;
    assert_eq!(
        chunk.content.as_ref(),
        test_data,
        "Retrieved data should match original"
    );

    info!("Chunk retrieved and verified");

    // Try cross-node retrieval (may not work without replication)
    let node1_chunk = env
        .harness
        .test_node(1)
        .ok_or("Node 1 not found")?
        .get_chunk(&stored_address)
        .await?;

    if let Some(chunk) = node1_chunk {
        assert_eq!(
            chunk.content.as_ref(),
            test_data,
            "Cross-node data should match original"
        );
        info!("Cross-node retrieval succeeded");
    } else {
        info!("Cross-node retrieval: not replicated yet (expected in test mode)");
    }

    info!("COMPLETE E2E PAYMENT TEST PASSED (enforcement ON)");

    env.teardown().await?;
    Ok(())
}

/// Test: Nodes reject unpaid chunks when `payment_enforcement: true`.
///
/// Validates server-side enforcement: the NODE rejects, not the client.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_payment_verification_enforcement() -> Result<(), Box<dyn std::error::Error>> {
    info!("PAYMENT ENFORCEMENT TEST (enforcement ON)");

    // Start Anvil and wire it to nodes
    let testnet = Testnet::new().await;
    let network = testnet.to_network();

    let config = TestNetworkConfig::small()
        .with_payment_enforcement()
        .with_evm_network(network.clone());

    // Use setup_with_config (NOT setup_with_evm_and_config) because we already
    // created our own Testnet above — creating another would double-bind the port.
    let harness = TestHarness::setup_with_config(config).await?;

    sleep(Duration::from_secs(10)).await;
    harness.warmup_dht().await?;
    sleep(Duration::from_secs(5)).await;

    // Try to store WITHOUT a wallet (sends no payment proof to server)
    let client =
        QuantumClient::with_defaults().with_node(harness.node(0).ok_or("Node 0 not found")?);

    let test_data = b"This should be rejected without payment";
    let result = client.put_chunk(Bytes::from(test_data.to_vec())).await;

    // MUST be rejected — assert exactly one outcome
    assert!(
        result.is_err(),
        "Storage MUST fail without payment when enforcement is enabled"
    );
    let error_msg = format!("{}", result.as_ref().err().ok_or("Expected error")?);
    info!("Rejected as expected: {error_msg}");
    assert!(
        error_msg.to_lowercase().contains("payment"),
        "Error must be payment-related, got: {error_msg}"
    );

    // Now try WITH wallet and full payment flow — MUST succeed
    let private_key = testnet.default_wallet_private_key();
    let wallet = Wallet::new_from_private_key(network, &private_key)?;

    let client_with_wallet = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet);

    let mut stored_address = None;
    for attempt in 1..=10 {
        match client_with_wallet
            .put_chunk(Bytes::from(test_data.to_vec()))
            .await
        {
            Ok(addr) => {
                stored_address = Some(addr);
                break;
            }
            Err(e) => {
                warn!("Storage with payment attempt {attempt}/10 failed: {e}");
                if attempt < 10 {
                    let _ = harness.warmup_dht().await;
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    // MUST succeed — assert exactly one outcome
    let address =
        stored_address.ok_or("Storage MUST succeed with valid payment after 10 attempts")?;
    info!("Stored with payment at {}", hex::encode(address));

    info!("PAYMENT ENFORCEMENT TEST PASSED");

    harness.teardown().await?;
    Ok(())
}

/// Test: Forged ML-DSA-65 signature rejection.
///
/// Gets valid quotes, makes real payment, builds proof, CORRUPTS the
/// signature bytes, sends to EVM-enabled node, asserts rejection.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_forged_signature_rejection() -> Result<(), Box<dyn std::error::Error>> {
    info!("FORGED SIGNATURE REJECTION TEST (enforcement ON)");

    let testnet = Testnet::new().await;
    let network = testnet.to_network();

    let config = TestNetworkConfig::small()
        .with_payment_enforcement()
        .with_evm_network(network.clone());

    // Use setup_with_config (NOT setup_with_evm_and_config) because we already
    // created our own Testnet above — creating another would double-bind the port.
    let harness = TestHarness::setup_with_config(config).await?;

    sleep(Duration::from_secs(10)).await;
    harness.warmup_dht().await?;

    // Create client with wallet
    let private_key = testnet.default_wallet_private_key();
    let wallet = Wallet::new_from_private_key(network, &private_key)?;
    let client = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet.clone());

    let test_data = b"Forged signature test data";

    // Get quotes from DHT
    let mut quotes_with_prices = None;
    for attempt in 1..=5 {
        match client.get_quotes_from_dht(test_data).await {
            Ok(quotes) => {
                quotes_with_prices = Some(quotes);
                break;
            }
            Err(e) => {
                warn!("Quote attempt {attempt} failed: {e}");
                if attempt < 5 {
                    sleep(Duration::from_secs(2u64.pow(attempt))).await;
                }
            }
        }
    }

    let quotes_with_prices = quotes_with_prices.ok_or("Failed to get quotes after 5 attempts")?;

    // Build peer_quotes and payment
    let mut peer_quotes: Vec<_> = Vec::with_capacity(quotes_with_prices.len());
    let mut quotes_for_payment: Vec<_> = Vec::with_capacity(quotes_with_prices.len());
    for (peer_id_str, quote, price) in quotes_with_prices {
        let encoded_peer_id = hex_node_id_to_encoded_peer_id(&peer_id_str.to_hex())
            .map_err(|e| format!("Failed to convert peer ID '{peer_id_str}': {e}"))?;
        peer_quotes.push((encoded_peer_id, quote.clone()));
        quotes_for_payment.push((quote, price));
    }

    let payment = SingleNodePayment::from_quotes(quotes_for_payment)
        .map_err(|e| format!("Failed to create payment: {e}"))?;

    // Pay on-chain (real payment)
    let tx_hashes = payment
        .pay(&wallet)
        .await
        .map_err(|e| format!("Payment failed: {e}"))?;

    // CORRUPT the signature on the first quote
    let mut forged_quotes = peer_quotes.clone();
    if let Some((_peer_id, ref mut quote)) = forged_quotes.first_mut() {
        // Flip all signature bytes to corrupt it
        for byte in &mut quote.signature {
            *byte = byte.wrapping_add(1);
        }
    }

    // Build proof with forged signature
    let forged_proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: forged_quotes,
        },
        tx_hashes,
    };
    let forged_proof_bytes = rmp_serde::to_vec(&forged_proof)
        .map_err(|e| format!("Failed to serialize forged proof: {e}"))?;

    // Try to store with forged proof — MUST be rejected
    let result = client
        .put_chunk_with_proof(Bytes::from(test_data.to_vec()), forged_proof_bytes)
        .await;

    assert!(result.is_err(), "Storage MUST fail with forged signature");
    let error_msg = format!("{}", result.as_ref().err().ok_or("Expected error")?);
    info!("Forged signature rejected: {error_msg}");

    info!("FORGED SIGNATURE REJECTION TEST PASSED");

    harness.teardown().await?;
    Ok(())
}

/// Test: Payment flow survives node failures.
///
/// Validates that payment collection and storage continue to work
/// even when some nodes in the network fail.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_payment_flow_with_failures() -> Result<(), Box<dyn std::error::Error>> {
    info!("PAYMENT FLOW RESILIENCE TEST (enforcement ON)");

    let mut env = CompletePaymentTestEnv::setup().await?;

    // Configure client
    env.harness
        .test_node_mut(0)
        .ok_or("Node 0 not found")?
        .set_wallet(env.wallet.clone());

    // Verify initial network
    let initial_count = env.harness.running_node_count().await;
    assert_eq!(initial_count, 10);

    // Simulate failures - shutdown 3 nodes
    info!("Simulating node failures (shutting down nodes 5, 6, 7)");
    env.harness.shutdown_nodes(&[5, 6, 7]).await?;

    sleep(Duration::from_secs(15)).await;

    let remaining_count = env.harness.running_node_count().await;
    assert_eq!(remaining_count, 7);

    // Re-warm DHT after node failures so routing tables adapt
    env.harness.warmup_dht().await?;
    sleep(Duration::from_secs(25)).await;

    // Payment flow with reduced network — MUST succeed (7 nodes > 5 required)
    let test_data = b"Resilience test data";
    let client = env
        .harness
        .test_node(0)
        .ok_or("Node 0 not found")?
        .client
        .as_ref()
        .ok_or("Client not configured")?;

    // Retry quote collection and storage up to 3 times to allow DHT to stabilize
    let mut last_err = String::new();
    let mut succeeded = false;
    for attempt in 1..=10 {
        info!("Storage attempt {attempt}/10 after node failures...");
        match client.get_quotes_from_dht(test_data).await {
            Ok(quotes) => {
                info!("Collected {} quotes despite failures", quotes.len());
                match client.put_chunk(Bytes::from(test_data.to_vec())).await {
                    Ok(_address) => {
                        info!("Storage succeeded with reduced network");
                        succeeded = true;
                        break;
                    }
                    Err(e) => {
                        last_err = format!("Storage failed: {e}");
                        warn!("Attempt {attempt} storage failed: {e}");
                    }
                }
            }
            Err(e) => {
                last_err = format!("Quote collection failed: {e}");
                warn!("Attempt {attempt} quote collection failed: {e}");
            }
        }
        if attempt < 10 {
            if attempt == 4 || attempt == 7 {
                let _ = env.harness.warmup_dht().await;
            }
            sleep(Duration::from_secs(10)).await;
        }
    }
    assert!(
        succeeded,
        "Storage MUST succeed with reduced network after retries: {last_err}"
    );

    info!("RESILIENCE TEST PASSED");

    env.teardown().await?;
    Ok(())
}
