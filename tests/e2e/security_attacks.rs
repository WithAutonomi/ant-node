//! Security attack tests: adversarial payment bypass attempts.
//!
//! These tests simulate a malicious attacker trying to store data on the
//! saorsa network WITHOUT paying. Every test uses `payment_enforcement: true`
//! on all nodes. Every test MUST verify the attack is REJECTED.
//!
//! The attacker cannot modify source code -- only craft malicious messages.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::harness::TestHarness;
use super::testnet::TestNetworkConfig;
use ant_evm::ProofOfPayment;
use bytes::Bytes;
use evmlib::testnet::Testnet;
use evmlib::wallet::Wallet;
use rand::Rng;
use saorsa_node::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ProtocolError,
};
use saorsa_node::client::{hex_node_id_to_encoded_peer_id, QuantumClient};
use saorsa_node::compute_address;
use saorsa_node::payment::{PaymentProof, SingleNodePayment};
use serial_test::serial;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a `ChunkMessageBody` indicates payment rejection.
fn is_payment_rejection(body: &ChunkMessageBody) -> bool {
    matches!(
        body,
        ChunkMessageBody::PutResponse(
            ChunkPutResponse::PaymentRequired { .. }
                | ChunkPutResponse::Error(ProtocolError::PaymentFailed(_))
        )
    )
}

/// Send a PUT request directly to a node's `AntProtocol` handler.
async fn send_put_to_node(
    harness: &TestHarness,
    node_index: usize,
    request: ChunkPutRequest,
) -> Result<ChunkMessage, String> {
    let node = harness
        .test_node(node_index)
        .ok_or_else(|| format!("Node {node_index} not found"))?;
    let protocol = node
        .ant_protocol
        .as_ref()
        .ok_or("No ant_protocol on node")?;

    let request_id: u64 = rand::thread_rng().gen();
    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::PutRequest(request),
    };
    let message_bytes = message
        .encode()
        .map_err(|e| format!("Encode failed: {e}"))?;
    let response_bytes = protocol
        .handle_message(&message_bytes)
        .await
        .map_err(|e| format!("Handle failed: {e}"))?;
    ChunkMessage::decode(&response_bytes).map_err(|e| format!("Decode failed: {e}"))
}

/// Create a lightweight test harness with payment enforcement and Anvil wiring.
/// Returns (harness, testnet) -- keep testnet alive to avoid Anvil teardown.
async fn setup_enforcement_env() -> Result<(TestHarness, Testnet), Box<dyn std::error::Error>> {
    let testnet = Testnet::new().await;
    let network = testnet.to_network();
    let config = TestNetworkConfig::minimal()
        .with_payment_enforcement()
        .with_evm_network(network);
    let harness = TestHarness::setup_with_config(config).await?;
    sleep(Duration::from_secs(5)).await;
    Ok((harness, testnet))
}

/// Create a full test harness (10 nodes) with DHT warmup for quote collection.
/// Returns (harness, testnet, wallet).
async fn setup_full_payment_env(
) -> Result<(TestHarness, Testnet, Wallet), Box<dyn std::error::Error>> {
    let testnet = Testnet::new().await;
    let network = testnet.to_network();
    let config = TestNetworkConfig::small()
        .with_payment_enforcement()
        .with_evm_network(network.clone());
    let harness = TestHarness::setup_with_config(config).await?;
    sleep(Duration::from_secs(10)).await;
    harness.warmup_dht().await?;
    let private_key = testnet.default_wallet_private_key();
    let wallet = Wallet::new_from_private_key(network, &private_key)?;
    Ok((harness, testnet, wallet))
}

// ===========================================================================
// Category 1: No/Invalid Proof Bytes (Direct Protocol Handler)
// ===========================================================================

/// Attack: Send a valid chunk with NO payment proof at all.
/// Node MUST reject with `PaymentRequired`.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_no_payment_proof() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: no payment proof");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: no payment proof whatsoever";
    let address = compute_address(test_data);
    let request = ChunkPutRequest::new(address, test_data.to_vec());

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Attack MUST be rejected with payment error, got: {response:?}"
    );
    info!("Correctly rejected: no payment proof");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Send a chunk with an empty byte array as payment proof (0 bytes).
/// Node MUST reject (proof too small, minimum 32 bytes).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_empty_proof_bytes() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: empty proof bytes");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: empty proof bytes";
    let address = compute_address(test_data);
    let request = ChunkPutRequest::with_payment(address, test_data.to_vec(), vec![]);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Attack MUST be rejected with payment error, got: {response:?}"
    );
    info!("Correctly rejected: empty proof bytes");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Send 64 bytes of random garbage as payment proof.
/// Node MUST reject (deserialization failure).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_garbage_bytes_as_proof() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: garbage bytes as proof");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: garbage bytes as proof";
    let address = compute_address(test_data);
    let garbage: Vec<u8> = (0..64).map(|_| rand::thread_rng().gen()).collect();
    let request = ChunkPutRequest::with_payment(address, test_data.to_vec(), garbage);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Attack MUST be rejected with payment error, got: {response:?}"
    );
    info!("Correctly rejected: garbage bytes");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Send a valid MessagePack-serialized `PaymentProof` but with empty quotes.
/// Node MUST reject ("Payment has no quotes").
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_valid_msgpack_empty_quotes() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: valid msgpack, empty quotes");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: valid msgpack, empty quotes";
    let address = compute_address(test_data);

    // Build a structurally valid but semantically empty proof
    let empty_proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: vec![],
        },
        tx_hashes: vec![],
    };
    let proof_bytes =
        rmp_serde::to_vec(&empty_proof).map_err(|e| format!("Serialize failed: {e}"))?;

    // Pad to >= 32 bytes if needed (msgpack of empty proof is likely > 32 already)
    let mut padded = proof_bytes;
    while padded.len() < 32 {
        padded.push(0);
    }

    let request = ChunkPutRequest::with_payment(address, test_data.to_vec(), padded);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Attack MUST be rejected with payment error, got: {response:?}"
    );
    info!("Correctly rejected: empty quotes");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Send 200KB of garbage as payment proof (exceeds 100KB max).
/// Node MUST reject (proof too large).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_proof_too_large() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: proof too large (200KB)");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: oversized proof bytes";
    let address = compute_address(test_data);
    let oversized: Vec<u8> = vec![0xAA; 200 * 1024]; // 200KB of junk
    let request = ChunkPutRequest::with_payment(address, test_data.to_vec(), oversized);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Attack MUST be rejected with payment error, got: {response:?}"
    );
    info!("Correctly rejected: proof too large");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 2: Cryptographic Attacks (Real Quotes + Anvil)
// ===========================================================================

/// Helper: get quotes from DHT with retries (up to 5 attempts, exponential backoff).
async fn get_quotes_with_retries(
    client: &QuantumClient,
    test_data: &[u8],
) -> Result<
    Vec<(
        saorsa_core::identity::PeerId,
        ant_evm::PaymentQuote,
        ant_evm::Amount,
    )>,
    String,
> {
    let mut last_err = String::new();
    for attempt in 1..=5u32 {
        match client.get_quotes_from_dht(test_data).await {
            Ok(quotes) => {
                info!("Got {} quotes on attempt {attempt}", quotes.len());
                return Ok(quotes);
            }
            Err(e) => {
                last_err = format!("{e}");
                warn!("Quote attempt {attempt} failed: {e}");
                if attempt < 5 {
                    sleep(Duration::from_secs(2u64.pow(attempt))).await;
                }
            }
        }
    }
    Err(format!("Failed to get quotes after 5 attempts: {last_err}"))
}

/// Helper: build a valid proof from quotes + wallet payment.
/// Returns (`proof_bytes`, `tx_hashes`).
async fn build_valid_proof(
    quotes_with_prices: Vec<(
        saorsa_core::identity::PeerId,
        ant_evm::PaymentQuote,
        ant_evm::Amount,
    )>,
    wallet: &Wallet,
) -> Result<(Vec<u8>, Vec<evmlib::common::TxHash>), Box<dyn std::error::Error>> {
    let mut peer_quotes = Vec::with_capacity(quotes_with_prices.len());
    let mut quotes_for_payment = Vec::with_capacity(quotes_with_prices.len());
    for (peer_id_str, quote, price) in quotes_with_prices {
        let encoded = hex_node_id_to_encoded_peer_id(&peer_id_str.to_hex())
            .map_err(|e| format!("Peer ID conversion failed: {e}"))?;
        peer_quotes.push((encoded, quote.clone()));
        quotes_for_payment.push((quote, price));
    }
    let payment = SingleNodePayment::from_quotes(quotes_for_payment)
        .map_err(|e| format!("Payment creation failed: {e}"))?;
    let tx_hashes = payment
        .pay(wallet)
        .await
        .map_err(|e| format!("Payment failed: {e}"))?;
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes: tx_hashes.clone(),
    };
    let proof_bytes = rmp_serde::to_vec(&proof).map_err(|e| format!("Serialize failed: {e}"))?;
    Ok((proof_bytes, tx_hashes))
}

/// Attack: Forge ALL ML-DSA-65 signatures on valid quotes + real payment.
/// Node MUST reject because signature verification fails.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_attack_forged_ml_dsa_signature() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: forged ML-DSA-65 signatures (ALL quotes)");

    let (harness, _testnet, wallet) = setup_full_payment_env().await?;

    let client = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet.clone());

    let test_data = b"Attack: forge all ML-DSA signatures";
    let quotes = get_quotes_with_retries(&client, test_data).await?;

    // Build peer_quotes and payment
    let mut peer_quotes = Vec::with_capacity(quotes.len());
    let mut quotes_for_payment = Vec::with_capacity(quotes.len());
    for (peer_id_str, quote, price) in quotes {
        let encoded = hex_node_id_to_encoded_peer_id(&peer_id_str.to_hex())
            .map_err(|e| format!("Peer ID conversion failed: {e}"))?;
        peer_quotes.push((encoded, quote.clone()));
        quotes_for_payment.push((quote, price));
    }
    let payment = SingleNodePayment::from_quotes(quotes_for_payment)
        .map_err(|e| format!("Payment creation failed: {e}"))?;
    let tx_hashes = payment
        .pay(&wallet)
        .await
        .map_err(|e| format!("Payment failed: {e}"))?;

    // CORRUPT ALL signatures (flip every byte)
    let mut forged_quotes = peer_quotes;
    for (_peer_id, ref mut quote) in &mut forged_quotes {
        for byte in &mut quote.signature {
            *byte = byte.wrapping_add(1);
        }
    }

    let forged_proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: forged_quotes,
        },
        tx_hashes,
    };
    let forged_bytes =
        rmp_serde::to_vec(&forged_proof).map_err(|e| format!("Serialize failed: {e}"))?;

    // Try to store with forged proof
    let result = client
        .put_chunk_with_proof(Bytes::from(test_data.to_vec()), forged_bytes)
        .await;

    assert!(
        result.is_err(),
        "Attack MUST be rejected with forged signatures"
    );
    let err_msg = format!("{}", result.expect_err("just asserted is_err"));
    info!("Correctly rejected forged signatures: {err_msg}");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Pay for chunk A, try to store chunk B using chunk A's proof.
/// The proof was generated for A's xorname; on-chain verification should fail for B.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_attack_wrong_chunk_address() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: wrong chunk address (use A's proof for B)");

    let (harness, _testnet, wallet) = setup_full_payment_env().await?;

    let client = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet.clone());

    // Get quotes and pay for chunk A
    let chunk_a_data = b"Attack: this is chunk A with valid payment";
    let quotes = get_quotes_with_retries(&client, chunk_a_data).await?;
    let (proof_bytes_a, _tx_hashes) = build_valid_proof(quotes, &wallet).await?;

    // Try to store chunk B using chunk A's proof
    let chunk_b_data = b"Attack: this is chunk B, using A's proof";
    let result = client
        .put_chunk_with_proof(Bytes::from(chunk_b_data.to_vec()), proof_bytes_a)
        .await;

    assert!(
        result.is_err(),
        "Attack MUST be rejected: proof was for a different chunk"
    );
    let err_msg = format!("{}", result.expect_err("just asserted is_err"));
    info!("Correctly rejected wrong chunk address: {err_msg}");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Replay chunk A's proof to store chunk B.
/// First legitimately store chunk A, then try to reuse its proof for chunk B.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_attack_replay_different_chunk() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: replay proof from chunk A to store chunk B");

    let (harness, _testnet, wallet) = setup_full_payment_env().await?;

    let client = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet.clone());

    // Legitimately upload chunk A
    let chunk_a_data = b"Attack: legitimate chunk A for replay test";
    let quotes = get_quotes_with_retries(&client, chunk_a_data).await?;
    let (proof_bytes_a, _tx_hashes) = build_valid_proof(quotes, &wallet).await?;

    // Store chunk A (should succeed) — retry for slow DHT on CI
    let mut chunk_a_stored = false;
    for attempt in 1..=5u32 {
        match client
            .put_chunk_with_proof(Bytes::from(chunk_a_data.to_vec()), proof_bytes_a.clone())
            .await
        {
            Ok(_addr) => {
                chunk_a_stored = true;
                break;
            }
            Err(e) => {
                warn!("Legitimate store of chunk A attempt {attempt}/5 failed: {e}");
                if attempt < 5 {
                    let _ = harness.warmup_dht().await;
                    sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }
    assert!(
        chunk_a_stored,
        "Legitimate store of chunk A should succeed after retries"
    );
    info!("Chunk A stored successfully (legitimate)");

    // Now replay A's proof for chunk B
    let chunk_b_data = b"Attack: trying to replay A's proof for chunk B";
    let result_b = client
        .put_chunk_with_proof(Bytes::from(chunk_b_data.to_vec()), proof_bytes_a)
        .await;

    assert!(
        result_b.is_err(),
        "Replay attack MUST be rejected: proof is for chunk A, not B"
    );
    let err_msg = format!("{}", result_b.expect_err("just asserted is_err"));
    info!("Correctly rejected replay attack: {err_msg}");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Build proof with real quotes but NO on-chain payment (empty `tx_hashes`).
/// Node MUST reject because on-chain verification finds no payment.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_attack_zero_amount_payment() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: real quotes but no on-chain payment (empty tx_hashes)");

    let (harness, _testnet, wallet) = setup_full_payment_env().await?;

    let client = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet.clone());

    let test_data = b"Attack: quotes but no payment";
    let quotes = get_quotes_with_retries(&client, test_data).await?;

    // Build peer_quotes from real quotes but skip on-chain payment
    let mut peer_quotes = Vec::with_capacity(quotes.len());
    for (peer_id_str, quote, _price) in quotes {
        let encoded = hex_node_id_to_encoded_peer_id(&peer_id_str.to_hex())
            .map_err(|e| format!("Peer ID conversion failed: {e}"))?;
        peer_quotes.push((encoded, quote));
    }

    // Build proof with valid structure but NO payment
    let unpaid_proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes: vec![], // No on-chain payment!
    };
    let proof_bytes =
        rmp_serde::to_vec(&unpaid_proof).map_err(|e| format!("Serialize failed: {e}"))?;

    let result = client
        .put_chunk_with_proof(Bytes::from(test_data.to_vec()), proof_bytes)
        .await;

    assert!(
        result.is_err(),
        "Attack MUST be rejected: no on-chain payment exists"
    );
    let err_msg = format!("{}", result.expect_err("just asserted is_err"));
    info!("Correctly rejected zero-amount payment: {err_msg}");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Use real quotes but fabricate a random tx hash (no corresponding on-chain tx).
/// Node MUST reject because on-chain verification fails.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_attack_fabricated_tx_hash() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: fabricated transaction hash");

    let (harness, _testnet, wallet) = setup_full_payment_env().await?;

    let client = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet.clone());

    let test_data = b"Attack: fabricated tx hash";
    let quotes = get_quotes_with_retries(&client, test_data).await?;

    // Build peer_quotes from real quotes
    let mut peer_quotes = Vec::with_capacity(quotes.len());
    for (peer_id_str, quote, _price) in quotes {
        let encoded = hex_node_id_to_encoded_peer_id(&peer_id_str.to_hex())
            .map_err(|e| format!("Peer ID conversion failed: {e}"))?;
        peer_quotes.push((encoded, quote));
    }

    // Fabricate a fake tx hash
    let fake_tx = alloy::primitives::FixedBytes::from([0xDE; 32]);

    let fake_proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes: vec![fake_tx],
    };
    let proof_bytes =
        rmp_serde::to_vec(&fake_proof).map_err(|e| format!("Serialize failed: {e}"))?;

    let result = client
        .put_chunk_with_proof(Bytes::from(test_data.to_vec()), proof_bytes)
        .await;

    assert!(
        result.is_err(),
        "Attack MUST be rejected: fabricated tx hash has no on-chain payment"
    );
    let err_msg = format!("{}", result.expect_err("just asserted is_err"));
    info!("Correctly rejected fabricated tx hash: {err_msg}");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 3: Advanced Protocol Attacks
// ===========================================================================

/// Attack: Double-spend the same proof for the same chunk (idempotent check).
/// The first store succeeds; the second returns `AlreadyExists` (not an error).
/// This proves double-spend is prevented by idempotent storage.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_attack_double_spend_same_proof() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: double-spend same proof for same chunk");

    let (harness, _testnet, wallet) = setup_full_payment_env().await?;

    let client = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet.clone());

    let test_data = b"Attack: double-spend same proof";
    let quotes = get_quotes_with_retries(&client, test_data).await?;
    let (proof_bytes, _tx_hashes) = build_valid_proof(quotes, &wallet).await?;

    // First store: should succeed — retry for slow DHT on CI
    let mut first_stored = false;
    for attempt in 1..=5u32 {
        match client
            .put_chunk_with_proof(Bytes::from(test_data.to_vec()), proof_bytes.clone())
            .await
        {
            Ok(_addr) => {
                first_stored = true;
                break;
            }
            Err(e) => {
                warn!("First store attempt {attempt}/5 failed: {e}");
                if attempt < 5 {
                    let _ = harness.warmup_dht().await;
                    sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }
    assert!(
        first_stored,
        "First store MUST succeed with valid payment after retries"
    );
    info!("First store succeeded (legitimate)");

    // Second store with same proof: should return AlreadyExists (idempotent)
    let result2 = client
        .put_chunk_with_proof(Bytes::from(test_data.to_vec()), proof_bytes)
        .await;

    // AlreadyExists is returned as Ok (it's idempotent success), proving the chunk
    // was cached and the proof cannot be used to double-store different data.
    match result2 {
        Ok(addr) => {
            let expected = compute_address(test_data);
            assert_eq!(addr, expected, "AlreadyExists should return same address");
            info!("Double-spend correctly returned existing address (idempotent)");
        }
        Err(e) => {
            // Some implementations may also reject duplicates -- both behaviors are safe
            info!("Double-spend rejected outright: {e}");
        }
    }

    harness.teardown().await?;
    Ok(())
}

/// Attack: Corrupt the ML-DSA-65 public key in quotes (replace with random bytes).
/// Node MUST reject because public key parsing or signature verification fails.
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn test_attack_corrupted_public_key() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: corrupted ML-DSA-65 public key");

    let (harness, _testnet, wallet) = setup_full_payment_env().await?;

    let client = QuantumClient::with_defaults()
        .with_node(harness.node(0).ok_or("Node 0 not found")?)
        .with_wallet(wallet.clone());

    let test_data = b"Attack: corrupted public key";
    let quotes = get_quotes_with_retries(&client, test_data).await?;

    // Build peer_quotes and payment
    let mut peer_quotes = Vec::with_capacity(quotes.len());
    let mut quotes_for_payment = Vec::with_capacity(quotes.len());
    for (peer_id_str, quote, price) in quotes {
        let encoded = hex_node_id_to_encoded_peer_id(&peer_id_str.to_hex())
            .map_err(|e| format!("Peer ID conversion failed: {e}"))?;
        peer_quotes.push((encoded, quote.clone()));
        quotes_for_payment.push((quote, price));
    }
    let payment = SingleNodePayment::from_quotes(quotes_for_payment)
        .map_err(|e| format!("Payment creation failed: {e}"))?;
    let tx_hashes = payment
        .pay(&wallet)
        .await
        .map_err(|e| format!("Payment failed: {e}"))?;

    // CORRUPT ALL public keys (replace with random bytes of same length)
    let mut corrupted_quotes = peer_quotes;
    for (_peer_id, ref mut quote) in &mut corrupted_quotes {
        let key_len = quote.pub_key.len();
        quote.pub_key = (0..key_len).map(|_| rand::thread_rng().gen()).collect();
    }

    let corrupted_proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: corrupted_quotes,
        },
        tx_hashes,
    };
    let proof_bytes =
        rmp_serde::to_vec(&corrupted_proof).map_err(|e| format!("Serialize failed: {e}"))?;

    let result = client
        .put_chunk_with_proof(Bytes::from(test_data.to_vec()), proof_bytes)
        .await;

    assert!(
        result.is_err(),
        "Attack MUST be rejected: corrupted public keys"
    );
    let err_msg = format!("{}", result.expect_err("just asserted is_err"));
    info!("Correctly rejected corrupted public key: {err_msg}");

    harness.teardown().await?;
    Ok(())
}

/// Attack: Use `QuantumClient` without wallet (no proof sent to server).
/// Server-side enforcement MUST reject the storage attempt.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_client_without_wallet() -> Result<(), Box<dyn std::error::Error>> {
    info!("ATTACK TEST: QuantumClient without wallet");

    let (harness, _testnet) = setup_enforcement_env().await?;

    // Create client WITHOUT wallet -- sends no payment proof
    let client =
        QuantumClient::with_defaults().with_node(harness.node(0).ok_or("Node 0 not found")?);

    let test_data = b"Attack: client with no wallet configured";
    let result = client.put_chunk(Bytes::from(test_data.to_vec())).await;

    assert!(
        result.is_err(),
        "Storage MUST fail without wallet when enforcement is enabled"
    );
    let err_msg = format!("{}", result.expect_err("just asserted is_err"));
    assert!(
        err_msg.to_lowercase().contains("payment"),
        "Error must be payment-related, got: {err_msg}"
    );
    info!("Correctly rejected client without wallet: {err_msg}");

    harness.teardown().await?;
    Ok(())
}
