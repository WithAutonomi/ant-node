//! Security attack tests: adversarial payment bypass attempts.
//!
//! These tests simulate a malicious attacker trying to store data on the
//! Autonomi network WITHOUT paying. Every test uses `payment_enforcement: true`
//! on all nodes. Every test MUST verify the attack is REJECTED.
//!
//! The attacker cannot modify source code -- only craft malicious messages.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::harness::TestHarness;
use super::testnet::TestNetworkConfig;
use ant_node::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ProtocolError,
};
use ant_node::compute_address;
use ant_node::payment::PaymentProof;
use evmlib::testnet::Testnet;
use evmlib::ProofOfPayment;
use rand::Rng;
use serial_test::serial;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

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
        .try_handle_request(&message_bytes)
        .await
        .map_err(|e| format!("Handle failed: {e}"))?
        .ok_or("expected response")?;
    ChunkMessage::decode(&response_bytes).map_err(|e| format!("Decode failed: {e}"))
}

/// Create a lightweight test harness with payment enforcement and Anvil wiring.
/// Returns (harness, testnet) -- keep testnet alive to avoid Anvil teardown.
async fn setup_enforcement_env() -> Result<(TestHarness, Testnet), Box<dyn std::error::Error>> {
    let testnet = Testnet::new().await?;
    let network = testnet.to_network();
    let config = TestNetworkConfig::minimal()
        .with_payment_enforcement()
        .with_evm_network(network);
    let harness = TestHarness::setup_with_config(config).await?;
    sleep(Duration::from_secs(5)).await;
    Ok((harness, testnet))
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
