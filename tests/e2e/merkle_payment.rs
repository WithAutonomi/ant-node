//! E2E tests for merkle batch payment verification across live nodes.
//!
//! These tests validate merkle payment security and correctness by sending
//! crafted merkle proofs to live testnet nodes with `payment_enforcement: true`.
//!
//! **Test Coverage**:
//! - Merkle-tagged garbage rejected
//! - Valid merkle proof with wrong xorname rejected
//! - Merkle proof with tampered candidate signatures rejected
//! - Merkle proof construction, serialization, and size validation
//! - Concurrent merkle proof verification across multiple nodes

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::harness::TestHarness;
use super::testnet::TestNetworkConfig;
use ant_node::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ProtocolError,
    PROOF_TAG_MERKLE,
};
use ant_node::compute_address;
use ant_node::payment::{
    serialize_merkle_proof, MAX_PAYMENT_PROOF_SIZE_BYTES, MIN_PAYMENT_PROOF_SIZE_BYTES,
};
use evmlib::common::Amount;
use evmlib::merkle_payments::{
    MerklePaymentCandidateNode, MerklePaymentCandidatePool, MerklePaymentProof, MerkleTree,
    CANDIDATES_PER_POOL,
};
use evmlib::testnet::Testnet;
use evmlib::RewardsAddress;
use rand::Rng;
use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::MlDsaSecretKey;
use saorsa_pqc::pqc::MlDsaOperations;
use serial_test::serial;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a `ChunkMessageBody` indicates a rejection (payment or address error).
fn is_rejection(body: &ChunkMessageBody) -> bool {
    matches!(
        body,
        ChunkMessageBody::PutResponse(
            ChunkPutResponse::PaymentRequired { .. }
                | ChunkPutResponse::Error(
                    ProtocolError::PaymentFailed(_) | ProtocolError::AddressMismatch { .. }
                )
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
        .ok_or("No response returned (unexpected None)")?;
    ChunkMessage::decode(&response_bytes).map_err(|e| format!("Decode failed: {e}"))
}

/// Create a lightweight test harness with payment enforcement and Anvil wiring.
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

/// Data for a single entry in the merkle tree: the content bytes and the
/// BLAKE3-derived xorname used as the chunk address.
struct TreeEntry {
    content: Vec<u8>,
    address: xor_name::XorName,
}

/// Result of building a valid merkle proof.
struct ValidMerkleProof {
    /// The tree entry the proof is bound to (first address).
    target: TreeEntry,
    /// The serialized & tagged proof bytes.
    tagged_proof: Vec<u8>,
    /// All entries in the tree (including `target`).
    entries: Vec<TreeEntry>,
}

/// Build a valid `MerklePaymentProof` with real ML-DSA-65 signatures.
///
/// Addresses are derived via BLAKE3 (`compute_address`) so that they match
/// the protocol handler's address verification step.
fn build_valid_merkle_proof() -> ValidMerkleProof {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();

    // Build content blobs and derive BLAKE3 addresses for the merkle tree.
    let entries: Vec<TreeEntry> = (0..4u8)
        .map(|i| {
            let content = vec![i; 64];
            let blake3_hash = compute_address(&content);
            TreeEntry {
                content,
                address: xor_name::XorName(blake3_hash),
            }
        })
        .collect();

    let addresses: Vec<xor_name::XorName> = entries.iter().map(|e| e.address).collect();
    let tree = MerkleTree::from_xornames(addresses).expect("tree");

    let candidate_nodes: [MerklePaymentCandidateNode; CANDIDATES_PER_POOL] =
        build_candidate_nodes(timestamp);

    let reward_candidates = tree
        .reward_candidates(timestamp)
        .expect("reward candidates");
    let midpoint_proof = reward_candidates
        .first()
        .expect("at least one candidate")
        .clone();

    let pool = MerklePaymentCandidatePool {
        midpoint_proof,
        candidate_nodes,
    };

    let first_address = entries.first().expect("first entry").address;
    let address_proof = tree
        .generate_address_proof(0, first_address)
        .expect("proof");

    let merkle_proof = MerklePaymentProof::new(first_address, address_proof, pool);
    let tagged = serialize_merkle_proof(&merkle_proof).expect("serialize merkle proof");

    ValidMerkleProof {
        target: TreeEntry {
            content: entries.first().expect("first entry").content.clone(),
            address: first_address,
        },
        tagged_proof: tagged,
        entries,
    }
}

/// Build 16 validly-signed ML-DSA-65 candidate nodes for a merkle proof.
fn build_candidate_nodes(timestamp: u64) -> [MerklePaymentCandidateNode; CANDIDATES_PER_POOL] {
    std::array::from_fn(|i| {
        let ml_dsa = MlDsa65::new();
        let (pub_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");
        let price = Amount::from(1024u64);
        #[allow(clippy::cast_possible_truncation)]
        let reward_address = RewardsAddress::new([i as u8; 20]);
        let msg = MerklePaymentCandidateNode::bytes_to_sign(&price, &reward_address, timestamp);
        let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
        let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

        MerklePaymentCandidateNode {
            pub_key: pub_key.as_bytes().to_vec(),
            price,
            reward_address,
            merkle_payment_timestamp: timestamp,
            signature,
        }
    })
}

// ===========================================================================
// Category 1: Merkle-tagged garbage (Direct Protocol Handler)
// ===========================================================================

/// Attack: Send merkle-tagged garbage to a live node.
/// Node MUST reject with a deserialization/payment error.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_tagged_garbage() -> Result<(), Box<dyn std::error::Error>> {
    info!("MERKLE ATTACK TEST: merkle-tagged garbage bytes");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: merkle-tagged garbage";
    let address = compute_address(test_data);

    // Build garbage with correct merkle tag but invalid body
    let mut garbage = vec![PROOF_TAG_MERKLE];
    garbage.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    // Pad to minimum proof size
    while garbage.len() < MIN_PAYMENT_PROOF_SIZE_BYTES {
        garbage.push(0x00);
    }

    let request = ChunkPutRequest::with_payment(address, test_data.to_vec(), garbage);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_rejection(&response.body),
        "Merkle-tagged garbage MUST be rejected, got: {response:?}"
    );
    info!("Correctly rejected: merkle-tagged garbage");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 2: Valid merkle proof, wrong xorname
// ===========================================================================

/// Attack: Send a structurally valid merkle proof but for the wrong chunk.
/// Node MUST reject with address mismatch.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_proof_wrong_xorname() -> Result<(), Box<dyn std::error::Error>> {
    info!("MERKLE ATTACK TEST: valid merkle proof, wrong xorname");

    let (harness, _testnet) = setup_enforcement_env().await?;

    // Build a valid merkle proof for one xorname
    let proof = build_valid_merkle_proof();

    // Try to use it for a completely different chunk
    let wrong_data = b"This chunk was never paid for via this merkle proof";
    let wrong_address = compute_address(wrong_data);

    let request =
        ChunkPutRequest::with_payment(wrong_address, wrong_data.to_vec(), proof.tagged_proof);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_rejection(&response.body),
        "Merkle proof for wrong xorname MUST be rejected, got: {response:?}"
    );
    info!("Correctly rejected: merkle proof for wrong xorname");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 3: Tampered candidate signatures
// ===========================================================================

/// Attack: Send a merkle proof where one candidate's ML-DSA-65 signature is tampered.
/// Node MUST reject — the tampered signature prevents pool verification.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_tampered_candidate_signature() -> Result<(), Box<dyn std::error::Error>>
{
    info!("MERKLE ATTACK TEST: tampered candidate signature");

    let (harness, _testnet) = setup_enforcement_env().await?;

    // Build a valid proof then tamper the first candidate's signature
    let proof = build_valid_merkle_proof();
    let mut tampered_proof =
        ant_node::payment::deserialize_merkle_proof(&proof.tagged_proof).expect("deserialize");
    if let Some(byte) = tampered_proof
        .winner_pool
        .candidate_nodes
        .first_mut()
        .and_then(|c| c.signature.first_mut())
    {
        *byte ^= 0xFF;
    }
    let tagged_proof = serialize_merkle_proof(&tampered_proof).expect("re-serialize");

    // Build request with correct content whose BLAKE3 hash matches the proof address
    let content = proof.target.content;
    let address = proof.target.address.0;
    let request = ChunkPutRequest::with_payment(address, content, tagged_proof);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_rejection(&response.body),
        "Merkle proof with tampered signature MUST be rejected, got: {response:?}"
    );
    info!("Correctly rejected: tampered candidate signature");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 4: Merkle proof construction and serialization validation
// ===========================================================================

/// Verify that a full merkle proof with 16 ML-DSA-65 candidates
/// serializes within the allowed size limits.
#[test]
fn test_merkle_proof_serialized_size_e2e() {
    let proof = build_valid_merkle_proof();

    // 16 candidates with ~1952-byte pub keys and ~3309-byte signatures ≈ ~130 KB
    assert!(
        proof.tagged_proof.len() >= MIN_PAYMENT_PROOF_SIZE_BYTES,
        "Merkle proof ({} bytes) must be >= {MIN_PAYMENT_PROOF_SIZE_BYTES} bytes",
        proof.tagged_proof.len()
    );
    assert!(
        proof.tagged_proof.len() <= MAX_PAYMENT_PROOF_SIZE_BYTES,
        "Merkle proof ({} bytes) must be <= {MAX_PAYMENT_PROOF_SIZE_BYTES} bytes",
        proof.tagged_proof.len()
    );
}

/// Verify merkle proof tag detection works correctly end-to-end.
#[test]
fn test_merkle_proof_tag_detection_e2e() {
    let proof = build_valid_merkle_proof();

    assert_eq!(
        proof.tagged_proof.first().copied(),
        Some(PROOF_TAG_MERKLE),
        "First byte must be PROOF_TAG_MERKLE (0x02)"
    );

    let detected = ant_node::payment::detect_proof_type(&proof.tagged_proof);
    assert_eq!(
        detected,
        Some(ant_node::payment::ProofType::Merkle),
        "detect_proof_type must identify as Merkle"
    );
}

// ===========================================================================
// Category 5: Concurrent merkle attacks across multiple nodes
// ===========================================================================

/// Attack: Send merkle-tagged garbage to ALL nodes concurrently.
/// Every node MUST reject independently.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_garbage_all_nodes_concurrent() -> Result<(), Box<dyn std::error::Error>>
{
    info!("MERKLE ATTACK TEST: garbage to all nodes concurrently");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: concurrent merkle garbage";
    let address = compute_address(test_data);

    let mut garbage = vec![PROOF_TAG_MERKLE];
    garbage.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    while garbage.len() < MIN_PAYMENT_PROOF_SIZE_BYTES {
        garbage.push(0x00);
    }

    // Send to all available nodes concurrently
    let node_count = harness.node_count();
    let mut handles = Vec::new();

    for i in 0..node_count {
        if harness.test_node(i).is_some() {
            let request =
                ChunkPutRequest::with_payment(address, test_data.to_vec(), garbage.clone());
            let msg = ChunkMessage {
                request_id: rand::thread_rng().gen(),
                body: ChunkMessageBody::PutRequest(request),
            };
            let msg_bytes = msg.encode().expect("encode");

            if let Some(protocol) = harness.test_node(i).and_then(|n| n.ant_protocol.as_ref()) {
                let proto = protocol.clone();
                handles.push(tokio::spawn(async move {
                    let resp_bytes = proto
                        .try_handle_request(&msg_bytes)
                        .await
                        .map_err(|e| format!("Node {i}: {e}"))?
                        .ok_or_else(|| format!("Node {i}: unexpected None response"))?;
                    let resp = ChunkMessage::decode(&resp_bytes)
                        .map_err(|e| format!("Node {i} decode: {e}"))?;
                    Ok::<(usize, ChunkMessage), String>((i, resp))
                }));
            }
        }
    }

    let mut rejection_count = 0;
    for handle in handles {
        let (node_idx, response) = handle.await.expect("task panicked")?;
        assert!(
            is_rejection(&response.body),
            "Node {node_idx} MUST reject merkle garbage, got: {response:?}"
        );
        rejection_count += 1;
    }

    assert!(
        rejection_count > 0,
        "At least one node should have been tested"
    );
    info!("All {rejection_count} nodes correctly rejected merkle garbage");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 6: Replay / cross-chunk proof reuse
// ===========================================================================

/// Attack: Build a valid merkle proof for address[0] in the tree, then try
/// to use it to store a chunk whose address matches address[1] in the same
/// tree. The proof's `address` field is bound to address[0], so the node
/// must reject the mismatch.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_proof_cross_address_replay() -> Result<(), Box<dyn std::error::Error>> {
    info!("MERKLE ATTACK TEST: cross-address replay within same tree");

    let (harness, _testnet) = setup_enforcement_env().await?;

    // Build proof bound to entries[0]
    let proof = build_valid_merkle_proof();

    // Try to use it for entries[1] (different address in the same tree)
    let second = proof.entries.get(1).expect("should have 4 entries");

    // Build request with second entry's correct content/address pair,
    // but using the proof that was bound to entries[0].
    let request =
        ChunkPutRequest::with_payment(second.address.0, second.content.clone(), proof.tagged_proof);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_rejection(&response.body),
        "Cross-address replay MUST be rejected, got: {response:?}"
    );
    info!("Correctly rejected: cross-address replay within same tree");

    harness.teardown().await?;
    Ok(())
}
