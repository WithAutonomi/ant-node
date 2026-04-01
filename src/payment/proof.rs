//! Payment proof wrapper that includes transaction hashes.
//!
//! `PaymentProof` bundles a `ProofOfPayment` (quotes + peer IDs) with the
//! on-chain transaction hashes returned by the wallet after payment.

use crate::ant_protocol::{PROOF_TAG_MERKLE, PROOF_TAG_SINGLE_NODE};
use evmlib::common::TxHash;
use evmlib::merkle_payments::MerklePaymentProof;
use evmlib::ProofOfPayment;
use serde::{Deserialize, Serialize};

/// A payment proof that includes both the quote-based proof and on-chain tx hashes.
///
/// This replaces the bare `ProofOfPayment` in serialized proof bytes, adding
/// the transaction hashes that were previously discarded after `payment.pay()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    /// The original quote-based proof (peer IDs + quotes with ML-DSA-65 signatures).
    pub proof_of_payment: ProofOfPayment,
    /// Transaction hashes from the on-chain payment.
    /// Typically contains one hash for the median (non-zero) quote.
    pub tx_hashes: Vec<TxHash>,
}

/// The detected type of a payment proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofType {
    /// `SingleNode` payment (5 quotes, median-paid).
    SingleNode,
    /// Merkle batch payment (one tx for many chunks).
    Merkle,
}

/// Detect the proof type from the first byte (version tag).
///
/// Returns `None` if the tag byte is unrecognized or the slice is empty.
#[must_use]
pub fn detect_proof_type(bytes: &[u8]) -> Option<ProofType> {
    match bytes.first() {
        Some(&PROOF_TAG_SINGLE_NODE) => Some(ProofType::SingleNode),
        Some(&PROOF_TAG_MERKLE) => Some(ProofType::Merkle),
        _ => None,
    }
}

/// Serialize a `PaymentProof` (single-node) with the version tag prefix.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_single_node_proof(
    proof: &PaymentProof,
) -> std::result::Result<Vec<u8>, rmp_serde::encode::Error> {
    let body = rmp_serde::to_vec(proof)?;
    let mut tagged = Vec::with_capacity(1 + body.len());
    tagged.push(PROOF_TAG_SINGLE_NODE);
    tagged.extend_from_slice(&body);
    Ok(tagged)
}

/// Serialize a `MerklePaymentProof` with the version tag prefix.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_merkle_proof(
    proof: &MerklePaymentProof,
) -> std::result::Result<Vec<u8>, rmp_serde::encode::Error> {
    let body = rmp_serde::to_vec(proof)?;
    let mut tagged = Vec::with_capacity(1 + body.len());
    tagged.push(PROOF_TAG_MERKLE);
    tagged.extend_from_slice(&body);
    Ok(tagged)
}

/// Deserialize proof bytes from the `PaymentProof` format (single-node).
///
/// Expects the first byte to be `PROOF_TAG_SINGLE_NODE`.
/// Returns `(ProofOfPayment, Vec<TxHash>)`.
///
/// # Errors
///
/// Returns an error if the tag is missing or the bytes cannot be deserialized.
pub fn deserialize_proof(bytes: &[u8]) -> Result<(ProofOfPayment, Vec<TxHash>), String> {
    if bytes.first() != Some(&PROOF_TAG_SINGLE_NODE) {
        return Err("Missing single-node proof tag byte".to_string());
    }
    let payload = bytes
        .get(1..)
        .ok_or_else(|| "Single-node proof tag present but no payload".to_string())?;
    let proof = rmp_serde::from_slice::<PaymentProof>(payload)
        .map_err(|e| format!("Failed to deserialize single-node proof: {e}"))?;
    Ok((proof.proof_of_payment, proof.tx_hashes))
}

/// Deserialize proof bytes as a `MerklePaymentProof`.
///
/// Expects the first byte to be `PROOF_TAG_MERKLE`.
///
/// # Errors
///
/// Returns an error if the bytes cannot be deserialized or the tag is wrong.
pub fn deserialize_merkle_proof(bytes: &[u8]) -> std::result::Result<MerklePaymentProof, String> {
    if bytes.first() != Some(&PROOF_TAG_MERKLE) {
        return Err("Missing merkle proof tag byte".to_string());
    }
    let payload = bytes
        .get(1..)
        .ok_or_else(|| "Merkle proof tag present but no payload".to_string())?;
    rmp_serde::from_slice::<MerklePaymentProof>(payload)
        .map_err(|e| format!("Failed to deserialize merkle proof: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use alloy::primitives::FixedBytes;
    use evmlib::common::Amount;
    use evmlib::merkle_payments::{
        MerklePaymentCandidateNode, MerklePaymentCandidatePool, MerklePaymentProof, MerkleTree,
        CANDIDATES_PER_POOL,
    };
    use evmlib::EncodedPeerId;
    use evmlib::PaymentQuote;
    use evmlib::RewardsAddress;
    use saorsa_core::MlDsa65;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;
    use saorsa_pqc::pqc::MlDsaOperations;
    use std::time::SystemTime;
    use xor_name::XorName;

    fn make_test_quote() -> PaymentQuote {
        PaymentQuote {
            content: XorName::random(&mut rand::thread_rng()),
            timestamp: SystemTime::now(),
            price: Amount::from(1u64),
            rewards_address: RewardsAddress::new([1u8; 20]),
            pub_key: vec![],
            signature: vec![],
        }
    }

    fn make_proof_of_payment() -> ProofOfPayment {
        let random_peer = EncodedPeerId::new(rand::random());
        ProofOfPayment {
            peer_quotes: vec![(random_peer, make_test_quote())],
        }
    }

    #[test]
    fn test_payment_proof_serialization_roundtrip() {
        let tx_hash = FixedBytes::from([0xABu8; 32]);
        let proof = PaymentProof {
            proof_of_payment: make_proof_of_payment(),
            tx_hashes: vec![tx_hash],
        };

        let bytes = serialize_single_node_proof(&proof).unwrap();
        let (pop, hashes) = deserialize_proof(&bytes).unwrap();

        assert_eq!(pop.peer_quotes.len(), 1);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes.first().unwrap(), &tx_hash);
    }

    #[test]
    fn test_payment_proof_with_empty_tx_hashes() {
        let proof = PaymentProof {
            proof_of_payment: make_proof_of_payment(),
            tx_hashes: vec![],
        };

        let bytes = serialize_single_node_proof(&proof).unwrap();
        let (pop, hashes) = deserialize_proof(&bytes).unwrap();

        assert_eq!(pop.peer_quotes.len(), 1);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_deserialize_proof_rejects_garbage() {
        let garbage = vec![0xFF, 0x00, 0x01, 0x02];
        let result = deserialize_proof(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_proof_rejects_untagged() {
        // Raw msgpack without tag byte must be rejected
        let proof = PaymentProof {
            proof_of_payment: make_proof_of_payment(),
            tx_hashes: vec![],
        };
        let raw_bytes = rmp_serde::to_vec(&proof).unwrap();
        let result = deserialize_proof(&raw_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_payment_proof_multiple_tx_hashes() {
        let tx1 = FixedBytes::from([0x11u8; 32]);
        let tx2 = FixedBytes::from([0x22u8; 32]);
        let proof = PaymentProof {
            proof_of_payment: make_proof_of_payment(),
            tx_hashes: vec![tx1, tx2],
        };

        let bytes = serialize_single_node_proof(&proof).unwrap();
        let (_, hashes) = deserialize_proof(&bytes).unwrap();

        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes.first().unwrap(), &tx1);
        assert_eq!(hashes.get(1).unwrap(), &tx2);
    }

    // =========================================================================
    // detect_proof_type tests
    // =========================================================================

    #[test]
    fn test_detect_proof_type_single_node() {
        let bytes = [PROOF_TAG_SINGLE_NODE, 0x00, 0x01];
        let result = detect_proof_type(&bytes);
        assert_eq!(result, Some(ProofType::SingleNode));
    }

    #[test]
    fn test_detect_proof_type_merkle() {
        let bytes = [PROOF_TAG_MERKLE, 0x00, 0x01];
        let result = detect_proof_type(&bytes);
        assert_eq!(result, Some(ProofType::Merkle));
    }

    #[test]
    fn test_detect_proof_type_unknown_tag() {
        let bytes = [0xFF, 0x00, 0x01];
        let result = detect_proof_type(&bytes);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_proof_type_empty_bytes() {
        let bytes: &[u8] = &[];
        let result = detect_proof_type(bytes);
        assert_eq!(result, None);
    }

    // =========================================================================
    // Tagged serialize/deserialize round-trip tests
    // =========================================================================

    #[test]
    fn test_serialize_single_node_proof_roundtrip_with_tag() {
        let tx_hash = FixedBytes::from([0xCCu8; 32]);
        let proof = PaymentProof {
            proof_of_payment: make_proof_of_payment(),
            tx_hashes: vec![tx_hash],
        };

        let tagged_bytes = serialize_single_node_proof(&proof).unwrap();

        // First byte must be the single-node tag
        assert_eq!(
            tagged_bytes.first().copied(),
            Some(PROOF_TAG_SINGLE_NODE),
            "Tagged proof must start with PROOF_TAG_SINGLE_NODE"
        );

        // detect_proof_type should identify it
        assert_eq!(
            detect_proof_type(&tagged_bytes),
            Some(ProofType::SingleNode)
        );

        // deserialize_proof handles the tag transparently
        let (pop, hashes) = deserialize_proof(&tagged_bytes).unwrap();
        assert_eq!(pop.peer_quotes.len(), 1);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes.first().unwrap(), &tx_hash);
    }

    // =========================================================================
    // Merkle proof serialize/deserialize round-trip tests
    // =========================================================================

    /// Create a minimal valid `MerklePaymentProof` from a small merkle tree.
    fn make_test_merkle_proof() -> MerklePaymentProof {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build a tree with 4 addresses (minimal depth)
        let addresses: Vec<xor_name::XorName> = (0..4u8)
            .map(|i| xor_name::XorName::from_content(&[i]))
            .collect();
        let tree = MerkleTree::from_xornames(addresses.clone()).unwrap();

        // Build candidate nodes with ML-DSA-65 signing (matching production)
        let candidate_nodes: [MerklePaymentCandidateNode; CANDIDATES_PER_POOL] =
            std::array::from_fn(|i| {
                let ml_dsa = MlDsa65::new();
                let (pub_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");
                let price = Amount::from(1024u64);
                #[allow(clippy::cast_possible_truncation)]
                let reward_address = RewardsAddress::new([i as u8; 20]);
                let msg =
                    MerklePaymentCandidateNode::bytes_to_sign(&price, &reward_address, timestamp);
                let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
                let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

                MerklePaymentCandidateNode {
                    pub_key: pub_key.as_bytes().to_vec(),
                    price,
                    reward_address,
                    merkle_payment_timestamp: timestamp,
                    signature,
                }
            });

        let reward_candidates = tree.reward_candidates(timestamp).unwrap();
        let midpoint_proof = reward_candidates.first().unwrap().clone();

        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        };

        let first_address = *addresses.first().unwrap();
        let address_proof = tree.generate_address_proof(0, first_address).unwrap();

        MerklePaymentProof::new(first_address, address_proof, pool)
    }

    #[test]
    fn test_serialize_merkle_proof_roundtrip() {
        let merkle_proof = make_test_merkle_proof();

        let tagged_bytes = serialize_merkle_proof(&merkle_proof).unwrap();

        // First byte must be the merkle tag
        assert_eq!(
            tagged_bytes.first().copied(),
            Some(PROOF_TAG_MERKLE),
            "Tagged merkle proof must start with PROOF_TAG_MERKLE"
        );

        // detect_proof_type should identify it as merkle
        assert_eq!(detect_proof_type(&tagged_bytes), Some(ProofType::Merkle));

        // deserialize_merkle_proof should recover the original proof
        let recovered = deserialize_merkle_proof(&tagged_bytes).unwrap();
        assert_eq!(recovered.address, merkle_proof.address);
        assert_eq!(
            recovered.winner_pool.candidate_nodes.len(),
            CANDIDATES_PER_POOL
        );
    }

    #[test]
    fn test_deserialize_merkle_proof_rejects_wrong_tag() {
        let merkle_proof = make_test_merkle_proof();
        let mut tagged_bytes = serialize_merkle_proof(&merkle_proof).unwrap();

        // Replace the tag with the single-node tag
        if let Some(first) = tagged_bytes.first_mut() {
            *first = PROOF_TAG_SINGLE_NODE;
        }

        let result = deserialize_merkle_proof(&tagged_bytes);
        assert!(result.is_err(), "Should reject wrong tag byte");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("Missing merkle proof tag"),
            "Error should mention missing tag: {err_msg}"
        );
    }

    #[test]
    fn test_deserialize_merkle_proof_rejects_empty() {
        let result = deserialize_merkle_proof(&[]);
        assert!(result.is_err());
    }
}
