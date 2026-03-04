//! Payment proof wrapper that includes transaction hashes.
//!
//! `PaymentProof` bundles a `ProofOfPayment` (quotes + peer IDs) with the
//! on-chain transaction hashes returned by the wallet after payment.

use ant_evm::ProofOfPayment;
use evmlib::common::TxHash;
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

/// Deserialize proof bytes from the `PaymentProof` format.
///
/// Returns `(ProofOfPayment, Vec<TxHash>)`.
///
/// # Errors
///
/// Returns an error if the bytes cannot be deserialized.
pub fn deserialize_proof(
    bytes: &[u8],
) -> std::result::Result<(ProofOfPayment, Vec<TxHash>), rmp_serde::decode::Error> {
    let proof = rmp_serde::from_slice::<PaymentProof>(bytes)?;
    Ok((proof.proof_of_payment, proof.tx_hashes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloy::primitives::FixedBytes;
    use ant_evm::RewardsAddress;
    use ant_evm::{EncodedPeerId, PaymentQuote};
    use evmlib::quoting_metrics::QuotingMetrics;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;
    use std::time::SystemTime;
    use xor_name::XorName;

    fn make_test_quote() -> PaymentQuote {
        PaymentQuote {
            content: XorName::random(&mut rand::thread_rng()),
            timestamp: SystemTime::now(),
            quoting_metrics: QuotingMetrics {
                data_size: 1024,
                data_type: 0,
                close_records_stored: 0,
                records_per_type: vec![],
                max_records: 1000,
                received_payment_count: 0,
                live_time: 0,
                network_density: None,
                network_size: None,
            },
            rewards_address: RewardsAddress::new([1u8; 20]),
            pub_key: vec![],
            signature: vec![],
        }
    }

    fn make_proof_of_payment() -> ProofOfPayment {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::from(peer_id), make_test_quote())],
        }
    }

    #[test]
    fn test_payment_proof_serialization_roundtrip() {
        let tx_hash = FixedBytes::from([0xABu8; 32]);
        let proof = PaymentProof {
            proof_of_payment: make_proof_of_payment(),
            tx_hashes: vec![tx_hash],
        };

        let bytes = rmp_serde::to_vec(&proof).unwrap();
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

        let bytes = rmp_serde::to_vec(&proof).unwrap();
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
    fn test_payment_proof_multiple_tx_hashes() {
        let tx1 = FixedBytes::from([0x11u8; 32]);
        let tx2 = FixedBytes::from([0x22u8; 32]);
        let proof = PaymentProof {
            proof_of_payment: make_proof_of_payment(),
            tx_hashes: vec![tx1, tx2],
        };

        let bytes = rmp_serde::to_vec(&proof).unwrap();
        let (_, hashes) = deserialize_proof(&bytes).unwrap();

        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes.first().unwrap(), &tx1);
        assert_eq!(hashes.get(1).unwrap(), &tx2);
    }
}
