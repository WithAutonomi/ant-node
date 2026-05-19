//! End-to-end PoC for the **F2/F5 pay-yourself** primitive against a live
//! Anvil chain with the real `PaymentVaultV2` deployed.
//!
//! The offline tests in `tests/poc_f2_f5_price_floor.rs` prove the pre-RPC
//! recipient+floor *filter*. They cannot exercise the decisive on-chain step,
//! where the real exploit lives:
//!
//! `PaymentVaultV2.payForQuotes` is unauthenticated and lets the caller set
//! `{quoteHash, rewardsAddress, amount}` independently — it sends the ANT to
//! the caller-chosen `rewardsAddress` and stores
//! `completedPayments[quoteHash] = { rewardsAddress: first16(thatAddr),
//! amount }`. So an attacker can register an on-chain payment record for a
//! VICTIM-addressed quote's hash while sending the money to their OWN wallet.
//!
//! Pre-fix the verifier only checked `completedPayments(hash).amount` and
//! discarded `.rewardsAddress`, so this was accepted → free storage. The fix
//! also requires `completedPayments(hash).rewardsAddress ==
//! first16(local_rewards_address)` on the same quote.
//!
//! This test performs the real pay-yourself transaction on Anvil and asserts
//! the production `PaymentVerifier` REJECTS it, then asserts an honest
//! payment to the node IS accepted (positive control).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use super::anvil::TestAnvil;
use ant_node::payment::EvmVerifierConfig;
use ant_node::payment::{
    serialize_single_node_proof, PaymentProof, PaymentStatus, PaymentVerifier,
    PaymentVerifierConfig, PriceFloorProvider,
};
use evmlib::common::Amount;
use evmlib::data_payments::{EncodedPeerId, PaymentQuote, ProofOfPayment};
use evmlib::RewardsAddress;
use saorsa_core::identity::node_identity::peer_id_from_public_key_bytes;
use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::MlDsaSecretKey;
use saorsa_pqc::pqc::MlDsaOperations;
use serial_test::serial;
use std::sync::Arc;
use std::time::SystemTime;

const CLOSE_GROUP_SIZE: usize = 7;
const PRICE_ATTO: u128 = 1_000_000; // well above the test floor below
const FLOOR_ATTO: u128 = 1_000; // node's min acceptable per-record price

fn mint_quote(
    content: [u8; 32],
    price: Amount,
    rewards: RewardsAddress,
) -> (EncodedPeerId, PaymentQuote) {
    let ml_dsa = MlDsa65::new();
    let (pk, sk) = ml_dsa.generate_keypair().expect("keypair");
    let mut q = PaymentQuote {
        content: xor_name::XorName(content),
        timestamp: SystemTime::now(),
        price,
        rewards_address: rewards,
        pub_key: pk.as_bytes().to_vec(),
        signature: vec![],
    };
    let sk = MlDsaSecretKey::from_bytes(sk.as_bytes()).expect("sk");
    q.signature = ml_dsa
        .sign(&sk, &q.bytes_for_sig())
        .expect("sign")
        .as_bytes()
        .to_vec();
    let pid = peer_id_from_public_key_bytes(&q.pub_key).expect("peer id");
    (EncodedPeerId::new(*pid.as_bytes()), q)
}

/// Build a 7-quote proof. `recipient` is the rewards address put on EVERY
/// quote (so the one whose hash we pay is victim-addressed and passes the
/// pre-RPC recipient+floor filter), all priced at `PRICE_ATTO`.
fn proof_paying(content: [u8; 32], recipient: RewardsAddress) -> (Vec<u8>, PaymentQuote) {
    let mut quotes: Vec<(EncodedPeerId, PaymentQuote)> = Vec::new();
    for _ in 0..CLOSE_GROUP_SIZE {
        quotes.push(mint_quote(content, Amount::from(PRICE_ATTO), recipient));
    }
    let paid = quotes[0].1.clone();
    let bytes = serialize_single_node_proof(&PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: quotes,
        },
        tx_hashes: vec![],
    })
    .expect("serialize");
    (bytes, paid)
}

fn verifier(network: evmlib::Network, node_rewards: RewardsAddress) -> PaymentVerifier {
    PaymentVerifier::new(PaymentVerifierConfig {
        evm: EvmVerifierConfig { network },
        cache_capacity: 64,
        local_rewards_address: node_rewards,
        price_floor: Some(PriceFloorProvider::new(Arc::new(move || {
            Amount::from(FLOOR_ATTO)
        }))),
    })
}

#[tokio::test]
#[serial]
async fn poc_f2_f5_pay_yourself_on_chain_is_rejected() {
    let anvil = TestAnvil::new().await.expect("anvil up");
    let network = anvil.to_network();
    let attacker = anvil.create_funded_wallet().expect("funded wallet");

    // The victim node's own rewards address (the node we attack).
    let node_rewards = RewardsAddress::from([0xDEu8; 20]);
    let content = [0x77u8; 32];

    // Proof whose quotes all carry the VICTIM's rewards address — passes the
    // verifier's pre-RPC recipient+floor filter (price >> floor).
    let (proof_bytes, victim_quote) = proof_paying(content, node_rewards);
    let expected = Amount::from(PRICE_ATTO) * Amount::from(3u64);

    // THE ATTACK: register an on-chain payment for the victim-addressed
    // quote's hash, but route the ANT to the ATTACKER's own wallet.
    let (_tx, _gas) = attacker
        .pay_for_quotes([(victim_quote.hash(), attacker.address(), expected)])
        .await
        .expect("attacker self-payment tx");

    // Pre-fix this was accepted (verifier checked only `.amount`). The fix
    // also requires the on-chain record's recipient == this node.
    let status = verifier(network.clone(), node_rewards)
        .verify_payment(&content, Some(&proof_bytes))
        .await;

    let err = status.expect_err(
        "pay-yourself proof MUST be rejected: the on-chain payment went to the \
         attacker's wallet, not this node (F2/F5)",
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("paid >=3x \non-chain TO THIS NODE")
            || msg.contains("paid >=3x on-chain TO THIS NODE")
            || msg.contains("TO THIS NODE"),
        "rejection must be the on-chain recipient binding, got: {msg}"
    );
}

#[tokio::test]
#[serial]
async fn poc_f2_f5_honest_payment_to_node_is_accepted() {
    let anvil = TestAnvil::new().await.expect("anvil up");
    let network = anvil.to_network();
    let payer = anvil.create_funded_wallet().expect("funded wallet");

    let node_rewards = RewardsAddress::from([0xDEu8; 20]);
    let content = [0x42u8; 32];

    let (proof_bytes, node_quote) = proof_paying(content, node_rewards);
    let expected = Amount::from(PRICE_ATTO) * Amount::from(3u64);

    // Honest payment: pay 3x TO THE NODE's rewards address for the node's
    // quote hash.
    payer
        .pay_for_quotes([(node_quote.hash(), node_rewards, expected)])
        .await
        .expect("honest payment tx");

    let status = verifier(network, node_rewards)
        .verify_payment(&content, Some(&proof_bytes))
        .await
        .expect("an honest 3x payment to this node must be accepted");
    assert_eq!(
        status,
        PaymentStatus::PaymentVerified,
        "honest payment to the node's address must verify (no false reject)"
    );
}
