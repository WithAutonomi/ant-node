//! Proof-of-concept regression test for finding **F2/F5** (free storage).
//!
//! ## The vulnerability (pre-fix)
//!
//! `verify_evm_payment` reconstructed the payment from the attacker's own
//! quotes and delegated the decision to `SingleNodePayment::verify`, which
//! accepts if **any quote tied at the median price** was paid 3× on-chain.
//! Combined with `validate_local_recipient` only checking that this node's
//! rewards address appears in *some* quote (`.any()`), an attacker could:
//!
//!  * **underprice**: submit 7 self-signed 1-atto quotes (one carrying our
//!    address) and pay a negligible 3 atto; and/or
//!  * **pay yourself**: include one quote with our address purely to pass the
//!    recipient check, but route the actual 3× on-chain payment to a quote
//!    whose `rewards_address` is the attacker's OWN wallet.
//!
//! Either way the attacker stores arbitrary data while this node earns
//! nothing — free storage. The single-node path has no DHT/identity binding.
//!
//! ## The fix — sound invariant
//!
//! `verify_evm_payment` now accepts only if there exists a quote `Q` where
//! ALL of: (a) `Q.rewards_address == this node's local_rewards_address`,
//! (b) `Q.price >= price_floor` (`calculate_price(records_stored)/TOL`, wired
//! live in production), and (c) on-chain `completedPayments(Q.hash) >= 3 *
//! Q.price`. (a)+(b) are checked on the SAME quote whose 3× payment is
//! verified in (c), so both the underpricing and pay-yourself primitives are
//! closed.
//!
//! These tests prove BOTH attack variants are now rejected, that an honest
//! fair payment to this node still passes the price/recipient gate, and
//! (flip) that without the recipient binding the pay-yourself proof would
//! sail past every pre-on-chain check.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use ant_node::payment::EvmVerifierConfig;
use ant_node::payment::{
    serialize_single_node_proof, PaymentProof, PaymentVerifier, PaymentVerifierConfig,
    PriceFloorProvider,
};
use evmlib::common::Amount;
use evmlib::data_payments::{EncodedPeerId, PaymentQuote, ProofOfPayment};
use evmlib::RewardsAddress;
use saorsa_core::identity::node_identity::peer_id_from_public_key_bytes;
use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::MlDsaSecretKey;
use saorsa_pqc::pqc::MlDsaOperations;
use std::sync::Arc;
use std::time::SystemTime;

const CLOSE_GROUP_SIZE: usize = 7;

/// A loaded node's honest per-record price floor for the test (independent of
/// the pricing constants; represents "this node is not free").
const FLOOR_ATTO: u128 = 1_000_000_000_000_000;

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

fn serialize(quotes: Vec<(EncodedPeerId, PaymentQuote)>) -> Vec<u8> {
    serialize_single_node_proof(&PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: quotes,
        },
        tx_hashes: vec![],
    })
    .expect("serialize")
}

fn verifier_with_floor(victim_rewards: RewardsAddress, floor_atto: u128) -> PaymentVerifier {
    PaymentVerifier::new(PaymentVerifierConfig {
        evm: EvmVerifierConfig::default(),
        cache_capacity: 64,
        local_rewards_address: victim_rewards,
        price_floor: Some(PriceFloorProvider::new(Arc::new(move || {
            Amount::from(floor_atto)
        }))),
    })
}

/// F5 — underpricing: 7 self-signed 1-atto quotes (one carrying our address).
/// No quote both pays this node AND meets the floor, so the proof is rejected
/// before any on-chain call.
#[tokio::test]
async fn poc_f2_f5_underpriced_proof_rejected() {
    let victim = RewardsAddress::new([0xDE; 20]);
    let attacker = RewardsAddress::new([0xA1; 20]);
    let content = [0x99u8; 32];

    let mut quotes = vec![mint_quote(content, Amount::from(1u64), victim)];
    for _ in 1..CLOSE_GROUP_SIZE {
        quotes.push(mint_quote(content, Amount::from(1u64), attacker));
    }

    let err = format!(
        "{}",
        verifier_with_floor(victim, FLOOR_ATTO)
            .verify_payment(&content, Some(&serialize(quotes)))
            .await
            .expect_err("underpriced proof must be rejected (F2/F5)")
    );
    assert!(
        err.contains("No quote in the single-node proof both pays this node"),
        "must be rejected by the recipient+floor gate BEFORE any RPC, got: {err}"
    );
}

/// F2 — pay-yourself: the priced quotes are ABOVE the floor (so a naive
/// price-only floor would pass), but every above-floor quote pays the
/// ATTACKER's wallet; the only quote with our address is a 1-atto decoy
/// included solely to pass the legacy `.any()` recipient check. The sound
/// invariant requires the SAME quote to both pay us and meet the floor, so
/// this is rejected before any on-chain call — the attacker can no longer
/// route the 3× payment to itself.
#[tokio::test]
async fn poc_f2_f5_pay_yourself_decoy_rejected() {
    let victim = RewardsAddress::new([0xDE; 20]);
    let attacker = RewardsAddress::new([0xA1; 20]);
    let content = [0x77u8; 32];

    // 1-atto decoy paying the victim (passes legacy .any() recipient check)…
    let mut quotes = vec![mint_quote(content, Amount::from(1u64), victim)];
    // …plus 6 well-above-floor quotes, ALL paying the attacker's wallet.
    let rich = Amount::from(FLOOR_ATTO * 10);
    for _ in 1..CLOSE_GROUP_SIZE {
        quotes.push(mint_quote(content, rich, attacker));
    }

    let err = format!(
        "{}",
        verifier_with_floor(victim, FLOOR_ATTO)
            .verify_payment(&content, Some(&serialize(quotes)))
            .await
            .expect_err("pay-yourself decoy proof must be rejected (F2/F5)")
    );
    // No quote satisfies (pays us) AND (>= floor): the decoy pays us but is
    // 1 atto; the rich quotes meet the floor but pay the attacker.
    assert!(
        err.contains("No quote in the single-node proof both pays this node"),
        "pay-yourself proof must be rejected by the recipient+floor gate \
         BEFORE any RPC, got: {err}"
    );
}

/// Flip / control: WITHOUT the recipient+floor binding (modelled by
/// `price_floor: None`, which also disables the underpricing bound) the
/// pay-yourself proof is NOT stopped by the recipient/price gate — it reaches
/// the on-chain step. Pre-fix, against a real chain where the attacker paid
/// itself 3×, this is exactly the free-storage acceptance. This proves the
/// new binding is what closes F2/F5.
#[tokio::test]
async fn poc_f2_f5_without_binding_pay_yourself_passes_gate() {
    let victim = RewardsAddress::new([0xDE; 20]);
    let attacker = RewardsAddress::new([0xA1; 20]);
    let content = [0x77u8; 32];

    let mut quotes = vec![mint_quote(content, Amount::from(1u64), victim)];
    let rich = Amount::from(FLOOR_ATTO * 10);
    for _ in 1..CLOSE_GROUP_SIZE {
        quotes.push(mint_quote(content, rich, attacker));
    }

    let verifier = PaymentVerifier::new(PaymentVerifierConfig {
        evm: EvmVerifierConfig::default(),
        cache_capacity: 64,
        local_rewards_address: victim,
        price_floor: None, // pre-fix behaviour
    });

    let err = format!(
        "{}",
        verifier
            .verify_payment(&content, Some(&serialize(quotes)))
            .await
            .expect_err("offline: no EVM endpoint, so the on-chain step errors")
    );
    // The decisive flip assertion. WITHOUT the binding, the pre-on-chain
    // recipient+floor gate does NOT exist, so the proof reaches the on-chain
    // lookup. Offline, `completedPayments` resolves to 0, so it's rejected
    // with the on-chain "not paid >=3x" message (last on-chain amount 0) —
    // NOT the pre-RPC recipient+floor rejection. Pre-fix, against a REAL
    // chain where the attacker paid itself 3×, that same on-chain check
    // returns >= expected for the attacker-self-paid quote and the store is
    // ACCEPTED = free storage. The post-binding code (other tests) rejects
    // these proofs *before* ever reaching the chain.
    assert!(
        !err.contains("No quote in the single-node proof both pays this node"),
        "without a floor the proof must NOT be stopped by the pre-RPC gate \
         (it reaches the on-chain step); got: {err}"
    );
    assert!(
        err.contains("No quote paying this node at/above the price floor was paid >=3x"),
        "expected the proof to reach the on-chain step and fail there \
         (offline → 0 paid); pre-fix on a real self-paid chain this is \
         instead ACCEPTED = free storage. got: {err}"
    );
}

/// Positive control: an honest client paying THIS node a fair (>= floor)
/// price passes the recipient+floor gate and only fails later at the on-chain
/// step (offline). The fix must not reject legitimate payments.
#[tokio::test]
async fn poc_f2_f5_fair_payment_passes_gate() {
    let victim = RewardsAddress::new([0xDE; 20]);
    let attacker = RewardsAddress::new([0xB0; 20]);
    let content = [0x42u8; 32];

    // A fair quote paying THIS node well above the floor.
    let fair = Amount::from(FLOOR_ATTO * 5);
    let mut quotes = vec![mint_quote(content, fair, victim)];
    for _ in 1..CLOSE_GROUP_SIZE {
        quotes.push(mint_quote(content, fair, attacker));
    }

    let err = format!(
        "{}",
        verifier_with_floor(victim, FLOOR_ATTO)
            .verify_payment(&content, Some(&serialize(quotes)))
            .await
            .expect_err("offline: on-chain step errors")
    );
    // A fair quote pays THIS node above the floor, so it satisfies (a)+(b)
    // and becomes an on-chain candidate — i.e. it PASSES the recipient+floor
    // gate (it is not rejected pre-RPC). Offline the on-chain lookup yields 0
    // so it then fails the 3× check; on a real chain with a genuine payment
    // it would be accepted. The fix must not pre-reject honest payments.
    assert!(
        !err.contains("No quote in the single-node proof both pays this node"),
        "a fair payment to this node must PASS the recipient+floor gate \
         (not be pre-RPC rejected); got: {err}"
    );
    assert!(
        err.contains("No quote paying this node at/above the price floor was paid >=3x")
            && err.contains("last on-chain (amount, recipient16) Some((0,"),
        "fair payment should pass the gate and reach (then fail at) the \
         on-chain step offline; got: {err}"
    );
}
