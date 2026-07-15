//! Live-Anvil verification of the receiver-side price floor (ADR-0006).
//!
//! The unit tests in `src/payment/verifier.rs` prove the floor logic against
//! the `completed_payment` test override. This suite closes the gap the
//! override cannot: it exercises the **real** production paths end to end —
//!
//! - a **real deployed payment vault** on a local Anvil chain, paid with a
//!   **real on-chain `pay_for_quotes` transaction**, read back through the
//!   production `completedPayments` contract call (NOT the test override); and
//! - the **real `ResponderCommitmentState`** as the floor's commitment source,
//!   so the local price is derived through the same production
//!   `current_binding_snapshot` → `calculate_price(committed_key_count)` path
//!   this node's own `QuoteGenerator` prices from.
//!
//! What each test asserts maps directly to a PR claim:
//! - shadow mode never rejects, even when the settlement is below floor;
//! - enforcement rejects the cheapest-of-K one-quote settlement;
//! - enforcement accepts an honest at-floor overpayment;
//! - reading the floor does not mutate commitment answerability.
//!
//! Run: `cargo test --test poc_price_floor_live --features test-utils`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::SystemTime;

use ant_node::payment::{
    calculate_price, serialize_single_node_proof, EvmVerifierConfig, PaymentProof, PaymentStatus,
    PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig, VerificationContext,
};
use ant_node::replication::commitment_state::{BuiltCommitment, ResponderCommitmentState};
use ant_node::CLOSE_GROUP_SIZE;
use evmlib::common::Amount;
use evmlib::testnet::Testnet;
use evmlib::wallet::Wallet;
use evmlib::{EncodedPeerId, PaymentQuote, ProofOfPayment, RewardsAddress};
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};

/// Committed key count for the receiver in the floor tests. Chosen large
/// enough that `calculate_price(count)` sits well above twice the baseline, so
/// a baseline-priced (cheapest-of-K) settlement is genuinely below a 50%
/// floor. Asserted in-test so a pricing-curve change fails loudly.
const RECEIVER_COMMITTED_KEYS: u32 = 500_000;

/// The receiver's own commitment-derived local price, via the real pricing
/// curve — the exact value the production floor computes.
fn receiver_local_price() -> Amount {
    calculate_price(RECEIVER_COMMITTED_KEYS as usize)
}

/// 3x baseline: an honest 3x settlement of the *cheapest* possible quote
/// (committed count 0). This is the cheapest-of-K amount a modified client can
/// settle while still paying an honest 3x of the quote it chose.
fn cheapest_of_k_settlement() -> Amount {
    calculate_price(0) * Amount::from(3u64)
}

/// The settled amount an at-floor honest overpayment must reach under a 50%
/// floor: `3 x 50% x local_price`.
fn at_floor_settlement() -> Amount {
    receiver_local_price() * Amount::from(50u64) / Amount::from(100u64) * Amount::from(3u64)
}

fn keypair() -> (MlDsaPublicKey, MlDsaSecretKey) {
    ml_dsa_65().generate_keypair().unwrap()
}

/// Build the receiver's real commitment source, rotated to a commitment over
/// `RECEIVER_COMMITTED_KEYS` keys so `current_binding_snapshot` reports that
/// count — the same object type production wires into both the quote generator
/// and (via this PR) the verifier's floor.
fn receiver_commitment_source() -> Arc<ResponderCommitmentState> {
    let (public_key, secret_key) = keypair();
    let peer_id_bytes = *blake3::hash(&public_key.to_bytes()).as_bytes();
    let entries: Vec<([u8; 32], [u8; 32])> = (0..RECEIVER_COMMITTED_KEYS)
        .map(|i| {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            (k, *blake3::hash(&k).as_bytes())
        })
        .collect();
    let built =
        BuiltCommitment::build(entries, &peer_id_bytes, &secret_key, &public_key.to_bytes())
            .unwrap();
    assert_eq!(built.commitment().key_count, RECEIVER_COMMITTED_KEYS);
    let state = ResponderCommitmentState::new();
    state.rotate(built);
    Arc::new(state)
}

/// A real ML-DSA-signed single-node quote for `xorname` at `price`, plus the
/// issuer's encoded peer id (BLAKE3(pubkey), matching production binding).
fn signed_quote(
    xorname: [u8; 32],
    price: Amount,
    rewards_address: RewardsAddress,
) -> (EncodedPeerId, PaymentQuote) {
    let (public_key, secret_key) = keypair();
    let pub_key_bytes: Vec<u8> = public_key.to_bytes();
    let peer_id = EncodedPeerId::new(*blake3::hash(&pub_key_bytes).as_bytes());
    let mut quote = PaymentQuote {
        content: xor_name::XorName(xorname),
        timestamp: SystemTime::now(),
        price,
        rewards_address,
        committed_key_count: 0,
        commitment_pin: None,
        pub_key: pub_key_bytes,
        signature: Vec::new(),
    };
    quote.signature = ml_dsa_65()
        .sign(&secret_key, &quote.bytes_for_sig())
        .unwrap()
        .to_bytes();
    (peer_id, quote)
}

fn serialize_proof(peer_quotes: Vec<(EncodedPeerId, PaymentQuote)>) -> Vec<u8> {
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment { peer_quotes },
        tx_hashes: vec![],
        commitment_sidecars: vec![],
    };
    serialize_single_node_proof(&proof).unwrap()
}

/// Build a verifier wired to the live Anvil vault and the real commitment
/// source, with the given floor policy. No `P2PNode` is attached, so the
/// issuer K-closest check fail-opens under `test-utils` — that isolates the
/// on-chain settlement read and the floor as the load-bearing checks.
fn live_verifier(network: evmlib::Network, floor: PriceFloorConfig) -> PaymentVerifier {
    let verifier = PaymentVerifier::new(PaymentVerifierConfig {
        evm: EvmVerifierConfig { network },
        cache_capacity: 128,
        close_group_size: CLOSE_GROUP_SIZE,
        local_rewards_address: RewardsAddress::new([0x11; 20]),
        price_floor: floor,
    });
    verifier.attach_local_commitment_source(receiver_commitment_source());
    verifier
}

/// Pay `amount` on-chain for `quote` via a real vault transaction, then return
/// the serialized single-node proof for that quote. The quote's price stays the
/// cheap baseline; the *settled* amount is what the floor compares.
async fn pay_and_build_proof(
    wallet: &Wallet,
    peer_id: EncodedPeerId,
    quote: PaymentQuote,
    amount: Amount,
) -> Vec<u8> {
    let quote_payment = (quote.hash(), quote.rewards_address, amount);
    wallet
        .pay_for_quotes(std::iter::once(quote_payment))
        .await
        .expect("on-chain pay_for_quotes should settle on Anvil");
    serialize_proof(vec![(peer_id, quote)])
}

/// Shadow mode (the shipping default) must NEVER reject on the floor, even when
/// the real on-chain settlement is genuinely below the receiver's floor.
#[tokio::test(flavor = "multi_thread")]
async fn shadow_mode_accepts_below_floor_real_settlement() {
    let testnet = Testnet::new().await.unwrap();
    let network = testnet.to_network();
    let wallet = Wallet::new_from_private_key(
        network.clone(),
        &testnet.default_wallet_private_key().unwrap(),
    )
    .unwrap();
    let verifier = live_verifier(network, PriceFloorConfig::default());
    assert!(!verifier.price_floor_config().enforce, "default is shadow");
    assert!(
        cheapest_of_k_settlement() < at_floor_settlement(),
        "test fixture must keep the cheap settlement below the floor"
    );

    let xorname = [0xA1u8; 32];
    let (peer_id, quote) = signed_quote(xorname, calculate_price(0), RewardsAddress::new([2; 20]));
    let proof = pay_and_build_proof(&wallet, peer_id, quote, cheapest_of_k_settlement()).await;

    let status = verifier
        .verify_payment(&xorname, Some(&proof), VerificationContext::ClientPut)
        .await
        .expect("shadow mode must accept a real below-floor settlement");
    assert_eq!(status, PaymentStatus::PaymentVerified);
}

/// Enforcement rejects the cheapest-of-K one-quote settlement: a real 3x-baseline
/// on-chain payment against a fuller receiver, read from the real vault.
#[tokio::test(flavor = "multi_thread")]
async fn enforced_floor_rejects_cheapest_of_k_real_settlement() {
    let testnet = Testnet::new().await.unwrap();
    let network = testnet.to_network();
    let wallet = Wallet::new_from_private_key(
        network.clone(),
        &testnet.default_wallet_private_key().unwrap(),
    )
    .unwrap();
    let verifier = live_verifier(
        network,
        PriceFloorConfig {
            enforce: true,
            tolerance_percent: 50,
        },
    );

    let xorname = [0xA2u8; 32];
    let (peer_id, quote) = signed_quote(xorname, calculate_price(0), RewardsAddress::new([3; 20]));
    let proof = pay_and_build_proof(&wallet, peer_id, quote, cheapest_of_k_settlement()).await;

    let err = verifier
        .verify_payment(&xorname, Some(&proof), VerificationContext::ClientPut)
        .await
        .expect_err("a real 3x-baseline settlement must not clear a fuller receiver's floor");
    assert!(
        err.to_string().contains("below this node's price floor"),
        "unexpected rejection reason: {err}"
    );
}

/// Enforcement accepts an honest at-floor overpayment: the client overpays the
/// cheap quote to `3 x 50% x local_price`, settled for real on-chain.
#[tokio::test(flavor = "multi_thread")]
async fn enforced_floor_accepts_at_floor_real_overpayment() {
    let testnet = Testnet::new().await.unwrap();
    let network = testnet.to_network();
    let wallet = Wallet::new_from_private_key(
        network.clone(),
        &testnet.default_wallet_private_key().unwrap(),
    )
    .unwrap();
    let source = receiver_commitment_source();
    // Snapshot the commitment hash BEFORE verification so we can prove the
    // floor read did not rotate/refresh/age retention (claim: non-mutating).
    let hash_before = source.current().map(|c| c.hash());
    let verifier = PaymentVerifier::new(PaymentVerifierConfig {
        evm: EvmVerifierConfig {
            network: network.clone(),
        },
        cache_capacity: 128,
        close_group_size: CLOSE_GROUP_SIZE,
        local_rewards_address: RewardsAddress::new([0x11; 20]),
        price_floor: PriceFloorConfig {
            enforce: true,
            tolerance_percent: 50,
        },
    });
    let concrete = Arc::clone(&source);
    let dyn_source: Arc<dyn ant_node::payment::quote::CommitmentSource> = concrete;
    verifier.attach_local_commitment_source(dyn_source);

    let xorname = [0xA3u8; 32];
    let (peer_id, quote) = signed_quote(xorname, calculate_price(0), RewardsAddress::new([4; 20]));
    let proof = pay_and_build_proof(&wallet, peer_id, quote, at_floor_settlement()).await;

    let status = verifier
        .verify_payment(&xorname, Some(&proof), VerificationContext::ClientPut)
        .await
        .expect("an exactly-at-floor real settlement must pass under enforcement");
    assert_eq!(status, PaymentStatus::PaymentVerified);

    // The floor read the commitment via the non-mutating snapshot: the current
    // commitment (and thus retention) is unchanged after verification.
    let hash_after = source.current().map(|c| c.hash());
    assert_eq!(
        hash_before, hash_after,
        "reading the floor must not mutate commitment state"
    );
    assert_eq!(source.retained_slot_count(), 1);
}
