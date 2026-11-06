//! Live-Anvil verification of the receiver-side price floor (ADR-0006).
//!
//! The unit tests in `src/payment/verifier.rs` prove the floor logic against
//! the `completed_payment` test override. This suite closes the gap the
//! override cannot: it exercises the **real** production paths end to end —
//!
//! - a **real deployed payment vault** on a local Anvil chain, paid with a
//!   **real on-chain `pay_for_quotes` transaction**, read back through the
//!   production `completedPayments` contract call (NOT the test override);
//! - the **real `ResponderCommitmentState`** as this node's own commitment
//!   source, read through the same production `current_binding_snapshot` →
//!   `calculate_price(committed_key_count)` path this node's own
//!   `QuoteGenerator` prices from; and
//! - a gossip cache of **real signed neighbour commitments**, the close-group
//!   view the floor prices against.
//!
//! What each test asserts maps directly to a PR claim:
//! - the floor refuses a real 3x-baseline settlement;
//! - an honest at-floor overpayment is admitted, and one atto less is not;
//! - reading the floor does not mutate commitment answerability.
//!
//! Run: `cargo test --test poc_price_floor_live --features test-utils`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use ant_node::payment::quote::CommitmentSource;
use ant_node::payment::{
    calculate_price, serialize_single_node_proof, EvmVerifierConfig, PaymentProof, PaymentStatus,
    PaymentVerifier, PaymentVerifierConfig, VerificationContext, PRICE_FLOOR_TOLERANCE_PERCENT,
};
use ant_node::replication::commitment_state::{
    BuiltCommitment, PeerCommitmentRecord, ResponderCommitmentState,
};
use ant_node::CLOSE_GROUP_SIZE;
use evmlib::common::Amount;
use evmlib::testnet::Testnet;
use evmlib::wallet::Wallet;
use evmlib::{EncodedPeerId, Network, PaymentQuote, ProofOfPayment, RewardsAddress};
use saorsa_core::identity::PeerId;
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};
use tokio::sync::RwLock;

/// Committed key count for the receiver. Above every neighbour, so the
/// own-price cap does not bind and the reference is the group median.
const RECEIVER_COMMITTED_KEYS: u32 = 8_000;

/// The receiver's close group: fifteen neighbours, exactly the floor's minimum
/// sample, shaped like a production group around a ~4,000-key median.
const NEIGHBOUR_KEY_COUNTS: [u32; 15] = [
    3_000, 3_200, 3_400, 3_600, 3_800, 4_000, 4_200, 4_400, 4_600, 4_800, 5_000, 5_200, 5_400,
    5_600, 5_800,
];

/// Lower median of the neighbours plus the receiver's own (larger) count: the
/// eighth smallest of sixteen.
const GROUP_MEDIAN_KEYS: u32 = 4_400;

/// 3x baseline: an honest 3x settlement of the *cheapest* possible quote
/// (committed count 0). This is the near-empty-quoter amount a modified client
/// can settle while still paying an honest 3x of the quote it chose.
fn baseline_settlement() -> Amount {
    calculate_price(0) * Amount::from(3u64)
}

/// The settled amount an at-floor honest overpayment must reach:
/// `3 x tolerance x` the group median price.
fn at_floor_settlement() -> Amount {
    calculate_price(GROUP_MEDIAN_KEYS as usize) * Amount::from(PRICE_FLOOR_TOLERANCE_PERCENT)
        / Amount::from(100u64)
        * Amount::from(3u64)
}

fn keypair() -> (MlDsaPublicKey, MlDsaSecretKey) {
    ml_dsa_65().generate_keypair().unwrap()
}

/// A real signed commitment over `key_count` keys, and its issuer's peer id
/// (BLAKE3 of the public key, matching production binding).
fn signed_commitment(key_count: u32) -> ([u8; 32], BuiltCommitment) {
    let (public_key, secret_key) = keypair();
    let peer_id_bytes = *blake3::hash(&public_key.to_bytes()).as_bytes();
    let entries: Vec<([u8; 32], [u8; 32])> = (0..key_count)
        .map(|i| {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            (k, *blake3::hash(&k).as_bytes())
        })
        .collect();
    let built =
        BuiltCommitment::build(entries, &peer_id_bytes, &secret_key, &public_key.to_bytes())
            .unwrap();
    assert_eq!(built.commitment().key_count, key_count);
    (peer_id_bytes, built)
}

/// Build the receiver's real commitment source, rotated to a commitment over
/// `RECEIVER_COMMITTED_KEYS` keys so `current_binding_snapshot` reports that
/// count — the same object type production wires into both the quote generator
/// and the verifier's floor.
fn receiver_commitment_source() -> Arc<ResponderCommitmentState> {
    let (_, built) = signed_commitment(RECEIVER_COMMITTED_KEYS);
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

/// Build a verifier wired to the live Anvil vault, the real commitment source
/// and a close-group view of real signed neighbour commitments. No `P2PNode`
/// is attached, so the K-closest set comes from the test override: the
/// neighbours plus every quote issuer in `issuers`.
fn live_verifier(
    network: Network,
    source: Arc<ResponderCommitmentState>,
    issuers: &[&EncodedPeerId],
) -> PaymentVerifier {
    let verifier = PaymentVerifier::new(PaymentVerifierConfig {
        evm: EvmVerifierConfig { network },
        cache_capacity: 128,
        close_group_size: CLOSE_GROUP_SIZE,
        local_rewards_address: RewardsAddress::new([0x11; 20]),
    });
    let dyn_source: Arc<dyn CommitmentSource> = source;
    verifier.attach_local_commitment_source(dyn_source);

    let received_at = Instant::now();
    let mut cache = HashMap::new();
    let mut k_closest = Vec::with_capacity(NEIGHBOUR_KEY_COUNTS.len() + issuers.len());
    for count in NEIGHBOUR_KEY_COUNTS {
        let (peer, built) = signed_commitment(count);
        cache.insert(
            PeerId::from_bytes(peer),
            PeerCommitmentRecord::from_verified(built.commitment().clone(), received_at),
        );
        k_closest.push(peer);
    }
    k_closest.extend(issuers.iter().map(|issuer| *issuer.as_bytes()));
    verifier.attach_commitment_cache(Arc::new(RwLock::new(cache)));
    verifier.set_paid_quote_k_closest_for_tests(k_closest);
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

fn anvil_wallet(testnet: &Testnet) -> (Network, Wallet) {
    let network = testnet.to_network();
    let wallet = Wallet::new_from_private_key(
        network.clone(),
        &testnet.default_wallet_private_key().unwrap(),
    )
    .unwrap();
    (network, wallet)
}

/// The floor refuses a real 3x-baseline settlement, paid to a near-empty
/// quoter, at a receiver that knows its close group.
#[tokio::test(flavor = "multi_thread")]
async fn rejects_a_real_below_floor_settlement() {
    let testnet = Testnet::new().await.unwrap();
    let (network, wallet) = anvil_wallet(&testnet);
    assert!(
        baseline_settlement() < at_floor_settlement(),
        "test fixture must keep the baseline settlement below the floor"
    );

    let xorname = [0xA1u8; 32];
    let (peer_id, quote) = signed_quote(xorname, calculate_price(0), RewardsAddress::new([2; 20]));
    let verifier = live_verifier(network, receiver_commitment_source(), &[&peer_id]);
    let proof = pay_and_build_proof(&wallet, peer_id, quote, baseline_settlement()).await;

    let err = verifier
        .verify_payment(&xorname, Some(&proof), VerificationContext::ClientPut)
        .await
        .expect_err("a real 3x-baseline settlement must not clear the floor");
    assert!(
        err.to_string()
            .contains("below the close-group price floor"),
        "unexpected rejection reason: {err}"
    );
}

/// Enforcement accepts an honest at-floor overpayment and refuses one atto
/// less: the client overpays the cheap quote to exactly `3 x tolerance x` the
/// group median, settled for real on-chain.
#[tokio::test(flavor = "multi_thread")]
async fn enforced_floor_accepts_at_floor_real_overpayment() {
    let testnet = Testnet::new().await.unwrap();
    let (network, wallet) = anvil_wallet(&testnet);
    let source = receiver_commitment_source();
    assert!(
        calculate_price(RECEIVER_COMMITTED_KEYS as usize)
            > calculate_price(GROUP_MEDIAN_KEYS as usize),
        "the receiver must sit above its group so the reference is the group median"
    );
    // Snapshot the commitment hash BEFORE verification so we can prove the
    // floor read did not rotate/refresh/age retention (claim: non-mutating).
    let hash_before = source.current().map(|c| c.hash());

    let short_name = [0xA3u8; 32];
    let (short_peer, short_quote) =
        signed_quote(short_name, calculate_price(0), RewardsAddress::new([4; 20]));
    let xorname = [0xA4u8; 32];
    let (peer_id, quote) = signed_quote(xorname, calculate_price(0), RewardsAddress::new([5; 20]));
    let verifier = live_verifier(network, Arc::clone(&source), &[&short_peer, &peer_id]);

    let one_short = at_floor_settlement() - Amount::from(1u64);
    let short_proof = pay_and_build_proof(&wallet, short_peer, short_quote, one_short).await;
    let err = verifier
        .verify_payment(
            &short_name,
            Some(&short_proof),
            VerificationContext::ClientPut,
        )
        .await
        .expect_err("one atto below the floor must be refused");
    assert!(err
        .to_string()
        .contains("below the close-group price floor"));

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
