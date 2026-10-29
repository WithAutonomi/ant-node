//! ADR-0006 price-floor A/B workload test, env-gated and never run in CI.
//!
//! Builds a production-wired local testnet whose nodes hold production-sized
//! commitments, then drives two workloads against it with real on-chain
//! payments (Anvil):
//!
//! - **honest** uploads: quotes from the close group, the median settled 3x,
//!   the chunk PUT to every close-group storer;
//! - **near-empty quoter** uploads: a node that joined after seeding (no
//!   commitment, so it quotes the baseline price) is paid 3x its quote, and the
//!   chunk is PUT to it and to the mature storers.
//!
//! After a tail long enough for fresh replication, `PaidNotify` and the
//! (shortened) possession checks to play out, it reports who stored each key
//! and whose paid list holds it. Compare the `PF-METRIC` lines, plus the log
//! counts the runner greps for (possession failures naming a near-empty key,
//! contested fan-outs, floor refusals), across builds. It returns at once
//! unless `PRICE_FLOOR_AB=1` is set, so CI only compiles it.
//!
//! ```bash
//! PRICE_FLOOR_AB=1 RUST_LOG=info \
//!   cargo test --test e2e --features test-utils price_floor_ab_workload -- --nocapture
//! ```
//!
//! Neighbour commitments are delivered straight into each node's gossip cache
//! after seeding, exactly the signed commitments neighbour sync would carry.
//! At production-sized key sets the in-process testnet's sync rounds do not
//! deliver them within any useful time, and the floor skips every admission
//! until they arrive. Everything after that (quotes, payments, PUTs, fresh
//! replication, `PaidNotify`, possession checks) runs on the live paths.
//!
//! It fails, rather than reporting, when its own preconditions do not hold:
//! fewer than 15 known neighbour commitments on the median node (the floor
//! would skip everything) or fewer uploads completed than requested. It also
//! asserts what the floor promises: every honest upload reaches a storage
//! quorum with no floor refusal, no peer that refused a near-empty write or
//! that the quoter fanned it out to loses penalty-sized trust in the quoter's
//! view, and every near-empty write stays off a quorum, every refusal being
//! the floor's (a mature storer whose own price is low enough may accept it,
//! as the cap allows).
//!
//! Knobs (env): `PF_NODES`, `PF_KEYS_PER_NODE`, `PF_HONEST`, `PF_NEAR_EMPTY`,
//! `PF_TAIL_SECS`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unnested_or_patterns,
    clippy::cast_precision_loss,
    clippy::too_many_lines
)]

use ant_node::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest,
    ChunkQuoteResponse, CLOSE_GROUP_SIZE,
};
use ant_node::client::{compute_address, send_and_await_chunk_response};
use ant_node::payment::quote::CommitmentSource;
use ant_node::payment::{serialize_single_node_proof, PaymentProof, PRICE_FLOOR_TOLERANCE_PERCENT};
use ant_node::replication::commitment_state::PeerCommitmentRecord;
use ant_node::ReplicationConfig;
use bytes::Bytes;
use evmlib::common::Amount;
use evmlib::wallet::Wallet;
use evmlib::{EncodedPeerId, PaymentQuote, ProofOfPayment};
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use serial_test::serial;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing_subscriber::EnvFilter;

use super::anvil::TestAnvil;
use super::harness::POSSESSION_PENALTY_TRUST_RATIO;
use super::testnet::{TestNetwork, TestNetworkConfig, TestNode};

/// The verifier accepts a settlement of at least 3x the median quote price.
const PAYMENT_MULTIPLIER: u64 = 3;

/// Per-request timeout for quote/PUT round trips.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Substring of the node's price-floor refusal.
const FLOOR_REFUSAL: &str = "below the close-group price floor";

/// Size of each synthetic seeding chunk.
const SEED_CHUNK_BYTES: usize = 64;

/// Neighbour commitments a node must know before its floor evaluates at all
/// (`PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS`, private to the verifier).
const FLOOR_MIN_NEIGHBOURS: usize = 15;

/// Stores a chunk upload needs (`CLOSE_GROUP_MAJORITY`).
const STORE_QUORUM: usize = 4;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
        *o = x ^ y;
    }
    out
}

/// Indices of `peers` sorted by XOR distance to `address`, closest first.
fn closest_indices(address: &[u8; 32], peers: &[[u8; 32]]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..peers.len()).collect();
    order.sort_by_key(|&i| peers.get(i).map(|p| xor_distance(address, p)));
    order
}

/// Wire one node exactly like production `node.rs`: commitment source into the
/// quote generator, gossip cache into the verifier, monetized-pin sender into
/// the verifier. The e2e testnet does not wire these by default.
fn wire_like_production(node: &TestNode) {
    if let (Some(protocol), Some(engine)) =
        (node.ant_protocol.as_ref(), node.replication_engine.as_ref())
    {
        let concrete = Arc::clone(engine.commitment_state());
        let source: Arc<dyn CommitmentSource> = concrete;
        protocol.attach_commitment_source(source);
        protocol
            .payment_verifier_arc()
            .attach_commitment_cache(Arc::clone(engine.last_commitment_by_peer()));
        protocol
            .payment_verifier_arc()
            .attach_monetized_pin_sender(engine.monetized_pin_sender());
    }
}

fn peer_bytes(node: &TestNode) -> [u8; 32] {
    *node
        .p2p_node
        .as_ref()
        .expect("node p2p")
        .peer_id()
        .as_bytes()
}

async fn request_quote(
    client: &Arc<P2PNode>,
    peer: &PeerId,
    address: [u8; 32],
    data_size: u64,
) -> Result<PaymentQuote, String> {
    let request_id: u64 = rand::thread_rng().gen();
    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::QuoteRequest(ChunkQuoteRequest {
            address,
            data_size,
            data_type: 0,
        }),
    };
    let message_bytes = message
        .encode()
        .map_err(|e| format!("encode quote request: {e}"))?;
    let quote_bytes = send_and_await_chunk_response(
        client,
        peer,
        message_bytes,
        request_id,
        REQUEST_TIMEOUT,
        &[],
        |body| match body {
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success { quote, .. }) => {
                Some(Ok(quote))
            }
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(e)) => {
                Some(Err(format!("quote error: {e:?}")))
            }
            _ => None,
        },
        |e| format!("send quote request: {e}"),
        || "quote request timed out".to_string(),
    )
    .await?;
    rmp_serde::from_slice(&quote_bytes).map_err(|e| format!("decode quote: {e}"))
}

/// One storer's answer to a paid PUT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PutOutcome {
    Stored,
    FloorRefused,
    OtherError,
}

async fn paid_put(
    client: &Arc<P2PNode>,
    peer: &PeerId,
    address: [u8; 32],
    data: &[u8],
    proof_bytes: Vec<u8>,
) -> (PutOutcome, String) {
    let request_id: u64 = rand::thread_rng().gen();
    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::PutRequest(ChunkPutRequest::with_payment(
            address,
            Bytes::copy_from_slice(data),
            proof_bytes,
        )),
    };
    let Ok(message_bytes) = message.encode() else {
        return (PutOutcome::OtherError, "encode put".to_string());
    };
    let result = send_and_await_chunk_response(
        client,
        peer,
        message_bytes,
        request_id,
        REQUEST_TIMEOUT,
        &[],
        |body| match body {
            ChunkMessageBody::PutResponse(ChunkPutResponse::Success { .. })
            | ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { .. }) => Some(Ok(())),
            ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => {
                Some(Err(format!("payment required: {message}")))
            }
            ChunkMessageBody::PutResponse(ChunkPutResponse::Error(e)) => {
                Some(Err(format!("put error: {e:?}")))
            }
            _ => None,
        },
        |e| format!("send put: {e}"),
        || "put timed out".to_string(),
    )
    .await;
    match result {
        Ok(()) => (PutOutcome::Stored, String::new()),
        Err(e) if e.contains(FLOOR_REFUSAL) => (PutOutcome::FloorRefused, e),
        Err(e) => (PutOutcome::OtherError, e),
    }
}

/// Settle `amount` for `quote` on chain and build the single-quote proof.
async fn pay(wallet: &Wallet, issuer: &PeerId, quote: &PaymentQuote, amount: Amount) -> Vec<u8> {
    let (tx_by_quote, _gas) = wallet
        .pay_for_quotes(vec![(quote.hash(), quote.rewards_address, amount)])
        .await
        .expect("pay_for_quotes on Anvil");
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::new(*issuer.as_bytes()), quote.clone())],
        },
        tx_hashes: tx_by_quote.values().copied().collect(),
        commitment_sidecars: vec![],
    };
    serialize_single_node_proof(&proof).expect("serialize proof")
}

/// How many of `nodes` store `key`, and how many hold it in their paid list.
fn holders_and_votes(nodes: &[TestNode], key: &[u8; 32]) -> (usize, usize) {
    let mut holders = 0;
    let mut votes = 0;
    for node in nodes {
        if let Some(protocol) = node.ant_protocol.as_ref() {
            if protocol.storage().exists(key).unwrap_or(false) {
                holders += 1;
            }
        }
        if let Some(engine) = node.replication_engine.as_ref() {
            if engine.paid_list().contains(key).unwrap_or(false) {
                votes += 1;
            }
        }
    }
    (holders, votes)
}

fn median(mut xs: Vec<usize>) -> usize {
    xs.sort_unstable();
    xs.get(xs.len() / 2).copied().unwrap_or(0)
}

async fn sync_rounds(network: &TestNetwork, rounds: usize) {
    for _ in 0..rounds {
        for node in network.nodes() {
            if let Some(engine) = node.replication_engine.as_ref() {
                engine.trigger_neighbor_sync();
            }
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
}

async fn cache_sizes(network: &TestNetwork) -> Vec<usize> {
    let mut sizes = Vec::new();
    for node in network.nodes() {
        if let Some(engine) = node.replication_engine.as_ref() {
            sizes.push(engine.last_commitment_by_peer().read().await.len());
        }
    }
    sizes
}

/// Put every node's current signed commitment into every other node's gossip
/// cache, as neighbour sync would.
async fn deliver_commitments(network: &TestNetwork) {
    let commitments: Vec<(PeerId, _)> = network
        .nodes()
        .iter()
        .filter_map(|node| {
            let engine = node.replication_engine.as_ref()?;
            let current = engine.commitment_state().current()?;
            Some((
                PeerId::from_bytes(peer_bytes(node)),
                current.commitment().clone(),
            ))
        })
        .collect();
    let now = Instant::now();
    for node in network.nodes() {
        let own = PeerId::from_bytes(peer_bytes(node));
        if let Some(engine) = node.replication_engine.as_ref() {
            let mut cache = engine.last_commitment_by_peer().write().await;
            for (peer, commitment) in &commitments {
                if *peer != own {
                    cache.insert(
                        *peer,
                        PeerCommitmentRecord::from_verified(commitment.clone(), now),
                    );
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn price_floor_ab_workload() {
    if std::env::var("PRICE_FLOOR_AB").ok().as_deref() != Some("1") {
        eprintln!("price_floor_ab_workload skipped: set PRICE_FLOOR_AB=1 to run");
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    let nodes = env_usize("PF_NODES", 24);
    let keys_per_node = env_usize("PF_KEYS_PER_NODE", 4_500);
    let honest_uploads = env_usize("PF_HONEST", 12);
    let near_empty_uploads = env_usize("PF_NEAR_EMPTY", 8);

    let tail_secs = env_usize("PF_TAIL_SECS", 90);
    eprintln!(
        "PF-CONFIG nodes={nodes} keys_per_node={keys_per_node} honest={honest_uploads} \
         near_empty={near_empty_uploads} tail_secs={tail_secs}"
    );

    let anvil = TestAnvil::new().await.expect("start anvil");
    let wallet = anvil.create_funded_wallet().expect("funded wallet");
    let replication_config = ReplicationConfig {
        neighbor_sync_interval_min: Duration::from_secs(5),
        neighbor_sync_interval_max: Duration::from_secs(10),
        possession_check_delay_min: Duration::from_secs(20),
        possession_check_delay_max: Duration::from_secs(30),
        subtree_round1_responder_cooldown: Duration::from_millis(1),
        ..ReplicationConfig::default()
    };
    let mut config = TestNetworkConfig {
        node_count: nodes,
        payment_enforcement: true,
        replication_config: Some(replication_config),
        ..TestNetworkConfig::default()
    };
    config.evm_network = Some(anvil.to_network());
    let mut network = TestNetwork::new(config).await.expect("build network");
    network.start().await.expect("start network");
    network.warmup_dht().await.expect("warmup dht");
    for node in network.nodes() {
        wire_like_production(node);
    }

    let client_index = nodes.saturating_sub(1);
    let client = network
        .nodes()
        .get(client_index)
        .and_then(|n| n.p2p_node.as_ref())
        .map(Arc::clone)
        .expect("client node p2p");

    // ---- Seed: write synthetic chunks straight into the stores of the seven
    // XOR-closest nodes (each node's own close group in a full routing table),
    // then rotate commitments, so every node commits to a production-sized key
    // set without thousands of on-chain payments.
    let peers: Vec<[u8; 32]> = network.nodes().iter().map(peer_bytes).collect();
    let seed_chunks = keys_per_node * nodes / CLOSE_GROUP_SIZE;
    let mut rng = rand::thread_rng();
    let mut assignments: Vec<Vec<([u8; 32], Vec<u8>)>> = vec![Vec::new(); nodes];
    for i in 0..seed_chunks {
        let mut content = vec![0u8; SEED_CHUNK_BYTES];
        rng.fill(&mut content[..]);
        if let Some(prefix) = content.get_mut(..8) {
            prefix.copy_from_slice(&(i as u64).to_le_bytes());
        }
        let address = compute_address(&content);
        for index in closest_indices(&address, &peers)
            .into_iter()
            .take(CLOSE_GROUP_SIZE)
        {
            if let Some(slot) = assignments.get_mut(index) {
                slot.push((address, content.clone()));
            }
        }
    }
    let mut writers = Vec::new();
    for (node, chunks) in network.nodes().iter().zip(assignments) {
        if let Some(protocol) = node.ant_protocol.as_ref() {
            let storage = protocol.storage();
            writers.push(tokio::spawn(async move {
                for (address, content) in chunks {
                    storage.put(&address, &content).await.expect("seed put");
                }
            }));
        }
    }
    for writer in writers {
        writer.await.expect("seed writer");
    }
    for node in network.nodes() {
        if let Some(engine) = node.replication_engine.as_ref() {
            engine.rebuild_commitment_now().await.expect("rebuild");
        }
    }
    let counts: Vec<usize> = network
        .nodes()
        .iter()
        .filter_map(|n| n.replication_engine.as_ref())
        .filter_map(|e| e.commitment_state().current())
        .map(|c| c.commitment().key_count as usize)
        .collect();
    eprintln!(
        "PF-METRIC phase=seed chunks={seed_chunks} committed_nodes={} key_count_min={} \
         key_count_median={} key_count_max={}",
        counts.len(),
        counts.iter().min().copied().unwrap_or(0),
        median(counts.clone()),
        counts.iter().max().copied().unwrap_or(0)
    );

    deliver_commitments(&network).await;
    let sizes = cache_sizes(&network).await;
    eprintln!(
        "PF-METRIC phase=gossip mode=delivered cache_min={} cache_median={} cache_max={}",
        sizes.iter().min().copied().unwrap_or(0),
        median(sizes.clone()),
        sizes.iter().max().copied().unwrap_or(0)
    );
    assert!(
        median(sizes.clone()) >= FLOOR_MIN_NEIGHBOURS,
        "precondition unmet: the median node knows fewer than {FLOOR_MIN_NEIGHBOURS} neighbour \
         commitments, so the floor would skip every admission"
    );

    // ---- Honest uploads.
    eprintln!("PF-METRIC phase=build tolerance_percent={PRICE_FLOOR_TOLERANCE_PERCENT}");
    let mut honest_keys = Vec::new();
    let (mut honest_stored, mut honest_floor, mut honest_other) = (0usize, 0usize, 0usize);
    for i in 0..honest_uploads {
        let mut data = vec![0u8; 4096];
        rng.fill(&mut data[..]);
        let address = compute_address(&data);
        let storers: Vec<PeerId> = closest_indices(&address, &peers)
            .into_iter()
            .filter(|&j| j != client_index)
            .take(CLOSE_GROUP_SIZE)
            .filter_map(|j| peers.get(j).map(|p| PeerId::from_bytes(*p)))
            .collect();
        let mut quotes = Vec::new();
        for peer in &storers {
            if let Ok(q) = request_quote(&client, peer, address, data.len() as u64).await {
                quotes.push((*peer, q));
            }
        }
        quotes.sort_by_key(|(_, q)| q.price);
        let Some((issuer, median_quote)) = quotes.get(quotes.len() / 2).cloned() else {
            eprintln!("PF-WARN honest {i}: no quotes");
            continue;
        };
        let amount = median_quote.price * Amount::from(PAYMENT_MULTIPLIER);
        let proof = pay(&wallet, &issuer, &median_quote, amount).await;
        let (mut stored, mut floor, mut other) = (0usize, 0usize, 0usize);
        for peer in &storers {
            match paid_put(&client, peer, address, &data, proof.clone()).await {
                (PutOutcome::Stored, _) => stored += 1,
                (PutOutcome::FloorRefused, _) => floor += 1,
                (PutOutcome::OtherError, e) => {
                    other += 1;
                    eprintln!("PF-WARN honest {i} put to {peer}: {e}");
                }
            }
        }
        eprintln!(
            "PF-METRIC phase=honest upload={i} key={} quotes={} paid_price={} stored={stored} \
             floor_refused={floor} other_error={other}",
            hex::encode(address),
            quotes.len(),
            median_quote.price
        );
        assert!(
            stored >= STORE_QUORUM && floor == 0,
            "honest upload {i} must reach a storage quorum with no floor refusal"
        );
        honest_stored += stored;
        honest_floor += floor;
        honest_other += other;
        honest_keys.push(address);
    }

    // ---- A node joins after seeding: no data, no commitment, baseline quotes.
    let before = network.node_count();
    let fresh_index = match network.add_node().await {
        Ok(index) => index,
        // The node is started and registered before the harness waits on its
        // replication bootstrap, which can outlast the harness's fixed timeout
        // on a seeded network. The node is still usable: it holds no
        // commitment either way, which is all this phase needs.
        Err(e) if network.node_count() > before => {
            eprintln!("PF-WARN fresh node bootstrap: {e}; continuing with it");
            before
        }
        Err(e) => panic!("add fresh node: {e}"),
    };
    if let Some(node) = network.nodes().get(fresh_index) {
        wire_like_production(node);
    }
    let fresh_peer_bytes = network
        .nodes()
        .get(fresh_index)
        .map(peer_bytes)
        .expect("fresh node");
    let fresh_peer = PeerId::from_bytes(fresh_peer_bytes);
    sync_rounds(&network, 3).await;
    let mut all_peers = peers.clone();
    all_peers.push(fresh_peer_bytes);
    let fresh_p2p = network
        .nodes()
        .get(fresh_index)
        .and_then(|n| n.p2p_node.as_ref())
        .map(Arc::clone)
        .expect("fresh node p2p");
    let trust_before: HashMap<[u8; 32], f64> = peers
        .iter()
        .map(|p| (*p, fresh_p2p.peer_trust(&PeerId::from_bytes(*p))))
        .collect();
    let mut refusers: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut fan_out_targets: BTreeSet<[u8; 32]> = BTreeSet::new();
    let fan_out_group_size = ReplicationConfig::default().close_group_size;

    // ---- Near-empty quoter uploads: pay the fresh node's baseline quote 3x.
    let mut near_empty_keys = Vec::new();
    let (mut ne_mature_stored, mut ne_mature_floor, mut ne_mature_other, mut ne_fresh_stored) =
        (0usize, 0usize, 0usize, 0usize);
    let mut attempts = 0usize;
    while near_empty_keys.len() < near_empty_uploads && attempts < near_empty_uploads * 20 {
        attempts += 1;
        let mut data = vec![0u8; 4096];
        rng.fill(&mut data[..]);
        let address = compute_address(&data);
        let order = closest_indices(&address, &all_peers);
        // Only addresses where the fresh node is among the eight closest, so
        // every receiver counts it K-close and the floor is what decides.
        let Some(rank) = order.iter().position(|&j| j == fresh_index) else {
            continue;
        };
        if rank >= 8 {
            continue;
        }
        let quote = match request_quote(&client, &fresh_peer, address, data.len() as u64).await {
            Ok(q) => q,
            Err(e) => {
                eprintln!("PF-WARN near-empty quote: {e}");
                continue;
            }
        };
        let amount = quote.price * Amount::from(PAYMENT_MULTIPLIER);
        let proof = pay(&wallet, &fresh_peer, &quote, amount).await;
        let mature: Vec<PeerId> = order
            .iter()
            .copied()
            .filter(|&j| j != client_index && j != fresh_index)
            .take(CLOSE_GROUP_SIZE)
            .filter_map(|j| all_peers.get(j).map(|p| PeerId::from_bytes(*p)))
            .collect();
        // The quoter first, as a client paying it would: its store is what
        // triggers the fan-out whose possession check is under test.
        let (fresh_outcome, fresh_err) =
            paid_put(&client, &fresh_peer, address, &data, proof.clone()).await;
        // The fan-out goes to the quoter's own view of the close group, which
        // can differ from the order above and can include the client node.
        fan_out_targets.extend(
            fresh_p2p
                .dht_manager()
                .find_closest_nodes_local_with_self(&address, fan_out_group_size)
                .await
                .iter()
                .filter(|n| n.peer_id != fresh_peer)
                .map(|n| *n.peer_id.as_bytes()),
        );
        let (mut stored, mut floor, mut other) = (0usize, 0usize, 0usize);
        for peer in &mature {
            match paid_put(&client, peer, address, &data, proof.clone()).await {
                (PutOutcome::Stored, _) => stored += 1,
                (PutOutcome::FloorRefused, _) => {
                    floor += 1;
                    refusers.insert(*peer.as_bytes());
                }
                (PutOutcome::OtherError, e) => {
                    other += 1;
                    eprintln!("PF-WARN near-empty put to {peer}: {e}");
                }
            }
        }
        assert_eq!(
            fresh_outcome,
            PutOutcome::Stored,
            "the near-empty quoter must store its own write: {fresh_err}"
        );
        // A mature storer whose own price is at most the payment over
        // 3 x the tolerance accepts by design (the cap), so a few may store it
        // in a low-count region. What the floor promises is that the write
        // does not reach a storage quorum, and that every refusal is the
        // floor's. The quoter's own store counts toward the quorum too.
        assert!(
            other == 0 && floor + stored == mature.len() && stored + 1 < STORE_QUORUM,
            "the floor must keep a near-empty payment off a storage quorum, refusing it \
             on the floor (stored={stored} floor={floor} other={other})"
        );
        eprintln!(
            "PF-METRIC phase=near_empty upload={} key={} fresh_rank={rank} paid_price={} \
             mature_stored={stored} mature_floor_refused={floor} mature_other_error={other} \
             fresh_node={fresh_outcome:?}",
            near_empty_keys.len(),
            hex::encode(address),
            quote.price
        );
        ne_mature_stored += stored;
        ne_mature_floor += floor;
        ne_mature_other += other;
        ne_fresh_stored += usize::from(fresh_outcome == PutOutcome::Stored);
        near_empty_keys.push(address);
    }

    assert_eq!(
        honest_keys.len(),
        honest_uploads,
        "every requested honest upload must complete"
    );
    assert_eq!(
        near_empty_keys.len(),
        near_empty_uploads,
        "precondition unmet: not every requested near-empty upload was attempted"
    );

    // ---- Tail: fresh offers, PaidNotify and possession checks play out.
    eprintln!("PF-METRIC phase=tail sleeping_secs={tail_secs}");
    tokio::time::sleep(Duration::from_secs(tail_secs as u64)).await;

    let mut honest_holders = Vec::new();
    let mut honest_votes = Vec::new();
    for key in &honest_keys {
        let (h, v) = holders_and_votes(network.nodes(), key);
        eprintln!(
            "PF-METRIC phase=after kind=honest key={} holders={h} paid_votes={v}",
            hex::encode(key)
        );
        honest_holders.push(h);
        honest_votes.push(v);
    }
    let mut ne_holders = Vec::new();
    let mut ne_votes = Vec::new();
    for key in &near_empty_keys {
        let (h, v) = holders_and_votes(network.nodes(), key);
        assert!(
            h < STORE_QUORUM,
            "the floor must keep a near-empty write off a storage quorum"
        );
        eprintln!(
            "PF-METRIC phase=after kind=near_empty key={} holders={h} paid_votes={v}",
            hex::encode(key)
        );
        ne_holders.push(h);
        ne_votes.push(v);
    }

    // The node that stored the near-empty writes fanned them out; it must not
    // have penalised any peer that refused them, nor any peer it fanned them
    // out to.
    let mut min_ratio = f64::INFINITY;
    let mut penalty_sized = 0usize;
    let judged: Vec<&[u8; 32]> = refusers.union(&fan_out_targets).collect();
    for &peer in &judged {
        let before = trust_before.get(peer).copied().unwrap_or(0.5);
        let after = fresh_p2p.peer_trust(&PeerId::from_bytes(*peer));
        let ratio = if before > 0.0 { after / before } else { 1.0 };
        min_ratio = min_ratio.min(ratio);
        if ratio <= POSSESSION_PENALTY_TRUST_RATIO {
            penalty_sized += 1;
        }
    }
    eprintln!(
        "PF-METRIC phase=trust refusers={} fan_out_targets={} judged={} \
         min_trust_ratio={min_ratio:.3} penalty_sized_drops={penalty_sized}",
        refusers.len(),
        fan_out_targets.len(),
        judged.len()
    );
    assert_eq!(
        penalty_sized, 0,
        "no refuser or fan-out target may be penalised for a write under the price floor"
    );

    eprintln!(
        "PF-SUMMARY honest_uploads={} honest_stored={honest_stored} honest_floor_refused={honest_floor} \
         honest_other_error={honest_other} honest_holders_median={} honest_paid_votes_median={} \
         near_empty_uploads={} near_empty_mature_stored={ne_mature_stored} \
         near_empty_mature_floor_refused={ne_mature_floor} near_empty_mature_other_error={ne_mature_other} \
         near_empty_fresh_stored={ne_fresh_stored} near_empty_holders_median={} \
         near_empty_paid_votes_median={}",
        honest_keys.len(),
        median(honest_holders),
        median(honest_votes),
        near_empty_keys.len(),
        median(ne_holders),
        median(ne_votes),
    );

    network.shutdown().await.expect("shutdown network");
}
