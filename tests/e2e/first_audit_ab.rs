//! ADR-0004 first-audit A/B workload driver (NOT a pass/fail regression test).
//!
//! Drives a production-shaped paid-upload workload against a local testnet
//! with real on-chain payment verification (Anvil), so the monetized
//! first-audit pipeline runs end-to-end exactly as in production:
//! quote collection (with commitment sidecars) -> median payment on chain ->
//! `ChunkPutRequest` with the full proof -> storer-side `verify_payment` ->
//! monetized-pin nomination -> first-audit drainer -> subtree audits over QUIC.
//!
//! Run the SAME file against two builds (baseline `main` vs the scheduler-fix
//! branch) and compare the emitted `AB-METRIC` lines plus log-event counts
//! (audit launches, timeouts, responder drops). Skipped entirely unless
//! `FIRST_AUDIT_AB=1` is set, so it never runs in CI.
//!
//! ```bash
//! FIRST_AUDIT_AB=1 RUST_LOG=info,ant_node::replication=debug \
//!   cargo test --test e2e first_audit_ab_workload -- --nocapture
//! ```
//!
//! Knobs (env): `AB_NODES`, `AB_SEED_UPLOADS`, `AB_UPLOADS`, `AB_GAP_MS`,
//! `AB_REBUILD_EVERY`, `AB_DOWNLOADS`, `AB_TAIL_SECS`, `AB_CHUNK_KIB`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unnested_or_patterns,
    clippy::cast_precision_loss,
    clippy::redundant_closure_for_method_calls
)]

use ant_node::ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteResponse, CLOSE_GROUP_SIZE,
};
use ant_node::client::send_and_await_chunk_response;
use ant_node::payment::{serialize_single_node_proof, PaymentProof};
use evmlib::common::Amount;
use evmlib::{EncodedPeerId, ProofOfPayment};
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use serial_test::serial;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::anvil::TestAnvil;
use super::testnet::{TestNetwork, TestNetworkConfig};

/// The verifier accepts a settlement of at least 3x the median quote price.
/// Mirrors `PAID_QUOTE_PAYMENT_MULTIPLIER` (private to the verifier).
const PAYMENT_MULTIPLIER: u64 = 3;

/// Per-request timeout for quote/PUT/GET protocol round trips.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// One collected quote: the issuing peer, the decoded quote, and the raw
/// commitment sidecar blob (when the quote pinned a commitment).
struct CollectedQuote {
    peer: PeerId,
    quote: evmlib::PaymentQuote,
    sidecar: Option<Vec<u8>>,
}

/// Request a signed quote (plus ADR-0004 commitment sidecar) from one peer.
async fn request_quote(
    client: &Arc<P2PNode>,
    peer: &PeerId,
    address: [u8; 32],
    data_size: u64,
) -> Result<CollectedQuote, String> {
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

    let (quote_bytes, sidecar) = send_and_await_chunk_response(
        client,
        peer,
        message_bytes,
        request_id,
        REQUEST_TIMEOUT,
        &[],
        |body| match body {
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
                quote,
                already_stored: _,
                commitment,
            }) => Some(Ok((quote, commitment))),
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(e)) => {
                Some(Err(format!("quote error: {e:?}")))
            }
            _ => None,
        },
        |e| format!("send quote request: {e}"),
        || "quote request timed out".to_string(),
    )
    .await?;

    let quote: evmlib::PaymentQuote =
        rmp_serde::from_slice(&quote_bytes).map_err(|e| format!("decode quote: {e}"))?;
    Ok(CollectedQuote {
        peer: *peer,
        quote,
        sidecar,
    })
}

/// Send a paid PUT to one peer; `Ok(true)` when it stored (or already had it).
async fn paid_put(
    client: &Arc<P2PNode>,
    peer: &PeerId,
    address: [u8; 32],
    data: &[u8],
    proof_bytes: Vec<u8>,
) -> Result<bool, String> {
    let request_id: u64 = rand::thread_rng().gen();
    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::PutRequest(ChunkPutRequest::with_payment(
            address,
            bytes::Bytes::copy_from_slice(data),
            proof_bytes,
        )),
    };
    let message_bytes = message
        .encode()
        .map_err(|e| format!("encode put request: {e}"))?;

    send_and_await_chunk_response(
        client,
        peer,
        message_bytes,
        request_id,
        REQUEST_TIMEOUT,
        &[],
        |body| match body {
            ChunkMessageBody::PutResponse(ChunkPutResponse::Success { .. })
            | ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { .. }) => {
                Some(Ok(true))
            }
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
    .await
}

/// Fetch a chunk from one peer; `Ok(true)` when the bytes came back.
async fn get_chunk(
    client: &Arc<P2PNode>,
    peer: &PeerId,
    address: [u8; 32],
) -> Result<bool, String> {
    let request_id: u64 = rand::thread_rng().gen();
    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::GetRequest(ChunkGetRequest::new(address)),
    };
    let message_bytes = message
        .encode()
        .map_err(|e| format!("encode get request: {e}"))?;

    send_and_await_chunk_response(
        client,
        peer,
        message_bytes,
        request_id,
        REQUEST_TIMEOUT,
        &[],
        |body| match body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::Success { .. }) => Some(Ok(true)),
            ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { .. }) => Some(Ok(false)),
            ChunkMessageBody::GetResponse(ChunkGetResponse::Error(e)) => {
                Some(Err(format!("get error: {e:?}")))
            }
            _ => None,
        },
        |e| format!("send get: {e}"),
        || "get timed out".to_string(),
    )
    .await
}

/// Outcome of one full paid upload.
struct UploadOutcome {
    duration: Duration,
    pinned_quotes: usize,
    total_quotes: usize,
    stored_acks: usize,
}

/// One production-shaped paid upload: collect quotes from the close group,
/// pay the median issuer 3x on chain, then PUT the chunk (with the full quote
/// bundle + sidecars) to every close-group peer.
async fn paid_upload(
    client: &Arc<P2PNode>,
    client_peer: &PeerId,
    wallet: &evmlib::wallet::Wallet,
    data: &[u8],
) -> Result<(UploadOutcome, [u8; 32]), String> {
    let address = ant_node::compute_address(data);
    let started = Instant::now();

    let closest = client
        .dht()
        .find_closest_nodes(&address, CLOSE_GROUP_SIZE + 1)
        .await
        .map_err(|e| format!("find closest: {e}"))?;
    let storers: Vec<PeerId> = closest
        .iter()
        .map(|n| n.peer_id)
        .filter(|p| p != client_peer)
        .take(CLOSE_GROUP_SIZE)
        .collect();
    if storers.is_empty() {
        return Err("no close-group peers found".to_string());
    }

    let mut quotes: Vec<CollectedQuote> = Vec::with_capacity(storers.len());
    for peer in &storers {
        match request_quote(client, peer, address, data.len() as u64).await {
            Ok(q) => quotes.push(q),
            Err(e) => eprintln!("AB-WARN quote from {peer} failed: {e}"),
        }
    }
    if quotes.is_empty() {
        return Err("no quotes collected".to_string());
    }

    // Median selection mirrors the node verifier: sort by price, index len/2,
    // settle 3x that price to the median issuer.
    quotes.sort_by_key(|q| q.quote.price);
    let median = quotes
        .get(quotes.len() / 2)
        .ok_or_else(|| "median index out of range".to_string())?;
    let amount = median
        .quote
        .price
        .checked_mul(Amount::from(PAYMENT_MULTIPLIER))
        .ok_or_else(|| "payment amount overflow".to_string())?;
    let (tx_by_quote, _gas) = wallet
        .pay_for_quotes(vec![(
            median.quote.hash(),
            median.quote.rewards_address,
            amount,
        )])
        .await
        .map_err(|e| format!("pay_for_quotes: {e:?}"))?;
    let tx_hashes: Vec<evmlib::common::TxHash> = tx_by_quote.values().copied().collect();

    let pinned_quotes = quotes
        .iter()
        .filter(|q| q.quote.commitment_pin.is_some())
        .count();
    let total_quotes = quotes.len();
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: quotes
                .iter()
                .map(|q| (EncodedPeerId::new(*q.peer.as_bytes()), q.quote.clone()))
                .collect(),
        },
        tx_hashes,
        commitment_sidecars: quotes.iter().filter_map(|q| q.sidecar.clone()).collect(),
    };
    let proof_bytes =
        serialize_single_node_proof(&proof).map_err(|e| format!("serialize proof: {e}"))?;

    let mut stored_acks = 0usize;
    for peer in &storers {
        match paid_put(client, peer, address, data, proof_bytes.clone()).await {
            Ok(true) => stored_acks += 1,
            Ok(false) => {}
            Err(e) => eprintln!("AB-WARN put to {peer} failed: {e}"),
        }
    }
    if stored_acks == 0 {
        return Err("no storer accepted the paid put".to_string());
    }

    Ok((
        UploadOutcome {
            duration: started.elapsed(),
            pinned_quotes,
            total_quotes,
            stored_acks,
        },
        address,
    ))
}

/// Rebuild every node's storage commitment (simulates the hourly rotation
/// that re-arms pin-level dedup in production).
async fn rebuild_all_commitments(network: &TestNetwork) {
    for node in network.nodes() {
        if let Some(engine) = node.replication_engine.as_ref() {
            if let Err(e) = engine.rebuild_commitment_now().await {
                eprintln!(
                    "AB-WARN commitment rebuild failed on node {}: {e}",
                    node.index
                );
            }
        }
    }
}

fn percentile_ms(sorted: &[Duration], pct: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let last = sorted.len() - 1;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let idx = ((sorted.len() as f64 * pct) as usize).min(last);
    sorted.get(idx).map_or(0, |d| d.as_millis())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[allow(clippy::too_many_lines)]
async fn first_audit_ab_workload() {
    if std::env::var("FIRST_AUDIT_AB").ok().as_deref() != Some("1") {
        eprintln!("first_audit_ab_workload skipped: set FIRST_AUDIT_AB=1 to run");
        return;
    }
    // Route node logs to stderr so the runner script can count audit events.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    let nodes = env_usize("AB_NODES", 20);
    let seed_uploads = env_usize("AB_SEED_UPLOADS", 25);
    let uploads = env_usize("AB_UPLOADS", 40);
    let gap_ms = env_u64("AB_GAP_MS", 2000);
    let rebuild_every = env_usize("AB_REBUILD_EVERY", 15);
    let downloads = env_usize("AB_DOWNLOADS", 15);
    let tail_secs = env_u64("AB_TAIL_SECS", 90);
    let chunk_kib = env_usize("AB_CHUNK_KIB", 64);

    eprintln!(
        "AB-CONFIG nodes={nodes} seed_uploads={seed_uploads} uploads={uploads} gap_ms={gap_ms} \
         rebuild_every={rebuild_every} downloads={downloads} tail_secs={tail_secs} chunk_kib={chunk_kib}"
    );

    // Anvil FIRST so nodes verify payments against it for real.
    let anvil = TestAnvil::new().await.expect("start anvil");
    let wallet = anvil.create_funded_wallet().expect("funded wallet");

    let mut config = TestNetworkConfig {
        node_count: nodes,
        payment_enforcement: true,
        ..TestNetworkConfig::default()
    };
    config.evm_network = Some(anvil.to_network());
    let mut network = TestNetwork::new(config).await.expect("build network");
    network.start().await.expect("start network");
    network.warmup_dht().await.expect("warmup dht");

    // Wire each node exactly like production `node.rs`: commitment source into
    // the quote generator, gossip cache into the verifier, and the
    // monetized-pin sender into the verifier (the trio the e2e testnet does
    // not wire by default).
    for node in network.nodes() {
        if let (Some(protocol), Some(engine)) =
            (node.ant_protocol.as_ref(), node.replication_engine.as_ref())
        {
            let concrete = Arc::clone(engine.commitment_state());
            let source: Arc<dyn ant_node::payment::quote::CommitmentSource> = concrete;
            protocol.attach_commitment_source(source);
            protocol
                .payment_verifier_arc()
                .attach_commitment_cache(Arc::clone(engine.last_commitment_by_peer()));
            protocol
                .payment_verifier_arc()
                .attach_monetized_pin_sender(engine.monetized_pin_sender());
        }
    }

    // The last node acts as the uploading/downloading client.
    let client_index = nodes.saturating_sub(1);
    let client = network
        .nodes()
        .get(client_index)
        .and_then(|n| n.p2p_node.as_ref())
        .map(Arc::clone)
        .expect("client node p2p");
    let client_peer = *client.peer_id();

    let chunk_bytes = chunk_kib * 1024;
    let mut rng = rand::thread_rng();
    let mut make_chunk = move || {
        let mut data = vec![0u8; chunk_bytes];
        rng.fill(&mut data[..]);
        data
    };

    // ---- Seed phase: give nodes stored chunks, then build commitments so
    // subsequent quotes carry pins (production steady state).
    let mut seeded = 0usize;
    for _ in 0..seed_uploads {
        let data = make_chunk();
        match paid_upload(&client, &client_peer, &wallet, &data).await {
            Ok(_) => seeded += 1,
            Err(e) => eprintln!("AB-WARN seed upload failed: {e}"),
        }
    }
    eprintln!("AB-METRIC phase=seed uploads_ok={seeded}/{seed_uploads}");
    rebuild_all_commitments(&network).await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ---- Measurement phase: steady paid uploads, with periodic commitment
    // rotation (the production re-arming mechanism).
    let mut upload_durations: Vec<Duration> = Vec::with_capacity(uploads);
    let mut uploaded_addresses: Vec<[u8; 32]> = Vec::with_capacity(uploads);
    let mut pinned_total = 0usize;
    let mut quotes_total = 0usize;
    let mut acks_total = 0usize;
    let mut failures = 0usize;
    let measure_started = Instant::now();
    for i in 0..uploads {
        if i > 0 && rebuild_every > 0 && i % rebuild_every == 0 {
            rebuild_all_commitments(&network).await;
            eprintln!("AB-METRIC phase=measure rotation_at_upload={i}");
        }
        let data = make_chunk();
        match paid_upload(&client, &client_peer, &wallet, &data).await {
            Ok((outcome, address)) => {
                eprintln!(
                    "AB-METRIC phase=measure upload={i} ms={} pinned={}/{} acks={}",
                    outcome.duration.as_millis(),
                    outcome.pinned_quotes,
                    outcome.total_quotes,
                    outcome.stored_acks
                );
                pinned_total += outcome.pinned_quotes;
                quotes_total += outcome.total_quotes;
                acks_total += outcome.stored_acks;
                upload_durations.push(outcome.duration);
                uploaded_addresses.push(address);
            }
            Err(e) => {
                failures += 1;
                eprintln!("AB-WARN measure upload {i} failed: {e}");
            }
        }
        tokio::time::sleep(Duration::from_millis(gap_ms)).await;
    }

    // ---- Download phase.
    let mut download_durations: Vec<Duration> = Vec::with_capacity(downloads);
    let mut download_failures = 0usize;
    for (i, address) in uploaded_addresses.iter().rev().take(downloads).enumerate() {
        let started = Instant::now();
        let closest = client
            .dht()
            .find_closest_nodes(address, CLOSE_GROUP_SIZE)
            .await
            .unwrap_or_default();
        let mut found = false;
        for peer in closest.iter().map(|n| n.peer_id) {
            if peer == client_peer {
                continue;
            }
            if get_chunk(&client, &peer, *address).await == Ok(true) {
                found = true;
                break;
            }
        }
        if found {
            let elapsed = started.elapsed();
            eprintln!(
                "AB-METRIC phase=download get={i} ms={}",
                elapsed.as_millis()
            );
            download_durations.push(elapsed);
        } else {
            download_failures += 1;
            eprintln!("AB-WARN download {i} failed");
        }
    }

    // ---- Tail: let in-flight and pending audits play out before teardown so
    // their outcomes land in the captured logs.
    eprintln!("AB-METRIC phase=tail sleeping_secs={tail_secs}");
    tokio::time::sleep(Duration::from_secs(tail_secs)).await;

    upload_durations.sort_unstable();
    download_durations.sort_unstable();
    eprintln!(
        "AB-SUMMARY uploads_ok={} uploads_failed={failures} upload_p50_ms={} upload_p90_ms={} \
         downloads_ok={} downloads_failed={download_failures} download_p50_ms={} download_p90_ms={} \
         pinned_quote_ratio={pinned_total}/{quotes_total} storer_acks={acks_total} \
         measure_wall_secs={}",
        upload_durations.len(),
        percentile_ms(&upload_durations, 0.50),
        percentile_ms(&upload_durations, 0.90),
        download_durations.len(),
        percentile_ms(&download_durations, 0.50),
        percentile_ms(&download_durations, 0.90),
        measure_started.elapsed().as_secs(),
    );

    network.shutdown().await.expect("shutdown network");
}
