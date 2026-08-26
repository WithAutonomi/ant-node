//! Live driver for the settlement-version quote gate (ADR-0013).
//!
//! Every other test of this gate calls the handler in-process. This one puts
//! the four cases on a real QUIC connection between two nodes built from this
//! branch, which is the one thing ADR-0013 records as never having been done:
//! "the gate itself has never run over a real connection, because the devnet
//! speaks the pre-versioned dialect".
//!
//! Four cases per quote path, all against the same node so routing state and
//! quote pricing are shared:
//!
//! - **Unversioned** request — the old client against an upgraded node. Must
//!   still be served, because a node cannot tell a client that settles
//!   correctly but predates the version field from one that does not.
//! - **Current version** — the new client against an upgraded node. Must be
//!   served, so the gate is invisible to clients that can pay.
//! - **Below the minimum** — must come back `ClientUpdateRequired`, refused
//!   *before* any quote is issued, so nothing has been committed on-chain.
//! - **Above this node's current** — must come back `StorerUpdateRequired`.
//!   A lagging node never reports a client fault.
//!
//! Both refusals are unreachable in production today (`MIN` and `CURRENT` are
//! both the first declarable version), so they are driven here by crafting the
//! versions directly, which is what a future settlement bump will make real.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::TestNetworkConfig;
use super::TestHarness;
use ant_node::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkQuoteRequest, ChunkQuoteRequestV2, ChunkQuoteResponse,
    MerkleCandidateQuoteRequest, MerkleCandidateQuoteRequestV2, MerkleCandidateQuoteResponse,
    ProtocolError, CURRENT_SETTLEMENT_VERSION, MIN_SUPPORTED_SETTLEMENT_VERSION,
};
use ant_node::client::send_and_await_chunk_response;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use serial_test::serial;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Node that answers every quote in this driver.
const STORER_INDEX: usize = 1;
/// Node the requests are sent from.
const CLIENT_INDEX: usize = 3;
/// Wire timeout for one quote round trip.
const QUOTE_TIMEOUT: Duration = Duration::from_secs(20);
/// Quote size used throughout; well under `MAX_CHUNK_SIZE`.
const QUOTE_DATA_SIZE: u64 = 4096;

/// Request ids, unique per request so a late response cannot be mistaken for
/// the answer to a later one. That matters here specifically: the fallback
/// path this gate coexists with re-asks under a *new* id.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(0x5E77_1E00);

fn next_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Send one chunk message and return the single-node quote response.
async fn single_node_quote(
    client: &Arc<P2PNode>,
    storer: &PeerId,
    request_id: u64,
    body: ChunkMessageBody,
) -> ChunkQuoteResponse {
    let message = ChunkMessage { request_id, body };
    let bytes = message.encode().expect("encode quote request");
    send_and_await_chunk_response(
        client,
        storer,
        bytes,
        request_id,
        QUOTE_TIMEOUT,
        &[],
        |body| match body {
            ChunkMessageBody::QuoteResponse(response) => Some(Ok(response)),
            _ => None,
        },
        |e| format!("send single-node quote request: {e}"),
        || "single-node quote request timed out".to_string(),
    )
    .await
    .expect("single-node quote round trip")
}

/// Send one chunk message and return the merkle candidate quote response.
async fn merkle_quote(
    client: &Arc<P2PNode>,
    storer: &PeerId,
    request_id: u64,
    body: ChunkMessageBody,
) -> MerkleCandidateQuoteResponse {
    let message = ChunkMessage { request_id, body };
    let bytes = message.encode().expect("encode merkle quote request");
    send_and_await_chunk_response(
        client,
        storer,
        bytes,
        request_id,
        QUOTE_TIMEOUT,
        &[],
        |body| match body {
            ChunkMessageBody::MerkleCandidateQuoteResponse(response) => Some(Ok(response)),
            _ => None,
        },
        |e| format!("send merkle quote request: {e}"),
        || "merkle quote request timed out".to_string(),
    )
    .await
    .expect("merkle quote round trip")
}

/// A version below the minimum this node accepts. `saturating_sub` rather than
/// `- 1` because `MIN` is a constant that a future bump moves.
fn below_minimum_version() -> u32 {
    MIN_SUPPORTED_SETTLEMENT_VERSION.saturating_sub(1)
}

/// A version newer than this node understands.
fn above_current_version() -> u32 {
    CURRENT_SETTLEMENT_VERSION.saturating_add(1)
}

#[tokio::test]
#[serial]
async fn settlement_version_gate_observed_on_live_network() {
    // Route node logs to stderr so a run with
    // `RUST_LOG=ant_node::quote::settlement=warn` shows the refusal lines an
    // operator would have to find in production.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    let harness = TestHarness::setup_with_config(TestNetworkConfig::minimal())
        .await
        .expect("setup settlement-gate network");
    harness.warmup_dht().await.expect("warmup");

    let client = harness.node(CLIENT_INDEX).expect("client node");
    let storer_peer = *harness.node(STORER_INDEX).expect("storer node").peer_id();

    let address = [0x51_u8; 32];
    let merkle_address = [0x52_u8; 32];
    let timestamp = unix_now();

    // -- Old client, upgraded node. The pre-versioned request shape, which is
    //    every client released to date, must still get a quote.
    let legacy = single_node_quote(
        &client,
        &storer_peer,
        next_request_id(),
        ChunkMessageBody::QuoteRequest(ChunkQuoteRequest {
            address,
            data_size: QUOTE_DATA_SIZE,
            data_type: 0,
        }),
    )
    .await;
    let legacy_merkle = merkle_quote(
        &client,
        &storer_peer,
        next_request_id(),
        ChunkMessageBody::MerkleCandidateQuoteRequest(MerkleCandidateQuoteRequest {
            address: merkle_address,
            data_type: 0,
            data_size: QUOTE_DATA_SIZE,
            merkle_payment_timestamp: timestamp,
        }),
    )
    .await;

    // -- New client, upgraded node. The case the whole fleet lands on.
    let current = single_node_quote(
        &client,
        &storer_peer,
        next_request_id(),
        ChunkMessageBody::QuoteRequestV2(ChunkQuoteRequestV2::new(address, QUOTE_DATA_SIZE)),
    )
    .await;
    let current_merkle = merkle_quote(
        &client,
        &storer_peer,
        next_request_id(),
        ChunkMessageBody::MerkleCandidateQuoteRequestV2(MerkleCandidateQuoteRequestV2::new(
            merkle_address,
            QUOTE_DATA_SIZE,
            timestamp,
        )),
    )
    .await;

    // -- A client this node will not settle with. Refused, and refused with a
    //    verdict about the client.
    let mut stale = ChunkQuoteRequestV2::new(address, QUOTE_DATA_SIZE);
    stale.settlement_version = below_minimum_version();
    let refused = single_node_quote(
        &client,
        &storer_peer,
        next_request_id(),
        ChunkMessageBody::QuoteRequestV2(stale),
    )
    .await;

    let mut stale_merkle =
        MerkleCandidateQuoteRequestV2::new(merkle_address, QUOTE_DATA_SIZE, timestamp);
    stale_merkle.settlement_version = below_minimum_version();
    let refused_merkle = merkle_quote(
        &client,
        &storer_peer,
        next_request_id(),
        ChunkMessageBody::MerkleCandidateQuoteRequestV2(stale_merkle),
    )
    .await;

    // -- A client newer than this node. Refused, with a verdict about the
    //    *node*, so an up-to-date user is never told to upgrade.
    let mut ahead = ChunkQuoteRequestV2::new(address, QUOTE_DATA_SIZE);
    ahead.settlement_version = above_current_version();
    let node_behind = single_node_quote(
        &client,
        &storer_peer,
        next_request_id(),
        ChunkMessageBody::QuoteRequestV2(ahead),
    )
    .await;

    let mut ahead_merkle =
        MerkleCandidateQuoteRequestV2::new(merkle_address, QUOTE_DATA_SIZE, timestamp);
    ahead_merkle.settlement_version = above_current_version();
    let node_behind_merkle = merkle_quote(
        &client,
        &storer_peer,
        next_request_id(),
        ChunkMessageBody::MerkleCandidateQuoteRequestV2(ahead_merkle),
    )
    .await;

    println!(
        "SETTLEMENT-GATE-RESULT min={MIN_SUPPORTED_SETTLEMENT_VERSION} \
         current={CURRENT_SETTLEMENT_VERSION}"
    );

    assert!(
        matches!(legacy, ChunkQuoteResponse::Success { .. }),
        "REGRESSION: an unversioned single-node quote was not served: {legacy:?}"
    );
    assert!(
        matches!(legacy_merkle, MerkleCandidateQuoteResponse::Success { .. }),
        "REGRESSION: an unversioned merkle quote was not served: {legacy_merkle:?}"
    );
    assert!(
        matches!(current, ChunkQuoteResponse::Success { .. }),
        "REGRESSION: the gate is not invisible to a current client: {current:?}"
    );
    assert!(
        matches!(current_merkle, MerkleCandidateQuoteResponse::Success { .. }),
        "REGRESSION: the gate is not invisible to a current merkle client: {current_merkle:?}"
    );

    match refused {
        ChunkQuoteResponse::Error(ProtocolError::ClientUpdateRequired {
            client_settlement_version,
            min_settlement_version,
        }) => {
            assert_eq!(client_settlement_version, below_minimum_version());
            assert_eq!(min_settlement_version, MIN_SUPPORTED_SETTLEMENT_VERSION);
        }
        other => panic!("a stale single-node client was not refused as its own fault: {other:?}"),
    }
    match refused_merkle {
        MerkleCandidateQuoteResponse::Error(ProtocolError::ClientUpdateRequired {
            client_settlement_version,
            min_settlement_version,
        }) => {
            assert_eq!(client_settlement_version, below_minimum_version());
            assert_eq!(min_settlement_version, MIN_SUPPORTED_SETTLEMENT_VERSION);
        }
        other => panic!("a stale merkle client was not refused as its own fault: {other:?}"),
    }
    match node_behind {
        ChunkQuoteResponse::Error(ProtocolError::StorerUpdateRequired {
            client_settlement_version,
            node_settlement_version,
        }) => {
            assert_eq!(client_settlement_version, above_current_version());
            assert_eq!(node_settlement_version, CURRENT_SETTLEMENT_VERSION);
        }
        other => panic!("a lagging node blamed the client instead of itself: {other:?}"),
    }
    match node_behind_merkle {
        MerkleCandidateQuoteResponse::Error(ProtocolError::StorerUpdateRequired {
            client_settlement_version,
            node_settlement_version,
        }) => {
            assert_eq!(client_settlement_version, above_current_version());
            assert_eq!(node_settlement_version, CURRENT_SETTLEMENT_VERSION);
        }
        other => panic!("a lagging node blamed the merkle client instead of itself: {other:?}"),
    }

    harness.teardown().await.expect("teardown");
}
