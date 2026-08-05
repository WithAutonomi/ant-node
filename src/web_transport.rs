//! ADR-0009 WebTransport interoperability proof.
//!
//! This module is feature-gated, disabled by default, and intentionally keeps
//! the browser-facing HTTP/3 stack separate from native Saorsa QUIC. It is not
//! the production endpoint-record or certificate-rotation implementation.

use crate::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest,
    ChunkQuoteResponse, MAX_CHUNK_SIZE,
};
use crate::browser::{BrowserEndpoint, BrowserPaymentNetwork, BROWSER_WEBTRANSPORT_PATH};
use crate::config::WebTransportConfig;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::payment::{serialize_single_node_proof, PaymentProof};
use crate::storage::AntProtocol;
use evmlib::common::{Amount, TxHash};
use evmlib::{EncodedPeerId, PaymentQuote, ProofOfPayment, RewardsAddress};
use parking_lot::RwLock;
use saorsa_core::{P2PNode, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wtransport::endpoint::IncomingSession;
use wtransport::stream::{RecvStream, SendStream};
use wtransport::{Endpoint, Identity, ServerConfig};

const PROTOCOL_VERSION: u16 = 3;
const PROTOCOL_NAME: &str = "autonomi.web.poc.v3";
const MAX_FIND_NODE_RESULTS: usize = 20;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Browser endpoints known to one or more listeners in the same process.
///
/// Production nodes will populate this information from signed endpoint
/// records. The in-process devnet shares one catalog so browser clients can
/// exercise a real multi-node iterative lookup before that DHT record type is
/// available.
#[derive(Default)]
pub struct BrowserEndpointCatalog {
    endpoints: RwLock<HashMap<PeerId, BrowserEndpoint>>,
}

impl BrowserEndpointCatalog {
    fn insert(&self, peer_id: PeerId, endpoint: BrowserEndpoint) {
        self.endpoints.write().insert(peer_id, endpoint);
    }

    fn get(&self, peer_id: &PeerId) -> Option<BrowserEndpoint> {
        self.endpoints.read().get(peer_id).cloned()
    }
}

/// A running browser listener and the endpoint clients use to reach it.
pub struct WebTransportServer {
    /// Direct endpoint with its certificate pin embedded in the multiaddress.
    pub endpoint: BrowserEndpoint,
    /// Listener background task.
    pub task: JoinHandle<()>,
}

/// Start the feature-gated browser listener and return its endpoint and task.
pub fn spawn(
    config: &WebTransportConfig,
    p2p: Arc<P2PNode>,
    ant_protocol: Option<Arc<AntProtocol>>,
    evm_network: &evmlib::Network,
    shutdown: CancellationToken,
    endpoint_catalog: Arc<BrowserEndpointCatalog>,
) -> Result<WebTransportServer> {
    validate_config(config)?;

    let identity = Identity::self_signed(&config.certificate_sans)
        .map_err(|error| Error::Config(format!("invalid WebTransport certificate SAN: {error}")))?;
    let certificate = identity
        .certificate_chain()
        .as_slice()
        .first()
        .ok_or_else(|| Error::Startup("WebTransport identity has no certificate".to_string()))?;
    let certificate_sha256 = *certificate.hash().as_ref();

    let server_config = ServerConfig::builder()
        .with_bind_address(config.bind)
        .with_identity(identity)
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .build();
    let endpoint = Endpoint::server(server_config).map_err(|error| {
        Error::Startup(format!("failed to bind WebTransport endpoint: {error}"))
    })?;
    let local_addr = endpoint.local_addr().map_err(|error| {
        Error::Startup(format!(
            "failed to read WebTransport bound address: {error}"
        ))
    })?;
    let advertised_url = advertised_url(config, local_addr);

    let peer_id = *p2p.peer_id();
    let browser_endpoint = BrowserEndpoint::new(&advertised_url, &peer_id, &[certificate_sha256])
        .map_err(Error::Config)?;
    endpoint_catalog.insert(peer_id, browser_endpoint.clone());

    let state = Arc::new(ServerState {
        config: config.clone(),
        p2p,
        ant_protocol,
        payment: BrowserPaymentNetwork::from_evm_network(evm_network),
        endpoint: browser_endpoint.clone(),
        endpoint_catalog,
    });
    let connection_limit = Arc::new(Semaphore::new(config.max_connections));

    info!(
        bind = %local_addr,
        multiaddr = %browser_endpoint.multiaddr,
        "ADR-0009 WebTransport PoC listening"
    );

    let task = tokio::spawn(async move {
        serve(endpoint, state, connection_limit, shutdown).await;
    });
    Ok(WebTransportServer {
        endpoint: browser_endpoint,
        task,
    })
}

fn validate_config(config: &WebTransportConfig) -> Result<()> {
    if config.path != BROWSER_WEBTRANSPORT_PATH {
        return Err(Error::Config(format!(
            "webtransport.path must be {BROWSER_WEBTRANSPORT_PATH}"
        )));
    }
    if config.allowed_origins.is_empty() {
        return Err(Error::Config(
            "webtransport.allowed_origins must not be empty".to_string(),
        ));
    }
    if config.certificate_sans.is_empty() {
        return Err(Error::Config(
            "webtransport.certificate_sans must not be empty".to_string(),
        ));
    }
    if config.max_connections == 0 {
        return Err(Error::Config(
            "webtransport.max_connections must be greater than zero".to_string(),
        ));
    }
    if config.max_request_bytes == 0 || config.max_request_bytes > MAX_RESPONSE_HEADER_BYTES {
        return Err(Error::Config(format!(
            "webtransport.max_request_bytes must be between 1 and {MAX_RESPONSE_HEADER_BYTES}"
        )));
    }
    if let Some(url) = config.advertised_url.as_deref() {
        if !url.starts_with("https://") {
            return Err(Error::Config(
                "webtransport.advertised_url must use https://".to_string(),
            ));
        }
    }
    Ok(())
}

fn advertised_url(config: &WebTransportConfig, local_addr: SocketAddr) -> String {
    if let Some(url) = config.advertised_url.as_ref() {
        return url.clone();
    }

    let host = match local_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".to_string(),
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) if ip.is_unspecified() => "[::1]".to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    format!("https://{host}:{}{}", local_addr.port(), config.path)
}

async fn serve(
    endpoint: Endpoint<wtransport::endpoint::endpoint_side::Server>,
    state: Arc<ServerState>,
    connection_limit: Arc<Semaphore>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            incoming = endpoint.accept() => {
                match Arc::clone(&connection_limit).try_acquire_owned() {
                    Ok(permit) => {
                        let state = Arc::clone(&state);
                        let connection_shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_incoming(
                                incoming,
                                state,
                                connection_shutdown,
                                permit,
                            ).await {
                                debug!("WebTransport session ended: {error}");
                            }
                        });
                    }
                    Err(_) => {
                        tokio::spawn(reject_busy(incoming));
                    }
                }
            }
        }
    }
    endpoint.close(0u32.into(), b"node shutting down");
    info!("ADR-0009 WebTransport PoC stopped");
}

async fn reject_busy(incoming: IncomingSession) {
    match tokio::time::timeout(REQUEST_TIMEOUT, incoming).await {
        Ok(Ok(request)) => request.too_many_requests().await,
        Ok(Err(error)) => debug!("Could not reject busy WebTransport session: {error}"),
        Err(_) => debug!("Timed out while rejecting busy WebTransport session"),
    }
}

async fn handle_incoming(
    incoming: IncomingSession,
    state: Arc<ServerState>,
    shutdown: CancellationToken,
    _permit: OwnedSemaphorePermit,
) -> ServerResult<()> {
    let request = tokio::select! {
        () = shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout(REQUEST_TIMEOUT, incoming) => {
            result
                .map_err(|_| "session negotiation timed out".to_string())?
                .map_err(|error| format!("session negotiation failed: {error}"))?
        }
    };

    if request.path() != state.config.path {
        request.not_found().await;
        return Ok(());
    }
    if !origin_allowed(&state.config.allowed_origins, request.origin()) {
        warn!(origin = ?request.origin(), "Rejected WebTransport Origin");
        request.forbidden().await;
        return Ok(());
    }

    let remote = request.remote_address();
    let connection = request
        .accept()
        .await
        .map_err(|error| format!("session accept failed: {error}"))?;
    debug!(remote = %remote, "Accepted browser WebTransport session");

    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            stream = connection.accept_bi() => {
                let (send, recv) = stream
                    .map_err(|error| format!("bidirectional stream accept failed: {error}"))?;
                handle_stream(send, recv, Arc::clone(&state)).await?;
            }
            stream = connection.accept_uni() => {
                let recv = stream
                    .map_err(|error| format!("unidirectional stream accept failed: {error}"))?;
                recv.stop(1u32.into());
            }
            datagram = connection.receive_datagram() => {
                datagram.map_err(|error| format!("datagram receive failed: {error}"))?;
                debug!("Discarded unsupported WebTransport datagram");
            }
        }
    }
}

async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    state: Arc<ServerState>,
) -> ServerResult<()> {
    let (request, content) = match read_request(&mut recv, state.config.max_request_bytes).await {
        Ok(request) => request,
        Err(error) => {
            let response = Response::error(0, "invalid_request", error);
            return write_response(&mut send, &response, &[]).await;
        }
    };

    if request.version != PROTOCOL_VERSION {
        let request_id = request.id;
        let response = Response::error(
            request_id,
            "unsupported_version",
            format!(
                "protocol version {} is unsupported; expected {PROTOCOL_VERSION}",
                request.version
            ),
        );
        return write_response(&mut send, &response, &[]).await;
    }

    let (response, content) = process_request(request, content, &state).await;
    write_response(&mut send, &response, content.as_deref().unwrap_or_default()).await
}

async fn read_request(
    recv: &mut RecvStream,
    max_header_bytes: usize,
) -> ServerResult<(Request, Vec<u8>)> {
    let mut bytes = Vec::new();
    let max_frame_bytes = 4usize
        .saturating_add(max_header_bytes)
        .saturating_add(MAX_CHUNK_SIZE);
    let mut limited = recv.take((max_frame_bytes + 1) as u64);
    tokio::time::timeout(REQUEST_TIMEOUT, limited.read_to_end(&mut bytes))
        .await
        .map_err(|_| "request body timed out".to_string())?
        .map_err(|error| format!("request body read failed: {error}"))?;

    if bytes.len() > max_frame_bytes {
        return Err(format!(
            "request exceeds the {max_frame_bytes}-byte frame limit"
        ));
    }
    let prefix = bytes
        .get(..4)
        .ok_or_else(|| "request ended before its four-byte header length".to_string())?;
    let header_len = u32::from_be_bytes(
        prefix
            .try_into()
            .map_err(|_| "request header prefix is invalid".to_string())?,
    ) as usize;
    if header_len == 0 || header_len > max_header_bytes {
        return Err(format!(
            "request header length {header_len} is outside 1..={max_header_bytes}"
        ));
    }
    let content_offset = 4usize
        .checked_add(header_len)
        .ok_or_else(|| "request header length overflow".to_string())?;
    let header = bytes
        .get(4..content_offset)
        .ok_or_else(|| "request ended inside its JSON header".to_string())?;
    let request: Request = serde_json::from_slice(header)
        .map_err(|error| format!("request JSON is invalid: {error}"))?;
    if request.content_length > MAX_CHUNK_SIZE {
        return Err(format!(
            "request content length {} exceeds {MAX_CHUNK_SIZE}",
            request.content_length
        ));
    }
    let expected_len = content_offset
        .checked_add(request.content_length)
        .ok_or_else(|| "request content length overflow".to_string())?;
    if bytes.len() != expected_len {
        return Err(format!(
            "request length mismatch: declared {} content bytes",
            request.content_length
        ));
    }
    Ok((request, bytes[content_offset..].to_vec()))
}

async fn process_request(
    request: Request,
    content: Vec<u8>,
    state: &ServerState,
) -> (Response, Option<Vec<u8>>) {
    if !matches!(&request.body, RequestBody::PutChunk { .. }) && !content.is_empty() {
        return (
            Response::error(
                request.id,
                "unexpected_content",
                "only put_chunk accepts binary request content".to_string(),
            ),
            None,
        );
    }
    match request.body {
        RequestBody::Hello => (
            Response::ok(
                request.id,
                ResponseBody::Hello {
                    protocol: PROTOCOL_NAME.to_string(),
                    peer_id: state.p2p.peer_id().to_hex(),
                    max_chunk_size: MAX_CHUNK_SIZE,
                    endpoint: state.endpoint.clone(),
                    payment: state.payment.clone(),
                    capabilities: vec![
                        "find_node".to_string(),
                        "get_chunk".to_string(),
                        "quote_chunk".to_string(),
                        "put_chunk".to_string(),
                    ],
                },
                0,
            ),
            None,
        ),
        RequestBody::FindNode { target, count } => {
            process_find_node(request.id, target, count, state).await
        }
        RequestBody::GetChunk { address } => process_get_chunk(request.id, address, state).await,
        RequestBody::QuoteChunk { address, size } => {
            process_quote_chunk(request.id, address, size, state).await
        }
        RequestBody::PutChunk {
            address,
            quote,
            transaction_hash,
        } => {
            process_put_chunk(
                request.id,
                address,
                *quote,
                transaction_hash,
                content,
                state,
            )
            .await
        }
    }
}

async fn process_find_node(
    request_id: u64,
    target: String,
    count: Option<usize>,
    state: &ServerState,
) -> (Response, Option<Vec<u8>>) {
    let target_bytes = match decode_32_byte_hex(&target) {
        Ok(bytes) => bytes,
        Err(error) => return (Response::error(request_id, "invalid_target", error), None),
    };
    let count = count
        .unwrap_or(MAX_FIND_NODE_RESULTS)
        .clamp(1, MAX_FIND_NODE_RESULTS);
    let nodes = state
        .p2p
        .dht_manager()
        .find_closest_nodes_local_with_self(&target_bytes, count)
        .await
        .into_iter()
        .map(|node| {
            let peer_id = node.peer_id.to_hex();
            BrowserNode {
                webtransport: state.endpoint_catalog.get(&node.peer_id),
                peer_id,
                native_addresses: node
                    .addresses_by_priority()
                    .into_iter()
                    .map(|address| address.to_string())
                    .collect(),
                reliability: node.reliability,
            }
        })
        .collect();
    (
        Response::ok(request_id, ResponseBody::Nodes { target, nodes }, 0),
        None,
    )
}

async fn process_get_chunk(
    request_id: u64,
    address: String,
    state: &ServerState,
) -> (Response, Option<Vec<u8>>) {
    let address_bytes = match decode_32_byte_hex(&address) {
        Ok(bytes) => bytes,
        Err(error) => return (Response::error(request_id, "invalid_address", error), None),
    };
    let Some(ant_protocol) = state.ant_protocol.as_ref() else {
        return (
            Response::error(
                request_id,
                "storage_disabled",
                "chunk storage is disabled on this node".to_string(),
            ),
            None,
        );
    };

    match ant_protocol.storage().get(&address_bytes).await {
        Ok(Some(content)) if content.len() <= MAX_CHUNK_SIZE => {
            let content_length = content.len();
            (
                Response::ok(
                    request_id,
                    ResponseBody::Chunk {
                        address,
                        size: content_length,
                    },
                    content_length,
                ),
                Some(content),
            )
        }
        Ok(Some(content)) => (
            Response::error(
                request_id,
                "oversize_chunk",
                format!(
                    "stored content is {} bytes; maximum is {MAX_CHUNK_SIZE}",
                    content.len()
                ),
            ),
            None,
        ),
        Ok(None) => (Response::not_found(request_id, address), None),
        Err(error) => (
            Response::error(
                request_id,
                "storage_error",
                format!("chunk read failed: {error}"),
            ),
            None,
        ),
    }
}

async fn process_quote_chunk(
    request_id: u64,
    address: String,
    size: u64,
    state: &ServerState,
) -> (Response, Option<Vec<u8>>) {
    let address_bytes = match decode_32_byte_hex(&address) {
        Ok(bytes) => bytes,
        Err(error) => return (Response::error(request_id, "invalid_address", error), None),
    };
    if size > MAX_CHUNK_SIZE as u64 {
        return (
            Response::error(
                request_id,
                "oversize_chunk",
                format!("chunk size {size} exceeds {MAX_CHUNK_SIZE}"),
            ),
            None,
        );
    }
    let Some(ant_protocol) = state.ant_protocol.as_ref() else {
        return (
            Response::error(
                request_id,
                "storage_disabled",
                "chunk storage is disabled on this node".to_string(),
            ),
            None,
        );
    };

    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::QuoteRequest(ChunkQuoteRequest::new(address_bytes, size)),
    };
    let response = match handle_ant_message(ant_protocol, &message).await {
        Ok(response) => response,
        Err(error) => return (Response::error(request_id, "quote_failed", error), None),
    };
    match response.body {
        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
            quote,
            already_stored,
            commitment,
        }) => {
            let quote: PaymentQuote = match rmp_serde::from_slice(&quote) {
                Ok(quote) => quote,
                Err(error) => {
                    return (
                        Response::error(
                            request_id,
                            "invalid_quote",
                            format!("node generated an invalid quote: {error}"),
                        ),
                        None,
                    )
                }
            };
            let artifact = match BrowserQuoteArtifact::from_quote(
                state.p2p.peer_id(),
                &quote,
                commitment.as_deref(),
            ) {
                Ok(artifact) => artifact,
                Err(error) => return (Response::error(request_id, "invalid_quote", error), None),
            };
            (
                Response::ok(
                    request_id,
                    ResponseBody::StorageQuote {
                        address,
                        already_stored,
                        quote: artifact,
                    },
                    0,
                ),
                None,
            )
        }
        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(error)) => (
            Response::error(request_id, "quote_rejected", error.to_string()),
            None,
        ),
        other => (
            Response::error(
                request_id,
                "invalid_quote_response",
                format!("unexpected storage response: {other:?}"),
            ),
            None,
        ),
    }
}

async fn process_put_chunk(
    request_id: u64,
    address: String,
    quote: BrowserQuoteArtifact,
    transaction_hash: String,
    content: Vec<u8>,
    state: &ServerState,
) -> (Response, Option<Vec<u8>>) {
    let address_bytes = match decode_32_byte_hex(&address) {
        Ok(bytes) => bytes,
        Err(error) => return (Response::error(request_id, "invalid_address", error), None),
    };
    let Some(ant_protocol) = state.ant_protocol.as_ref() else {
        return (
            Response::error(
                request_id,
                "storage_disabled",
                "chunk storage is disabled on this node".to_string(),
            ),
            None,
        );
    };
    let proof = match build_payment_proof(address_bytes, quote, &transaction_hash) {
        Ok(proof) => proof,
        Err(error) => {
            return (
                Response::error(request_id, "invalid_payment_proof", error),
                None,
            )
        }
    };

    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::PutRequest(ChunkPutRequest::with_payment(
            address_bytes,
            bytes::Bytes::from(content),
            proof,
        )),
    };
    let response = match handle_ant_message(ant_protocol, &message).await {
        Ok(response) => response,
        Err(error) => return (Response::error(request_id, "put_failed", error), None),
    };
    match response.body {
        ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address }) => (
            Response::ok(
                request_id,
                ResponseBody::ChunkStored {
                    address: hex::encode(address),
                    already_stored: false,
                },
                0,
            ),
            None,
        ),
        ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { address }) => (
            Response::ok(
                request_id,
                ResponseBody::ChunkStored {
                    address: hex::encode(address),
                    already_stored: true,
                },
                0,
            ),
            None,
        ),
        ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => (
            Response::error(request_id, "payment_required", message),
            None,
        ),
        ChunkMessageBody::PutResponse(ChunkPutResponse::Error(error)) => (
            Response::error(request_id, "put_rejected", error.to_string()),
            None,
        ),
        other => (
            Response::error(
                request_id,
                "invalid_put_response",
                format!("unexpected storage response: {other:?}"),
            ),
            None,
        ),
    }
}

fn build_payment_proof(
    expected_content: [u8; 32],
    quote: BrowserQuoteArtifact,
    transaction_hash: &str,
) -> ServerResult<Vec<u8>> {
    let (peer_id, payment_quote, commitment) = quote.into_payment_quote(expected_content)?;
    let transaction_hash = TxHash::from_str(transaction_hash)
        .map_err(|error| format!("invalid EVM transaction hash: {error}"))?;
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::new(peer_id), payment_quote)],
        },
        tx_hashes: vec![transaction_hash],
        commitment_sidecars: commitment.into_iter().collect(),
    };
    serialize_single_node_proof(&proof)
        .map_err(|error| format!("failed to serialize payment proof: {error}"))
}

async fn handle_ant_message(
    ant_protocol: &AntProtocol,
    message: &ChunkMessage,
) -> ServerResult<ChunkMessage> {
    let encoded = message
        .encode()
        .map_err(|error| format!("storage request encoding failed: {error}"))?;
    let response = ant_protocol
        .try_handle_request(&encoded)
        .await
        .map_err(|error| format!("storage request failed: {error}"))?
        .ok_or_else(|| "storage handler returned no response".to_string())?;
    ChunkMessage::decode(&response)
        .map_err(|error| format!("storage response decoding failed: {error}"))
}

async fn write_response(
    send: &mut SendStream,
    response: &Response,
    content: &[u8],
) -> ServerResult<()> {
    let header = serde_json::to_vec(response)
        .map_err(|error| format!("response JSON serialization failed: {error}"))?;
    if header.len() > MAX_RESPONSE_HEADER_BYTES {
        return Err("response header exceeds protocol limit".to_string());
    }
    let header_len = u32::try_from(header.len())
        .map_err(|_| "response header length does not fit u32".to_string())?;
    send.write_all(&header_len.to_be_bytes())
        .await
        .map_err(|error| format!("response prefix write failed: {error}"))?;
    send.write_all(&header)
        .await
        .map_err(|error| format!("response header write failed: {error}"))?;
    if !content.is_empty() {
        send.write_all(content)
            .await
            .map_err(|error| format!("response content write failed: {error}"))?;
    }
    send.finish()
        .await
        .map_err(|error| format!("response finish failed: {error}"))
}

fn origin_allowed(allowed: &[String], origin: Option<&str>) -> bool {
    allowed.iter().any(|candidate| candidate == "*")
        || origin.is_some_and(|origin| allowed.iter().any(|candidate| candidate == origin))
}

fn decode_32_byte_hex(value: &str) -> ServerResult<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|error| format!("expected hexadecimal: {error}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, received {}", bytes.len()))
}

type ServerResult<T> = std::result::Result<T, String>;

#[derive(Debug, Deserialize)]
struct Request {
    version: u16,
    #[serde(rename = "request_id")]
    id: u64,
    content_length: usize,
    #[serde(flatten)]
    body: RequestBody,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RequestBody {
    Hello,
    FindNode {
        target: String,
        #[serde(default)]
        count: Option<usize>,
    },
    GetChunk {
        address: String,
    },
    QuoteChunk {
        address: String,
        size: u64,
    },
    PutChunk {
        address: String,
        quote: Box<BrowserQuoteArtifact>,
        transaction_hash: String,
    },
}

#[derive(Debug, Serialize)]
struct Response {
    version: u16,
    request_id: u64,
    status: ResponseStatus,
    content_length: usize,
    #[serde(flatten)]
    body: ResponseBody,
}

impl Response {
    fn ok(request_id: u64, body: ResponseBody, content_length: usize) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            status: ResponseStatus::Ok,
            content_length,
            body,
        }
    }

    fn not_found(request_id: u64, address: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            status: ResponseStatus::NotFound,
            content_length: 0,
            body: ResponseBody::ChunkNotFound { address },
        }
    }

    fn error(request_id: u64, code: &str, message: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            status: ResponseStatus::Error,
            content_length: 0,
            body: ResponseBody::Error {
                code: code.to_string(),
                message,
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResponseStatus {
    Ok,
    NotFound,
    Error,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ResponseBody {
    Hello {
        protocol: String,
        peer_id: String,
        max_chunk_size: usize,
        endpoint: BrowserEndpoint,
        payment: BrowserPaymentNetwork,
        capabilities: Vec<String>,
    },
    Nodes {
        target: String,
        nodes: Vec<BrowserNode>,
    },
    Chunk {
        address: String,
        size: usize,
    },
    ChunkNotFound {
        address: String,
    },
    StorageQuote {
        address: String,
        already_stored: bool,
        quote: BrowserQuoteArtifact,
    },
    ChunkStored {
        address: String,
        already_stored: bool,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Serialize)]
struct BrowserNode {
    peer_id: String,
    native_addresses: Vec<String>,
    reliability: f64,
    webtransport: Option<BrowserEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserQuoteArtifact {
    peer_id: String,
    content: String,
    timestamp_secs: u64,
    price: String,
    rewards_address: String,
    public_key: String,
    signature: String,
    committed_key_count: u32,
    commitment_pin: Option<String>,
    quote_hash: String,
    commitment: Option<BrowserCommitmentArtifact>,
}

impl BrowserQuoteArtifact {
    fn from_quote(
        peer_id: &PeerId,
        quote: &PaymentQuote,
        commitment: Option<&[u8]>,
    ) -> ServerResult<Self> {
        let timestamp_secs = quote
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|error| format!("quote timestamp predates the Unix epoch: {error}"))?
            .as_secs();
        let commitment = commitment
            .map(BrowserCommitmentArtifact::from_bytes)
            .transpose()?;
        Ok(Self {
            peer_id: peer_id.to_hex(),
            content: hex::encode(quote.content.0),
            timestamp_secs,
            price: quote.price.to_string(),
            rewards_address: format!("{:?}", quote.rewards_address),
            public_key: hex::encode(&quote.pub_key),
            signature: hex::encode(&quote.signature),
            committed_key_count: quote.committed_key_count,
            commitment_pin: quote.commitment_pin.map(hex::encode),
            quote_hash: hex::encode(quote.hash()),
            commitment,
        })
    }

    fn into_payment_quote(
        self,
        expected_content: [u8; 32],
    ) -> ServerResult<([u8; 32], PaymentQuote, Option<Vec<u8>>)> {
        let peer_id = decode_32_byte_hex(&self.peer_id)?;
        let content = decode_32_byte_hex(&self.content)?;
        if content != expected_content {
            return Err("payment quote is for a different chunk address".to_string());
        }
        let price = Amount::from_str(&self.price)
            .map_err(|error| format!("payment quote has an invalid price: {error}"))?;
        let rewards_address = RewardsAddress::from_str(&self.rewards_address)
            .map_err(|error| format!("payment quote has an invalid rewards address: {error}"))?;
        let public_key = hex::decode(&self.public_key)
            .map_err(|error| format!("payment quote public key is not hexadecimal: {error}"))?;
        let signature = hex::decode(&self.signature)
            .map_err(|error| format!("payment quote signature is not hexadecimal: {error}"))?;
        let commitment_pin = self
            .commitment_pin
            .as_deref()
            .map(decode_32_byte_hex)
            .transpose()?;
        let timestamp = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(self.timestamp_secs))
            .ok_or_else(|| "payment quote timestamp is out of range".to_string())?;
        let quote = PaymentQuote {
            content: xor_name::XorName(content),
            timestamp,
            price,
            rewards_address,
            pub_key: public_key,
            signature,
            committed_key_count: self.committed_key_count,
            commitment_pin,
        };
        if hex::encode(quote.hash()) != self.quote_hash.to_ascii_lowercase() {
            return Err("payment quote hash does not match its signed fields".to_string());
        }
        let commitment = self
            .commitment
            .map(|artifact| {
                hex::decode(artifact.encoded)
                    .map_err(|error| format!("commitment is not hexadecimal: {error}"))
            })
            .transpose()?;
        Ok((peer_id, quote, commitment))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserCommitmentArtifact {
    encoded: String,
    root: String,
    key_count: u32,
    sender_peer_id: String,
    sender_public_key: String,
    signature: String,
}

impl BrowserCommitmentArtifact {
    fn from_bytes(encoded: &[u8]) -> ServerResult<Self> {
        let commitment: ::ant_protocol::payment::commitment::StorageCommitment =
            rmp_serde::from_slice(encoded)
                .map_err(|error| format!("node generated an invalid commitment: {error}"))?;
        Ok(Self {
            encoded: hex::encode(encoded),
            root: hex::encode(commitment.root),
            key_count: commitment.key_count,
            sender_peer_id: hex::encode(commitment.sender_peer_id),
            sender_public_key: hex::encode(commitment.sender_public_key),
            signature: hex::encode(commitment.signature),
        })
    }
}

struct ServerState {
    config: WebTransportConfig,
    p2p: Arc<P2PNode>,
    ant_protocol: Option<Arc<AntProtocol>>,
    payment: BrowserPaymentNetwork,
    endpoint: BrowserEndpoint,
    endpoint_catalog: Arc<BrowserEndpointCatalog>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_versioned_requests() {
        let request: Request = serde_json::from_str(
            r#"{"version":3,"request_id":7,"content_length":0,"type":"find_node","target":"0000000000000000000000000000000000000000000000000000000000000000","count":20}"#,
        )
        .expect("valid request");

        assert_eq!(request.version, PROTOCOL_VERSION);
        assert_eq!(request.id, 7);
        assert!(matches!(request.body, RequestBody::FindNode { .. }));
    }

    #[test]
    fn validates_fixed_width_hex() {
        assert_eq!(
            decode_32_byte_hex(&"ab".repeat(32)).expect("32 bytes"),
            [0xab; 32]
        );
        assert!(decode_32_byte_hex("abcd").is_err());
        assert!(decode_32_byte_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn payment_quote_hash_vector_uses_evm_keccak256() {
        // Shared with ant-client-web's paymentQuoteHash test. ANT addresses use
        // BLAKE3, but the quote hash paid to the EVM vault is evmlib Keccak-256.
        assert_eq!(
            hex::encode(evmlib::cryptography::hash([0_u8, 1, 2, 3])),
            "d98f2e8134922f73748703c8e7084d42f13d2fa1439936ef5a3abcf5646fe83f"
        );
    }

    #[test]
    fn origins_are_exact_unless_wildcard_is_configured() {
        let exact = vec!["http://localhost:5173".to_string()];
        assert!(origin_allowed(&exact, Some("http://localhost:5173")));
        assert!(!origin_allowed(&exact, Some("http://evil.test")));
        assert!(!origin_allowed(&exact, None));
        assert!(origin_allowed(&["*".to_string()], None));
    }

    #[test]
    fn response_header_declares_raw_content_length() {
        let response = Response::ok(
            42,
            ResponseBody::Chunk {
                address: "11".repeat(32),
                size: 3,
            },
            3,
        );
        let value = serde_json::to_value(response).expect("serialize response");
        assert_eq!(value["version"], 3);
        assert_eq!(value["request_id"], 42);
        assert_eq!(value["status"], "ok");
        assert_eq!(value["content_length"], 3);
        assert_eq!(value["type"], "chunk");
    }

    #[test]
    fn derives_ipv6_urls_with_brackets() {
        let config = WebTransportConfig::default();
        let url = advertised_url(&config, "[::1]:23456".parse().expect("socket"));
        assert_eq!(url, "https://[::1]:23456/autonomi/webtransport/v1");
    }
}
