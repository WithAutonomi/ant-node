//! ADR-0009 WebRTC Direct browser transport.
//!
//! The listener uses Saorsa's signaling-free WebRTC Direct transport for ICE,
//! DTLS, SCTP, and reliable ordered `DataChannels`. ANT's ML-DSA HELLO binds the
//! pinned WebRTC endpoint to the node identity without a libp2p or Noise layer.

use crate::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest,
    ChunkQuoteResponse, MAX_CHUNK_SIZE,
};
use crate::browser::{BrowserEndpoint, BrowserPaymentNetwork};
use crate::config::WebRtcDirectConfig;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::payment::{serialize_single_node_proof, PaymentProof};
use crate::storage::AntProtocol;
use evmlib::common::{Amount, TxHash};
use evmlib::{EncodedPeerId, PaymentQuote, ProofOfPayment, RewardsAddress};
use parking_lot::RwLock;
use saorsa_core::identity::NodeIdentity;
use saorsa_core::{DHTNode, KnownReachability, MultiAddr, P2PNode, PeerId};
use saorsa_transport::webrtc_direct::{
    WebRtcCertificate, WebRtcDataChannel, WebRtcDirectConnection, WebRtcDirectListener,
    MAX_DATA_CHANNEL_MESSAGE_SIZE,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const PROTOCOL_VERSION: u16 = 3;
const PROTOCOL_NAME: &str = "autonomi.web.poc.v3";
const DATA_CHANNEL_LABEL: &str = "autonomi.web.v3";
const MAX_FIND_NODE_RESULTS: usize = 20;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const REQUEST_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const WEBRTC_WRITE_CHUNK_BYTES: usize = MAX_DATA_CHANNEL_MESSAGE_SIZE;
const AUTOMATIC_PORT_MIN: u32 = 32_768;
const AUTOMATIC_PORT_COUNT: u32 = 65_536 - AUTOMATIC_PORT_MIN;

/// Filename containing the node's canonical browser bootstrap address.
///
/// The file is written below the node root directory after the listener has
/// bound and is safe for deployment tooling to copy or print. Its contents are
/// public bootstrap metadata, not key material.
pub const WEBRTC_DIRECT_MULTIADDR_FILENAME: &str = "webrtc-direct.multiaddr";

/// Resolve the zero-configuration listener values used by ordinary nodes.
///
/// A zero bind port is mapped deterministically from the native QUIC port into
/// the high UDP range. That keeps the complete browser multiaddress stable
/// across restarts and fits the high-port firewall range used by `ant-testnet`.
/// A wildcard bind without an explicit advertised address prefers the public
/// IP observed by the native transport and otherwise uses the IP selected by
/// the host routing table.
pub fn resolve_automatic_config(
    config: &WebRtcDirectConfig,
    native_port: u16,
    observed_ip: Option<IpAddr>,
) -> WebRtcDirectConfig {
    let mut resolved = config.clone();
    if resolved.bind.port() == 0 {
        let port = resolved
            .advertised_addr
            .map_or_else(|| automatic_webrtc_port(native_port), |addr| addr.port());
        resolved.bind.set_port(port);
    }

    if resolved.advertised_addr.is_none() && resolved.bind.ip().is_unspecified() {
        let bind_is_ipv4 = resolved.bind.is_ipv4();
        let advertised_ip = observed_ip
            .filter(|ip| ip.is_ipv4() == bind_is_ipv4 && !ip.is_unspecified())
            .or_else(|| routed_local_ip(bind_is_ipv4))
            .unwrap_or({
                if bind_is_ipv4 {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                }
            });
        resolved.advertised_addr = Some(SocketAddr::new(advertised_ip, resolved.bind.port()));
    }

    resolved
}

fn automatic_webrtc_port(native_port: u16) -> u16 {
    let native = u32::from(native_port);
    let offset = if native < AUTOMATIC_PORT_MIN {
        native
    } else {
        (native - AUTOMATIC_PORT_MIN + AUTOMATIC_PORT_COUNT / 2) % AUTOMATIC_PORT_COUNT
    };
    u16::try_from(AUTOMATIC_PORT_MIN + offset).unwrap_or(u16::MAX)
}

fn routed_local_ip(ipv4: bool) -> Option<IpAddr> {
    let (bind, route_probe) = if ipv4 {
        (
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9)),
        )
    } else {
        (
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 9)),
        )
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(route_probe).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// Browser endpoints known to one or more listeners in the same process.
///
/// The in-process devnet shares this catalog so its listeners can expose one
/// another immediately. Independently deployed nodes discover endpoints from
/// the authenticated DHT address sets; this remains a local fast-path and
/// fallback while those records converge.
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
pub struct WebRtcDirectServer {
    /// Direct endpoint with its certificate pin embedded in the multiaddress.
    pub endpoint: BrowserEndpoint,
    /// Listener background task.
    pub task: JoinHandle<()>,
}

/// Start the feature-gated browser listener and return its endpoint and task.
pub async fn spawn(
    config: &WebRtcDirectConfig,
    root_dir: &Path,
    p2p: Arc<P2PNode>,
    ant_protocol: Option<Arc<AntProtocol>>,
    evm_network: &evmlib::Network,
    shutdown: CancellationToken,
    endpoint_catalog: Arc<BrowserEndpointCatalog>,
) -> Result<WebRtcDirectServer> {
    validate_webrtc_config(config)?;
    let certificate_path = certificate_path(config, root_dir);
    let certificate = load_or_generate_certificate(&certificate_path).await?;
    let certificate_sha256 = certificate
        .sha256_digest()
        .map_err(|error| Error::Startup(error.to_string()))?;
    let listener = WebRtcDirectListener::bind(config.bind, certificate)
        .await
        .map_err(|error| {
            Error::Startup(format!("failed to bind WebRTC Direct listener: {error}"))
        })?;
    let local_addr = listener.local_addr();
    let advertised_addr = advertised_addr(config, local_addr)?;
    let peer_id = *p2p.peer_id();
    let identity = Arc::clone(p2p.transport().node_identity());
    let browser_endpoint = BrowserEndpoint::new(advertised_addr, &peer_id, certificate_sha256)
        .map_err(Error::Config)?;
    persist_browser_endpoint(root_dir, &browser_endpoint).await?;
    endpoint_catalog.insert(peer_id, browser_endpoint.clone());
    let dht = Arc::clone(p2p.dht_manager());

    let state = Arc::new(ServerState {
        config: config.clone(),
        identity,
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
        certificate = %certificate_path.display(),
        "ADR-0009 WebRTC Direct listening"
    );

    let task = tokio::spawn(async move {
        serve_webrtc(listener, state, connection_limit, shutdown).await;
    });
    dht.set_supplemental_self_addresses(vec![browser_endpoint.multiaddr.clone()])
        .await;
    Ok(WebRtcDirectServer {
        endpoint: browser_endpoint,
        task,
    })
}

async fn persist_browser_endpoint(root_dir: &Path, endpoint: &BrowserEndpoint) -> Result<()> {
    let path = root_dir.join(WEBRTC_DIRECT_MULTIADDR_FILENAME);
    let contents = format!("{}\n", endpoint.multiaddr);
    tokio::fs::write(&path, contents).await.map_err(|error| {
        Error::Startup(format!(
            "failed to write WebRTC Direct endpoint {}: {error}",
            path.display()
        ))
    })
}

fn validate_webrtc_config(config: &WebRtcDirectConfig) -> Result<()> {
    if config.max_connections == 0 {
        return Err(Error::Config(
            "webrtc_direct.max_connections must be greater than zero".to_string(),
        ));
    }
    if config.max_request_bytes == 0 || config.max_request_bytes > MAX_RESPONSE_HEADER_BYTES {
        return Err(Error::Config(format!(
            "webrtc_direct.max_request_bytes must be between 1 and {MAX_RESPONSE_HEADER_BYTES}"
        )));
    }
    if config.advertised_addr.is_some_and(|addr| addr.port() == 0) {
        return Err(Error::Config(
            "webrtc_direct.advertised_addr must not use port zero".to_string(),
        ));
    }
    Ok(())
}

fn certificate_path(config: &WebRtcDirectConfig, root_dir: &Path) -> PathBuf {
    match config.certificate_path.as_ref() {
        Some(path) if path.is_absolute() => path.clone(),
        Some(path) => root_dir.join(path),
        None => root_dir.join("webrtc-direct.pem"),
    }
}

async fn load_or_generate_certificate(path: &Path) -> Result<WebRtcCertificate> {
    match tokio::fs::read_to_string(path).await {
        Ok(pem) => WebRtcCertificate::from_pem(&pem).map_err(|error| {
            Error::Startup(format!(
                "failed to load WebRTC certificate {}: {error}",
                path.display()
            ))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let certificate = WebRtcCertificate::generate().map_err(|error| {
                Error::Startup(format!("failed to generate WebRTC certificate: {error}"))
            })?;
            tokio::fs::write(path, certificate.serialize_pem()).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
            }
            Ok(certificate)
        }
        Err(error) => Err(error.into()),
    }
}

fn advertised_addr(config: &WebRtcDirectConfig, local_addr: SocketAddr) -> Result<SocketAddr> {
    if let Some(addr) = config.advertised_addr {
        return Ok(addr);
    }
    if local_addr.ip().is_unspecified() {
        return Err(Error::Config(
            "webrtc_direct.advertised_addr is required for a wildcard bind".to_string(),
        ));
    }
    Ok(local_addr)
}

async fn serve_webrtc(
    mut listener: WebRtcDirectListener,
    state: Arc<ServerState>,
    connection_limit: Arc<Semaphore>,
    shutdown: CancellationToken,
) {
    loop {
        let connection = tokio::select! {
            () = shutdown.cancelled() => break,
            connection = listener.accept() => connection,
        };
        match connection {
            Ok(connection) => {
                let remote_addr = connection.remote_addr();
                let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
                    debug!(remote = %remote_addr, "Rejected WebRTC Direct connection: busy");
                    if let Err(error) = connection.close().await {
                        debug!(remote = %remote_addr, %error, "Failed to close busy connection");
                    }
                    continue;
                };
                let connection_state = Arc::clone(&state);
                let connection_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) =
                        handle_connection(connection, connection_state, connection_shutdown).await
                    {
                        debug!(remote = %remote_addr, "WebRTC Direct connection ended: {error}");
                    }
                });
            }
            Err(error) => {
                warn!("WebRTC Direct listener error: {error}");
            }
        }
    }
    if let Err(error) = listener.close().await {
        debug!("WebRTC Direct listener close failed: {error}");
    }
    info!("ADR-0009 WebRTC Direct stopped");
}

async fn handle_connection(
    mut connection: WebRtcDirectConnection,
    state: Arc<ServerState>,
    shutdown: CancellationToken,
) -> ServerResult<()> {
    let authenticated = Arc::new(AtomicBool::new(false));
    loop {
        let channel = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            result = connection.accept_data_channel() => {
                result.map_err(|error| format!("DataChannel accept failed: {error}"))?
            }
        };
        let state = Arc::clone(&state);
        let authenticated = Arc::clone(&authenticated);
        tokio::spawn(async move {
            if let Err(error) = handle_webrtc_channel(channel, state, authenticated).await {
                debug!("WebRTC Direct DataChannel ended: {error}");
            }
        });
    }
}

async fn handle_webrtc_channel(
    channel: WebRtcDataChannel,
    state: Arc<ServerState>,
    authenticated: Arc<AtomicBool>,
) -> ServerResult<()> {
    if channel.label() != DATA_CHANNEL_LABEL {
        if let Err(error) = channel.close().await {
            debug!("Failed to close unsupported DataChannel: {error}");
        }
        return Err(format!(
            "unsupported DataChannel label {:?}",
            channel.label()
        ));
    }

    loop {
        let (request, content) =
            match read_webrtc_request(&channel, state.config.max_request_bytes).await {
                Ok(request) => request,
                Err(error)
                    if matches!(
                        error.as_str(),
                        "DataChannel closed" | "request idle timeout" | "request frame timed out"
                    ) =>
                {
                    if let Err(close_error) = channel.close().await {
                        debug!("Failed to close idle WebRTC DataChannel: {close_error}");
                    }
                    return Ok(());
                }
                Err(error) => {
                    let response = Response::error(0, "invalid_request", error);
                    write_webrtc_response(&channel, &response, &[]).await?;
                    return Ok(());
                }
            };
        if request.version != PROTOCOL_VERSION {
            let response = Response::error(
                request.id,
                "unsupported_version",
                format!(
                    "protocol version {} is unsupported; expected {PROTOCOL_VERSION}",
                    request.version
                ),
            );
            write_webrtc_response(&channel, &response, &[]).await?;
            continue;
        }

        let is_hello = matches!(&request.body, RequestBody::Hello { .. });
        if !is_hello && !authenticated.load(Ordering::Acquire) {
            let response = Response::error(
                request.id,
                "authentication_required",
                "HELLO must authenticate this WebRTC connection first".to_string(),
            );
            write_webrtc_response(&channel, &response, &[]).await?;
            continue;
        }

        let (response, content) = process_request(request, content, &state).await;
        if is_hello && matches!(&response.status, ResponseStatus::Ok) {
            authenticated.store(true, Ordering::Release);
        }
        write_webrtc_response(&channel, &response, content.as_deref().unwrap_or_default()).await?;
    }
}

async fn read_webrtc_request(
    channel: &WebRtcDataChannel,
    max_header_bytes: usize,
) -> ServerResult<(Request, Vec<u8>)> {
    let first_message = tokio::time::timeout(REQUEST_IDLE_TIMEOUT, channel.receive())
        .await
        .map_err(|_| "request idle timeout".to_string())?
        .map_err(|error| format!("request message read failed: {error}"))?;
    if first_message.is_empty() {
        return Err("DataChannel closed".to_string());
    }
    let read = async {
        let mut frame = Vec::new();
        let mut expected_length = None;
        let mut next_message = Some(first_message);
        let max_frame_bytes = 4 + max_header_bytes + MAX_CHUNK_SIZE;
        loop {
            let message = if let Some(message) = next_message.take() {
                message
            } else {
                channel
                    .receive()
                    .await
                    .map_err(|error| format!("request message read failed: {error}"))?
            };
            if message.is_empty() {
                return Err("DataChannel closed".to_string());
            }
            if frame.len() + message.len() > max_frame_bytes {
                return Err(format!(
                    "request exceeds the {max_frame_bytes}-byte frame limit"
                ));
            }
            frame.extend_from_slice(&message);

            if expected_length.is_none() && frame.len() >= 4 {
                let header_len = u32::from_be_bytes(
                    frame[..4]
                        .try_into()
                        .map_err(|_| "request prefix is incomplete".to_string())?,
                ) as usize;
                if header_len == 0 || header_len > max_header_bytes {
                    return Err(format!(
                        "request header length {header_len} is outside 1..={max_header_bytes}"
                    ));
                }
                if frame.len() >= 4 + header_len {
                    let request: Request = serde_json::from_slice(&frame[4..4 + header_len])
                        .map_err(|error| format!("request JSON is invalid: {error}"))?;
                    if request.content_length > MAX_CHUNK_SIZE {
                        return Err(format!(
                            "request content length {} exceeds {MAX_CHUNK_SIZE}",
                            request.content_length
                        ));
                    }
                    expected_length = Some((4 + header_len + request.content_length, request));
                }
            }

            if let Some((length, _)) = expected_length.as_ref() {
                if frame.len() > *length {
                    return Err("request contains bytes after its declared frame".to_string());
                }
                if frame.len() == *length {
                    let (_, request) = expected_length
                        .take()
                        .ok_or_else(|| "request length state was lost".to_string())?;
                    let header_len = u32::from_be_bytes(
                        frame[..4]
                            .try_into()
                            .map_err(|_| "request prefix is incomplete".to_string())?,
                    ) as usize;
                    return Ok((request, frame.split_off(4 + header_len)));
                }
            }
        }
    };
    tokio::time::timeout(REQUEST_FRAME_TIMEOUT, read)
        .await
        .map_err(|_| "request frame timed out".to_string())?
}

async fn write_webrtc_response(
    channel: &WebRtcDataChannel,
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
    let mut frame = Vec::with_capacity(4 + header.len() + content.len());
    frame.extend_from_slice(&header_len.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(content);
    for chunk in frame.chunks(WEBRTC_WRITE_CHUNK_BYTES) {
        channel
            .send(chunk)
            .await
            .map_err(|error| format!("response message write failed: {error}"))?;
    }
    Ok(())
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
        RequestBody::Hello { challenge } => {
            let challenge_bytes = match decode_32_byte_hex(&challenge) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return (
                        Response::error(request.id, "invalid_challenge", error),
                        None,
                    )
                }
            };
            let peer_id = state.p2p.peer_id().to_hex();
            let transcript = hello_transcript(&challenge_bytes, &peer_id, &state.endpoint);
            let signature = match state.identity.sign(&transcript) {
                Ok(signature) => signature,
                Err(error) => {
                    return (
                        Response::error(
                            request.id,
                            "identity_signing_failed",
                            format!("could not sign HELLO: {error}"),
                        ),
                        None,
                    )
                }
            };
            (
                Response::ok(
                    request.id,
                    ResponseBody::Hello {
                        protocol: PROTOCOL_NAME.to_string(),
                        peer_id,
                        challenge,
                        public_key: hex::encode(state.identity.public_key().as_bytes()),
                        signature: hex::encode(signature.as_bytes()),
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
            )
        }
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
    let dht = state.p2p.dht_manager();
    let dht_nodes = dht
        .find_closest_nodes_local_with_self(&target_bytes, count)
        .await;
    let mut nodes = Vec::with_capacity(dht_nodes.len());
    for node in dht_nodes {
        let supplemental = dht
            .supplemental_address_records_for_peer(&node.peer_id)
            .await;
        nodes.push(browser_node_from_dht(
            &node,
            &supplemental,
            &state.endpoint_catalog,
        ));
    }
    (
        Response::ok(request_id, ResponseBody::Nodes { target, nodes }, 0),
        None,
    )
}

fn browser_node_from_dht(
    node: &DHTNode,
    supplemental: &[(MultiAddr, KnownReachability)],
    endpoint_catalog: &BrowserEndpointCatalog,
) -> BrowserNode {
    let addresses = node.addresses_by_priority();
    let discovered_endpoint = supplemental
        .iter()
        .find(|(address, reachability)| {
            matches!(
                reachability,
                KnownReachability::Direct | KnownReachability::Lan
            ) && address.is_webrtc_direct()
                && address.peer_id().is_some_and(|peer| peer == &node.peer_id)
        })
        .map(|(address, _)| address.clone())
        .map(|multiaddr| BrowserEndpoint { multiaddr });
    BrowserNode {
        webrtc_direct: discovered_endpoint.or_else(|| endpoint_catalog.get(&node.peer_id)),
        peer_id: node.peer_id.to_hex(),
        native_addresses: addresses
            .into_iter()
            .filter(|address| !address.is_webrtc_direct())
            .map(|address| address.to_string())
            .collect(),
        reliability: node.reliability,
    }
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

fn decode_32_byte_hex(value: &str) -> ServerResult<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|error| format!("expected hexadecimal: {error}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, received {}", bytes.len()))
}

fn hello_transcript(challenge: &[u8; 32], peer_id: &str, endpoint: &BrowserEndpoint) -> Vec<u8> {
    let mut transcript = b"autonomi-webrtc-direct-hello-v1\0".to_vec();
    transcript.extend_from_slice(challenge);
    transcript.extend_from_slice(peer_id.as_bytes());
    transcript.extend_from_slice(endpoint.multiaddr.to_string().as_bytes());
    transcript
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
    Hello {
        challenge: String,
    },
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
        challenge: String,
        public_key: String,
        signature: String,
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
    webrtc_direct: Option<BrowserEndpoint>,
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
    config: WebRtcDirectConfig,
    identity: Arc<NodeIdentity>,
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
    fn derives_stable_high_port_from_native_port() {
        assert_eq!(automatic_webrtc_port(10_000), 42_768);
        assert_eq!(automatic_webrtc_port(10_001), 42_769);
        assert_eq!(automatic_webrtc_port(32_768), 49_152);
        assert_ne!(automatic_webrtc_port(40_000), 40_000);
    }

    #[test]
    fn resolves_default_public_listener_from_observed_ip() {
        let config = WebRtcDirectConfig::default();
        let resolved = resolve_automatic_config(
            &config,
            10_000,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        );

        assert_eq!(resolved.bind, "0.0.0.0:42768".parse().expect("bind"));
        assert_eq!(
            resolved.advertised_addr,
            Some("203.0.113.7:42768".parse().expect("advertised"))
        );
    }

    #[test]
    fn explicit_listener_addresses_are_preserved() {
        let config = WebRtcDirectConfig {
            bind: "0.0.0.0:11000".parse().expect("bind"),
            advertised_addr: Some("198.51.100.4:11000".parse().expect("advertised")),
            ..WebRtcDirectConfig::default()
        };

        assert_eq!(
            resolve_automatic_config(&config, 10_000, None).bind,
            config.bind
        );
        assert_eq!(
            resolve_automatic_config(&config, 10_000, None).advertised_addr,
            config.advertised_addr
        );
    }

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
    fn derives_ipv6_advertised_address() {
        let config = WebRtcDirectConfig::default();
        let addr = advertised_addr(&config, "[::1]:23456".parse().expect("socket"))
            .expect("advertised address");
        assert_eq!(addr, "[::1]:23456".parse().expect("socket"));
    }

    #[tokio::test]
    async fn dtls_certificate_is_stable_across_reloads() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("webrtc-direct.pem");
        let first = load_or_generate_certificate(&path)
            .await
            .expect("generate certificate");
        let second = load_or_generate_certificate(&path)
            .await
            .expect("reload certificate");

        assert_eq!(
            first.sha256_digest().expect("first fingerprint"),
            second.sha256_digest().expect("second fingerprint")
        );
        assert!(path.exists());
    }

    #[tokio::test]
    async fn persists_canonical_browser_bootstrap_address() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let peer_id = PeerId::from_bytes([0x42; 32]);
        let endpoint = BrowserEndpoint::new(
            "203.0.113.7:11000".parse().expect("socket address"),
            &peer_id,
            [0x24; 32],
        )
        .expect("browser endpoint");

        persist_browser_endpoint(directory.path(), &endpoint)
            .await
            .expect("persist endpoint");

        let contents =
            tokio::fs::read_to_string(directory.path().join(WEBRTC_DIRECT_MULTIADDR_FILENAME))
                .await
                .expect("read endpoint file");
        assert_eq!(contents, format!("{}\n", endpoint.multiaddr));
    }

    #[test]
    fn find_node_exposes_propagated_webrtc_endpoint_separately() {
        let peer_id = PeerId::from_bytes([0x31; 32]);
        let endpoint = BrowserEndpoint::new(
            "203.0.113.9:42768".parse().expect("socket address"),
            &peer_id,
            [0x52; 32],
        )
        .expect("browser endpoint");
        let native = "/ip4/203.0.113.9/udp/10000/quic"
            .parse()
            .expect("native multiaddress");
        let node = DHTNode {
            peer_id,
            addresses: vec![native],
            address_types: Vec::new(),
            distance: None,
            reliability: 0.75,
        };

        let supplemental = (endpoint.multiaddr.clone(), KnownReachability::Direct);
        let browser_node = browser_node_from_dht(
            &node,
            std::slice::from_ref(&supplemental),
            &BrowserEndpointCatalog::default(),
        );

        assert_eq!(browser_node.webrtc_direct, Some(endpoint));
        assert_eq!(
            browser_node.native_addresses,
            vec!["/ip4/203.0.113.9/udp/10000/quic"]
        );
    }

    #[test]
    fn find_node_hides_relay_only_webrtc_endpoint() {
        let peer_id = PeerId::from_bytes([0x32; 32]);
        let endpoint = BrowserEndpoint::new(
            "203.0.113.10:42768".parse().expect("socket address"),
            &peer_id,
            [0x53; 32],
        )
        .expect("browser endpoint");
        let node = DHTNode {
            peer_id,
            addresses: Vec::new(),
            address_types: Vec::new(),
            distance: None,
            reliability: 0.75,
        };
        let supplemental = (endpoint.multiaddr, KnownReachability::Relay);

        let browser_node = browser_node_from_dht(
            &node,
            std::slice::from_ref(&supplemental),
            &BrowserEndpointCatalog::default(),
        );

        assert!(browser_node.webrtc_direct.is_none());
    }
}
