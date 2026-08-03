//! ADR-0009 WebTransport interoperability proof.
//!
//! This module is feature-gated, disabled by default, and intentionally keeps
//! the browser-facing HTTP/3 stack separate from native Saorsa QUIC. It is not
//! the production endpoint-record or certificate-rotation implementation.

use crate::ant_protocol::MAX_CHUNK_SIZE;
use crate::browser::BrowserEndpoint;
use crate::config::WebTransportConfig;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::storage::AntProtocol;
use parking_lot::RwLock;
use saorsa_core::P2PNode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wtransport::endpoint::IncomingSession;
use wtransport::stream::{RecvStream, SendStream};
use wtransport::{Endpoint, Identity, ServerConfig};

const PROTOCOL_VERSION: u16 = 1;
const PROTOCOL_NAME: &str = "autonomi.web.poc.v1";
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
    endpoints: RwLock<HashMap<String, BrowserEndpoint>>,
}

impl BrowserEndpointCatalog {
    fn insert(&self, peer_id: String, endpoint: BrowserEndpoint) {
        self.endpoints.write().insert(peer_id, endpoint);
    }

    fn get(&self, peer_id: &str) -> Option<BrowserEndpoint> {
        self.endpoints.read().get(peer_id).cloned()
    }
}

/// A running browser listener and the endpoint clients use to reach it.
pub struct WebTransportServer {
    /// Direct endpoint and certificate pin.
    pub endpoint: BrowserEndpoint,
    /// Listener background task.
    pub task: JoinHandle<()>,
}

/// Start the feature-gated browser listener and return its endpoint and task.
pub fn spawn(
    config: &WebTransportConfig,
    p2p: Arc<P2PNode>,
    ant_protocol: Option<Arc<AntProtocol>>,
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
    let certificate_sha256 = hex::encode(certificate.hash().as_ref());

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

    let browser_endpoint = BrowserEndpoint {
        url: advertised_url.clone(),
        certificate_sha256: certificate_sha256.clone(),
    };
    endpoint_catalog.insert(p2p.peer_id().to_hex(), browser_endpoint.clone());

    let state = Arc::new(ServerState {
        config: config.clone(),
        p2p,
        ant_protocol,
        endpoint: browser_endpoint.clone(),
        endpoint_catalog,
    });
    let connection_limit = Arc::new(Semaphore::new(config.max_connections));

    info!(
        bind = %local_addr,
        url = %advertised_url,
        certificate_sha256 = %certificate_sha256,
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
    if !config.path.starts_with('/') {
        return Err(Error::Config(
            "webtransport.path must start with '/'".to_string(),
        ));
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
    let request = match read_request(&mut recv, state.config.max_request_bytes).await {
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

    let (response, content) = process_request(request, &state).await;
    write_response(&mut send, &response, content.as_deref().unwrap_or_default()).await
}

async fn read_request(recv: &mut RecvStream, max_bytes: usize) -> ServerResult<Request> {
    let mut bytes = Vec::new();
    let mut limited = recv.take((max_bytes + 1) as u64);
    tokio::time::timeout(REQUEST_TIMEOUT, limited.read_to_end(&mut bytes))
        .await
        .map_err(|_| "request body timed out".to_string())?
        .map_err(|error| format!("request body read failed: {error}"))?;

    if bytes.len() > max_bytes {
        return Err(format!("request exceeds the {max_bytes}-byte limit"));
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("request JSON is invalid: {error}"))
}

async fn process_request(request: Request, state: &ServerState) -> (Response, Option<Vec<u8>>) {
    match request.body {
        RequestBody::Hello => (
            Response::ok(
                request.id,
                ResponseBody::Hello {
                    protocol: PROTOCOL_NAME.to_string(),
                    peer_id: state.p2p.peer_id().to_hex(),
                    max_chunk_size: MAX_CHUNK_SIZE,
                    endpoint: state.endpoint.clone(),
                    capabilities: vec!["find_node".to_string(), "get_chunk".to_string()],
                },
                0,
            ),
            None,
        ),
        RequestBody::FindNode { target, count } => {
            process_find_node(request.id, target, count, state).await
        }
        RequestBody::GetChunk { address } => process_get_chunk(request.id, address, state).await,
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
                webtransport: state.endpoint_catalog.get(&peer_id),
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

struct ServerState {
    config: WebTransportConfig,
    p2p: Arc<P2PNode>,
    ant_protocol: Option<Arc<AntProtocol>>,
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
            r#"{"version":1,"request_id":7,"type":"find_node","target":"0000000000000000000000000000000000000000000000000000000000000000","count":20}"#,
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
        assert_eq!(value["version"], 1);
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
