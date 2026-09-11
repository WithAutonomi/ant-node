//! ADR-0013 WebRTC Direct browser transport.
//!
//! The listener uses Saorsa's signaling-free WebRTC Direct transport for ICE,
//! DTLS, SCTP, and reliable ordered `DataChannels`. A shared application layer
//! in `saorsa_transport::webrtc` uses ML-KEM-768, ML-DSA-65, and ChaCha20-Poly1305 to bind
//! the node identity and protect every browser RPC without libp2p or Noise.

mod errors;

use crate::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest,
    ChunkQuoteResponse, MAX_CHUNK_SIZE,
};
use crate::browser::{browser_payment_network, BrowserEndpoint, BrowserPaymentNetwork};
use crate::config::WebRtcDirectConfig;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::payment::{serialize_single_node_proof, PaymentProof};
use crate::storage::AntProtocol;
use errors::{decode_response, error_response, public_error};
use evmlib::common::{Amount, TxHash};
use evmlib::{EncodedPeerId, PaymentQuote, ProofOfPayment, RewardsAddress};
use parking_lot::{Mutex, RwLock};
use saorsa_core::identity::NodeIdentity;
use saorsa_core::{AddressType, DHTNode, MultiAddr, P2PNode, PeerId};
use saorsa_transport::webrtc::{
    accept_pq_session, decode_pq_frame, encode_response_frame, parse_request_header,
    pq_frame_length, source_ip_bucket, transfer_timeout, BrowserCommitmentArtifact, BrowserNode,
    BrowserQuoteArtifact, BrowserRequest as Request, BrowserRequestBody as RequestBody,
    BrowserResponse as Response, BrowserResponseBody as ResponseBody,
    BrowserResponseStatus as ResponseStatus, PqSession, BROWSER_PROTOCOL_NAME,
    BROWSER_PROTOCOL_VERSION, MAX_BROWSER_FRAME_BYTES, MAX_BROWSER_HEADER_BYTES,
    PQ_CLIENT_HELLO_BYTES, PQ_ENCRYPTED_OVERHEAD_BYTES, PQ_FRAME_PREFIX_BYTES,
    WEBRTC_DIRECT_DATA_CHANNEL, WEBRTC_WRITE_CHUNK_BYTES,
};
use saorsa_transport::webrtc_direct::{
    WebRtcAdmissionLimits, WebRtcCertificate, WebRtcDataChannel, WebRtcDiagnostics,
    WebRtcDiagnosticsSnapshot, WebRtcDirectConnection, WebRtcDirectListener,
};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

const MAX_FIND_NODE_RESULTS: usize = 20;
// Browser dials use a 10-second channel-open timeout. Give successful clients
// modest server-side headroom while bounding associations that never open one.
const FIRST_DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_IDLE_TIMEOUT: Duration = Duration::from_mins(1);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const ADDRESS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const TRACKED_SOURCE_MULTIPLIER: usize = 4;
const MIN_TRACKED_SOURCES: usize = 64;
const CONNECTION_CAPACITY_ERROR: &str = "global connection capacity exhausted";
const SOURCE_CONNECTION_CAPACITY_ERROR: &str = "source connection capacity exhausted";
const FIRST_DATA_CHANNEL_TIMEOUT_ERROR: &str = "DataChannel opening timed out";
const CHANNEL_CAPACITY_ERROR: &str = "global DataChannel capacity exhausted";
const REQUEST_CAPACITY_ERROR: &str = "global request capacity exhausted";
const REQUEST_RATE_ERROR: &str = "request rate limit exceeded";
const GLOBAL_BYTE_CAPACITY_ERROR: &str = "global in-flight byte capacity exhausted";
const SOURCE_BYTE_CAPACITY_ERROR: &str = "source in-flight byte capacity exhausted";

/// Filename containing the node's canonical browser bootstrap address.
///
/// The file is written below the node root directory after the listener has
/// bound and is safe for deployment tooling to copy or print. Its contents are
/// public bootstrap metadata, not key material.
pub const WEBRTC_DIRECT_MULTIADDR_FILENAME: &str = "webrtc-direct.multiaddr";

/// Browser endpoints known to one or more listeners in the same process.
///
/// Only the in-process devnet supplies this catalog. Independently deployed
/// nodes discover endpoints exclusively from authenticated DHT address
/// records.
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

/// Fixed-capacity token bucket with a one-second burst allowance.
///
/// The bucket is deliberately constant-space: source churn must not turn the
/// request limiter itself into a memory-exhaustion surface.
struct RequestRateBucket {
    rate_per_second: u128,
    token_units: u128,
    last_refill: Instant,
}

impl RequestRateBucket {
    fn new(rate_per_second: usize) -> Self {
        let rate_per_second = rate_per_second as u128;
        Self {
            rate_per_second,
            token_units: rate_per_second.saturating_mul(1_000_000_000),
            last_refill: Instant::now(),
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let capacity = self.rate_per_second.saturating_mul(1_000_000_000);
        let refill = elapsed.as_nanos().saturating_mul(self.rate_per_second);
        self.token_units = self.token_units.saturating_add(refill).min(capacity);
        if self.token_units < 1_000_000_000 {
            return false;
        }
        self.token_units -= 1_000_000_000;
        true
    }
}

/// Atomic byte budget and an RAII reservation within it.
///
/// A custom counter is used instead of a semaphore because WebRTC frames grow
/// incrementally and the accounting must resize without queueing an unbounded
/// number of waiters.
struct ByteBudget {
    rejections: Arc<AtomicU64>,
    limit: usize,
    in_use: AtomicUsize,
}

impl ByteBudget {
    fn with_rejections(limit: usize, rejections: Arc<AtomicU64>) -> Self {
        Self {
            rejections,
            limit,
            in_use: AtomicUsize::new(0),
        }
    }

    fn try_acquire(
        self: &Arc<Self>,
        amount: usize,
        error: &'static str,
    ) -> ServerResult<ByteReservation> {
        self.in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(amount)
                    .filter(|next| *next <= self.limit)
            })
            .map_err(|_| {
                self.rejections.fetch_add(1, Ordering::Relaxed);
                error.to_string()
            })?;
        Ok(ByteReservation {
            budget: Arc::clone(self),
            amount,
            error,
        })
    }

    #[cfg(test)]
    fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }
}

struct ByteReservation {
    budget: Arc<ByteBudget>,
    amount: usize,
    error: &'static str,
}

impl ByteReservation {
    fn try_grow(&mut self, amount: usize) -> ServerResult<()> {
        self.budget
            .in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(amount)
                    .filter(|next| *next <= self.budget.limit)
            })
            .map_err(|_| {
                self.budget.rejections.fetch_add(1, Ordering::Relaxed);
                self.error.to_string()
            })?;
        self.amount += amount;
        Ok(())
    }

    fn shrink(&mut self, amount: usize) {
        let released = amount.min(self.amount);
        self.amount -= released;
        self.budget.in_use.fetch_sub(released, Ordering::AcqRel);
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.budget.in_use.fetch_sub(self.amount, Ordering::AcqRel);
    }
}

struct InFlightByteReservation {
    source: ByteReservation,
    global: ByteReservation,
}

impl InFlightByteReservation {
    fn try_grow(&mut self, amount: usize) -> ServerResult<()> {
        self.source.try_grow(amount)?;
        if let Err(error) = self.global.try_grow(amount) {
            self.source.shrink(amount);
            return Err(error);
        }
        Ok(())
    }

    fn resize(&mut self, amount: usize) -> ServerResult<()> {
        if amount > self.source.amount {
            self.try_grow(amount - self.source.amount)
        } else {
            let released = self.source.amount - amount;
            self.source.shrink(released);
            self.global.shrink(released);
            Ok(())
        }
    }
}

struct TrackedBytes {
    bytes: Vec<u8>,
    reservation: InFlightByteReservation,
}

impl TrackedBytes {
    fn reserve_length(&mut self, length: usize) -> ServerResult<()> {
        self.reservation.resize(length)?;
        if self.bytes.capacity() < length {
            self.bytes.reserve_exact(length - self.bytes.len());
        }
        Ok(())
    }
}

struct SourceQuota {
    request_rate: Mutex<RequestRateBucket>,
    bytes: Arc<ByteBudget>,
}

struct SourceEntry {
    active_connections: usize,
    last_seen: Instant,
    quota: Arc<SourceQuota>,
}

#[derive(Default)]
struct SourceAdmissionState {
    sources: HashMap<IpAddr, SourceEntry>,
}

/// Admission and accounting shared by every association on one listener.
struct ListenerResources {
    running: AtomicBool,
    connection_rejections: AtomicU64,
    channel_rejections: AtomicU64,
    request_rejections: AtomicU64,
    rate_rejections: AtomicU64,
    byte_rejections: Arc<AtomicU64>,
    listener_errors: AtomicU64,
    connection_errors: AtomicU64,
    channel_errors: AtomicU64,
    task_failures: AtomicU64,
    connection_limit: Arc<Semaphore>,
    channel_limit: Arc<Semaphore>,
    request_limit: Arc<Semaphore>,
    global_request_rate: Mutex<RequestRateBucket>,
    global_bytes: Arc<ByteBudget>,
    source_state: Mutex<SourceAdmissionState>,
    max_connections_per_ip: usize,
    max_requests_per_second_per_ip: usize,
    max_requests_per_second_per_connection: usize,
    max_in_flight_bytes_per_ip: usize,
    max_tracked_sources: usize,
}

impl ListenerResources {
    fn new(config: &WebRtcDirectConfig) -> Arc<Self> {
        let byte_rejections = Arc::new(AtomicU64::new(0));
        Arc::new(Self {
            running: AtomicBool::new(false),
            connection_rejections: AtomicU64::new(0),
            channel_rejections: AtomicU64::new(0),
            request_rejections: AtomicU64::new(0),
            rate_rejections: AtomicU64::new(0),
            listener_errors: AtomicU64::new(0),
            connection_errors: AtomicU64::new(0),
            channel_errors: AtomicU64::new(0),
            task_failures: AtomicU64::new(0),
            byte_rejections: Arc::clone(&byte_rejections),
            connection_limit: Arc::new(Semaphore::new(config.max_connections)),
            channel_limit: Arc::new(Semaphore::new(config.max_channels)),
            request_limit: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            global_request_rate: Mutex::new(RequestRateBucket::new(config.max_requests_per_second)),
            global_bytes: Arc::new(ByteBudget::with_rejections(
                config.max_in_flight_bytes,
                byte_rejections,
            )),
            source_state: Mutex::new(SourceAdmissionState::default()),
            max_connections_per_ip: config.max_connections_per_ip,
            max_requests_per_second_per_ip: config.max_requests_per_second_per_ip,
            max_requests_per_second_per_connection: config.max_requests_per_second_per_connection,
            max_in_flight_bytes_per_ip: config.max_in_flight_bytes_per_ip,
            max_tracked_sources: config
                .max_connections
                .saturating_mul(TRACKED_SOURCE_MULTIPLIER)
                .max(MIN_TRACKED_SOURCES),
        })
    }

    fn try_admit_connection(
        self: &Arc<Self>,
        remote_addr: SocketAddr,
    ) -> ServerResult<ConnectionAdmission> {
        self.admit_connection(remote_addr).inspect_err(|_| {
            self.connection_rejections.fetch_add(1, Ordering::Relaxed);
        })
    }

    fn admit_connection(
        self: &Arc<Self>,
        remote_addr: SocketAddr,
    ) -> ServerResult<ConnectionAdmission> {
        let global = Arc::clone(&self.connection_limit)
            .try_acquire_owned()
            .map_err(|_| CONNECTION_CAPACITY_ERROR.to_string())?;
        let ip = source_ip_bucket(remote_addr.ip());
        let source = {
            let mut state = self.source_state.lock();
            if !state.sources.contains_key(&ip) && state.sources.len() >= self.max_tracked_sources {
                let eviction = state
                    .sources
                    .iter()
                    .filter(|(_, entry)| entry.active_connections == 0)
                    .min_by_key(|(_, entry)| entry.last_seen)
                    .map(|(ip, _)| *ip);
                let Some(eviction) = eviction else {
                    return Err(CONNECTION_CAPACITY_ERROR.to_string());
                };
                state.sources.remove(&eviction);
            }

            let entry = state.sources.entry(ip).or_insert_with(|| SourceEntry {
                active_connections: 0,
                last_seen: Instant::now(),
                quota: Arc::new(SourceQuota {
                    request_rate: Mutex::new(RequestRateBucket::new(
                        self.max_requests_per_second_per_ip,
                    )),
                    bytes: Arc::new(ByteBudget::with_rejections(
                        self.max_in_flight_bytes_per_ip,
                        Arc::clone(&self.byte_rejections),
                    )),
                }),
            });
            if entry.active_connections >= self.max_connections_per_ip {
                return Err(SOURCE_CONNECTION_CAPACITY_ERROR.to_string());
            }
            entry.active_connections += 1;
            entry.last_seen = Instant::now();
            Arc::clone(&entry.quota)
        };
        let context = Arc::new(ConnectionResources {
            listener: Arc::clone(self),
            source,
            request_rate: Mutex::new(RequestRateBucket::new(
                self.max_requests_per_second_per_connection,
            )),
        });
        Ok(ConnectionAdmission {
            listener: Arc::clone(self),
            ip,
            context,
            _global: global,
        })
    }

    fn release_connection(&self, ip: IpAddr) {
        let mut state = self.source_state.lock();
        if let Some(entry) = state.sources.get_mut(&ip) {
            entry.active_connections = entry.active_connections.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }
}

struct ConnectionResources {
    listener: Arc<ListenerResources>,
    source: Arc<SourceQuota>,
    request_rate: Mutex<RequestRateBucket>,
}

impl ConnectionResources {
    fn try_admit_request(&self) -> ServerResult<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.listener.request_limit)
            .try_acquire_owned()
            .map_err(|_| {
                self.listener
                    .request_rejections
                    .fetch_add(1, Ordering::Relaxed);
                REQUEST_CAPACITY_ERROR.to_string()
            })?;
        let now = Instant::now();
        if !self.source.request_rate.lock().allow(now)
            || !self.request_rate.lock().allow(now)
            || !self.listener.global_request_rate.lock().allow(now)
        {
            self.listener
                .rate_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(REQUEST_RATE_ERROR.to_string());
        }
        Ok(permit)
    }

    fn try_reserve_bytes(&self, amount: usize) -> ServerResult<InFlightByteReservation> {
        let source = self
            .source
            .bytes
            .try_acquire(amount, SOURCE_BYTE_CAPACITY_ERROR)?;
        let global = self
            .listener
            .global_bytes
            .try_acquire(amount, GLOBAL_BYTE_CAPACITY_ERROR)?;
        Ok(InFlightByteReservation { source, global })
    }
}

struct ConnectionAdmission {
    listener: Arc<ListenerResources>,
    ip: IpAddr,
    context: Arc<ConnectionResources>,
    _global: OwnedSemaphorePermit,
}

impl Drop for ConnectionAdmission {
    fn drop(&mut self) {
        self.listener.release_connection(self.ip);
    }
}

/// Internal browser-listener diagnostics, sampled without network I/O.
#[derive(Clone, Debug)]
pub struct WebRtcServerSnapshot {
    /// Bound local UDP socket.
    pub local_addr: SocketAddr,
    /// Both accept loop and UDP driver are alive; no external probe is implied.
    pub running: bool,
    /// Transport connection lifecycle and `DataChannel` traffic counters.
    pub transport: WebRtcDiagnosticsSnapshot,
    /// Application connection slots currently held, including setup.
    pub active_connections: usize,
    /// Configured application connection capacity.
    pub max_connections: usize,
    /// `DataChannel` handler slots currently held.
    pub active_channels: usize,
    /// Configured `DataChannel` handler capacity.
    pub max_channels: usize,
    /// Request permits currently held, including frame assembly.
    pub active_requests: usize,
    /// Configured concurrent request capacity.
    pub max_concurrent_requests: usize,
    /// Frame bytes currently reserved by handlers.
    pub in_flight_bytes: usize,
    /// Configured frame-memory capacity.
    pub max_in_flight_bytes: usize,
    /// Application connection admissions denied by capacity policy.
    pub connection_rejections: u64,
    /// `DataChannels` rejected by global or per-connection capacity policy.
    pub channel_rejections: u64,
    /// Requests rejected because all worker permits are in use.
    pub request_rejections: u64,
    /// Requests rejected by a global, source, or association rate limit.
    pub rate_rejections: u64,
    /// Failed frame-memory reservations, including buffer growth.
    pub byte_rejections: u64,
    /// Transport accept errors observed by the application listener.
    pub listener_errors: u64,
    /// Connection handlers that returned an error.
    pub connection_errors: u64,
    /// `DataChannel` handlers that returned an error, including PQ setup failures.
    pub channel_errors: u64,
    /// Connection or `DataChannel` tasks that panicked or were unexpectedly cancelled.
    pub task_failures: u64,
}

/// Cloneable diagnostics handle for a running or stopped browser listener.
#[derive(Clone)]
pub struct WebRtcServerDiagnostics {
    local_addr: SocketAddr,
    transport: WebRtcDiagnostics,
    resources: Arc<ListenerResources>,
    config: WebRtcDirectConfig,
}

impl WebRtcServerDiagnostics {
    /// Sample listener state, lifecycle counts, traffic, and resource pressure.
    pub fn snapshot(&self) -> WebRtcServerSnapshot {
        let resources = &self.resources;
        let transport = self.transport.snapshot();
        WebRtcServerSnapshot {
            local_addr: self.local_addr,
            running: resources.running.load(Ordering::Acquire) && transport.running,
            transport,
            active_connections: self
                .config
                .max_connections
                .saturating_sub(resources.connection_limit.available_permits()),
            max_connections: self.config.max_connections,
            active_channels: self
                .config
                .max_channels
                .saturating_sub(resources.channel_limit.available_permits()),
            max_channels: self.config.max_channels,
            active_requests: self
                .config
                .max_concurrent_requests
                .saturating_sub(resources.request_limit.available_permits()),
            max_concurrent_requests: self.config.max_concurrent_requests,
            in_flight_bytes: resources.global_bytes.in_use.load(Ordering::Acquire),
            max_in_flight_bytes: self.config.max_in_flight_bytes,
            connection_rejections: resources.connection_rejections.load(Ordering::Relaxed),
            channel_rejections: resources.channel_rejections.load(Ordering::Relaxed),
            request_rejections: resources.request_rejections.load(Ordering::Relaxed),
            rate_rejections: resources.rate_rejections.load(Ordering::Relaxed),
            byte_rejections: resources.byte_rejections.load(Ordering::Relaxed),
            listener_errors: resources.listener_errors.load(Ordering::Relaxed),
            connection_errors: resources.connection_errors.load(Ordering::Relaxed),
            channel_errors: resources.channel_errors.load(Ordering::Relaxed),
            task_failures: resources.task_failures.load(Ordering::Relaxed),
        }
    }
}

struct ListenerRunGuard(Arc<ListenerResources>);

impl Drop for ListenerRunGuard {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::Release);
    }
}

/// A running browser listener and the endpoint clients use to reach it.
pub struct WebRtcDirectServer {
    /// Local health, traffic, lifecycle, and admission diagnostics.
    pub diagnostics: WebRtcServerDiagnostics,
    /// Initial endpoint, absent until native address discovery yields a usable IP.
    /// Later updates are published through the DHT and the endpoint file.
    pub endpoint: Option<BrowserEndpoint>,
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
    endpoint_catalog: Option<Arc<BrowserEndpointCatalog>>,
) -> Result<WebRtcDirectServer> {
    validate_webrtc_config(config)?;
    let payment = browser_payment_network(evm_network).await?;
    let certificate_path = certificate_path(config, root_dir);
    let certificate = load_or_generate_certificate(&certificate_path).await?;
    let certificate_sha256 = certificate
        .sha256_digest()
        .map_err(|error| Error::Startup(error.to_string()))?;
    let listener = WebRtcDirectListener::bind_with_limits(
        config.bind,
        certificate,
        WebRtcAdmissionLimits {
            max_connections: config.max_connections,
            max_connections_per_ip: config.max_connections_per_ip,
        },
    )
    .await
    .map_err(|error| Error::Startup(format!("failed to bind WebRTC Direct listener: {error}")))?;
    let local_addr = listener.local_addr();
    let identity = Arc::clone(p2p.transport().node_identity());
    let state = Arc::new(ServerState {
        config: config.clone(),
        identity,
        p2p,
        ant_protocol,
        payment,
        endpoint: RwLock::new(None),
        endpoint_catalog,
    });
    refresh_browser_endpoint(&state, root_dir, local_addr, certificate_sha256).await?;
    let browser_endpoint = state.endpoint.read().clone();
    if browser_endpoint.is_none() {
        // Do not leave a previous run's socket advertised while discovery is pending.
        let path = root_dir.join(WEBRTC_DIRECT_MULTIADDR_FILENAME);
        match tokio::fs::remove_file(path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let resources = ListenerResources::new(config);
    let diagnostics = WebRtcServerDiagnostics {
        local_addr,
        transport: listener.diagnostics(),
        resources: Arc::clone(&resources),
        config: config.clone(),
    };
    resources.running.store(true, Ordering::Release);
    let run_guard = ListenerRunGuard(Arc::clone(&resources));
    info!(bind = %local_addr, certificate = %certificate_path.display(),
        "ADR-0013 WebRTC Direct listening");
    let root_dir = root_dir.to_path_buf();
    let task = tokio::spawn(async move {
        // Both futures are owned by the listener task. Address publication cannot
        // block accepting sessions, and shutdown cancels a pending publication.
        tokio::join!(
            serve_webrtc(
                listener,
                Arc::clone(&state),
                resources,
                shutdown.clone(),
                run_guard
            ),
            async {
                let refresh = async {
                    let mut interval = tokio::time::interval(ADDRESS_REFRESH_INTERVAL);
                    loop {
                        interval.tick().await;
                        if let Err(error) = refresh_browser_endpoint(
                            &state,
                            &root_dir,
                            local_addr,
                            certificate_sha256,
                        )
                        .await
                        {
                            warn!(%error, "Failed to update WebRTC Direct endpoint");
                        }
                    }
                };
                tokio::select! {
                    () = shutdown.cancelled() => {},
                    () = refresh => {},
                }
            },
        );
    });
    Ok(WebRtcDirectServer {
        diagnostics,
        endpoint: browser_endpoint,
        task,
    })
}

async fn refresh_browser_endpoint(
    state: &ServerState,
    root_dir: &Path,
    local_addr: SocketAddr,
    certificate_sha256: [u8; 32],
) -> Result<()> {
    let native = state.p2p.dht_manager().local_dht_node().await;
    let Some(address) = advertised_addr(&state.config, local_addr, &native.typed_addresses())
    else {
        // As with native publication, keep the last nonempty address set.
        return Ok(());
    };
    let peer_id = *state.p2p.peer_id();
    let endpoint = BrowserEndpoint::new(address, peer_id.to_bytes(), certificate_sha256)
        .map_err(|error| Error::Config(error.to_string()))?;
    if state.endpoint.read().as_ref() == Some(&endpoint) {
        return Ok(());
    }
    let supplemental = endpoint
        .multiaddr
        .parse()
        .map_err(|error| Error::Startup(format!("invalid WebRTC transport address: {error}")))?;
    persist_browser_endpoint(root_dir, &endpoint).await?;
    if let Some(catalog) = state.endpoint_catalog.as_ref() {
        catalog.insert(peer_id, endpoint.clone());
    }
    *state.endpoint.write() = Some(endpoint);
    state
        .p2p
        .dht_manager()
        .set_supplemental_self_addresses(vec![supplemental])
        .await;
    Ok(())
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
    for (name, value) in [
        ("max_connections", config.max_connections),
        ("max_connections_per_ip", config.max_connections_per_ip),
        (
            "max_channels_per_connection",
            config.max_channels_per_connection,
        ),
        ("max_channels", config.max_channels),
        ("max_concurrent_requests", config.max_concurrent_requests),
    ] {
        if value == 0 || value > Semaphore::MAX_PERMITS {
            return Err(Error::Config(format!(
                "webrtc_direct.{name} must be between 1 and {}",
                Semaphore::MAX_PERMITS
            )));
        }
    }
    for (name, value) in [
        ("max_requests_per_second", config.max_requests_per_second),
        (
            "max_requests_per_second_per_ip",
            config.max_requests_per_second_per_ip,
        ),
        (
            "max_requests_per_second_per_connection",
            config.max_requests_per_second_per_connection,
        ),
        ("max_in_flight_bytes", config.max_in_flight_bytes),
        (
            "max_in_flight_bytes_per_ip",
            config.max_in_flight_bytes_per_ip,
        ),
    ] {
        if value == 0 {
            return Err(Error::Config(format!(
                "webrtc_direct.{name} must be greater than zero"
            )));
        }
    }
    if config.max_connections_per_ip >= config.max_connections {
        return Err(Error::Config(
            "webrtc_direct.max_connections_per_ip must be lower than max_connections".to_string(),
        ));
    }
    let source_channel_ceiling = config
        .max_connections_per_ip
        .checked_mul(config.max_channels_per_connection)
        .ok_or_else(|| {
            Error::Config("webrtc_direct per-IP DataChannel ceiling overflows usize".to_string())
        })?;
    if source_channel_ceiling >= config.max_channels {
        return Err(Error::Config(
            "webrtc_direct max_connections_per_ip * max_channels_per_connection must be lower than max_channels"
                .to_string(),
        ));
    }
    if source_channel_ceiling >= config.max_concurrent_requests {
        return Err(Error::Config(
            "webrtc_direct max_connections_per_ip * max_channels_per_connection must be lower than max_concurrent_requests"
                .to_string(),
        ));
    }
    if config.max_requests_per_second_per_connection > config.max_requests_per_second_per_ip {
        return Err(Error::Config(
            "webrtc_direct.max_requests_per_second_per_connection must not exceed max_requests_per_second_per_ip"
                .to_string(),
        ));
    }
    if config.max_requests_per_second_per_ip >= config.max_requests_per_second {
        return Err(Error::Config(
            "webrtc_direct.max_requests_per_second_per_ip must be lower than max_requests_per_second"
                .to_string(),
        ));
    }
    if config.max_in_flight_bytes_per_ip >= config.max_in_flight_bytes {
        return Err(Error::Config(
            "webrtc_direct.max_in_flight_bytes_per_ip must be lower than max_in_flight_bytes"
                .to_string(),
        ));
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
            Ok(certificate)
        }
        Err(error) => Err(error.into()),
    }
}

fn advertised_addr(
    config: &WebRtcDirectConfig,
    local_addr: SocketAddr,
    native_addresses: &[(MultiAddr, AddressType)],
) -> Option<SocketAddr> {
    if let Some(addr) = config.advertised_addr {
        return Some(addr);
    }
    if !local_addr.ip().is_unspecified() {
        return Some(local_addr);
    }
    // The native self-address view already applies observation, scope and
    // priority policy. Relay sockets belong to the relay, not this listener.
    native_addresses
        .iter()
        .filter(|(_, kind)| *kind != AddressType::Relay)
        .filter_map(|(address, _)| address.socket_addr())
        .find(|addr| addr.is_ipv4() == local_addr.is_ipv4())
        .map(|addr| SocketAddr::new(addr.ip(), local_addr.port()))
}

#[allow(clippy::significant_drop_tightening)]
async fn serve_webrtc(
    mut listener: WebRtcDirectListener,
    state: Arc<ServerState>,
    resources: Arc<ListenerResources>,
    shutdown: CancellationToken,
    _run_guard: ListenerRunGuard,
) {
    let mut connection_tasks = JoinSet::new();
    loop {
        let connection = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            completed = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    resources.task_failures.fetch_add(1, Ordering::Relaxed);
                    warn!(%error, "WebRTC Direct connection task failed");
                }
                continue;
            }
            // Do not perform another ICE/DTLS/SCTP accept while every
            // application connection slot is occupied. The transport's
            // pending-association queue remains bounded, and completed
            // sessions release a permit before this branch becomes eligible.
            connection = listener.accept(), if resources.connection_limit.available_permits() > 0 => connection,
        };
        match connection {
            Ok(connection) => {
                let remote_addr = connection.remote_addr();
                let admission = match resources.try_admit_connection(remote_addr) {
                    Ok(admission) => admission,
                    Err(error) => {
                        debug!(remote = %remote_addr, %error, "Rejected WebRTC Direct connection");
                        if let Err(close_error) = connection.close().await {
                            debug!(remote = %remote_addr, %close_error, "Failed to close rejected connection");
                        }
                        continue;
                    }
                };
                let connection_resources = Arc::clone(&admission.context);
                let connection_state = Arc::clone(&state);
                let connection_shutdown = shutdown.clone();
                let diagnostic_resources = Arc::clone(&resources);
                connection_tasks.spawn(async move {
                    let _admission = admission;
                    if let Err(error) = handle_connection(
                        connection,
                        connection_state,
                        connection_resources,
                        connection_shutdown,
                    )
                    .await
                    {
                        diagnostic_resources
                            .connection_errors
                            .fetch_add(1, Ordering::Relaxed);
                        debug!(remote = %remote_addr, "WebRTC Direct connection ended: {error}");
                    }
                });
            }
            Err(error) => {
                resources.listener_errors.fetch_add(1, Ordering::Relaxed);
                warn!("WebRTC Direct listener error: {error}");
                if matches!(
                    error,
                    saorsa_transport::webrtc_direct::WebRtcDirectError::Closed
                ) {
                    break;
                }
            }
        }
    }
    if let Err(error) = listener.close().await {
        debug!("WebRTC Direct listener close failed: {error}");
    }
    let drained = tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while let Some(result) = connection_tasks.join_next().await {
            if let Err(error) = result {
                debug!(%error, "WebRTC Direct connection task failed during shutdown");
            }
        }
    })
    .await;
    if drained.is_err() {
        warn!("WebRTC Direct connection tasks did not drain before shutdown deadline");
        connection_tasks.abort_all();
        while connection_tasks.join_next().await.is_some() {}
    }
    info!("ADR-0013 WebRTC Direct stopped");
}

async fn handle_connection(
    mut connection: WebRtcDirectConnection,
    state: Arc<ServerState>,
    resources: Arc<ConnectionResources>,
    shutdown: CancellationToken,
) -> ServerResult<()> {
    let remote_addr = connection.remote_addr();
    let channel_shutdown = shutdown.child_token();
    let mut channel_tasks = JoinSet::new();

    let outcome = 'connection: {
        let first_channel =
            match wait_for_first_data_channel(&shutdown, FIRST_DATA_CHANNEL_TIMEOUT, async {
                connection
                    .accept_data_channel()
                    .await
                    .map_err(|error| format!("DataChannel accept failed: {error}"))
            })
            .await
            {
                Ok(Some(channel)) => channel,
                Ok(None) => break 'connection Ok(()),
                Err(error) => break 'connection Err(error),
            };
        if let Err(error) = start_data_channel_task(
            first_channel,
            &mut channel_tasks,
            &state,
            &resources,
            &channel_shutdown,
            remote_addr,
        )
        .await
        {
            break 'connection Err(error);
        }

        loop {
            let accepted = tokio::select! {
                biased;
                () = shutdown.cancelled() => break Ok(()),
                completed = channel_tasks.join_next(), if !channel_tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        resources.listener.task_failures.fetch_add(1, Ordering::Relaxed);
                        debug!(remote = %remote_addr, %error, "WebRTC Direct DataChannel task failed");
                    }
                    // The v4 protocol uses persistent channels; it has no channel
                    // reopen/continuation handshake. Once the last channel ends,
                    // close the association promptly instead of retaining a stale
                    // per-IP connection slot while waiting for another channel.
                    if channel_tasks.is_empty() {
                        break Ok(());
                    }
                    continue;
                }
                result = connection.accept_data_channel() => result,
            };
            let channel = match accepted {
                Ok(channel) => channel,
                Err(error) => break Err(format!("DataChannel accept failed: {error}")),
            };
            if let Err(error) = start_data_channel_task(
                channel,
                &mut channel_tasks,
                &state,
                &resources,
                &channel_shutdown,
                remote_addr,
            )
            .await
            {
                break Err(error);
            }
        }
    };

    // Stop every handler before returning its storage/P2P state. Closing the
    // association alone is not a sufficient wake-up guarantee for work that
    // is currently inside an application request.
    channel_shutdown.cancel();
    if let Err(error) = connection.close().await {
        debug!(remote = %remote_addr, %error, "Failed to close WebRTC Direct connection");
    }
    while let Some(result) = channel_tasks.join_next().await {
        if let Err(error) = result {
            debug!(remote = %remote_addr, %error, "WebRTC Direct DataChannel task failed during shutdown");
        }
    }
    outcome
}

async fn wait_for_first_data_channel<T>(
    shutdown: &CancellationToken,
    timeout: Duration,
    accept: impl Future<Output = ServerResult<T>>,
) -> ServerResult<Option<T>> {
    tokio::select! {
        biased;
        () = shutdown.cancelled() => Ok(None),
        result = tokio::time::timeout(timeout, accept) => result.map_or_else(
            |_| Err(FIRST_DATA_CHANNEL_TIMEOUT_ERROR.to_string()),
            |result| result.map(Some),
        ),
    }
}

async fn start_data_channel_task(
    channel: WebRtcDataChannel,
    channel_tasks: &mut JoinSet<()>,
    state: &Arc<ServerState>,
    resources: &Arc<ConnectionResources>,
    channel_shutdown: &CancellationToken,
    remote_addr: SocketAddr,
) -> ServerResult<()> {
    if channel_tasks.len() >= state.config.max_channels_per_connection {
        resources
            .listener
            .channel_rejections
            .fetch_add(1, Ordering::Relaxed);
        if let Err(error) = channel.close().await {
            debug!(remote = %remote_addr, %error, "Failed to close excess DataChannel");
        }
        return Err("per-connection DataChannel capacity exhausted".to_string());
    }
    let Ok(channel_permit) = Arc::clone(&resources.listener.channel_limit).try_acquire_owned()
    else {
        resources
            .listener
            .channel_rejections
            .fetch_add(1, Ordering::Relaxed);
        if let Err(error) = channel.close().await {
            debug!(remote = %remote_addr, %error, "Failed to close excess DataChannel");
        }
        return Err(CHANNEL_CAPACITY_ERROR.to_string());
    };
    let channel_state = Arc::clone(state);
    let channel_resources = Arc::clone(resources);
    let handler_shutdown = channel_shutdown.clone();
    let diagnostic_resources = Arc::clone(&resources.listener);
    channel_tasks.spawn(async move {
        let _channel_permit = channel_permit;
        if let Err(error) = handle_webrtc_channel(
            &channel,
            channel_state,
            channel_resources,
            handler_shutdown,
        )
        .await
        {
            diagnostic_resources.channel_errors.fetch_add(1, Ordering::Relaxed);
            debug!(remote = %remote_addr, channel = channel.id(), "WebRTC Direct DataChannel ended: {error}");
        }
        if let Err(error) = channel.close().await {
            debug!(remote = %remote_addr, channel = channel.id(), %error, "Failed to close WebRTC Direct DataChannel");
        }
    });
    Ok(())
}

#[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
async fn handle_webrtc_channel(
    channel: &WebRtcDataChannel,
    state: Arc<ServerState>,
    resources: Arc<ConnectionResources>,
    shutdown: CancellationToken,
) -> ServerResult<()> {
    if channel.label() != WEBRTC_DIRECT_DATA_CHANNEL {
        return Err(format!(
            "unsupported DataChannel label {:?}",
            channel.label()
        ));
    }

    let mut pq_session = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(()),
        result = establish_pq_session(channel, &state, &resources) => result?,
    };
    let mut hello_completed = false;
    loop {
        let admitted_result = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            result = read_webrtc_request(
                channel,
                &mut pq_session,
                &resources,
            ) => result,
        };
        let admitted = match admitted_result {
            Ok(request) => request,
            Err(error) if is_quiet_channel_close(&error) => return Ok(()),
            Err(error) => {
                let response = Response::error(0, "invalid_request", error);
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return Ok(()),
                    result = write_webrtc_response(
                        channel,
                        &mut pq_session,
                        &response,
                        None,
                        &resources,
                    ) => result?,
                }
                return Ok(());
            }
        };
        let AdmittedRequest {
            request,
            content,
            _request_permit,
            _in_flight_bytes,
        } = admitted;
        if request.version != BROWSER_PROTOCOL_VERSION {
            let response = Response::error(
                request.request_id,
                "unsupported_version",
                format!(
                    "protocol version {} is unsupported; expected {BROWSER_PROTOCOL_VERSION}",
                    request.version
                ),
            );
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                result = write_webrtc_response(
                    channel,
                    &mut pq_session,
                    &response,
                    None,
                    &resources,
                ) => result?,
            }
            continue;
        }

        let is_hello = matches!(&request.body, RequestBody::Hello);
        if !is_hello && !hello_completed {
            let response = Response::error(
                request.request_id,
                "authentication_required",
                "HELLO must initialize this encrypted WebRTC session first".to_string(),
            );
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                result = write_webrtc_response(
                    channel,
                    &mut pq_session,
                    &response,
                    None,
                    &resources,
                ) => result?,
            }
            continue;
        }

        let (response, content) = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            result = process_request(request, content, &state, &resources) => result?,
        };
        if is_hello && matches!(&response.status, ResponseStatus::Ok) {
            hello_completed = true;
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            result = write_webrtc_response(
                channel,
                &mut pq_session,
                &response,
                content.as_ref(),
                &resources,
            ) => result?,
        }
    }
}

fn is_quiet_channel_close(error: &str) -> bool {
    matches!(
        error,
        "DataChannel closed"
            | "request idle timeout"
            | "request frame timed out"
            | REQUEST_CAPACITY_ERROR
            | REQUEST_RATE_ERROR
            | GLOBAL_BYTE_CAPACITY_ERROR
            | SOURCE_BYTE_CAPACITY_ERROR
    ) || error.starts_with("PQ session:")
}

async fn establish_pq_session(
    channel: &WebRtcDataChannel,
    state: &ServerState,
    resources: &ConnectionResources,
) -> ServerResult<PqSession> {
    let first_message = receive_first_message(channel, "PQ client hello idle timeout").await?;
    // The post-quantum handshake is deliberately charged to the same work and
    // rate envelopes as an RPC. Otherwise a source could churn channels and
    // force unmetered ML-KEM/ML-DSA work without ever sending a request.
    let _handshake_permit = resources.try_admit_request()?;
    let client_hello = read_pq_payload_after_first(
        first_message,
        channel,
        PQ_CLIENT_HELLO_BYTES,
        "PQ client hello timed out",
        resources,
    )
    .await?;
    let peer_id = *state.p2p.peer_id().to_bytes();
    let public_key = state.identity.public_key().as_bytes();
    let (server_accept, session) =
        accept_pq_session(&client_hello.bytes, &peer_id, public_key, |transcript| {
            state
                .identity
                .sign(transcript)
                .map(|signature| signature.as_bytes().to_vec())
        })
        .map_err(|error| format!("PQ session: {error}"))?;
    write_pq_payload(channel, &server_accept, resources).await?;
    Ok(session)
}

struct AdmittedRequest {
    request: Request,
    content: Vec<u8>,
    _request_permit: OwnedSemaphorePermit,
    _in_flight_bytes: InFlightByteReservation,
}

async fn read_webrtc_request(
    channel: &WebRtcDataChannel,
    pq_session: &mut PqSession,
    resources: &ConnectionResources,
) -> ServerResult<AdmittedRequest> {
    let first_message = receive_first_message(channel, "request idle timeout").await?;
    // Admission happens as soon as a client starts a frame. Idle persistent
    // channels consume neither request-rate tokens nor request worker slots.
    let request_permit = resources.try_admit_request()?;
    let max_plaintext_bytes = MAX_BROWSER_FRAME_BYTES;
    let mut encrypted = read_pq_payload_after_first(
        first_message,
        channel,
        max_plaintext_bytes + PQ_ENCRYPTED_OVERHEAD_BYTES,
        "request frame timed out",
        resources,
    )
    .await?;
    let encrypted_len = encrypted.bytes.len();
    // AEAD opening briefly holds ciphertext and plaintext at once. Reserve the
    // second buffer before asking the cryptographic layer to allocate it.
    encrypted.reservation.try_grow(encrypted_len)?;
    let frame = pq_session
        .open(&encrypted.bytes)
        .map_err(|error| format!("PQ session: {error}"))?;
    let TrackedBytes {
        bytes: encrypted_bytes,
        mut reservation,
    } = encrypted;
    drop(encrypted_bytes);
    reservation.resize(frame.len())?;

    let (request, content_offset) =
        parse_request_header(&frame).map_err(|error| error.to_string())?;
    let content_len = frame.len() - content_offset;
    let accounted_request_bytes = frame.len();
    // serde owns the parsed header and the body copy below owns the content.
    // Account the copy while the complete plaintext frame is still live, then
    // retain one frame-sized reservation for the parsed request's lifetime.
    reservation.try_grow(content_len)?;
    let content = frame[content_offset..].to_vec();
    drop(frame);
    reservation.resize(accounted_request_bytes)?;
    Ok(AdmittedRequest {
        request,
        content,
        _request_permit: request_permit,
        _in_flight_bytes: reservation,
    })
}

async fn receive_first_message(
    channel: &WebRtcDataChannel,
    idle_timeout_message: &str,
) -> ServerResult<Vec<u8>> {
    let message = tokio::time::timeout(REQUEST_IDLE_TIMEOUT, channel.receive())
        .await
        .map_err(|_| idle_timeout_message.to_string())?
        .map_err(|error| format!("DataChannel message read failed: {error}"))?;
    if message.is_empty() {
        return Err("DataChannel closed".to_string());
    }
    Ok(message)
}

async fn read_pq_payload_after_first(
    first_message: Vec<u8>,
    channel: &WebRtcDataChannel,
    max_payload_bytes: usize,
    frame_timeout_message: &str,
    resources: &ConnectionResources,
) -> ServerResult<TrackedBytes> {
    let frame_started = tokio::time::Instant::now();
    let mut frame_deadline = frame_started + transfer_timeout(PQ_FRAME_PREFIX_BYTES);
    let mut frame = TrackedBytes {
        reservation: resources.try_reserve_bytes(first_message.len())?,
        bytes: first_message,
    };
    let mut expected_length = None;
    let max_frame_bytes = 4usize
        .checked_add(max_payload_bytes)
        .ok_or_else(|| "PQ frame limit overflow".to_string())?;
    loop {
        if frame.bytes.len() > max_frame_bytes {
            return Err(format!(
                "request exceeds the {max_frame_bytes}-byte frame limit"
            ));
        }

        if expected_length.is_none() {
            expected_length = pq_frame_length(&frame.bytes, max_payload_bytes)
                .map_err(|error| format!("PQ session: {error}"))?;
            if let Some(length) = expected_length {
                if frame.bytes.len() > length {
                    return Err("PQ frame contains bytes after its declared payload".to_string());
                }
                // Reserve the complete declared frame before accepting a slow
                // body. A sender cannot make many partial 4 MiB frames consume
                // unaccounted memory during their transfer windows.
                frame.reserve_length(length)?;
                frame_deadline = frame_started + transfer_timeout(length);
            }
        }

        if let Some(length) = expected_length {
            if frame.bytes.len() == length {
                let payload_len = length - PQ_FRAME_PREFIX_BYTES;
                frame.reservation.try_grow(payload_len)?;
                let payload = decode_pq_frame(&frame.bytes, max_payload_bytes)
                    .map_err(|error| format!("PQ session: {error}"))?;
                let TrackedBytes {
                    bytes: encoded_frame,
                    mut reservation,
                } = frame;
                drop(encoded_frame);
                reservation.resize(payload.len())?;
                return Ok(TrackedBytes {
                    bytes: payload,
                    reservation,
                });
            }
        }

        let message = tokio::time::timeout_at(frame_deadline, channel.receive())
            .await
            .map_err(|_| frame_timeout_message.to_string())?
            .map_err(|error| format!("DataChannel message read failed: {error}"))?;
        if message.is_empty() {
            return Err("DataChannel closed".to_string());
        }
        let next_length = frame
            .bytes
            .len()
            .checked_add(message.len())
            .ok_or_else(|| "PQ frame length overflow".to_string())?;
        if next_length > max_frame_bytes
            || expected_length.is_some_and(|length| next_length > length)
        {
            return Err("PQ frame contains bytes after its declared payload".to_string());
        }
        if expected_length.is_none() {
            frame.reserve_length(next_length)?;
        }
        frame.bytes.extend_from_slice(&message);
    }
}

async fn write_webrtc_response(
    channel: &WebRtcDataChannel,
    pq_session: &mut PqSession,
    response: &Response,
    content: Option<&TrackedBytes>,
    resources: &ConnectionResources,
) -> ServerResult<()> {
    // GET content carries its own reservation from before the storage read.
    // This reservation accounts only the new header, plaintext, and ciphertext
    // allocations made while encoding the response.
    let content = content.map_or(&[][..], |tracked| tracked.bytes.as_slice());
    let encode_reservation = 4usize
        .checked_add(MAX_BROWSER_HEADER_BYTES.saturating_mul(2))
        .and_then(|length| length.checked_add(content.len()))
        .ok_or_else(|| "response frame length overflow".to_string())?;
    let mut reservation = resources.try_reserve_bytes(encode_reservation)?;
    let plaintext = encode_response_frame(response, content).map_err(|error| error.to_string())?;
    reservation.resize(plaintext.len())?;
    let encrypted_len = plaintext
        .len()
        .checked_add(PQ_ENCRYPTED_OVERHEAD_BYTES)
        .ok_or_else(|| "encrypted response length overflow".to_string())?;
    reservation.try_grow(encrypted_len)?;
    let encrypted = pq_session
        .seal(&plaintext)
        .map_err(|error| format!("PQ session: {error}"))?;
    drop(plaintext);
    reservation.resize(content.len() + encrypted.len())?;
    write_framed_pq_payload(channel, &encrypted).await
}

async fn write_pq_payload(
    channel: &WebRtcDataChannel,
    payload: &[u8],
    resources: &ConnectionResources,
) -> ServerResult<()> {
    let _reservation = resources.try_reserve_bytes(payload.len())?;
    write_framed_pq_payload(channel, payload).await
}

async fn write_framed_pq_payload(channel: &WebRtcDataChannel, payload: &[u8]) -> ServerResult<()> {
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| "PQ session: payload length does not fit u32".to_string())?;
    let framed_len = PQ_FRAME_PREFIX_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| "PQ response frame length overflow".to_string())?;
    let deadline = tokio::time::Instant::now() + transfer_timeout(framed_len);
    tokio::time::timeout_at(deadline, channel.send(&payload_len.to_be_bytes()))
        .await
        .map_err(|_| "response frame timed out".to_string())?
        .map_err(|error| format!("response message write failed: {error}"))?;
    for chunk in payload.chunks(WEBRTC_WRITE_CHUNK_BYTES) {
        tokio::time::timeout_at(deadline, channel.send(chunk))
            .await
            .map_err(|_| "response frame timed out".to_string())?
            .map_err(|error| format!("response message write failed: {error}"))?;
    }
    Ok(())
}

async fn process_request(
    request: Request,
    content: Vec<u8>,
    state: &ServerState,
    resources: &ConnectionResources,
) -> ServerResult<(Response, Option<TrackedBytes>)> {
    if !matches!(
        &request.body,
        RequestBody::PutChunk { .. } | RequestBody::ChunkProtocol
    ) && !content.is_empty()
    {
        return Ok((
            Response::error(
                request.request_id,
                "unexpected_content",
                "only put_chunk and chunk_protocol accept binary request content".to_string(),
            ),
            None,
        ));
    }
    match request.body {
        RequestBody::ChunkProtocol => {
            let Some(protocol) = state.ant_protocol.as_ref() else {
                return Ok((
                    Response::error(
                        request.request_id,
                        "storage_disabled",
                        "chunk storage is disabled".to_string(),
                    ),
                    None,
                ));
            };
            // Charge the response before the shared handler can allocate it.
            // Requests retain the existing connection/rate/byte admission limits.
            let mut reservation =
                resources.try_reserve_bytes(2 * ant_protocol::MAX_WIRE_MESSAGE_SIZE)?;
            let response = protocol
                .try_handle_request(&content)
                .await
                .map_err(|error| public_error("chunk_protocol_failed", error))?
                .ok_or_else(|| "chunk protocol handler returned no response".to_string())?;
            if response.len() > ant_protocol::MAX_WIRE_MESSAGE_SIZE {
                return Err("chunk protocol response exceeds wire limit".to_string());
            }
            let response = decode_response(response)?;
            let bytes = response
                .encode()
                .map_err(|error| public_error("invalid_response", error))?;
            drop(response);
            reservation.resize(bytes.len())?;
            Ok((
                Response::ok(request.request_id, ResponseBody::ChunkProtocol, bytes.len()),
                Some(TrackedBytes { bytes, reservation }),
            ))
        }
        RequestBody::Hello => Ok((hello_response(request.request_id, state), None)),
        RequestBody::FindNode {
            target,
            count,
            with_address_records,
        } => {
            process_find_node(
                request.request_id,
                target,
                count,
                with_address_records,
                state,
                resources,
            )
            .await
        }
        RequestBody::GetChunk { address } => {
            process_get_chunk(request.request_id, address, state, resources).await
        }
        RequestBody::QuoteChunk { address, size } => {
            Ok(process_quote_chunk(request.request_id, address, size, state).await)
        }
        RequestBody::PutChunk {
            address,
            quote,
            transaction_hash,
        } => Ok(process_put_chunk(
            request.request_id,
            address,
            *quote,
            transaction_hash,
            content,
            state,
        )
        .await),
    }
}

fn hello_response(request_id: u64, state: &ServerState) -> Response {
    let Some(endpoint) = state.endpoint.read().clone() else {
        return Response::error(
            request_id,
            "endpoint_unavailable",
            "address discovery is pending".to_string(),
        );
    };
    Response::ok(
        request_id,
        ResponseBody::Hello {
            protocol: BROWSER_PROTOCOL_NAME.to_string(),
            peer_id: state.p2p.peer_id().to_hex(),
            max_chunk_size: MAX_CHUNK_SIZE,
            endpoint,
            payment: state.payment.clone(),
            capabilities: vec![
                "chunk_protocol".into(),
                "find_node".into(),
                ant_protocol::transport::ADDRESS_V2_CAPABILITY.into(),
                "get_chunk".into(),
                "quote_chunk".into(),
                "put_chunk".into(),
            ],
        },
        0,
    )
}

async fn process_find_node(
    request_id: u64,
    target: String,
    count: Option<usize>,
    with_address_records: bool,
    state: &ServerState,
    resources: &ConnectionResources,
) -> ServerResult<(Response, Option<TrackedBytes>)> {
    let target_bytes = match decode_32_byte_hex(&target) {
        Ok(bytes) => bytes,
        Err(error) => return Ok((Response::error(request_id, "invalid_target", error), None)),
    };
    let count = count
        .unwrap_or(MAX_FIND_NODE_RESULTS)
        .clamp(1, MAX_FIND_NODE_RESULTS);
    let dht = state.p2p.dht_manager();
    let dht_nodes = dht
        .find_closest_nodes_local_with_self(&target_bytes, count)
        .await;
    let mut nodes = Vec::with_capacity(dht_nodes.len());
    let mut proofs = Vec::new();
    let mut reservation = resources.try_reserve_bytes(if with_address_records {
        2 * dht_nodes.len() * (saorsa_core::signed_address::MAX_SIGNED_ADDRESS_BYTES + 4)
    } else {
        0
    })?;
    for node in dht_nodes {
        if with_address_records {
            let Some(proof) = dht.signed_address_record_for_peer(&node.peer_id).await else {
                continue;
            };
            proofs.push(proof);
        }
        let supplemental = dht.supplemental_addresses_for_peer(&node.peer_id).await;
        nodes.push(browser_node_from_dht(
            &node,
            &supplemental,
            state.endpoint_catalog.as_deref(),
        ));
    }
    let bytes = saorsa_core::signed_address::encode_record_bundle(&proofs)?;
    drop(proofs);
    reservation.resize(bytes.len())?;
    Ok((
        Response::ok(
            request_id,
            ResponseBody::Nodes { target, nodes },
            bytes.len(),
        ),
        Some(TrackedBytes { bytes, reservation }),
    ))
}

fn browser_node_from_dht(
    node: &DHTNode,
    supplemental: &[MultiAddr],
    endpoint_catalog: Option<&BrowserEndpointCatalog>,
) -> BrowserNode {
    let addresses = node.addresses_by_priority();
    let discovered_endpoint = supplemental
        .iter()
        .find(|address| {
            address.is_webrtc_direct()
                && address.peer_id().is_some_and(|peer| peer == &node.peer_id)
        })
        .cloned()
        .map(|multiaddr| BrowserEndpoint {
            multiaddr: multiaddr.to_string(),
        });
    BrowserNode {
        address_record: None,
        peer_record: rmp_serde::to_vec_named(node).ok().map(hex::encode),
        webrtc_direct: discovered_endpoint
            .or_else(|| endpoint_catalog.and_then(|catalog| catalog.get(&node.peer_id))),
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
    resources: &ConnectionResources,
) -> ServerResult<(Response, Option<TrackedBytes>)> {
    let address_bytes = match decode_32_byte_hex(&address) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok((Response::error(request_id, "invalid_address", error), None));
        }
    };
    let Some(ant_protocol) = state.ant_protocol.as_ref() else {
        return Ok((
            Response::error(
                request_id,
                "storage_disabled",
                "chunk storage is disabled on this node".to_string(),
            ),
            None,
        ));
    };

    // The storage API allocates its returned Vec internally, so reserve the
    // largest permitted chunk before awaiting it. This closes the interval in
    // which many concurrent GETs could materialize unaccounted full chunks.
    let mut content_reservation = resources.try_reserve_bytes(MAX_CHUNK_SIZE)?;
    let response = match ant_protocol.storage().get(&address_bytes).await {
        Ok(Some(content)) if content.len() <= MAX_CHUNK_SIZE => {
            let content_length = content.len();
            content_reservation.resize(content_length)?;
            Ok((
                Response::ok(
                    request_id,
                    ResponseBody::Chunk {
                        address,
                        size: content_length,
                    },
                    content_length,
                ),
                Some(TrackedBytes {
                    bytes: content,
                    reservation: content_reservation,
                }),
            ))
        }
        Ok(Some(content)) => Ok((
            Response::error(
                request_id,
                "oversize_chunk",
                format!(
                    "stored content is {} bytes; maximum is {MAX_CHUNK_SIZE}",
                    content.len()
                ),
            ),
            None,
        )),
        Ok(None) => Ok((Response::not_found(request_id, address), None)),
        Err(error) => Ok((error_response(request_id, "storage_error", error), None)),
    };
    response
}

async fn process_quote_chunk(
    request_id: u64,
    address: String,
    size: u64,
    state: &ServerState,
) -> (Response, Option<TrackedBytes>) {
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
        Err(error) => return (error_response(request_id, "quote_failed", error), None),
    };
    match response.body {
        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
            quote,
            already_stored,
            commitment,
        }) => {
            let quote: PaymentQuote = match rmp_serde::from_slice(&quote) {
                Ok(quote) => quote,
                Err(error) => return (error_response(request_id, "invalid_quote", error), None),
            };
            let artifact = match browser_quote_from_quote(
                state.p2p.peer_id(),
                &quote,
                commitment.as_deref(),
            ) {
                Ok(artifact) => artifact,
                Err(error) => return (error_response(request_id, "invalid_quote", error), None),
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
            error_response(
                request_id,
                "invalid_quote_response",
                format_args!("{other:?}"),
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
) -> (Response, Option<TrackedBytes>) {
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
        Err(error) => return (error_response(request_id, "put_failed", error), None),
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
            error_response(
                request_id,
                "invalid_put_response",
                format_args!("{other:?}"),
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
    let (peer_id, payment_quote, commitment) =
        payment_quote_from_browser_quote(quote, expected_content)?;
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
    decode_response(response)
}

fn decode_32_byte_hex(value: &str) -> ServerResult<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|error| format!("expected hexadecimal: {error}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, received {}", bytes.len()))
}

type ServerResult<T> = std::result::Result<T, String>;

fn browser_quote_from_quote(
    peer_id: &PeerId,
    quote: &PaymentQuote,
    commitment: Option<&[u8]>,
) -> ServerResult<BrowserQuoteArtifact> {
    let timestamp_secs = quote
        .timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| format!("quote timestamp predates the Unix epoch: {error}"))?
        .as_secs();
    let commitment = commitment.map(browser_commitment_from_bytes).transpose()?;
    Ok(BrowserQuoteArtifact {
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

fn payment_quote_from_browser_quote(
    artifact: BrowserQuoteArtifact,
    expected_content: [u8; 32],
) -> ServerResult<([u8; 32], PaymentQuote, Option<Vec<u8>>)> {
    let peer_id = decode_32_byte_hex(&artifact.peer_id)?;
    let content = decode_32_byte_hex(&artifact.content)?;
    if content != expected_content {
        return Err("payment quote is for a different chunk address".to_string());
    }
    let price = Amount::from_str(&artifact.price)
        .map_err(|error| format!("payment quote has an invalid price: {error}"))?;
    let rewards_address = RewardsAddress::from_str(&artifact.rewards_address)
        .map_err(|error| format!("payment quote has an invalid rewards address: {error}"))?;
    let public_key = hex::decode(&artifact.public_key)
        .map_err(|error| format!("payment quote public key is not hexadecimal: {error}"))?;
    let signature = hex::decode(&artifact.signature)
        .map_err(|error| format!("payment quote signature is not hexadecimal: {error}"))?;
    let commitment_pin = artifact
        .commitment_pin
        .as_deref()
        .map(decode_32_byte_hex)
        .transpose()?;
    let timestamp = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(artifact.timestamp_secs))
        .ok_or_else(|| "payment quote timestamp is out of range".to_string())?;
    let quote = PaymentQuote {
        content: xor_name::XorName(content),
        timestamp,
        price,
        rewards_address,
        pub_key: public_key,
        signature,
        committed_key_count: artifact.committed_key_count,
        commitment_pin,
    };
    if hex::encode(quote.hash()) != artifact.quote_hash.to_ascii_lowercase() {
        return Err("payment quote hash does not match its signed fields".to_string());
    }
    let commitment = artifact
        .commitment
        .map(|artifact| {
            hex::decode(artifact.encoded)
                .map_err(|error| format!("commitment is not hexadecimal: {error}"))
        })
        .transpose()?;
    Ok((peer_id, quote, commitment))
}

fn browser_commitment_from_bytes(encoded: &[u8]) -> ServerResult<BrowserCommitmentArtifact> {
    let commitment: ::ant_protocol::payment::commitment::StorageCommitment =
        rmp_serde::from_slice(encoded)
            .map_err(|error| format!("node generated an invalid commitment: {error}"))?;
    Ok(BrowserCommitmentArtifact {
        encoded: hex::encode(encoded),
        root: hex::encode(commitment.root),
        key_count: commitment.key_count,
        sender_peer_id: hex::encode(commitment.sender_peer_id),
        sender_public_key: hex::encode(commitment.sender_public_key),
        signature: hex::encode(commitment.signature),
    })
}

struct ServerState {
    config: WebRtcDirectConfig,
    identity: Arc<NodeIdentity>,
    p2p: Arc<P2PNode>,
    ant_protocol: Option<Arc<AntProtocol>>,
    payment: BrowserPaymentNetwork,
    endpoint: RwLock<Option<BrowserEndpoint>>,
    endpoint_catalog: Option<Arc<BrowserEndpointCatalog>>,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn diagnostics_report_capacity_rate_and_byte_pressure_without_leaking_slots() {
        let config = WebRtcDirectConfig {
            max_connections: 2,
            max_connections_per_ip: 1,
            max_concurrent_requests: 1,
            max_requests_per_second_per_connection: 1,
            max_in_flight_bytes: 8,
            max_in_flight_bytes_per_ip: 8,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let diagnostics = WebRtcServerDiagnostics {
            local_addr: "127.0.0.1:1234".parse().unwrap(),
            transport: WebRtcDiagnostics::default(),
            resources: Arc::clone(&resources),
            config,
        };
        let first = resources
            .try_admit_connection("192.0.2.1:1000".parse().unwrap())
            .unwrap();
        assert!(resources
            .try_admit_connection("192.0.2.1:1001".parse().unwrap())
            .is_err());
        let second = resources
            .try_admit_connection("192.0.2.2:1000".parse().unwrap())
            .unwrap();
        assert!(resources
            .try_admit_connection("192.0.2.3:1000".parse().unwrap())
            .is_err());
        let permit = first.context.try_admit_request().unwrap();
        assert!(second.context.try_admit_request().is_err());
        assert_eq!(diagnostics.snapshot().active_requests, 1);
        drop(permit);
        assert!(first.context.try_admit_request().is_err());
        let mut bytes = first.context.try_reserve_bytes(6).unwrap();
        assert!(second.context.try_reserve_bytes(3).is_err());
        assert!(bytes.try_grow(3).is_err());
        let busy = diagnostics.snapshot();
        assert_eq!(busy.active_connections, 2);
        assert_eq!(busy.connection_rejections, 2);
        assert_eq!(busy.request_rejections, 1);
        assert_eq!(busy.rate_rejections, 1);
        assert_eq!(busy.byte_rejections, 2);
        assert_eq!(busy.in_flight_bytes, 6);
        assert_eq!(busy.active_requests, 0);
        drop((bytes, first, second));
        let idle = diagnostics.snapshot();
        assert_eq!(idle.in_flight_bytes, 0);
        assert_eq!(idle.active_connections, 0);
        assert_eq!(idle.byte_rejections, 2);
    }

    #[tokio::test]
    async fn aborting_listener_task_clears_running_status() {
        let resources = ListenerResources::new(&WebRtcDirectConfig::default());
        resources.running.store(true, Ordering::Release);
        let guard = ListenerRunGuard(Arc::clone(&resources));
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!resources.running.load(Ordering::Acquire));
    }

    #[test]
    fn default_resource_limits_preserve_headroom_for_other_sources() {
        let config = WebRtcDirectConfig::default();
        validate_webrtc_config(&config).expect("default resource limits");

        let source_channel_ceiling =
            config.max_connections_per_ip * config.max_channels_per_connection;
        assert!(config.max_connections_per_ip < config.max_connections);
        assert!(source_channel_ceiling < config.max_channels);
        assert!(source_channel_ceiling < config.max_concurrent_requests);
        assert!(config.max_requests_per_second_per_ip < config.max_requests_per_second);
        assert!(config.max_in_flight_bytes_per_ip < config.max_in_flight_bytes);
    }

    #[test]
    fn rejects_resource_limits_that_let_one_ip_exhaust_a_global_pool() {
        let mut config = WebRtcDirectConfig::default();
        config.max_connections_per_ip = config.max_connections;
        assert!(validate_webrtc_config(&config).is_err());

        let mut config = WebRtcDirectConfig::default();
        config.max_channels = config.max_connections_per_ip * config.max_channels_per_connection;
        assert!(validate_webrtc_config(&config).is_err());

        let mut config = WebRtcDirectConfig::default();
        config.max_in_flight_bytes_per_ip = config.max_in_flight_bytes;
        assert!(validate_webrtc_config(&config).is_err());
    }

    #[tokio::test]
    async fn first_data_channel_timeout_releases_connection_admission() {
        let config = WebRtcDirectConfig::default();
        let resources = ListenerResources::new(&config);
        let remote_addr: SocketAddr = "198.51.100.1:1000".parse().expect("remote address");
        let shutdown = CancellationToken::new();

        let result = {
            let _admission = resources
                .try_admit_connection(remote_addr)
                .expect("connection admission");
            assert_eq!(
                resources.connection_limit.available_permits(),
                config.max_connections - 1
            );
            wait_for_first_data_channel(
                &shutdown,
                Duration::from_millis(10),
                std::future::pending::<ServerResult<()>>(),
            )
            .await
        };

        assert_eq!(
            result.err().as_deref(),
            Some(FIRST_DATA_CHANNEL_TIMEOUT_ERROR)
        );
        assert_eq!(
            resources.connection_limit.available_permits(),
            config.max_connections
        );
        assert_eq!(
            resources
                .source_state
                .lock()
                .sources
                .get(&remote_addr.ip())
                .expect("tracked source")
                .active_connections,
            0
        );
    }

    #[test]
    fn per_ip_connection_limit_cannot_starve_another_source() {
        let config = WebRtcDirectConfig::default();
        let resources = ListenerResources::new(&config);
        let attacker: SocketAddr = "198.51.100.1:1000".parse().expect("attacker address");
        let honest: SocketAddr = "203.0.113.2:2000".parse().expect("honest address");
        let mut attacker_admissions = Vec::new();

        for port in 0..config.max_connections_per_ip {
            let mut address = attacker;
            address.set_port(u16::try_from(port + 1).expect("test port"));
            attacker_admissions.push(
                resources
                    .try_admit_connection(address)
                    .expect("source share remains"),
            );
        }
        assert_eq!(attacker_admissions.len(), config.max_connections_per_ip);
        assert_eq!(
            resources.try_admit_connection(attacker).err().as_deref(),
            Some(SOURCE_CONNECTION_CAPACITY_ERROR)
        );
        let honest_admission = resources
            .try_admit_connection(honest)
            .expect("another source retains listener headroom");

        drop(attacker_admissions.pop());
        resources
            .try_admit_connection(attacker)
            .expect("released source slot is reusable");
        drop(honest_admission);
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_bypass_source_accounting() {
        let config = WebRtcDirectConfig::default();
        let resources = ListenerResources::new(&config);
        let v4: SocketAddr = "192.0.2.44:1000".parse().expect("IPv4 address");
        let mapped: SocketAddr = "[::ffff:192.0.2.44]:2000".parse().expect("mapped address");
        let mut admissions = vec![resources
            .try_admit_connection(v4)
            .expect("first connection")];
        for _ in 1..config.max_connections_per_ip {
            admissions.push(
                resources
                    .try_admit_connection(mapped)
                    .expect("mapped source share"),
            );
        }
        assert_eq!(admissions.len(), config.max_connections_per_ip);
        assert_eq!(
            resources.try_admit_connection(mapped).err().as_deref(),
            Some(SOURCE_CONNECTION_CAPACITY_ERROR)
        );
    }

    #[test]
    fn ipv6_hosts_share_connection_rate_and_byte_budgets_by_prefix() {
        let config = WebRtcDirectConfig::default();
        let resources = ListenerResources::new(&config);
        let mut admissions = Vec::new();
        for host in 1..=config.max_connections_per_ip {
            let addr = format!("[2001:db8:1234:5678::{host:x}]:1000")
                .parse()
                .expect("IPv6 host");
            admissions.push(resources.try_admit_connection(addr).expect("prefix share"));
        }
        assert!(Arc::ptr_eq(
            &admissions[0].context.source,
            &admissions[1].context.source
        ));
        let same_prefix = "[2001:db8:1234:5678::ffff]:2000"
            .parse()
            .expect("same prefix");
        assert_eq!(
            resources.try_admit_connection(same_prefix).err().as_deref(),
            Some(SOURCE_CONNECTION_CAPACITY_ERROR)
        );
        let other_prefix = "[2001:db8:1234:5679::1]:2000"
            .parse()
            .expect("other prefix");
        resources
            .try_admit_connection(other_prefix)
            .expect("independent prefix");
        drop(admissions.pop());
        resources
            .try_admit_connection(same_prefix)
            .expect("released prefix slot");
    }

    #[test]
    fn request_token_bucket_refills_without_growing_state() {
        let mut bucket = RequestRateBucket::new(2);
        let start = bucket.last_refill;
        assert!(bucket.allow(start));
        assert!(bucket.allow(start));
        assert!(!bucket.allow(start));
        assert!(bucket.allow(start + Duration::from_millis(500)));
        assert!(!bucket.allow(start + Duration::from_millis(500)));
        assert!(bucket.allow(start + Duration::from_secs(1)));
    }

    #[test]
    fn per_ip_request_rate_leaves_other_sources_admissible() {
        let config = WebRtcDirectConfig {
            max_requests_per_second: 4,
            max_requests_per_second_per_ip: 2,
            max_requests_per_second_per_connection: 2,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let attacker = resources
            .try_admit_connection("198.51.100.1:1000".parse().expect("attacker"))
            .expect("attacker connection");
        let honest = resources
            .try_admit_connection("203.0.113.2:2000".parse().expect("honest"))
            .expect("honest connection");

        assert!(attacker.context.try_admit_request().is_ok());
        assert!(attacker.context.try_admit_request().is_ok());
        assert_eq!(
            attacker.context.try_admit_request().err().as_deref(),
            Some(REQUEST_RATE_ERROR)
        );
        assert!(honest.context.try_admit_request().is_ok());
    }

    #[test]
    fn reconnecting_does_not_reset_the_source_request_bucket() {
        let config = WebRtcDirectConfig {
            max_requests_per_second: 100,
            max_requests_per_second_per_ip: 1,
            max_requests_per_second_per_connection: 1,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let address = "198.51.100.1:1000".parse().expect("source");
        let first = resources
            .try_admit_connection(address)
            .expect("first connection");
        assert!(first.context.try_admit_request().is_ok());
        drop(first);

        let replacement = resources
            .try_admit_connection(address)
            .expect("replacement connection");
        assert_eq!(
            replacement.context.try_admit_request().err().as_deref(),
            Some(REQUEST_RATE_ERROR)
        );
    }

    #[test]
    fn inactive_source_rate_state_has_a_hard_bound() {
        let config = WebRtcDirectConfig::default();
        let resources = ListenerResources::new(&config);
        for index in 0..resources.max_tracked_sources + 10 {
            let third = u8::try_from(index / 254).expect("third octet");
            let host = u8::try_from(index % 254 + 1).expect("host octet");
            let address = SocketAddr::from((Ipv4Addr::new(198, 51, third, host), 1000));
            drop(
                resources
                    .try_admit_connection(address)
                    .expect("sequential source"),
            );
        }
        assert_eq!(
            resources.source_state.lock().sources.len(),
            resources.max_tracked_sources
        );
    }

    #[test]
    fn byte_reservations_are_per_source_global_and_raii_released() {
        let config = WebRtcDirectConfig {
            max_in_flight_bytes: 256,
            max_in_flight_bytes_per_ip: 128,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let attacker = resources
            .try_admit_connection("198.51.100.1:1000".parse().expect("attacker"))
            .expect("attacker connection");
        let honest = resources
            .try_admit_connection("203.0.113.2:2000".parse().expect("honest"))
            .expect("honest connection");

        let attacker_bytes = attacker
            .context
            .try_reserve_bytes(128)
            .expect("attacker source budget");
        assert_eq!(resources.global_bytes.in_use(), 128);
        assert_eq!(
            attacker.context.try_reserve_bytes(1).err().as_deref(),
            Some(SOURCE_BYTE_CAPACITY_ERROR)
        );
        let honest_bytes = honest
            .context
            .try_reserve_bytes(64)
            .expect("another source retains byte headroom");
        assert_eq!(resources.global_bytes.in_use(), 192);

        drop(attacker_bytes);
        drop(honest_bytes);
        assert_eq!(resources.global_bytes.in_use(), 0);
        assert_eq!(attacker.context.source.bytes.in_use(), 0);
        assert_eq!(honest.context.source.bytes.in_use(), 0);
    }

    #[test]
    fn global_byte_rejection_rolls_back_the_source_reservation() {
        let config = WebRtcDirectConfig {
            max_in_flight_bytes: 100,
            max_in_flight_bytes_per_ip: 90,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let first = resources
            .try_admit_connection("198.51.100.1:1000".parse().expect("first"))
            .expect("first connection");
        let second = resources
            .try_admit_connection("203.0.113.2:2000".parse().expect("second"))
            .expect("second connection");
        let _first_bytes = first
            .context
            .try_reserve_bytes(60)
            .expect("first reservation");

        assert_eq!(
            second.context.try_reserve_bytes(50).err().as_deref(),
            Some(GLOBAL_BYTE_CAPACITY_ERROR)
        );
        assert_eq!(second.context.source.bytes.in_use(), 0);
        assert_eq!(resources.global_bytes.in_use(), 60);
    }

    #[test]
    fn wildcard_publication_waits_for_native_discovery_and_excludes_relays() {
        let config = WebRtcDirectConfig::default();
        let local = "0.0.0.0:43210".parse().expect("bound listener");
        assert_eq!(advertised_addr(&config, local, &[]), None);
        let addresses = vec![
            (
                MultiAddr::quic("203.0.113.1:1000".parse().expect("relay")),
                AddressType::Relay,
            ),
            (
                MultiAddr::quic("[2001:db8::1]:1000".parse().expect("IPv6")),
                AddressType::Direct,
            ),
        ];
        assert_eq!(advertised_addr(&config, local, &addresses), None);
        let mut addresses = addresses;
        addresses.push((
            MultiAddr::quic("198.51.100.2:1000".parse().expect("observed")),
            AddressType::Unverified,
        ));
        assert_eq!(
            advertised_addr(&config, local, &addresses),
            Some("198.51.100.2:43210".parse().expect("WebRTC"))
        );
        addresses[2].0 = MultiAddr::quic("198.51.100.3:2000".parse().expect("new observed"));
        assert_eq!(
            advertised_addr(&config, local, &addresses),
            Some("198.51.100.3:43210".parse().expect("updated WebRTC"))
        );
    }

    #[tokio::test]
    async fn automatic_port_is_os_assigned_and_explicit_advertisement_is_independent() {
        let certificate = WebRtcCertificate::generate().expect("certificate");
        let listener =
            WebRtcDirectListener::bind("127.0.0.1:0".parse().expect("bind"), certificate)
                .await
                .expect("ephemeral listener");
        let local = listener.local_addr();
        assert_ne!(local.port(), 0);
        assert_eq!(
            advertised_addr(&WebRtcDirectConfig::default(), local, &[]),
            Some(local)
        );
        let config = WebRtcDirectConfig {
            advertised_addr: Some("198.51.100.4:11000".parse().expect("advertised")),
            ..WebRtcDirectConfig::default()
        };
        assert_eq!(advertised_addr(&config, local, &[]), config.advertised_addr);
        listener.close().await.expect("close listener");
    }

    #[test]
    fn parses_versioned_requests() {
        let request: Request = serde_json::from_str(
            r#"{"version":5,"request_id":7,"content_length":0,"type":"find_node","target":"0000000000000000000000000000000000000000000000000000000000000000","count":20}"#,
        )
        .expect("valid request");

        assert_eq!(request.version, BROWSER_PROTOCOL_VERSION);
        assert_eq!(request.request_id, 7);
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
    fn largest_paid_upload_header_fits_fixed_protocol_limit() {
        // 0xff maximizes MessagePack's integer-array encoding. Exercise the
        // actual native commitment serializer, including the JSON duplication
        // of the commitment's public key and signature.
        let commitment = ::ant_protocol::payment::commitment::StorageCommitment {
            root: [0xff; 32],
            key_count: u32::MAX,
            sender_peer_id: [0xff; 32],
            sender_public_key: vec![0xff; 1952],
            signature: vec![0xff; 3309],
        };
        let encoded = rmp_serde::to_vec(&commitment).expect("serialize commitment");
        let quote = BrowserQuoteArtifact {
            peer_id: "ff".repeat(32),
            content: "ff".repeat(32),
            timestamp_secs: u64::MAX,
            price: "9".repeat(78), // decimal U256 width
            rewards_address: format!("0x{}", "ff".repeat(20)),
            public_key: "ff".repeat(1952),
            signature: "ff".repeat(3309),
            committed_key_count: u32::MAX,
            commitment_pin: Some("ff".repeat(32)),
            quote_hash: "ff".repeat(32),
            commitment: Some(browser_commitment_from_bytes(&encoded).expect("commitment artifact")),
        };
        let request = Request::new(
            u64::MAX,
            RequestBody::PutChunk {
                address: "ff".repeat(32),
                quote: Box::new(quote),
                transaction_hash: format!("0x{}", "ff".repeat(32)),
            },
            MAX_CHUNK_SIZE,
        );
        let header = serde_json::to_vec(&request).expect("serialize paid request");
        assert!(
            header.len() < MAX_BROWSER_HEADER_BYTES,
            "{} bytes",
            header.len()
        );
        let content = vec![0xff; MAX_CHUNK_SIZE];
        let frame = saorsa_transport::webrtc::encode_request_frame(&request, &content)
            .expect("largest paid upload fits");
        assert_eq!(
            parse_request_header(&frame).expect("parse upload").0,
            request
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
        assert_eq!(value["version"], BROWSER_PROTOCOL_VERSION);
        assert_eq!(value["request_id"], 42);
        assert_eq!(value["status"], "ok");
        assert_eq!(value["content_length"], 3);
        assert_eq!(value["type"], "chunk");
    }

    #[test]
    fn derives_ipv6_advertised_address() {
        let config = WebRtcDirectConfig::default();
        let addr = advertised_addr(&config, "[::1]:23456".parse().expect("socket"), &[])
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
            peer_id.to_bytes(),
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
            peer_id.to_bytes(),
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
            address_authority: None,
        };

        let supplemental = endpoint
            .multiaddr
            .parse()
            .expect("WebRTC Direct multiaddress");
        let browser_node = browser_node_from_dht(&node, std::slice::from_ref(&supplemental), None);

        assert_eq!(browser_node.webrtc_direct, Some(endpoint));
        assert_eq!(
            browser_node.native_addresses,
            vec!["/ip4/203.0.113.9/udp/10000/quic"]
        );
    }

    #[test]
    fn production_find_node_does_not_use_dev_endpoint_catalog() {
        let peer_id = PeerId::from_bytes([0x32; 32]);
        let endpoint = BrowserEndpoint::new(
            "203.0.113.10:42768".parse().expect("socket address"),
            peer_id.to_bytes(),
            [0x53; 32],
        )
        .expect("browser endpoint");
        let node = DHTNode {
            peer_id,
            addresses: Vec::new(),
            address_types: Vec::new(),
            distance: None,
            reliability: 0.75,
            address_authority: None,
        };
        let catalog = BrowserEndpointCatalog::default();
        catalog.insert(peer_id, endpoint.clone());

        let browser_node = browser_node_from_dht(&node, &[], None);

        assert!(browser_node.webrtc_direct.is_none());

        let devnet_node = browser_node_from_dht(&node, &[], Some(&catalog));
        assert_eq!(devnet_node.webrtc_direct, Some(endpoint));
    }
}
