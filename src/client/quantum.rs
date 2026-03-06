//! Quantum-resistant client operations for chunk storage.
//!
//! This module provides content-addressed chunk storage operations on the saorsa network
//! using post-quantum cryptography (ML-KEM-768 for key exchange, ML-DSA-65 for signatures).
//!
//! ## Data Model
//!
//! Chunks are the only data type supported:
//! - **Content-addressed**: Address = SHA256(content)
//! - **Immutable**: Once stored, content cannot change
//! - **Paid**: Storage requires EVM payment on Arbitrum when a wallet is configured;
//!   devnets with EVM disabled accept unpaid puts
//!
//! ## Security Features
//!
//! - **ML-KEM-768**: NIST FIPS 203 compliant key encapsulation for encryption
//! - **ML-DSA-65**: NIST FIPS 204 compliant signatures for authentication
//! - **ChaCha20-Poly1305**: Symmetric encryption for data at rest

use super::chunk_protocol::send_and_await_chunk_response;
use super::data_types::{compute_address, DataChunk, XorName};
use crate::ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteResponse,
};
use crate::error::{Error, Result};
use crate::payment::single_node::REQUIRED_QUOTES;
use crate::payment::{calculate_price, PaymentProof, SingleNodePayment};
use ant_evm::{Amount, EncodedPeerId, PaymentQuote, ProofOfPayment};
use bytes::Bytes;
use evmlib::wallet::Wallet;
use futures::stream::{FuturesUnordered, StreamExt};
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Default timeout for network operations in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Number of closest peers to consider for chunk routing.
const CLOSE_GROUP_SIZE: usize = 8;

/// Default number of replicas for data redundancy.
const DEFAULT_REPLICA_COUNT: u8 = 4;

/// Configuration for the quantum-resistant client.
#[derive(Debug, Clone)]
pub struct QuantumConfig {
    /// Timeout for network operations in seconds.
    pub timeout_secs: u64,
    /// Number of replicas for data redundancy.
    pub replica_count: u8,
    /// Enable encryption for all stored data.
    pub encrypt_data: bool,
}

impl Default for QuantumConfig {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            replica_count: DEFAULT_REPLICA_COUNT,
            encrypt_data: true,
        }
    }
}

/// Client for quantum-resistant chunk operations on the saorsa network.
///
/// This client uses post-quantum cryptography for all operations:
/// - ML-KEM-768 for key encapsulation
/// - ML-DSA-65 for digital signatures
/// - ChaCha20-Poly1305 for symmetric encryption
///
/// ## Chunk Storage Model
///
/// Chunks are content-addressed: the address is the SHA256 hash of the content.
/// This ensures data integrity - if the content matches the address, the data
/// is authentic. When a wallet is configured, chunk storage requires EVM payment
/// on Arbitrum. Without a wallet, chunks can be stored on devnets with EVM disabled.
pub struct QuantumClient {
    config: QuantumConfig,
    p2p_node: Option<Arc<P2PNode>>,
    wallet: Option<Arc<Wallet>>,
    next_request_id: AtomicU64,
}

impl QuantumClient {
    /// Create a new quantum client with the given configuration.
    #[must_use]
    pub fn new(config: QuantumConfig) -> Self {
        debug!("Creating quantum-resistant saorsa client");
        Self {
            config,
            p2p_node: None,
            wallet: None,
            next_request_id: AtomicU64::new(1),
        }
    }

    /// Create a quantum client with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(QuantumConfig::default())
    }

    /// Set the P2P node for network operations.
    #[must_use]
    pub fn with_node(mut self, node: Arc<P2PNode>) -> Self {
        self.p2p_node = Some(node);
        self
    }

    /// Set the wallet for payment operations.
    #[must_use]
    pub fn with_wallet(mut self, wallet: Wallet) -> Self {
        self.wallet = Some(Arc::new(wallet));
        self
    }

    /// Get a chunk from the saorsa network via ANT protocol.
    ///
    /// Sends a `ChunkGetRequest` to a connected peer and waits for the
    /// `ChunkGetResponse`.
    ///
    /// # Arguments
    ///
    /// * `address` - The `XorName` address of the chunk (SHA256 of content)
    ///
    /// # Returns
    ///
    /// The chunk data if found, or None if not present in the network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network operation fails.
    pub async fn get_chunk(&self, address: &XorName) -> Result<Option<DataChunk>> {
        if tracing::enabled!(tracing::Level::DEBUG) {
            let addr_hex = hex::encode(address);
            debug!("Querying saorsa network for chunk: {addr_hex}");
        }

        let Some(ref node) = self.p2p_node else {
            return Err(Error::Network("P2P node not configured".into()));
        };

        let target_peer = Self::pick_target_peer(node, address).await?;

        // Create and send GET request
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = ChunkGetRequest::new(*address);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::GetRequest(request),
        };
        let message_bytes = message
            .encode()
            .map_err(|e| Error::Network(format!("Failed to encode GET request: {e}")))?;

        let timeout = Duration::from_secs(self.config.timeout_secs);
        let addr_hex = hex::encode(address);
        let timeout_secs = self.config.timeout_secs;

        send_and_await_chunk_response(
            node,
            &target_peer,
            message_bytes,
            request_id,
            timeout,
            |body| match body {
                ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                    address: addr,
                    content,
                }) => {
                    if addr != *address {
                        if tracing::enabled!(tracing::Level::WARN) {
                            warn!(
                                "Peer returned chunk {} but we requested {}",
                                hex::encode(addr),
                                addr_hex
                            );
                        }
                        return Some(Err(Error::InvalidChunk(format!(
                            "Mismatched chunk address: expected {addr_hex}, got {}",
                            hex::encode(addr)
                        ))));
                    }

                    let computed = compute_address(&content);
                    if computed != addr {
                        if tracing::enabled!(tracing::Level::WARN) {
                            warn!(
                                "Peer returned chunk {} with invalid content hash {}",
                                addr_hex,
                                hex::encode(computed)
                            );
                        }
                        return Some(Err(Error::InvalidChunk(format!(
                            "Invalid chunk content: expected hash {addr_hex}, got {}",
                            hex::encode(computed)
                        ))));
                    }

                    if tracing::enabled!(tracing::Level::DEBUG) {
                        debug!(
                            "Found chunk {} on saorsa network ({} bytes)",
                            hex::encode(addr),
                            content.len()
                        );
                    }
                    Some(Ok(Some(DataChunk::new(addr, Bytes::from(content)))))
                }
                ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { .. }) => {
                    debug!("Chunk {} not found on saorsa network", addr_hex);
                    Some(Ok(None))
                }
                ChunkMessageBody::GetResponse(ChunkGetResponse::Error(e)) => Some(Err(
                    Error::Network(format!("Remote GET error for {addr_hex}: {e}")),
                )),
                _ => None,
            },
            |e| Error::Network(format!("Failed to send GET to peer {target_peer}: {e}")),
            || {
                Error::Network(format!(
                    "Timeout waiting for chunk {addr_hex} after {timeout_secs}s"
                ))
            },
        )
        .await
    }

    /// Store a chunk on the saorsa network with full payment workflow.
    ///
    /// This method implements the complete payment flow:
    /// 1. Request quotes from 5 closest nodes via DHT
    /// 2. Sort quotes by price and select median (index 2)
    /// 3. Pay median node 3x on Arbitrum, send 0 atto to other 4
    /// 4. Create `ProofOfPayment` with all 5 quotes
    /// 5. Send chunk with payment proof to storage nodes
    ///
    /// # Arguments
    ///
    /// * `content` - The data to store
    ///
    /// # Returns
    ///
    /// The `XorName` address where the chunk was stored.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Wallet is not configured
    /// - Quote collection fails
    /// - Payment fails
    /// - Storage operation fails
    pub async fn put_chunk_with_payment(
        &self,
        content: Bytes,
    ) -> Result<(XorName, Vec<evmlib::common::TxHash>)> {
        let content_len = content.len();
        info!("Storing chunk with payment ({content_len} bytes)");

        let Some(ref node) = self.p2p_node else {
            return Err(Error::Network("P2P node not configured".into()));
        };

        let Some(ref wallet) = self.wallet else {
            return Err(Error::Payment(
                "Wallet not configured - use with_wallet() to enable payments".to_string(),
            ));
        };

        // Compute content address
        let address = compute_address(&content);
        let content_size = content.len();
        let data_size = u64::try_from(content_size)
            .map_err(|e| Error::Network(format!("Content size too large: {e}")))?;

        // Step 1: Request quotes from network nodes via DHT
        let quotes_with_peers = self
            .get_quotes_from_dht_for_address(&address, data_size)
            .await?;

        if quotes_with_peers.len() != REQUIRED_QUOTES {
            return Err(Error::Payment(format!(
                "Expected {REQUIRED_QUOTES} quotes but received {}",
                quotes_with_peers.len()
            )));
        }

        // Step 2: Split quotes into peer_quotes (for ProofOfPayment) and
        // quotes_with_prices (for SingleNodePayment) in a single pass.
        let mut peer_quotes: Vec<(EncodedPeerId, PaymentQuote)> =
            Vec::with_capacity(quotes_with_peers.len());
        let mut quotes_with_prices: Vec<(PaymentQuote, Amount)> =
            Vec::with_capacity(quotes_with_peers.len());

        for (peer_id, quote, price) in quotes_with_peers {
            let encoded_peer_id = hex_node_id_to_encoded_peer_id(&peer_id.to_hex())?;
            peer_quotes.push((encoded_peer_id, quote.clone()));
            quotes_with_prices.push((quote, price));
        }

        // Step 3: Create SingleNodePayment (sorts by price, selects median, pays 3x)
        let payment = SingleNodePayment::from_quotes(quotes_with_prices)?;

        info!(
            "Payment prepared: {} atto total (3x median price)",
            payment.total_amount()
        );

        // Step 4: Pay on-chain — capture transaction hashes
        let tx_hashes = payment.pay(wallet).await?;
        info!(
            "Payment successful on Arbitrum ({} transactions)",
            tx_hashes.len()
        );

        // Step 5: Build proof AFTER payment succeeds, including tx hashes
        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: tx_hashes.clone(),
        };
        let payment_proof = rmp_serde::to_vec(&proof)
            .map_err(|e| Error::Network(format!("Failed to serialize payment proof: {e}")))?;

        // Step 6: Send chunk with payment proof to storage node
        let target_peer = Self::pick_target_peer(node, &address).await?;

        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = ChunkPutRequest::with_payment(address, content.to_vec(), payment_proof);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PutRequest(request),
        };
        let message_bytes = message
            .encode()
            .map_err(|e| Error::Network(format!("Failed to encode PUT request: {e}")))?;

        let stored_address = Self::send_put_and_await(
            node,
            &target_peer,
            message_bytes,
            request_id,
            self.config.timeout_secs,
            hex::encode(address),
            content_size,
        )
        .await?;

        Ok((stored_address, tx_hashes))
    }

    /// Store a chunk with a pre-built payment proof, skipping the internal payment flow.
    ///
    /// Use this when you have already obtained quotes and paid on-chain externally
    /// (e.g. via [`SingleNodePayment::pay`]) and want to avoid a redundant payment cycle.
    ///
    /// # Arguments
    ///
    /// * `content` - The data to store
    /// * `proof` - A serialised [`ProofOfPayment`] (msgpack bytes)
    ///
    /// # Returns
    ///
    /// The `XorName` address where the chunk was stored.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - P2P node is not configured
    /// - No remote peers found near the target address
    /// - Storage operation fails
    pub async fn put_chunk_with_proof(&self, content: Bytes, proof: Vec<u8>) -> Result<XorName> {
        let Some(ref node) = self.p2p_node else {
            return Err(Error::Network("P2P node not configured".into()));
        };

        let address = compute_address(&content);
        let content_size = content.len();

        let target_peer = Self::pick_target_peer(node, &address).await?;

        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = ChunkPutRequest::with_payment(address, content.to_vec(), proof);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PutRequest(request),
        };
        let message_bytes = message
            .encode()
            .map_err(|e| Error::Network(format!("Failed to encode PUT request: {e}")))?;

        Self::send_put_and_await(
            node,
            &target_peer,
            message_bytes,
            request_id,
            self.config.timeout_secs,
            hex::encode(address),
            content_size,
        )
        .await
    }

    /// Store a chunk on the saorsa network.
    ///
    /// Requires a wallet to be configured. Delegates to
    /// [`put_chunk_with_payment`](Self::put_chunk_with_payment) for the full
    /// payment flow (quotes, on-chain payment, proof).
    ///
    /// # Arguments
    ///
    /// * `content` - The data to store
    ///
    /// # Returns
    ///
    /// The `XorName` address where the chunk was stored.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No wallet is configured
    /// - P2P node is not configured
    /// - No remote peers found near the target address
    /// - The storage operation fails
    pub async fn put_chunk(&self, content: Bytes) -> Result<XorName> {
        if self.wallet.is_some() {
            let (address, _tx_hashes) = self.put_chunk_with_payment(content).await?;
            return Ok(address);
        }

        Err(Error::Payment(
            "No wallet configured — payment is required for chunk storage. \
             Use --private-key or set SECRET_KEY to provide a wallet."
                .to_string(),
        ))
    }

    /// Send a PUT request and await the response.
    ///
    /// Shared helper for all three PUT methods to avoid duplicating the
    /// response-matching logic.
    async fn send_put_and_await(
        node: &P2PNode,
        target_peer: &PeerId,
        message_bytes: Vec<u8>,
        request_id: u64,
        timeout_secs: u64,
        addr_hex: String,
        content_size: usize,
    ) -> Result<XorName> {
        let timeout = Duration::from_secs(timeout_secs);
        send_and_await_chunk_response(
            node,
            target_peer,
            message_bytes,
            request_id,
            timeout,
            |body| match body {
                ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: addr }) => {
                    info!(
                        "Chunk stored at address: {} ({content_size} bytes)",
                        hex::encode(addr),
                    );
                    Some(Ok(addr))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists {
                    address: addr,
                }) => {
                    info!("Chunk already exists at address: {}", hex::encode(addr));
                    Some(Ok(addr))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => {
                    Some(Err(Error::Network(format!("Payment required: {message}"))))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::Error(e)) => Some(Err(
                    Error::Network(format!("Remote PUT error for {addr_hex}: {e}")),
                )),
                _ => None,
            },
            |e| Error::Network(format!("Failed to send PUT to peer {target_peer}: {e}")),
            || {
                Error::Network(format!(
                    "Timeout waiting for store response for {addr_hex} after {timeout_secs}s"
                ))
            },
        )
        .await
    }

    /// Check if a chunk exists on the saorsa network.
    ///
    /// Implemented via `get_chunk` — returns `Ok(true)` on success,
    /// `Ok(false)` if not found.
    ///
    /// # Arguments
    ///
    /// * `address` - The `XorName` to check
    ///
    /// # Returns
    ///
    /// True if the chunk exists, false otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the network operation fails.
    pub async fn exists(&self, address: &XorName) -> Result<bool> {
        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Checking existence on saorsa network: {}",
                hex::encode(address)
            );
        }
        self.get_chunk(address).await.map(|opt| opt.is_some())
    }

    /// Pick the closest peer to `target` using an iterative Kademlia network lookup.
    ///
    /// Queries the DHT for the `CLOSE_GROUP_SIZE` closest nodes to the target
    /// address and returns the single closest remote peer (excluding ourselves).
    async fn pick_target_peer(node: &P2PNode, target: &XorName) -> Result<PeerId> {
        let local_peer_id = node.peer_id();

        let closest_nodes = node
            .dht()
            .find_closest_nodes(target, CLOSE_GROUP_SIZE)
            .await
            .map_err(|e| Error::Network(format!("Kademlia closest-nodes lookup failed: {e}")))?;

        let closest = closest_nodes
            .into_iter()
            .find(|n| n.peer_id != *local_peer_id)
            .ok_or_else(|| Error::Network("No remote peers found near target address".into()))?;

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Selected closest peer {} for target {}",
                closest.peer_id,
                hex::encode(target)
            );
        }

        Ok(closest.peer_id)
    }

    /// Get quotes from DHT peers for chunk storage.
    ///
    /// Computes the content address and requests quotes from the closest peers.
    /// Collects exactly `REQUIRED_QUOTES` quotes.
    ///
    /// # Arguments
    ///
    /// * `content` - The chunk data to get quotes for
    ///
    /// # Returns
    ///
    /// A vector of (`peer_id`, `PaymentQuote`, `Amount`) tuples containing the quoting peer's ID,
    /// the quote, and its price.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - DHT lookup fails
    /// - Failed to collect enough quotes
    /// - Quote deserialization fails
    pub async fn get_quotes_from_dht(
        &self,
        content: &[u8],
    ) -> Result<Vec<(PeerId, PaymentQuote, Amount)>> {
        let address = compute_address(content);
        let data_size = u64::try_from(content.len())
            .map_err(|e| Error::Network(format!("Content size too large: {e}")))?;
        self.get_quotes_from_dht_for_address(&address, data_size)
            .await
    }

    /// Get quotes from DHT peers for chunk storage using a pre-computed address.
    ///
    /// Queries the DHT for the closest peers to the chunk address and requests
    /// storage quotes from them. Collects exactly `REQUIRED_QUOTES` quotes.
    ///
    /// # Arguments
    ///
    /// * `address` - The pre-computed `XorName` address for the chunk
    /// * `data_size` - The size of the chunk data in bytes
    ///
    /// # Returns
    ///
    /// A vector of (`peer_id`, `PaymentQuote`, `Amount`) tuples containing the quoting peer's ID,
    /// the quote, and its price.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - DHT lookup fails
    /// - Failed to collect enough quotes
    /// - Quote deserialization fails
    #[allow(clippy::too_many_lines)]
    async fn get_quotes_from_dht_for_address(
        &self,
        address: &XorName,
        data_size: u64,
    ) -> Result<Vec<(PeerId, PaymentQuote, Amount)>> {
        let Some(ref node) = self.p2p_node else {
            return Err(Error::Network("P2P node not configured".into()));
        };

        if tracing::enabled!(tracing::Level::DEBUG) {
            let addr_hex = hex::encode(address);
            debug!(
                "Requesting {REQUIRED_QUOTES} quotes from DHT for chunk {addr_hex} (size: {data_size})"
            );
        }

        let local_peer_id = node.peer_id();

        // Find closest peers via DHT
        let closest_nodes = node
            .dht()
            .find_closest_nodes(address, CLOSE_GROUP_SIZE)
            .await
            .map_err(|e| Error::Network(format!("DHT closest-nodes lookup failed: {e}")))?;

        // Filter out self and collect remote peers
        let mut remote_peers: Vec<PeerId> = closest_nodes
            .into_iter()
            .filter(|n| n.peer_id != *local_peer_id)
            .map(|n| n.peer_id)
            .collect();

        // Fallback to connected_peers() if DHT has insufficient peers
        // This handles the case where DHT routing tables are still warming up
        if remote_peers.len() < REQUIRED_QUOTES {
            warn!(
                "DHT returned only {} peers for {}, falling back to connected_peers()",
                remote_peers.len(),
                hex::encode(address)
            );

            let connected = node.connected_peers().await;
            debug!("Found {} connected P2P peers for fallback", connected.len());

            // Add connected peers that aren't already in remote_peers (O(1) dedup via HashSet)
            let mut existing: HashSet<PeerId> = remote_peers.iter().copied().collect();
            for peer_id in connected {
                if existing.insert(peer_id) {
                    remote_peers.push(peer_id);
                }
            }

            if remote_peers.len() < REQUIRED_QUOTES {
                return Err(Error::Network(format!(
                    "Insufficient peers for quotes: found {} (DHT + P2P fallback), need {}",
                    remote_peers.len(),
                    REQUIRED_QUOTES
                )));
            }

            info!(
                "Fallback successful: now have {} peers for quote requests",
                remote_peers.len()
            );
        }

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Found {} remote peers, requesting quotes from first {}",
                remote_peers.len(),
                REQUIRED_QUOTES
            );
        }

        // Request quotes from all peers concurrently
        // Collect the first REQUIRED_QUOTES successful responses
        let timeout = Duration::from_secs(self.config.timeout_secs);

        // Create futures for all quote requests concurrently
        let mut quote_futures = FuturesUnordered::new();

        for peer_id in &remote_peers {
            let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            let request = ChunkQuoteRequest::new(*address, data_size);
            let message = ChunkMessage {
                request_id,
                body: ChunkMessageBody::QuoteRequest(request),
            };

            let message_bytes = match message.encode() {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!("Failed to encode quote request for {peer_id}: {e}");
                    continue;
                }
            };

            // Clone necessary data for the async task
            let peer_id_clone = *peer_id;
            let node_clone = node.clone();

            // Create a future for this quote request
            let quote_future = async move {
                let quote_result = send_and_await_chunk_response(
                    &node_clone,
                    &peer_id_clone,
                    message_bytes,
                    request_id,
                    timeout,
                    |body| match body {
                        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success { quote }) => {
                            // Deserialize the quote
                            match rmp_serde::from_slice::<PaymentQuote>(&quote) {
                                Ok(payment_quote) => {
                                    let price = calculate_price(&payment_quote.quoting_metrics);
                                    if tracing::enabled!(tracing::Level::DEBUG) {
                                        debug!(
                                            "Received quote from {peer_id_clone}: price = {price}"
                                        );
                                    }
                                    Some(Ok((payment_quote, price)))
                                }
                                Err(e) => Some(Err(Error::Network(format!(
                                    "Failed to deserialize quote from {peer_id_clone}: {e}"
                                )))),
                            }
                        }
                        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(e)) => Some(Err(
                            Error::Network(format!("Quote error from {peer_id_clone}: {e}")),
                        )),
                        _ => None,
                    },
                    |e| {
                        Error::Network(format!(
                            "Failed to send quote request to {peer_id_clone}: {e}"
                        ))
                    },
                    || Error::Network(format!("Timeout waiting for quote from {peer_id_clone}")),
                )
                .await;

                (peer_id_clone, quote_result)
            };

            quote_futures.push(quote_future);
        }

        // Collect quotes as they complete, stopping once we have REQUIRED_QUOTES
        let mut quotes_with_peers = Vec::with_capacity(REQUIRED_QUOTES);

        while let Some((peer_id, quote_result)) = quote_futures.next().await {
            match quote_result {
                Ok((quote, price)) => {
                    quotes_with_peers.push((peer_id, quote, price));

                    // Stop collecting once we have enough quotes
                    if quotes_with_peers.len() >= REQUIRED_QUOTES {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to get quote from {peer_id}: {e}");
                    // Continue trying other peers
                }
            }
        }

        if quotes_with_peers.len() < REQUIRED_QUOTES {
            return Err(Error::Network(format!(
                "Failed to collect enough quotes: got {}, need {}",
                quotes_with_peers.len(),
                REQUIRED_QUOTES
            )));
        }

        if tracing::enabled!(tracing::Level::INFO) {
            let quote_count = quotes_with_peers.len();
            let addr_hex = hex::encode(address);
            info!("Collected {quote_count} quotes for chunk {addr_hex}");
        }

        Ok(quotes_with_peers)
    }
}

/// Identity multihash code (stores raw bytes without hashing).
const MULTIHASH_IDENTITY_CODE: u64 = 0x00;

/// Convert a hex-encoded 32-byte saorsa-core node ID to an [`EncodedPeerId`].
///
/// Saorsa-core peer IDs are 64-character hex strings representing 32 raw bytes.
/// libp2p `PeerId` expects a multihash-encoded identity. This function bridges the two
/// formats by wrapping the raw bytes in an identity multihash (code 0x00) and then
/// converting to `EncodedPeerId` via `From<PeerId>`.
///
/// # Errors
///
/// Returns an error if the hex string is invalid or the peer ID cannot be constructed.
pub fn hex_node_id_to_encoded_peer_id(hex_id: &str) -> Result<EncodedPeerId> {
    let raw_bytes = hex::decode(hex_id)
        .map_err(|e| Error::Payment(format!("Invalid hex peer ID '{hex_id}': {e}")))?;

    let multihash =
        multihash::Multihash::<64>::wrap(MULTIHASH_IDENTITY_CODE, &raw_bytes).map_err(|e| {
            Error::Payment(format!(
                "Failed to create multihash for peer '{hex_id}': {e}"
            ))
        })?;

    let peer_id = libp2p::PeerId::from_multihash(multihash).map_err(|_| {
        Error::Payment(format!(
            "Failed to create PeerId from multihash for peer '{hex_id}'"
        ))
    })?;

    Ok(EncodedPeerId::from(peer_id))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_config_default() {
        let config = QuantumConfig::default();
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(config.replica_count, DEFAULT_REPLICA_COUNT);
        assert!(config.encrypt_data);
    }

    #[test]
    fn test_quantum_client_creation() {
        let client = QuantumClient::with_defaults();
        assert_eq!(client.config.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert!(client.p2p_node.is_none());
    }

    #[tokio::test]
    async fn test_get_chunk_without_node_fails() {
        let client = QuantumClient::with_defaults();
        let address = [0; 32];

        let result = client.get_chunk(&address).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_put_chunk_without_node_fails() {
        let client = QuantumClient::with_defaults();
        let content = Bytes::from("test data");

        let result = client.put_chunk(content).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_exists_without_node_fails() {
        let client = QuantumClient::with_defaults();
        let address = [0; 32];

        let result = client.exists(&address).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_node_id_to_encoded_peer_id_valid() {
        // A valid 32-byte hex-encoded node ID (64 hex chars)
        let hex_id = "80b6427dc1b0490ffe743d39a4d4d68c252f5053f6234a9154cfb017f92a1399";
        let result = hex_node_id_to_encoded_peer_id(hex_id);
        assert!(
            result.is_ok(),
            "Should convert valid hex node ID: {result:?}"
        );
    }

    #[test]
    fn test_hex_node_id_to_encoded_peer_id_invalid_hex() {
        let result = hex_node_id_to_encoded_peer_id("not-valid-hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_node_id_to_encoded_peer_id_all_zeros() {
        let hex_id = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = hex_node_id_to_encoded_peer_id(hex_id);
        assert!(result.is_ok());
    }
}
