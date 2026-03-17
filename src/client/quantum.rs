//! Quantum-resistant client operations for chunk storage.
//!
//! This module provides content-addressed chunk storage operations on the saorsa network
//! using post-quantum cryptography (ML-KEM-768 for key exchange, ML-DSA-65 for signatures).
//!
//! ## Data Model
//!
//! Chunks are the only data type supported:
//! - **Content-addressed**: Address = BLAKE3(content)
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
use std::collections::{BTreeMap, HashSet};
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

/// A chunk that has been quoted but not yet paid or stored.
///
/// Produced by [`QuantumClient::prepare_chunk_payment`] and consumed by
/// [`QuantumClient::batch_pay`] or [`QuantumClient::batch_pay_and_store`].
pub struct PreparedChunk {
    /// The raw chunk content.
    pub content: Bytes,
    /// Content-address (BLAKE3 hash).
    pub address: XorName,
    /// Peer ID + quote pairs for building `ProofOfPayment`.
    pub peer_quotes: Vec<(EncodedPeerId, PaymentQuote)>,
    /// The payment structure (sorted quotes, median selected).
    pub payment: SingleNodePayment,
    /// The closest peer to the chunk address, pinned during quote collection
    /// so that the storage target is always one of the paid peers.
    pub target_peer: PeerId,
}

/// A chunk that has been paid on-chain but not yet stored on the network.
///
/// Produced by [`QuantumClient::batch_pay`]. Store via
/// [`QuantumClient::put_chunk_with_proof`].
pub struct PaidChunk {
    /// The raw chunk content.
    pub content: Bytes,
    /// Serialized payment proof (msgpack bytes).
    pub proof_bytes: Vec<u8>,
    /// Transaction hashes from this chunk's on-chain payment.
    pub tx_hashes: Vec<evmlib::common::TxHash>,
    /// The closest peer to the chunk address, pinned during quote collection
    /// so that the storage target is always one of the paid peers.
    pub target_peer: PeerId,
}

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
/// Chunks are content-addressed: the address is the BLAKE3 hash of the content.
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
    /// * `address` - The `XorName` address of the chunk (BLAKE3 of content)
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

        // Step 1: Request quotes from network nodes via DHT.
        // The closest peer is pinned here so we store to a peer that was paid.
        let (target_peer, quotes_with_peers) = self
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

        // Step 6: Send chunk with payment proof to the peer pinned during quoting
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
    /// The `target_peer` should be the peer pinned during quote collection so that
    /// the storage target is guaranteed to be one of the paid peers. Use the
    /// `target_peer` field from [`PaidChunk`] or the first element returned by
    /// [`get_quotes_from_dht`](Self::get_quotes_from_dht).
    ///
    /// # Arguments
    ///
    /// * `content` - The data to store
    /// * `proof` - A serialised [`ProofOfPayment`] (msgpack bytes)
    /// * `target_peer` - The peer to send the chunk to (pinned during quoting)
    ///
    /// # Returns
    ///
    /// The `XorName` address where the chunk was stored.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - P2P node is not configured
    /// - Storage operation fails
    pub async fn put_chunk_with_proof(
        &self,
        content: Bytes,
        proof: Vec<u8>,
        target_peer: &PeerId,
    ) -> Result<XorName> {
        let Some(ref node) = self.p2p_node else {
            return Err(Error::Network("P2P node not configured".into()));
        };

        let address = compute_address(&content);
        let content_size = content.len();

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
            target_peer,
            message_bytes,
            request_id,
            self.config.timeout_secs,
            hex::encode(address),
            content_size,
        )
        .await
    }

    /// Collect quotes for a chunk without paying.
    ///
    /// Returns a [`PreparedChunk`] containing all the information needed to
    /// pay and store the chunk later. Use with [`batch_pay_and_store`](Self::batch_pay_and_store)
    /// to pay for multiple chunks in a single EVM transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if DHT lookup or quote collection fails.
    pub async fn prepare_chunk_payment(&self, content: Bytes) -> Result<PreparedChunk> {
        let content_len = content.len();
        debug!("Preparing payment for chunk ({content_len} bytes)");

        self.p2p_node
            .as_ref()
            .ok_or_else(|| Error::Network("P2P node not configured".into()))?;

        self.wallet.as_ref().ok_or_else(|| {
            Error::Payment(
                "Wallet not configured - use with_wallet() to enable payments".to_string(),
            )
        })?;

        let address = compute_address(&content);
        let data_size = u64::try_from(content.len())
            .map_err(|e| Error::Network(format!("Content size too large: {e}")))?;

        let (target_peer, quotes_with_peers) = self
            .get_quotes_from_dht_for_address(&address, data_size)
            .await?;

        if quotes_with_peers.len() != REQUIRED_QUOTES {
            return Err(Error::Payment(format!(
                "Expected {REQUIRED_QUOTES} quotes but received {}",
                quotes_with_peers.len()
            )));
        }

        let mut peer_quotes: Vec<(EncodedPeerId, PaymentQuote)> =
            Vec::with_capacity(quotes_with_peers.len());
        let mut quotes_with_prices: Vec<(PaymentQuote, Amount)> =
            Vec::with_capacity(quotes_with_peers.len());

        for (peer_id, quote, price) in quotes_with_peers {
            let encoded_peer_id = hex_node_id_to_encoded_peer_id(&peer_id.to_hex())?;
            peer_quotes.push((encoded_peer_id, quote.clone()));
            quotes_with_prices.push((quote, price));
        }

        let payment = SingleNodePayment::from_quotes(quotes_with_prices)?;

        Ok(PreparedChunk {
            content,
            address,
            peer_quotes,
            payment,
            target_peer,
        })
    }

    /// Pay for multiple prepared chunks in a single EVM transaction.
    ///
    /// Returns [`PaidChunk`]s ready for storage via [`put_chunk_with_proof`](Self::put_chunk_with_proof).
    /// Use this for pipelined uploads where stores from wave N overlap with
    /// quotes for wave N+1.
    ///
    /// # Errors
    ///
    /// Returns an error if the EVM payment fails.
    pub async fn batch_pay(&self, prepared: Vec<PreparedChunk>) -> Result<Vec<PaidChunk>> {
        let Some(ref wallet) = self.wallet else {
            return Err(Error::Payment(
                "Wallet not configured - use with_wallet() to enable payments".to_string(),
            ));
        };

        if prepared.is_empty() {
            return Ok(Vec::new());
        }

        let total_amount: Amount = prepared.iter().map(|p| p.payment.total_amount()).sum();
        let chunk_count = prepared.len();
        info!("Batch payment for {chunk_count} chunks: {total_amount} atto total");

        let all_quote_payments: Vec<(ant_evm::QuoteHash, ant_evm::RewardsAddress, Amount)> =
            prepared
                .iter()
                .flat_map(|p| &p.payment.quotes)
                .map(|q| (q.quote_hash, q.rewards_address, q.amount))
                .collect();

        let (tx_hash_map, _gas_info) = wallet.pay_for_quotes(all_quote_payments).await.map_err(
            |evmlib::wallet::PayForQuotesError(err, _)| {
                Error::Payment(format!("Batch payment failed: {err}"))
            },
        )?;

        let unique_tx_count = {
            let mut txs: Vec<_> = tx_hash_map.values().collect();
            txs.sort();
            txs.dedup();
            txs.len()
        };
        info!("Batch payment successful: {unique_tx_count} on-chain transaction(s) for {chunk_count} chunks");

        prepared
            .into_iter()
            .map(|prep| {
                let chunk_tx_hashes = Self::collect_chunk_tx_hashes(&prep.payment, &tx_hash_map);
                let proof = PaymentProof {
                    proof_of_payment: ProofOfPayment {
                        peer_quotes: prep.peer_quotes,
                    },
                    tx_hashes: chunk_tx_hashes.clone(),
                };
                let proof_bytes = rmp_serde::to_vec(&proof).map_err(|e| {
                    Error::Network(format!("Failed to serialize payment proof: {e}"))
                })?;
                Ok(PaidChunk {
                    content: prep.content,
                    proof_bytes,
                    tx_hashes: chunk_tx_hashes,
                    target_peer: prep.target_peer,
                })
            })
            .collect()
    }

    /// Pay for multiple chunks in a single EVM transaction, then store them.
    ///
    /// Convenience wrapper around [`batch_pay`](Self::batch_pay) followed by
    /// concurrent [`put_chunk_with_proof`](Self::put_chunk_with_proof) calls.
    ///
    /// # Errors
    ///
    /// Returns an error if payment or any chunk storage fails.
    pub async fn batch_pay_and_store(
        &self,
        prepared: Vec<PreparedChunk>,
    ) -> Result<Vec<(XorName, Vec<evmlib::common::TxHash>)>> {
        let chunk_count = prepared.len();
        let paid_chunks = self.batch_pay(prepared).await?;

        let mut store_futures = FuturesUnordered::new();
        for (idx, paid) in paid_chunks.into_iter().enumerate() {
            let tx_hashes = paid.tx_hashes.clone();
            let target_peer = paid.target_peer;
            let fut = async move {
                let address = self
                    .put_chunk_with_proof(paid.content, paid.proof_bytes, &target_peer)
                    .await?;
                Ok::<_, Error>((idx, address, tx_hashes))
            };
            store_futures.push(fut);
        }

        let mut results: Vec<Option<(XorName, Vec<evmlib::common::TxHash>)>> =
            vec![None; chunk_count];
        while let Some(result) = store_futures.next().await {
            let (idx, address, tx_hashes) = result?;
            results[idx] = Some((address, tx_hashes));
        }

        results
            .into_iter()
            .enumerate()
            .map(|(i, opt)| {
                opt.ok_or_else(|| {
                    Error::Network(format!("Missing store result for chunk index {i}"))
                })
            })
            .collect()
    }

    /// Extract transaction hashes relevant to a single chunk's payment.
    fn collect_chunk_tx_hashes(
        payment: &SingleNodePayment,
        tx_hash_map: &BTreeMap<ant_evm::QuoteHash, evmlib::common::TxHash>,
    ) -> Vec<evmlib::common::TxHash> {
        payment
            .quotes
            .iter()
            .filter(|q| q.amount > Amount::ZERO)
            .filter_map(|q| tx_hash_map.get(&q.quote_hash).copied())
            .collect()
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
    ) -> Result<(PeerId, Vec<(PeerId, PaymentQuote, Amount)>)> {
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
    ) -> Result<(PeerId, Vec<(PeerId, PaymentQuote, Amount)>)> {
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

        // Pin the closest peer as the storage target. This peer is always
        // among the quoted set, so the payment proof will include it.
        let closest_peer = remote_peers[0];

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Found {} remote peers, requesting quotes from first {} (closest: {})",
                remote_peers.len(),
                REQUIRED_QUOTES,
                closest_peer
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

        Ok((closest_peer, quotes_with_peers))
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
