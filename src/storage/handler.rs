//! ANT protocol handler for autonomi protocol messages.
//!
//! This handler processes chunk PUT/GET requests with optional payment verification,
//! storing chunks to LMDB and using the DHT for network-wide retrieval.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    AntProtocol                        │
//! ├─────────────────────────────────────────────────────────┤
//! │  protocol_id() = "autonomi.ant.chunk.v1"                  │
//! │                                                         │
//! │  try_handle_request(data) ──▶ decode ChunkMessage  │
//! │                                   │                     │
//! │         ┌─────────────────────────┼─────────────────┐  │
//! │         ▼                         ▼                 ▼  │
//! │   ChunkQuoteRequest           ChunkPutRequest    ChunkGetRequest
//! │         │                         │                 │  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteGenerator          PaymentVerifier    LmdbStorage│
//! │         │                         │                 │  │
//! │         └─────────────────────────┴─────────────────┘  │
//! │                           │                             │
//! │           return Ok(Some(response_bytes))              │
//! │           return Ok(None) for response messages       │
//! └─────────────────────────────────────────────────────────┘
//! ```

use crate::ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteResponse, MerkleCandidateQuoteRequest,
    MerkleCandidateQuoteResponse, ProtocolError, CHUNK_PROTOCOL_ID, DATA_TYPE_CHUNK,
    MAX_CHUNK_SIZE,
};
use crate::client::compute_address;
use crate::error::{Error, Result};
use crate::payment::{PaymentVerifier, QuoteGenerator};
use crate::replication::fresh::FreshWriteEvent;
use crate::storage::lmdb::LmdbStorage;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// ANT protocol handler.
///
/// Handles chunk PUT/GET/Quote requests using LMDB storage for persistence
/// and optional payment verification.
pub struct AntProtocol {
    /// LMDB storage for chunk persistence.
    storage: Arc<LmdbStorage>,
    /// Payment verifier for checking payments.
    payment_verifier: Arc<PaymentVerifier>,
    /// Quote generator for creating storage quotes.
    /// Also handles merkle candidate quote signing via ML-DSA-65.
    quote_generator: Arc<QuoteGenerator>,
    /// Channel for notifying the replication engine about newly-stored chunks.
    fresh_write_tx: Option<mpsc::UnboundedSender<FreshWriteEvent>>,
}

impl AntProtocol {
    /// Create a new ANT protocol handler.
    ///
    /// # Arguments
    ///
    /// * `storage` - LMDB storage for chunk persistence
    /// * `payment_verifier` - Payment verifier for validating payments
    /// * `quote_generator` - Quote generator for creating storage quotes
    #[must_use]
    pub fn new(
        storage: Arc<LmdbStorage>,
        payment_verifier: Arc<PaymentVerifier>,
        quote_generator: Arc<QuoteGenerator>,
    ) -> Self {
        Self {
            storage,
            payment_verifier,
            quote_generator,
            fresh_write_tx: None,
        }
    }

    /// Set the channel sender for fresh-write replication events.
    ///
    /// When set, successful chunk PUTs will notify the replication engine
    /// so it can fan out fresh offers to the close group.
    pub fn set_fresh_write_sender(&mut self, tx: mpsc::UnboundedSender<FreshWriteEvent>) {
        self.fresh_write_tx = Some(tx);
    }

    /// Get the protocol identifier.
    #[must_use]
    pub fn protocol_id(&self) -> &'static str {
        CHUNK_PROTOCOL_ID
    }

    /// Get a reference to the underlying LMDB storage.
    #[must_use]
    pub fn storage(&self) -> Arc<LmdbStorage> {
        Arc::clone(&self.storage)
    }

    /// Get a shared reference to the payment verifier.
    #[must_use]
    pub fn payment_verifier_arc(&self) -> Arc<PaymentVerifier> {
        Arc::clone(&self.payment_verifier)
    }

    /// Handle an incoming request and produce a response.
    ///
    /// Decodes the raw message, processes it if it is a request variant,
    /// and returns the encoded response bytes.  Returns `Ok(None)` for
    /// response messages (which are meant for client subscribers, not for
    /// the protocol handler).
    ///
    /// # Errors
    ///
    /// Returns an error if message decoding, handling, or encoding fails.
    pub async fn try_handle_request(&self, data: &[u8]) -> Result<Option<Bytes>> {
        let message = ChunkMessage::decode(data)
            .map_err(|e| Error::Protocol(format!("Failed to decode message: {e}")))?;

        let request_id = message.request_id;

        let response_body = match message.body {
            ChunkMessageBody::PutRequest(req) => {
                ChunkMessageBody::PutResponse(self.handle_put(req).await)
            }
            ChunkMessageBody::GetRequest(req) => {
                ChunkMessageBody::GetResponse(self.handle_get(req).await)
            }
            ChunkMessageBody::QuoteRequest(ref req) => {
                ChunkMessageBody::QuoteResponse(self.handle_quote(req))
            }
            ChunkMessageBody::MerkleCandidateQuoteRequest(ref req) => {
                ChunkMessageBody::MerkleCandidateQuoteResponse(
                    self.handle_merkle_candidate_quote(req),
                )
            }
            // Response messages are handled by client subscribers
            // (e.g. send_and_await_chunk_response), not by the protocol
            // handler. Returning None prevents the caller from sending a
            // reply, which would create an infinite ping-pong loop.
            ChunkMessageBody::PutResponse(_)
            | ChunkMessageBody::GetResponse(_)
            | ChunkMessageBody::QuoteResponse(_)
            | ChunkMessageBody::MerkleCandidateQuoteResponse(_) => return Ok(None),
        };

        let response = ChunkMessage {
            request_id,
            body: response_body,
        };

        response
            .encode()
            .map(|b| Some(Bytes::from(b)))
            .map_err(|e| Error::Protocol(format!("Failed to encode response: {e}")))
    }

    /// Handle a PUT request.
    async fn handle_put(&self, request: ChunkPutRequest) -> ChunkPutResponse {
        let address = request.address;
        let addr_hex = hex::encode(address);
        debug!("Handling PUT request for {addr_hex}");

        // 1. Validate chunk size
        if request.content.len() > MAX_CHUNK_SIZE {
            return ChunkPutResponse::Error(ProtocolError::ChunkTooLarge {
                size: request.content.len(),
                max_size: MAX_CHUNK_SIZE,
            });
        }

        // 2. Verify content address matches BLAKE3(content)
        let computed = compute_address(&request.content);
        if computed != address {
            return ChunkPutResponse::Error(ProtocolError::AddressMismatch {
                expected: address,
                actual: computed,
            });
        }

        // 3. Check if already exists (idempotent success)
        match self.storage.exists(&address) {
            Ok(true) => {
                debug!("Chunk {addr_hex} already exists");
                return ChunkPutResponse::AlreadyExists { address };
            }
            Err(e) => {
                return ChunkPutResponse::Error(ProtocolError::Internal(format!(
                    "Storage read failed: {e}"
                )));
            }
            Ok(false) => {}
        }

        // 4. Verify payment
        let payment_result = self
            .payment_verifier
            .verify_payment(&address, request.payment_proof.as_deref())
            .await;

        match payment_result {
            Ok(status) if status.can_store() => {
                // Payment verified or cached
            }
            Ok(_) => {
                return ChunkPutResponse::PaymentRequired {
                    message: "Payment required for new chunk".to_string(),
                };
            }
            Err(e) => {
                return ChunkPutResponse::Error(ProtocolError::PaymentFailed(e.to_string()));
            }
        }

        // 5. Store chunk
        match self.storage.put(&address, &request.content).await {
            Ok(_) => {
                let content_len = request.content.len();
                info!("Stored chunk {addr_hex} ({content_len} bytes)");
                // Record the store and payment in metrics
                self.quote_generator.record_store(DATA_TYPE_CHUNK);
                self.quote_generator.record_payment();

                // 6. Notify replication engine for fresh fan-out.
                //    Only emit when a real proof is present — cached-as-verified
                //    PUTs have no proof to forward, and the chunk would have
                //    already replicated on the original write that carried one.
                if let (Some(ref tx), Some(proof)) = (&self.fresh_write_tx, request.payment_proof) {
                    let event = FreshWriteEvent {
                        key: address,
                        data: request.content,
                        payment_proof: proof,
                    };
                    if tx.send(event).is_err() {
                        debug!("Fresh-write channel closed, skipping replication for {addr_hex}");
                    }
                }

                ChunkPutResponse::Success { address }
            }
            Err(e) => {
                warn!("Failed to store chunk {addr_hex}: {e}");
                ChunkPutResponse::Error(ProtocolError::StorageFailed(e.to_string()))
            }
        }
    }

    /// Handle a GET request.
    async fn handle_get(&self, request: ChunkGetRequest) -> ChunkGetResponse {
        let address = request.address;
        let addr_hex = hex::encode(address);
        debug!("Handling GET request for {addr_hex}");

        match self.storage.get(&address).await {
            Ok(Some(content)) => {
                let content_len = content.len();
                debug!("Retrieved chunk {addr_hex} ({content_len} bytes)");
                ChunkGetResponse::Success { address, content }
            }
            Ok(None) => {
                debug!("Chunk {addr_hex} not found");
                ChunkGetResponse::NotFound { address }
            }
            Err(e) => {
                warn!("Failed to retrieve chunk {addr_hex}: {e}");
                ChunkGetResponse::Error(ProtocolError::StorageFailed(e.to_string()))
            }
        }
    }

    /// Handle a quote request.
    fn handle_quote(&self, request: &ChunkQuoteRequest) -> ChunkQuoteResponse {
        let addr_hex = hex::encode(request.address);
        let data_size = request.data_size;
        debug!("Handling quote request for {addr_hex} (size: {data_size})");

        // Check if the chunk is already stored so we can tell the client
        // to skip payment (already_stored = true).
        let already_stored = match self.storage.exists(&request.address) {
            Ok(exists) => exists,
            Err(e) => {
                warn!("Storage check failed for {addr_hex}: {e}");
                false // Assume not stored on error — generate a normal quote.
            }
        };

        if already_stored {
            debug!("Chunk {addr_hex} already stored — returning quote with already_stored=true");
        }

        // Validate data size - data_size is u64, cast carefully and reject overflow
        let Ok(data_size_usize) = usize::try_from(request.data_size) else {
            return ChunkQuoteResponse::Error(ProtocolError::ChunkTooLarge {
                size: MAX_CHUNK_SIZE + 1,
                max_size: MAX_CHUNK_SIZE,
            });
        };
        if data_size_usize > MAX_CHUNK_SIZE {
            return ChunkQuoteResponse::Error(ProtocolError::ChunkTooLarge {
                size: data_size_usize,
                max_size: MAX_CHUNK_SIZE,
            });
        }

        match self
            .quote_generator
            .create_quote(request.address, data_size_usize, request.data_type)
        {
            Ok(quote) => {
                // Serialize the quote
                match rmp_serde::to_vec(&quote) {
                    Ok(quote_bytes) => ChunkQuoteResponse::Success {
                        quote: quote_bytes,
                        already_stored,
                    },
                    Err(e) => ChunkQuoteResponse::Error(ProtocolError::QuoteFailed(format!(
                        "Failed to serialize quote: {e}"
                    ))),
                }
            }
            Err(e) => ChunkQuoteResponse::Error(ProtocolError::QuoteFailed(e.to_string())),
        }
    }

    /// Handle a merkle candidate quote request.
    fn handle_merkle_candidate_quote(
        &self,
        request: &MerkleCandidateQuoteRequest,
    ) -> MerkleCandidateQuoteResponse {
        let addr_hex = hex::encode(request.address);
        let data_size = request.data_size;
        debug!(
            "Handling merkle candidate quote request for {addr_hex} (size: {data_size}, ts: {})",
            request.merkle_payment_timestamp
        );

        let Ok(data_size_usize) = usize::try_from(request.data_size) else {
            return MerkleCandidateQuoteResponse::Error(ProtocolError::QuoteFailed(format!(
                "data_size {} overflows usize",
                request.data_size
            )));
        };
        if data_size_usize > MAX_CHUNK_SIZE {
            return MerkleCandidateQuoteResponse::Error(ProtocolError::ChunkTooLarge {
                size: data_size_usize,
                max_size: MAX_CHUNK_SIZE,
            });
        }

        match self.quote_generator.create_merkle_candidate_quote(
            data_size_usize,
            request.data_type,
            request.merkle_payment_timestamp,
        ) {
            Ok(candidate_node) => match rmp_serde::to_vec(&candidate_node) {
                Ok(bytes) => MerkleCandidateQuoteResponse::Success {
                    candidate_node: bytes,
                },
                Err(e) => MerkleCandidateQuoteResponse::Error(ProtocolError::QuoteFailed(format!(
                    "Failed to serialize merkle candidate node: {e}"
                ))),
            },
            Err(e) => {
                MerkleCandidateQuoteResponse::Error(ProtocolError::QuoteFailed(e.to_string()))
            }
        }
    }

    /// Get storage statistics.
    #[must_use]
    pub fn storage_stats(&self) -> crate::storage::StorageStats {
        self.storage.stats()
    }

    /// Get payment cache statistics.
    #[must_use]
    pub fn payment_cache_stats(&self) -> crate::payment::CacheStats {
        self.payment_verifier.cache_stats()
    }

    /// Get a reference to the payment verifier.
    ///
    /// Exposed for **test harnesses only** — production code should not call
    /// this directly. Use `cache_insert()` on the returned verifier to
    /// pre-populate the payment cache in test setups.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn payment_verifier(&self) -> &PaymentVerifier {
        &self.payment_verifier
    }

    /// Check if a chunk exists locally.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage read fails.
    pub fn exists(&self, address: &[u8; 32]) -> Result<bool> {
        self.storage.exists(address)
    }

    /// Get a chunk directly from local storage.
    ///
    /// # Errors
    ///
    /// Returns an error if storage access fails.
    pub async fn get_local(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        self.storage.get(address).await
    }

    /// Store a chunk directly to local storage (bypasses payment verification).
    ///
    /// TEST ONLY - This method bypasses payment verification and should only be used in tests.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or content doesn't match address.
    #[cfg(test)]
    pub async fn put_local(&self, address: &[u8; 32], content: &[u8]) -> Result<bool> {
        self.storage.put(address, content).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::payment::metrics::QuotingMetricsTracker;
    use crate::payment::{EvmVerifierConfig, PaymentVerifierConfig};
    use crate::storage::LmdbStorageConfig;
    use evmlib::RewardsAddress;
    use saorsa_core::identity::NodeIdentity;
    use saorsa_core::MlDsa65;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;
    use tempfile::TempDir;

    async fn create_test_protocol() -> (AntProtocol, TempDir) {
        let temp_dir = TempDir::new().expect("create temp dir");

        let storage_config = LmdbStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            ..LmdbStorageConfig::test_default()
        };
        let storage = Arc::new(
            LmdbStorage::new(storage_config)
                .await
                .expect("create storage"),
        );

        let rewards_address = RewardsAddress::new([1u8; 20]);
        let payment_config = PaymentVerifierConfig {
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100_000,
            local_rewards_address: rewards_address,
        };
        let payment_verifier = Arc::new(PaymentVerifier::new(payment_config));
        let metrics_tracker = QuotingMetricsTracker::new(100);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing so quote requests succeed
        let identity = NodeIdentity::generate().expect("generate identity");
        let pub_key_bytes = identity.public_key().as_bytes().to_vec();
        let sk_bytes = identity.secret_key_bytes().to_vec();
        let sk = MlDsaSecretKey::from_bytes(&sk_bytes).expect("deserialize secret key");
        quote_generator.set_signer(pub_key_bytes, move |msg| {
            use saorsa_pqc::pqc::MlDsaOperations;
            let ml_dsa = MlDsa65::new();
            ml_dsa
                .sign(&sk, msg)
                .map_or_else(|_| vec![], |sig| sig.as_bytes().to_vec())
        });

        let protocol = AntProtocol::new(storage, payment_verifier, Arc::new(quote_generator));
        (protocol, temp_dir)
    }

    #[tokio::test]
    async fn test_put_and_get_chunk() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"hello world";
        let address = LmdbStorage::compute_address(content);

        // Pre-populate payment cache so EVM verification is bypassed
        protocol.payment_verifier().cache_insert(address);

        let put_request = ChunkPutRequest::new(address, content.to_vec());
        let put_msg = ChunkMessage {
            request_id: 1,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        // Handle PUT
        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 1);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: addr }) =
            response.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected PutResponse::Success, got: {response:?}");
        }

        // Create GET request
        let get_request = ChunkGetRequest::new(address);
        let get_msg = ChunkMessage {
            request_id: 2,
            body: ChunkMessageBody::GetRequest(get_request),
        };
        let get_bytes = get_msg.encode().expect("encode get");

        // Handle GET
        let response_bytes = protocol
            .try_handle_request(&get_bytes)
            .await
            .expect("handle get")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 2);
        if let ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
            address: addr,
            content: data,
        }) = response.body
        {
            assert_eq!(addr, address);
            assert_eq!(data, content.to_vec());
        } else {
            panic!("expected GetResponse::Success");
        }
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let (protocol, _temp) = create_test_protocol().await;

        let address = [0xAB; 32];
        let get_request = ChunkGetRequest::new(address);
        let get_msg = ChunkMessage {
            request_id: 10,
            body: ChunkMessageBody::GetRequest(get_request),
        };
        let get_bytes = get_msg.encode().expect("encode get");

        let response_bytes = protocol
            .try_handle_request(&get_bytes)
            .await
            .expect("handle get")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 10);
        if let ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address: addr }) =
            response.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected GetResponse::NotFound");
        }
    }

    #[tokio::test]
    async fn test_put_address_mismatch() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"test content";
        let wrong_address = [0xFF; 32]; // Wrong address

        // Pre-populate cache for the wrong address so we test address mismatch, not payment
        protocol.payment_verifier().cache_insert(wrong_address);

        let put_request = ChunkPutRequest::new(wrong_address, content.to_vec());
        let put_msg = ChunkMessage {
            request_id: 20,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 20);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Error(
            ProtocolError::AddressMismatch { .. },
        )) = response.body
        {
            // Expected
        } else {
            panic!("expected AddressMismatch error, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_put_chunk_too_large() {
        let (protocol, _temp) = create_test_protocol().await;

        // Create oversized content
        let content = vec![0u8; MAX_CHUNK_SIZE + 1];
        let address = LmdbStorage::compute_address(&content);

        let put_request = ChunkPutRequest::new(address, content);
        let put_msg = ChunkMessage {
            request_id: 30,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 30);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Error(
            ProtocolError::ChunkTooLarge { .. },
        )) = response.body
        {
            // Expected
        } else {
            panic!("expected ChunkTooLarge error");
        }
    }

    #[tokio::test]
    async fn test_put_already_exists() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"duplicate content";
        let address = LmdbStorage::compute_address(content);

        // Pre-populate cache so EVM verification is bypassed
        protocol.payment_verifier().cache_insert(address);

        let put_request = ChunkPutRequest::new(address, content.to_vec());
        let put_msg = ChunkMessage {
            request_id: 40,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        let _ = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put");

        // Store again - should return AlreadyExists
        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put 2")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 40);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { address: addr }) =
            response.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected AlreadyExists");
        }
    }

    #[tokio::test]
    async fn test_protocol_id() {
        let (protocol, _temp) = create_test_protocol().await;
        assert_eq!(protocol.protocol_id(), CHUNK_PROTOCOL_ID);
    }

    #[tokio::test]
    async fn test_exists_and_local_access() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"local access test";
        let address = LmdbStorage::compute_address(content);

        assert!(!protocol.exists(&address).expect("exists check"));

        protocol
            .put_local(&address, content)
            .await
            .expect("put local");

        assert!(protocol.exists(&address).expect("exists check"));

        let retrieved = protocol.get_local(&address).await.expect("get local");
        assert_eq!(retrieved, Some(content.to_vec()));
    }

    #[tokio::test]
    async fn test_cache_insert_is_visible() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"cache test content";
        let address = LmdbStorage::compute_address(content);

        // Before insert: cache should be empty
        let stats_before = protocol.payment_cache_stats();
        assert_eq!(stats_before.additions, 0);

        // Pre-populate cache
        protocol.payment_verifier().cache_insert(address);

        // After insert: cache should have the xorname
        let stats_after = protocol.payment_cache_stats();
        assert_eq!(stats_after.additions, 1);

        // PUT should succeed (cache hit)
        let put_request = ChunkPutRequest::new(address, content.to_vec());
        let put_msg = ChunkMessage {
            request_id: 100,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");
        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode");

        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Success { .. }) = response.body {
            // expected
        } else {
            panic!("expected success, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_put_same_chunk_twice_hits_cache() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"duplicate cache test";
        let address = LmdbStorage::compute_address(content);

        // Pre-populate cache for first PUT
        protocol.payment_verifier().cache_insert(address);

        // First PUT
        let put_request = ChunkPutRequest::new(address, content.to_vec());
        let put_msg = ChunkMessage {
            request_id: 110,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");
        let _ = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put 1");

        // Second PUT — should return AlreadyExists (checked in storage before payment)
        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put 2")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode");

        if let ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { .. }) = response.body
        {
            // expected — storage check comes before payment check
        } else {
            panic!("expected AlreadyExists, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_payment_cache_stats_returns_correct_values() {
        let (protocol, _temp) = create_test_protocol().await;

        let stats = protocol.payment_cache_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.additions, 0);

        // Pre-populate cache, then store a chunk to test stats
        let content = b"stats test";
        let address = LmdbStorage::compute_address(content);
        protocol.payment_verifier().cache_insert(address);

        let put_request = ChunkPutRequest::new(address, content.to_vec());
        let put_msg = ChunkMessage {
            request_id: 120,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");
        let _ = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put");

        let stats = protocol.payment_cache_stats();
        // Should have 1 addition (from cache_insert) + 1 hit (payment verification found cache)
        assert_eq!(stats.additions, 1);
        assert_eq!(stats.hits, 1);
    }

    #[tokio::test]
    async fn test_storage_stats() {
        let (protocol, _temp) = create_test_protocol().await;
        let stats = protocol.storage_stats();
        assert_eq!(stats.chunks_stored, 0);
    }

    #[tokio::test]
    async fn test_merkle_candidate_quote_request() {
        use crate::payment::quote::verify_merkle_candidate_signature;
        use evmlib::merkle_payments::MerklePaymentCandidateNode;

        // create_test_protocol already wires ML-DSA-65 signing
        let (protocol, _temp) = create_test_protocol().await;

        let address = [0x77; 32];
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let request = MerkleCandidateQuoteRequest {
            address,
            data_type: DATA_TYPE_CHUNK,
            data_size: 4096,
            merkle_payment_timestamp: timestamp,
        };
        let msg = ChunkMessage {
            request_id: 600,
            body: ChunkMessageBody::MerkleCandidateQuoteRequest(request),
        };
        let msg_bytes = msg.encode().expect("encode request");

        let response_bytes = protocol
            .try_handle_request(&msg_bytes)
            .await
            .expect("handle merkle candidate quote")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 600);
        match response.body {
            ChunkMessageBody::MerkleCandidateQuoteResponse(
                MerkleCandidateQuoteResponse::Success { candidate_node },
            ) => {
                let candidate: MerklePaymentCandidateNode =
                    rmp_serde::from_slice(&candidate_node).expect("deserialize candidate node");

                // Verify ML-DSA-65 signature
                assert!(
                    verify_merkle_candidate_signature(&candidate),
                    "ML-DSA-65 candidate signature must be valid"
                );

                assert_eq!(candidate.merkle_payment_timestamp, timestamp);
                // Node-calculated price based on records stored
                assert!(candidate.price >= evmlib::common::Amount::ZERO);
            }
            other => panic!("expected MerkleCandidateQuoteResponse::Success, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_unexpected_response_message() {
        let (protocol, _temp) = create_test_protocol().await;

        // Send a PutResponse as if it were a request — should return None
        let msg = ChunkMessage {
            request_id: 200,
            body: ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: [0u8; 32] }),
        };
        let msg_bytes = msg.encode().expect("encode");

        let result = protocol
            .try_handle_request(&msg_bytes)
            .await
            .expect("handle msg");

        assert!(
            result.is_none(),
            "expected None for response message, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_quote_already_stored_flag() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"already stored quote test";
        let address = LmdbStorage::compute_address(content);

        // Store the chunk first
        protocol.payment_verifier().cache_insert(address);
        let put_request = ChunkPutRequest::new(address, content.to_vec());
        let put_msg = ChunkMessage {
            request_id: 300,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");
        let _ = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put");

        // Now request a quote for the same address — already_stored should be true
        let quote_request = ChunkQuoteRequest {
            address,
            data_size: content.len() as u64,
            data_type: DATA_TYPE_CHUNK,
        };
        let quote_msg = ChunkMessage {
            request_id: 301,
            body: ChunkMessageBody::QuoteRequest(quote_request),
        };
        let quote_bytes = quote_msg.encode().expect("encode quote");
        let response_bytes = protocol
            .try_handle_request(&quote_bytes)
            .await
            .expect("handle quote")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode");

        match response.body {
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
                already_stored, ..
            }) => {
                assert!(
                    already_stored,
                    "already_stored should be true for existing chunk"
                );
            }
            other => panic!("expected Success with already_stored, got: {other:?}"),
        }

        // Request a quote for a chunk that does NOT exist — already_stored should be false
        let new_address = [0xFFu8; 32];
        let quote_request2 = ChunkQuoteRequest {
            address: new_address,
            data_size: 100,
            data_type: DATA_TYPE_CHUNK,
        };
        let quote_msg2 = ChunkMessage {
            request_id: 302,
            body: ChunkMessageBody::QuoteRequest(quote_request2),
        };
        let quote_bytes2 = quote_msg2.encode().expect("encode quote2");
        let response_bytes2 = protocol
            .try_handle_request(&quote_bytes2)
            .await
            .expect("handle quote2")
            .expect("expected response");
        let response2 = ChunkMessage::decode(&response_bytes2).expect("decode2");

        match response2.body {
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
                already_stored, ..
            }) => {
                assert!(
                    !already_stored,
                    "already_stored should be false for new chunk"
                );
            }
            other => panic!("expected Success with already_stored=false, got: {other:?}"),
        }
    }
}
