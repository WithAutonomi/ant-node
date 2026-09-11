//! Live ADR-0013 local-devnet protocol test.

use ant_node::devnet::{Devnet, DevnetConfig};
use ant_node::BrowserEndpoint;
#[cfg(feature = "test-utils")]
use bytes::Bytes;
#[cfg(feature = "test-utils")]
use evmlib::common::Amount;
#[cfg(feature = "test-utils")]
use evmlib::wallet::Wallet;
#[cfg(feature = "test-utils")]
use evmlib::EncodedPeerId;
#[cfg(feature = "test-utils")]
use evmlib::{PaymentQuote, ProofOfPayment};
use saorsa_transport::transport::{WebRtcCertificateHash, WebRtcDirectAddr};
#[cfg(feature = "test-utils")]
use saorsa_transport::webrtc::BROWSER_PROTOCOL_NAME;
use saorsa_transport::webrtc::{
    decode_pq_frame, encode_pq_frame, pq_frame_length, PqClientHandshake, PqSession,
    BROWSER_PROTOCOL_VERSION, PQ_ENCRYPTED_OVERHEAD_BYTES, PQ_SERVER_ACCEPT_BYTES,
    WEBRTC_DIRECT_DATA_CHANNEL, WEBRTC_WRITE_CHUNK_BYTES,
};
use saorsa_transport::webrtc_direct::{WebRtcDataChannel, WebRtcDirectClient};
#[cfg(feature = "test-utils")]
use self_encryption::{DataMap, EncryptedChunk};
use serde_json::{json, Value};
use std::error::Error;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct MockChainRpc {
    url: String,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl MockChainRpc {
    async fn new(body: String) -> io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!(
            "http://dummy-user:dummy-password@{}/v2/dummy-path-key?api_key=dummy-query-key",
            listener.local_addr()?
        );
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await?;
                let mut request = Vec::new();
                loop {
                    if socket.read_buf(&mut request).await? == 0 {
                        return Err(io::Error::other("truncated RPC request"));
                    }
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .ok_or_else(|| io::Error::other("missing RPC request length"))?;
                        if request.len() >= end + 4 + length {
                            let payload: Value = serde_json::from_slice(&request[end + 4..])?;
                            assert_eq!(payload["method"], "eth_chainId");
                            break;
                        }
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await?;
            }
        });
        Ok(Self { url, task })
    }

    fn network(&self) -> evmlib::Network {
        evmlib::Network::new_custom(
            &self.url,
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
        )
    }
}

impl Drop for MockChainRpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn encrypted_hello_and_manifest_never_disclose_verification_rpc() -> Result<(), Box<dyn Error>>
{
    let rpc =
        MockChainRpc::new(json!({"jsonrpc":"2.0", "id":1, "result":"0x7a69"}).to_string()).await?;
    let temp = tempfile::tempdir()?;
    let mut config = DevnetConfig::minimal();
    config.node_count = 2;
    config.bootstrap_count = 1;
    config.base_port = 0;
    config.webrtc_direct = true;
    config.data_dir = temp.path().join("rpc-privacy-devnet");
    config.spawn_delay = std::time::Duration::from_millis(20);
    config.evm_network = Some(rpc.network());
    let mut devnet = Devnet::new(config).await?;
    devnet.start().await?;
    let endpoints = devnet.browser_endpoints();
    let endpoint = endpoints
        .first()
        .ok_or_else(|| io::Error::other("missing browser endpoint"))?;
    let payment = devnet.browser_payment_network().await?;
    let manifest = ant_node::BrowserDevnetManifest::new(
        "rpc-privacy".to_string(),
        "2026-09-07T00:00:00Z".to_string(),
        endpoints.clone(),
        payment,
        vec![],
    );
    let mut client = BrowserRpcClient::connect(&endpoint.endpoint).await?;
    let (hello, content) = client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION, "request_id": 1, "type": "hello",
            }),
            &[],
        )
        .await?;
    client.close().await?;
    devnet.shutdown().await?;
    assert_eq!(hello["status"], "ok");
    assert!(content.is_empty());
    assert_eq!(
        hello["payment"],
        json!({
            "chain_id": 31337,
            "payment_token_address": "0x1111111111111111111111111111111111111111",
            "payment_vault_address": "0x2222222222222222222222222222222222222222",
        })
    );
    assert_eq!(hello["payment"], serde_json::to_value(&manifest.payment)?);
    let serialized = serde_json::to_string(&(hello, manifest))?;
    for private in [
        "rpc_url",
        "dummy-user",
        "dummy-password",
        "dummy-path-key",
        "dummy-query-key",
        &rpc.url,
    ] {
        assert!(
            !serialized.contains(private),
            "browser metadata disclosed {private}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn invalid_chain_identity_fails_without_exposing_provider_response(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    for body in [
        json!({"jsonrpc":"2.0", "id":1, "result":"0x01"}),
        json!({"jsonrpc":"2.0", "id":1, "result":"0x10000000000000000"}),
        json!({"jsonrpc":"2.0", "id":2, "result":"0x1"}),
        json!({"jsonrpc":"2.0", "id":1, "error":{"message":"dummy-private-url"}}),
    ] {
        let rpc = MockChainRpc::new(body.to_string()).await?;
        let mut config = DevnetConfig::minimal();
        config.data_dir = temp.path().join("invalid-rpc");
        config.evm_network = Some(rpc.network());
        let mut devnet = Devnet::new(config).await?;
        let error = devnet
            .browser_payment_network()
            .await
            .err()
            .ok_or_else(|| io::Error::other("accepted invalid chain identity"))?;
        assert!(!error.to_string().contains("dummy"));
        assert!(!error.to_string().contains(&rpc.url));
        devnet.shutdown().await?;
    }
    Ok(())
}

#[cfg(feature = "test-utils")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a five-node local network"]
#[serial_test::serial]
#[allow(clippy::too_many_lines)]
async fn seeded_public_file_downloads_and_paid_uploads_over_direct_node_endpoints(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let evm_testnet = evmlib::testnet::Testnet::new().await?;
    let evm_network = evm_testnet.to_network();
    let wallet = Wallet::new_from_private_key(
        evm_network.clone(),
        &evm_testnet.default_wallet_private_key()?,
    )?;
    let mut config = DevnetConfig::minimal();
    config.base_port = 0;
    config.webrtc_direct = true;
    config.webrtc_direct_base_port = 0;
    config.data_dir = temp.path().join("browser-devnet");
    config.spawn_delay = std::time::Duration::from_millis(20);
    config.evm_network = Some(evm_network);

    let mut devnet = Devnet::new(config).await?;
    devnet.start().await?;

    let content = b"browser devnet integration file";
    let public_file = devnet
        .publish_public_file(
            "browser-devnet.txt".to_string(),
            "text/plain".to_string(),
            content,
        )
        .await?;
    let endpoints = devnet.browser_endpoints();
    assert_eq!(endpoints.len(), 5);
    assert!(public_file.replicas > 0);

    let endpoint = endpoints
        .first()
        .ok_or_else(|| io::Error::other("browser-enabled devnet returned no direct endpoints"))?;
    let parsed_endpoint = endpoint.endpoint.parse().map_err(io::Error::other)?;
    let mut seed_client = BrowserRpcClient::connect(&endpoint.endpoint).await?;
    let (hello, hello_content) = seed_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 5,
                "type": "hello",
            }),
            &[],
        )
        .await?;
    assert_eq!(hello["status"], "ok");
    assert_eq!(hello["protocol"], BROWSER_PROTOCOL_NAME);
    assert_eq!(hello["payment"]["chain_id"], 31337);
    assert!(hello["payment"].get("rpc_url").is_none());
    assert_eq!(hello["peer_id"], parsed_endpoint.peer_id);
    assert_eq!(
        hello["endpoint"]["multiaddr"],
        endpoint.endpoint.multiaddr.clone()
    );
    assert!(hello_content.is_empty());

    let (closest, closest_content) = seed_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 6,
                "type": "find_node",
                "target": public_file.address,
                "count": 20,
            }),
            &[],
        )
        .await?;
    assert_eq!(closest["status"], "ok");
    assert_eq!(closest["type"], "nodes");
    assert_eq!(closest["target"], public_file.address);
    assert!(closest_content.is_empty());
    let discovered = closest["nodes"]
        .as_array()
        .and_then(|nodes| {
            nodes.iter().find(|node| {
                node["webrtc_direct"]["multiaddr"]
                    .as_str()
                    .is_some_and(|addr| addr != endpoint.endpoint.multiaddr)
            })
        })
        .ok_or_else(|| io::Error::other("FIND_NODE returned no browser endpoint"))?;
    let discovered_peer = discovered["peer_id"]
        .as_str()
        .ok_or_else(|| io::Error::other("FIND_NODE node omitted its peer ID"))?;
    let download_endpoint: BrowserEndpoint =
        serde_json::from_value(discovered["webrtc_direct"].clone())?;
    let parsed_download = download_endpoint.parse().map_err(io::Error::other)?;
    assert_eq!(parsed_download.peer_id, discovered_peer);
    let mut download_client = BrowserRpcClient::connect(&download_endpoint).await?;
    let (download_hello, _) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 7,
                "type": "hello",
            }),
            &[],
        )
        .await?;
    assert_eq!(download_hello["peer_id"], discovered_peer);
    let (next_hop, next_hop_content) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 8,
                "type": "find_node",
                "target": public_file.address,
                "count": 20,
            }),
            &[],
        )
        .await?;
    assert_eq!(next_hop["status"], "ok");
    assert_eq!(next_hop["type"], "nodes");
    assert!(next_hop["nodes"]
        .as_array()
        .is_some_and(|nodes| !nodes.is_empty()));
    assert!(next_hop_content.is_empty());
    let (header, data_map_bytes) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 9,
                "type": "get_chunk",
                "address": public_file.address,
            }),
            &[],
        )
        .await?;

    assert_eq!(header["status"], "ok");
    assert_eq!(header["type"], "chunk");
    assert_eq!(data_map_bytes.len(), public_file.data_map_size);
    let data_map: DataMap = rmp_serde::from_slice(&data_map_bytes)?;
    assert_eq!(data_map.original_file_size(), content.len());
    assert_eq!(public_file.chunks.len(), data_map.infos().len());

    let mut encrypted_chunks = Vec::new();
    for (index, chunk) in public_file.chunks.iter().enumerate() {
        let request_id = u64::try_from(index)?.saturating_add(10);
        let (chunk_header, chunk_bytes) = download_client
            .rpc(
                json!({
                    "version": BROWSER_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "type": "get_chunk",
                    "address": chunk.dst_hash,
                }),
                &[],
            )
            .await?;
        assert_eq!(chunk_header["status"], "ok");
        assert_eq!(chunk_header["type"], "chunk");
        encrypted_chunks.push(EncryptedChunk {
            content: Bytes::from(chunk_bytes),
        });
    }
    let decrypted = self_encryption::decrypt(&data_map, &encrypted_chunks)?;
    assert_eq!(decrypted, content.as_slice());

    let upload_content = b"paid browser WebRtcDirect upload";
    let upload_address = *blake3::hash(upload_content).as_bytes();
    let response = download_client
        .chunk_rpc(
            50,
            ant_protocol::ChunkMessageBody::QuoteRequest(ant_protocol::ChunkQuoteRequest::new(
                upload_address,
                upload_content.len() as u64,
            )),
        )
        .await?;
    let ant_protocol::ChunkMessageBody::QuoteResponse(ant_protocol::ChunkQuoteResponse::Success {
        quote,
        already_stored,
        commitment,
    }) = response
    else {
        return Err(io::Error::other("expected native quote response").into());
    };
    assert!(!already_stored);
    let quote: PaymentQuote = rmp_serde::from_slice(&quote)?;
    assert!(ant_protocol::payment::verify_quote_signature(&quote));
    let quote_hash = quote.hash();
    let (payments, _) = wallet
        .pay_for_quotes([(
            quote_hash,
            quote.rewards_address,
            quote.price * Amount::from(3),
        )])
        .await
        .map_err(|error| io::Error::other(format!("storage payment failed: {error:?}")))?;
    let transaction_hash = payments
        .get(&quote_hash)
        .ok_or_else(|| io::Error::other("missing transaction hash"))?;
    let proof = ant_protocol::payment::PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::new(parsed_download.peer_id_bytes()?), quote)],
        },
        tx_hashes: vec![*transaction_hash],
        commitment_sidecars: commitment.into_iter().collect(),
    };
    let proof = ant_protocol::payment::serialize_single_node_proof(&proof)?;
    let response = download_client
        .chunk_rpc(
            51,
            ant_protocol::ChunkMessageBody::PutRequest(
                ant_protocol::ChunkPutRequest::with_payment(
                    upload_address,
                    Bytes::copy_from_slice(upload_content),
                    proof,
                ),
            ),
        )
        .await?;
    assert!(
        matches!(response, ant_protocol::ChunkMessageBody::PutResponse(ant_protocol::ChunkPutResponse::Success { address }) if address == upload_address)
    );
    let response = download_client
        .chunk_rpc(
            52,
            ant_protocol::ChunkMessageBody::GetRequest(ant_protocol::ChunkGetRequest::new(
                upload_address,
            )),
        )
        .await?;
    assert!(
        matches!(response, ant_protocol::ChunkMessageBody::GetResponse(ant_protocol::ChunkGetResponse::Success { address, content }) if address == upload_address && content == upload_content)
    );
    let diagnostics = devnet.browser_listener_diagnostics();
    assert_eq!(diagnostics.len(), 5);
    assert!(diagnostics.iter().all(|listener| listener.running));
    assert!(
        diagnostics
            .iter()
            .map(|listener| listener.transport.successful_connections)
            .sum::<u64>()
            >= 2
    );
    assert!(
        diagnostics
            .iter()
            .map(|listener| listener.transport.bytes_received)
            .sum::<u64>()
            > 0
    );
    assert!(
        diagnostics
            .iter()
            .map(|listener| listener.transport.bytes_sent)
            .sum::<u64>()
            > 0
    );
    assert!(diagnostics
        .iter()
        .flat_map(|listener| &listener.transport.connections)
        .any(|connection| connection.connected_at.is_some() && connection.last_activity.is_some()));

    assert!(seed_client.requests_sent() >= 2);
    assert!(download_client.requests_sent() >= 6);

    download_client.close().await?;
    seed_client.close().await?;

    devnet.shutdown().await?;
    for listener in devnet.browser_listener_diagnostics() {
        assert!(!listener.running);
        assert_eq!(listener.active_connections, 0);
        assert_eq!(listener.active_channels, 0);
        assert_eq!(listener.active_requests, 0);
        assert_eq!(listener.in_flight_bytes, 0);
        assert!(listener.transport.connections.is_empty());
    }
    Ok(())
}

struct BrowserRpcClient {
    client: WebRtcDirectClient,
    pq_session: PqSession,
    requests_sent: usize,
}

impl BrowserRpcClient {
    async fn connect(endpoint: &BrowserEndpoint) -> Result<Self, Box<dyn Error>> {
        let parsed = endpoint.parse().map_err(io::Error::other)?;
        let direct_addr = WebRtcDirectAddr::new(
            parsed.socket_addr().map_err(io::Error::other)?,
            WebRtcCertificateHash::new(parsed.certificate_hash),
        )?;
        let client = WebRtcDirectClient::dial(&direct_addr, WEBRTC_DIRECT_DATA_CHANNEL)
            .await
            .map_err(|error| io::Error::other(format!("WebRTC Direct dial failed: {error}")))?;
        let expected_peer_id = parsed.peer_id_bytes().map_err(io::Error::other)?;
        let pq_session = establish_pq_session(client.data_channel(), &expected_peer_id).await?;
        Ok(Self {
            client,
            pq_session,
            requests_sent: 0,
        })
    }

    async fn rpc(
        &mut self,
        request: Value,
        content: &[u8],
    ) -> Result<(Value, Vec<u8>), Box<dyn Error>> {
        let request_type = request["type"].as_str().unwrap_or("unknown").to_string();
        let result = rpc_stream(
            self.client.data_channel(),
            &mut self.pq_session,
            request,
            content,
        )
        .await
        .map_err(|error| {
            io::Error::other(format!("WebRTC Direct {request_type} RPC failed: {error}"))
        })?;
        self.requests_sent += 1;
        Ok(result)
    }

    #[cfg(feature = "test-utils")]
    async fn chunk_rpc(
        &mut self,
        request_id: u64,
        body: ant_protocol::ChunkMessageBody,
    ) -> Result<ant_protocol::ChunkMessageBody, Box<dyn Error>> {
        let message = ant_protocol::ChunkMessage { request_id, body }.encode()?;
        let (header, content) = self.rpc(json!({
            "version": BROWSER_PROTOCOL_VERSION, "request_id": request_id, "type": "chunk_protocol",
        }), &message).await?;
        assert_eq!(header["type"], "chunk_protocol");
        let response = ant_protocol::ChunkMessage::decode(&content)?;
        assert_eq!(response.request_id, request_id);
        Ok(response.body)
    }

    #[cfg(feature = "test-utils")]
    const fn requests_sent(&self) -> usize {
        self.requests_sent
    }

    async fn close(self) -> Result<(), Box<dyn Error>> {
        self.client.close().await?;
        Ok(())
    }
}

async fn rpc_stream(
    channel: &WebRtcDataChannel,
    pq_session: &mut PqSession,
    mut request: Value,
    content: &[u8],
) -> Result<(Value, Vec<u8>), Box<dyn Error>> {
    request["content_length"] = json!(content.len());
    let request_header = serde_json::to_vec(&request)?;
    let mut request_frame = Vec::with_capacity(request_header.len() + content.len());
    request_frame.extend_from_slice(&request_header);
    request_frame.extend_from_slice(content);
    let encrypted = pq_session.seal(&request_frame)?;
    send_pq_payload(channel, &encrypted).await?;

    let encrypted = read_pq_payload(
        channel,
        saorsa_transport::webrtc::MAX_BROWSER_FRAME_BYTES + PQ_ENCRYPTED_OVERHEAD_BYTES,
    )
    .await?;
    let frame = pq_session.open(&encrypted)?;
    let parsed = saorsa_transport::webrtc::parse_response_frame(&frame)?;
    let header = serde_json::to_value(parsed.header)?;
    let content_offset = frame.len() - parsed.content.len();
    let content_length = header["content_length"]
        .as_u64()
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid content length"))?;
    let expected = content_offset
        .checked_add(content_length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response length overflow"))?;
    if frame.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WebRtcDirect response length does not match its header",
        )
        .into());
    }
    Ok((header, frame[content_offset..].to_vec()))
}

async fn establish_pq_session(
    channel: &WebRtcDataChannel,
    expected_peer_id: &[u8; 32],
) -> Result<PqSession, Box<dyn Error>> {
    let (handshake, client_hello) = PqClientHandshake::start()?;
    send_pq_payload(channel, &client_hello).await?;
    let server_accept = read_pq_payload(channel, PQ_SERVER_ACCEPT_BYTES).await?;
    Ok(handshake.finish(&server_accept, expected_peer_id)?)
}

async fn send_pq_payload(
    channel: &WebRtcDataChannel,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let frame = encode_pq_frame(payload)?;
    for chunk in frame.chunks(WEBRTC_WRITE_CHUNK_BYTES) {
        channel.send(chunk).await?;
    }
    Ok(())
}

async fn read_pq_payload(
    channel: &WebRtcDataChannel,
    max_payload_bytes: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = Vec::new();
    let expected = loop {
        let message = channel.receive().await?;
        if message.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "WebRtcDirect PQ frame channel closed",
            )
            .into());
        }
        frame.extend_from_slice(&message);
        if let Some(expected) = pq_frame_length(&frame, max_payload_bytes)? {
            if frame.len() > expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebRtcDirect PQ frame has trailing bytes",
                )
                .into());
            }
            if frame.len() == expected {
                break expected;
            }
        }
    };
    debug_assert_eq!(frame.len(), expected);
    Ok(decode_pq_frame(&frame, max_payload_bytes)?)
}
