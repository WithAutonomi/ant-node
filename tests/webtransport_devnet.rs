//! Live ADR-0009 local-devnet protocol test.

use ant_node::devnet::{Devnet, DevnetConfig};
use bytes::Bytes;
use self_encryption::{DataMap, EncryptedChunk};
use serde_json::{json, Value};
use std::error::Error;
use std::io;
use tokio::io::AsyncReadExt;
use wtransport::endpoint::ConnectOptions;
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Endpoint};

const TEST_ORIGIN: &str = "http://127.0.0.1:5173";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a five-node local network"]
#[allow(clippy::too_many_lines)]
async fn seeded_public_file_downloads_over_a_direct_node_endpoint() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut config = DevnetConfig::minimal();
    config.base_port = 0;
    config.webtransport = true;
    config.webtransport_base_port = 0;
    config.webtransport_allowed_origins = vec![TEST_ORIGIN.to_string()];
    config.data_dir = temp.path().join("browser-devnet");
    config.spawn_delay = std::time::Duration::from_millis(20);

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
    let (hello, hello_content) = rpc(
        &endpoint.endpoint.url,
        &endpoint.endpoint.certificate_sha256,
        json!({
            "version": 1,
            "request_id": 5,
            "type": "hello",
        }),
    )
    .await?;
    assert_eq!(hello["status"], "ok");
    assert_eq!(hello["protocol"], "autonomi.web.poc.v1");
    assert_eq!(hello["peer_id"], endpoint.peer_id);
    assert!(hello_content.is_empty());

    let (closest, closest_content) = rpc(
        &endpoint.endpoint.url,
        &endpoint.endpoint.certificate_sha256,
        json!({
            "version": 1,
            "request_id": 6,
            "type": "find_node",
            "target": public_file.address,
            "count": 20,
        }),
    )
    .await?;
    assert_eq!(closest["status"], "ok");
    assert_eq!(closest["type"], "nodes");
    assert_eq!(closest["target"], public_file.address);
    assert!(closest_content.is_empty());
    let discovered_peer = closest["nodes"]
        .as_array()
        .and_then(|nodes| nodes.iter().find(|node| node["webtransport"].is_object()))
        .and_then(|node| node["peer_id"].as_str())
        .ok_or_else(|| io::Error::other("FIND_NODE returned no browser endpoint"))?;
    let download_endpoint = endpoints
        .iter()
        .find(|candidate| candidate.peer_id == discovered_peer)
        .ok_or_else(|| io::Error::other("discovered endpoint was not in the devnet catalog"))?;
    let (header, data_map_bytes) = rpc(
        &download_endpoint.endpoint.url,
        &download_endpoint.endpoint.certificate_sha256,
        json!({
            "version": 1,
            "request_id": 7,
            "type": "get_chunk",
            "address": public_file.address,
        }),
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
        let (chunk_header, chunk_bytes) = rpc(
            &download_endpoint.endpoint.url,
            &download_endpoint.endpoint.certificate_sha256,
            json!({
                "version": 1,
                "request_id": request_id,
                "type": "get_chunk",
                "address": chunk.dst_hash,
            }),
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

    devnet.shutdown().await?;
    Ok(())
}

async fn rpc(
    url: &str,
    certificate_sha256: &str,
    request: Value,
) -> Result<(Value, Vec<u8>), Box<dyn Error>> {
    let hash: [u8; 32] =
        hex::decode(certificate_sha256)?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("certificate hash has {} bytes", bytes.len()),
                )
            })?;
    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([Sha256Digest::new(hash)])
        .build();
    let endpoint = Endpoint::client(client_config)?;
    let options = ConnectOptions::builder(url)
        .add_header("origin", TEST_ORIGIN)
        .build();
    let connection = endpoint.connect(options).await?;
    let (mut send, mut recv) = connection.open_bi().await?.await?;
    send.write_all(&serde_json::to_vec(&request)?).await?;
    send.finish().await?;

    let mut frame = Vec::new();
    recv.read_to_end(&mut frame).await?;
    if frame.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "WebTransport response has no header length",
        )
        .into());
    }
    let header_len = u32::from_be_bytes(frame[0..4].try_into()?) as usize;
    let content_offset = 4usize
        .checked_add(header_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "header length overflow"))?;
    if content_offset > frame.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "WebTransport response ended inside its JSON header",
        )
        .into());
    }
    let header = serde_json::from_slice(&frame[4..content_offset])?;
    Ok((header, frame[content_offset..].to_vec()))
}
