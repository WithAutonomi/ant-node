//! Self-encryption integration for file encrypt/decrypt.
//!
//! Wraps the `self_encryption` crate's streaming API to provide:
//! - **Streaming encryption** with bounded-memory concurrent upload
//! - **Streaming decryption** to file path (bounded memory via batch fetching)
//! - **`DataMap` serialization** for public/private data modes
//!
//! ## Public vs Private Data
//!
//! - **Public**: `DataMap` is stored as a chunk on the network; anyone with
//!   the `DataMap` address can reconstruct the file.
//! - **Private** (default): `DataMap` is returned to the caller and never
//!   uploaded. Only the holder of the `DataMap` can access the file.

use crate::client::data_types::XorName as ChunkAddress;
use crate::client::quantum::{PaidChunk, PreparedChunk, QuantumClient};
use crate::error::{Error, Result};
use bytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use self_encryption::DataMap;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::BuildHasher;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;
use tracing::{info, warn};
use xor_name::XorName;

/// Size of the read buffer used when streaming file data into the encryptor.
const READ_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum chunks per payment wave.
///
/// Balances EVM gas efficiency (more chunks per tx = fewer on-chain transactions)
/// against pipeline responsiveness (smaller waves = earlier store overlap).
/// evmlib supports up to 256 non-zero payments per transaction.
const PAYMENT_WAVE_SIZE: usize = 64;

/// Shared error capture used by `open_encrypt_stream`.
type ReadErrorCapture = Arc<Mutex<Option<std::io::Error>>>;

/// Open a file and produce a streaming encryption iterator.
///
/// Returns the encrypted-chunk stream and an error capture that should be
/// checked after iteration completes.
#[allow(clippy::type_complexity)]
fn open_encrypt_stream(
    file_path: &Path,
    file_size: usize,
) -> Result<(
    self_encryption::EncryptionStream<impl Iterator<Item = Bytes>>,
    ReadErrorCapture,
)> {
    let file = std::fs::File::open(file_path).map_err(Error::Io)?;
    let mut reader = BufReader::new(file);
    let read_error: Arc<Mutex<Option<std::io::Error>>> = Arc::new(Mutex::new(None));
    let read_error_writer = Arc::clone(&read_error);
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let data_iter = std::iter::from_fn(move || match reader.read(&mut buf) {
        Ok(0) => None,
        Err(e) => {
            if let Ok(mut guard) = read_error_writer.lock() {
                *guard = Some(e);
            }
            None
        }
        Ok(n) => Some(Bytes::copy_from_slice(&buf[..n])),
    });

    // NOTE: Chunk size headroom for encryption overhead is managed by the
    // self_encryption crate itself. See self_encryption::MAX_CHUNK_SIZE.
    let stream = self_encryption::stream_encrypt(file_size, data_iter)
        .map_err(|e| Error::Crypto(format!("Self-encryption failed: {e}")))?;

    Ok((stream, read_error))
}

/// Check whether the read-error capture from `open_encrypt_stream` recorded
/// an I/O error during iteration.
fn check_read_error(read_error: &ReadErrorCapture) -> Result<()> {
    if let Ok(guard) = read_error.lock() {
        if let Some(ref e) = *guard {
            return Err(Error::Io(std::io::Error::new(e.kind(), format!("{e}"))));
        }
    }
    Ok(())
}

/// Write a stream of decrypted chunks to a file atomically.
///
/// Writes to a temporary file first, then renames on success.
/// Cleans up the temp file on error.
fn write_stream_to_file(
    stream: impl Iterator<Item = std::result::Result<Bytes, self_encryption::Error>>,
    output_path: &Path,
) -> Result<()> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let unique: u64 = rand::random();
    let tmp_path = parent.join(format!(
        ".saorsa_decrypt_{}_{unique}.tmp",
        std::process::id()
    ));

    let result = (|| -> Result<()> {
        let mut file = std::fs::File::create(&tmp_path).map_err(Error::Io)?;
        for chunk_result in stream {
            let chunk_bytes =
                chunk_result.map_err(|e| Error::Crypto(format!("Decryption failed: {e}")))?;
            file.write_all(&chunk_bytes).map_err(Error::Io)?;
        }
        Ok(())
    })();

    if let Err(e) = result {
        if let Err(cleanup_err) = std::fs::remove_file(&tmp_path) {
            warn!(
                "Failed to remove temp file {}: {cleanup_err}",
                tmp_path.display()
            );
        }
        return Err(e);
    }

    // On Windows, rename fails if destination exists. Remove it first.
    if output_path.exists() {
        std::fs::remove_file(output_path).map_err(Error::Io)?;
    }
    std::fs::rename(&tmp_path, output_path).map_err(Error::Io)?;

    Ok(())
}

/// Encrypt a file using streaming self-encryption and upload chunks with
/// pipelined, wave-based EVM payment.
///
/// The upload proceeds as follows:
/// 1. **Stream** encrypted chunks lazily from the file — at most one wave
///    of chunks lives in memory at a time.
/// 2. **Wave loop** — for each wave of `PAYMENT_WAVE_SIZE` chunks:
///    - **Quote** the wave concurrently, while draining completed stores
///      from the previous wave via `select!`.
///    - **Pay** the wave in a single EVM transaction.
///    - **Launch stores** for the wave (non-blocking, added to the shared
///      store pool).
/// 3. **Drain** — await any remaining in-flight stores.
/// 4. **`DataMap`** — extract the `DataMap` after the encryption stream is
///    exhausted.
///
/// This gives us batched payments (no nonce collisions, fewer on-chain txs),
/// pipelining (stores from wave N overlap with quotes for wave N+1), and
/// bounded memory (only one wave of chunks buffered at a time).
///
/// Returns the `DataMap` after all chunks are uploaded, plus the list of
/// transaction hash strings from payment.
///
/// # Errors
///
/// Returns an error if encryption, quoting, payment, or storage fails.
#[allow(clippy::too_many_lines)]
pub async fn encrypt_and_upload_file(
    file_path: &Path,
    client: &QuantumClient,
) -> Result<(DataMap, Vec<String>)> {
    let metadata = std::fs::metadata(file_path).map_err(Error::Io)?;
    let file_size: usize = metadata
        .len()
        .try_into()
        .map_err(|_| Error::Crypto("File too large for this platform".into()))?;
    info!(
        "Encrypting file: {} ({file_size} bytes)",
        file_path.display()
    );

    let (mut stream, read_error) = open_encrypt_stream(file_path, file_size)?;
    let mut all_tx_hashes: Vec<String> = Vec::new();
    let mut chunk_count: usize = 0;
    let mut duplicates_skipped: usize = 0;

    // Track chunk addresses already paid for to avoid duplicate payments
    // across waves. Content-addressed chunks (BLAKE3) with identical content
    // share the same address, so we only need to pay once.
    let mut paid_addresses: HashSet<XorName> = HashSet::new();

    // Shared pool of in-flight store operations across all waves.
    let mut store_futs: FuturesUnordered<
        Pin<Box<dyn Future<Output = Result<ChunkAddress>> + Send + '_>>,
    > = FuturesUnordered::new();

    // Stream chunks lazily in waves — only one wave of content in memory at a time.
    // The block scope ensures `chunks_iter` (which borrows `stream` mutably)
    // is dropped before we call `stream.into_datamap()`.
    {
        let mut chunks_iter = stream.chunks();
        let mut wave_idx: usize = 0;

        loop {
            // Pull the next wave of chunks from the encryption stream,
            // skipping any chunk whose address was already paid in a prior wave.
            let mut wave: Vec<Bytes> = Vec::with_capacity(PAYMENT_WAVE_SIZE);
            for chunk_result in chunks_iter.by_ref() {
                let (hash, content) = chunk_result
                    .map_err(|e| Error::Crypto(format!("Self-encryption failed: {e}")))?;
                if !paid_addresses.insert(hash) {
                    duplicates_skipped += 1;
                    continue;
                }
                wave.push(content);
                if wave.len() >= PAYMENT_WAVE_SIZE {
                    break;
                }
            }

            if wave.is_empty() {
                break;
            }

            let wave_size = wave.len();
            chunk_count += wave_size;
            info!(
                "Wave {wave_idx}: quoting {wave_size} chunks ({} stores in flight)",
                store_futs.len()
            );

            // Quote this wave concurrently, draining completed stores in parallel.
            let prepared = quote_wave_pipelined(&wave, client, &mut store_futs).await?;

            // Pay for this wave (single EVM transaction).
            let paid = client.batch_pay(prepared).await?;

            // Launch stores for this wave — content moves into the futures,
            // freeing the wave buffer for the next iteration.
            for paid_chunk in paid {
                all_tx_hashes.extend(paid_chunk.tx_hashes.iter().map(|tx| format!("{tx:?}")));
                store_futs.push(Box::pin(store_paid_chunk(client, paid_chunk)));
            }

            wave_idx += 1;
        }
    }

    // Drain remaining stores.
    while let Some(result) = store_futs.next().await {
        result?;
    }

    check_read_error(&read_error)?;

    let data_map = stream
        .into_datamap()
        .ok_or_else(|| Error::Crypto("DataMap not available after encryption".into()))?;

    if duplicates_skipped > 0 {
        info!(
            "All {chunk_count} unique encrypted chunks uploaded ({duplicates_skipped} duplicates skipped)"
        );
    } else {
        info!("All {chunk_count} encrypted chunks uploaded");
    }
    Ok((data_map, all_tx_hashes))
}

/// Store a single paid chunk on the network.
async fn store_paid_chunk(client: &QuantumClient, paid: PaidChunk) -> Result<ChunkAddress> {
    client
        .put_chunk_with_proof(paid.content, paid.proof_bytes, &paid.target_peer)
        .await
}

/// Quote a wave of chunks while draining completed stores from prior waves.
///
/// Uses `select!` to multiplex between collecting quotes for the current wave
/// and acknowledging completed stores, so stores from the previous wave make
/// progress concurrently with the current wave's DHT quote requests.
async fn quote_wave_pipelined<'a>(
    wave: &[Bytes],
    client: &'a QuantumClient,
    store_futs: &mut FuturesUnordered<
        Pin<Box<dyn Future<Output = Result<ChunkAddress>> + Send + 'a>>,
    >,
) -> Result<Vec<PreparedChunk>> {
    let wave_len = wave.len();
    let mut quote_futs = FuturesUnordered::new();

    for (idx, content) in wave.iter().enumerate() {
        let content = content.clone();
        let fut = async move { (idx, client.prepare_chunk_payment(content).await) };
        quote_futs.push(fut);
    }

    let mut results: Vec<(usize, PreparedChunk)> = Vec::with_capacity(wave_len);

    while results.len() < wave_len {
        tokio::select! {
            biased;
            // Drain completed stores from previous waves to free resources.
            Some(store_result) = store_futs.next(), if !store_futs.is_empty() => {
                store_result?;
            }
            // Collect quotes for this wave.
            Some((idx, quote_result)) = quote_futs.next() => {
                results.push((idx, quote_result?));
            }
        }
    }

    results.sort_by_key(|(idx, _)| *idx);
    Ok(results.into_iter().map(|(_, prep)| prep).collect())
}

/// Encrypt a file from disk using `stream_encrypt`, returning the `DataMap`
/// and a list of `(XorName, Bytes)` encrypted chunks.
fn encrypt_file_to_chunks(
    file_path: &Path,
    file_size: usize,
) -> Result<(DataMap, Vec<(XorName, Bytes)>)> {
    let (mut stream, read_error) = open_encrypt_stream(file_path, file_size)?;

    let mut chunks = Vec::new();
    for chunk_result in stream.chunks() {
        let (hash, content) =
            chunk_result.map_err(|e| Error::Crypto(format!("Self-encryption failed: {e}")))?;
        chunks.push((hash, content));
    }

    check_read_error(&read_error)?;

    let data_map = stream
        .into_datamap()
        .ok_or_else(|| Error::Crypto("DataMap not available after encryption".into()))?;

    Ok((data_map, chunks))
}

/// Download and decrypt a file given its `DataMap`.
///
/// Uses `streaming_decrypt()` which yields decrypted chunks as an iterator,
/// fetching encrypted chunks on-demand in batches from the network.
///
/// The sync callback required by `streaming_decrypt` bridges to async via
/// `block_in_place` + `block_on`, but fetches all chunks in each batch
/// concurrently using `FuturesUnordered`. This means each `block_on` call
/// resolves an entire batch in parallel rather than fetching one chunk at a
/// time, reducing thread pool contention to one blocking call per batch
/// instead of one per chunk.
///
/// Memory usage is bounded by the batch size (default ~10 chunks), not
/// the total file size.
///
/// # Errors
///
/// Returns an error if any chunk cannot be fetched or decryption fails.
pub async fn download_and_decrypt_file(
    data_map: &DataMap,
    output_path: &Path,
    client: &QuantumClient,
) -> Result<()> {
    let chunk_count = data_map.chunk_identifiers.len();
    info!("Decrypting file: {chunk_count} chunk(s) to decrypt (fetching on-demand)");

    let handle = Handle::current();

    let stream = self_encryption::streaming_decrypt(data_map, |batch: &[(usize, XorName)]| {
        let batch_owned: Vec<(usize, XorName)> = batch.to_vec();

        // block_in_place panics on current_thread runtime, and handle.block_on
        // deadlocks there. Reject unsupported runtime flavors explicitly.
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
            return Err(self_encryption::Error::Generic(
                "download_and_decrypt_file requires a multi_thread tokio runtime".into(),
            ));
        }
        tokio::task::block_in_place(|| {
            handle.block_on(async {
                let mut futs = FuturesUnordered::new();
                for (idx, hash) in batch_owned {
                    let addr = hash.0;
                    futs.push(async move {
                        let result = client.get_chunk(&addr).await;
                        (idx, hash, result)
                    });
                }

                let mut results = Vec::with_capacity(futs.len());
                while let Some((idx, hash, result)) = futs.next().await {
                    let addr_hex = hex::encode(hash.0);
                    let chunk = result
                        .map_err(|e| {
                            self_encryption::Error::Generic(format!(
                                "Network fetch failed for {addr_hex}: {e}"
                            ))
                        })?
                        .ok_or_else(|| {
                            self_encryption::Error::Generic(format!(
                                "Chunk not found on network: {addr_hex}"
                            ))
                        })?;
                    results.push((idx, chunk.content));
                }
                Ok(results)
            })
        })
    })
    .map_err(|e| Error::Crypto(format!("Decryption failed: {e}")))?;

    write_stream_to_file(stream, output_path)?;

    info!("Decryption complete: {}", output_path.display());
    Ok(())
}

/// Serialize a `DataMap` to bytes using bincode (via `DataMap::to_bytes`).
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_data_map(data_map: &DataMap) -> Result<Vec<u8>> {
    data_map
        .to_bytes()
        .map_err(|e| Error::Serialization(format!("Failed to serialize DataMap: {e}")))
}

/// Deserialize a `DataMap` from bytes.
///
/// # Errors
///
/// Returns an error if deserialization fails.
pub fn deserialize_data_map(bytes: &[u8]) -> Result<DataMap> {
    DataMap::from_bytes(bytes)
        .map_err(|e| Error::Serialization(format!("Failed to deserialize DataMap: {e}")))
}

/// Store a `DataMap` as a chunk on the network (public mode).
///
/// Serializes the `DataMap` and uploads it as a regular content-addressed chunk.
/// Returns the address (BLAKE3 hash) of the stored `DataMap` chunk.
///
/// # Errors
///
/// Returns an error if serialization or upload fails.
pub async fn store_data_map_public(
    data_map: &DataMap,
    client: &QuantumClient,
) -> Result<(ChunkAddress, Vec<String>)> {
    let data_map_bytes = serialize_data_map(data_map)?;
    let content = Bytes::from(data_map_bytes);
    let (address, tx_hashes) = client.put_chunk_with_payment(content).await?;
    let tx_strs: Vec<String> = tx_hashes.iter().map(|tx| format!("{tx:?}")).collect();
    let address_hex = hex::encode(address);
    info!("DataMap stored publicly at {address_hex}");
    Ok((address, tx_strs))
}

/// Retrieve a `DataMap` from the network (public mode).
///
/// Fetches the `DataMap` chunk by address and deserializes it.
///
/// # Errors
///
/// Returns an error if the chunk is not found or deserialization fails.
pub async fn fetch_data_map_public(
    address: &ChunkAddress,
    client: &QuantumClient,
) -> Result<DataMap> {
    let chunk = client.get_chunk(address).await?.ok_or_else(|| {
        Error::Storage(format!(
            "DataMap chunk not found at {}",
            hex::encode(address)
        ))
    })?;
    deserialize_data_map(&chunk.content)
}

/// Encrypt a file to a local chunk store (no network). Useful for testing.
///
/// Returns the `DataMap` and a `HashMap` of `XorName` -> `Bytes` containing
/// all encrypted chunks.
///
/// # Errors
///
/// Returns an error if the file cannot be read or encryption fails.
pub fn encrypt_file_local(file_path: &Path) -> Result<(DataMap, HashMap<XorName, Bytes>)> {
    let file_size: usize = std::fs::metadata(file_path)
        .map_err(Error::Io)?
        .len()
        .try_into()
        .map_err(|_| Error::Crypto("File too large for this platform".into()))?;
    let (data_map, chunk_list) = encrypt_file_to_chunks(file_path, file_size)?;
    let store: HashMap<XorName, Bytes> = chunk_list.into_iter().collect();
    Ok((data_map, store))
}

/// Decrypt a file from a local chunk store (no network). Useful for testing.
///
/// # Errors
///
/// Returns an error if any chunk is missing or decryption fails.
pub fn decrypt_file_local<S: BuildHasher>(
    data_map: &DataMap,
    chunk_store: &HashMap<XorName, Bytes, S>,
    output_path: &Path,
) -> Result<()> {
    decrypt_from_store(data_map, chunk_store, output_path)
}

/// Shared helper: decrypt a `DataMap` using a chunk store `HashMap`.
fn decrypt_from_store<S: BuildHasher>(
    data_map: &DataMap,
    chunk_store: &HashMap<XorName, Bytes, S>,
    output_path: &Path,
) -> Result<()> {
    let stream = self_encryption::streaming_decrypt(data_map, |batch: &[(usize, XorName)]| {
        let mut results = Vec::with_capacity(batch.len());
        for &(idx, ref hash) in batch {
            let content = chunk_store.get(hash).ok_or_else(|| {
                self_encryption::Error::Generic(format!("Chunk not found: {hash:?}"))
            })?;
            results.push((idx, content.clone()));
        }
        Ok(results)
    })
    .map_err(|e| Error::Crypto(format!("Decryption failed: {e}")))?;

    write_stream_to_file(stream, output_path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::data_types::compute_address;
    use std::io::Write;

    fn create_temp_file(content: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_small() {
        let original = vec![0xABu8; 4096];
        let input_file = create_temp_file(&original);

        let (data_map, store) = encrypt_file_local(input_file.path()).unwrap();
        assert!(
            !data_map.chunk_identifiers.is_empty(),
            "DataMap should have chunk identifiers"
        );

        let output_file = tempfile::NamedTempFile::new().unwrap();
        decrypt_file_local(&data_map, &store, output_file.path()).unwrap();

        let decrypted = std::fs::read(output_file.path()).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_medium() {
        let original: Vec<u8> = (0u8..=255).cycle().take(1_048_576).collect();
        let input_file = create_temp_file(&original);

        let (data_map, store) = encrypt_file_local(input_file.path()).unwrap();

        let output_file = tempfile::NamedTempFile::new().unwrap();
        decrypt_file_local(&data_map, &store, output_file.path()).unwrap();

        let decrypted = std::fs::read(output_file.path()).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_produces_encrypted_output() {
        let original = b"This is a known plaintext pattern for testing encryption";
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend_from_slice(original);
        }
        let input_file = create_temp_file(&data);

        let (_data_map, store) = encrypt_file_local(input_file.path()).unwrap();

        let plaintext_str = "This is a known plaintext pattern";
        for content in store.values() {
            let chunk_str = String::from_utf8_lossy(content);
            assert!(
                !chunk_str.contains(plaintext_str),
                "Encrypted chunk should not contain plaintext"
            );
        }
    }

    #[test]
    fn test_data_map_serialization_roundtrip() {
        let original = vec![0xCDu8; 8192];
        let input_file = create_temp_file(&original);

        let (data_map, _store) = encrypt_file_local(input_file.path()).unwrap();

        let serialized = serialize_data_map(&data_map).unwrap();
        let deserialized = deserialize_data_map(&serialized).unwrap();

        assert_eq!(
            data_map.chunk_identifiers.len(),
            deserialized.chunk_identifiers.len()
        );
        assert_eq!(data_map.child, deserialized.child);
    }

    #[test]
    fn test_data_map_contains_correct_chunk_count() {
        let original = vec![0xEFu8; 1_048_576];
        let input_file = create_temp_file(&original);

        let (data_map, store) = encrypt_file_local(input_file.path()).unwrap();

        assert!(
            data_map.chunk_identifiers.len() >= 3,
            "Should have at least 3 chunk identifiers, got {}",
            data_map.chunk_identifiers.len()
        );

        for info in &data_map.chunk_identifiers {
            assert!(
                store.contains_key(&info.dst_hash),
                "Chunk store should contain chunk referenced by DataMap"
            );
        }
    }

    #[test]
    fn test_encrypted_chunks_have_valid_addresses() {
        let original = vec![0x42u8; 8192];
        let input_file = create_temp_file(&original);

        let (data_map, store) = encrypt_file_local(input_file.path()).unwrap();

        for info in &data_map.chunk_identifiers {
            let content = store.get(&info.dst_hash).expect("Chunk should exist");
            let computed = compute_address(content);
            assert_eq!(
                computed, info.dst_hash.0,
                "BLAKE3(encrypted_content) should equal dst_hash"
            );
        }
    }

    #[test]
    fn test_decryption_fails_without_correct_data_map() {
        let original = vec![0x11u8; 8192];
        let input_file = create_temp_file(&original);
        let (_data_map, store) = encrypt_file_local(input_file.path()).unwrap();

        let other = vec![0x22u8; 8192];
        let other_file = create_temp_file(&other);
        let (wrong_data_map, _) = encrypt_file_local(other_file.path()).unwrap();

        let output_file = tempfile::NamedTempFile::new().unwrap();
        let result = decrypt_file_local(&wrong_data_map, &store, output_file.path());

        assert!(result.is_err(), "Decryption with wrong DataMap should fail");
    }

    #[test]
    fn test_cannot_recover_data_from_chunks_alone() {
        let original = vec![0x33u8; 8192];
        let input_file = create_temp_file(&original);
        let (_data_map, store) = encrypt_file_local(input_file.path()).unwrap();

        let mut concatenated = Vec::new();
        for content in store.values() {
            concatenated.extend_from_slice(content);
        }

        assert_ne!(
            concatenated, original,
            "Concatenated chunks should not match original data"
        );
    }

    #[test]
    fn test_chunks_do_not_contain_plaintext_patterns() {
        let pattern = b"SENTINEL_PATTERN_12345";
        let mut data = Vec::with_capacity(pattern.len() * 500);
        for _ in 0..500 {
            data.extend_from_slice(pattern);
        }
        let input_file = create_temp_file(&data);

        let (_data_map, store) = encrypt_file_local(input_file.path()).unwrap();

        for content in store.values() {
            let found = content
                .windows(pattern.len())
                .any(|window| window == pattern);
            assert!(
                !found,
                "Encrypted chunks must not contain plaintext patterns"
            );
        }
    }

    #[test]
    fn test_missing_chunk_fails_decryption() {
        let original = vec![0x44u8; 8192];
        let input_file = create_temp_file(&original);
        let (data_map, mut store) = encrypt_file_local(input_file.path()).unwrap();

        if let Some(info) = data_map.chunk_identifiers.first() {
            store.remove(&info.dst_hash);
        }

        let output_file = tempfile::NamedTempFile::new().unwrap();
        let result = decrypt_file_local(&data_map, &store, output_file.path());

        assert!(
            result.is_err(),
            "Decryption should fail with a missing chunk"
        );
    }

    #[test]
    fn test_tampered_chunk_detected() {
        let original = vec![0x55u8; 8192];
        let input_file = create_temp_file(&original);
        let (data_map, mut store) = encrypt_file_local(input_file.path()).unwrap();

        if let Some(info) = data_map.chunk_identifiers.first() {
            if let Some(content) = store.get_mut(&info.dst_hash) {
                let mut tampered = content.to_vec();
                if let Some(byte) = tampered.first_mut() {
                    *byte ^= 0xFF;
                }
                *content = Bytes::from(tampered);
            }
        }

        let output_file = tempfile::NamedTempFile::new().unwrap();
        let result = decrypt_file_local(&data_map, &store, output_file.path());

        assert!(
            result.is_err(),
            "Decryption should fail with tampered chunk"
        );
    }

    #[test]
    fn test_wrong_data_map_fails_decryption() {
        let original_a = vec![0x66u8; 8192];
        let file_a = create_temp_file(&original_a);
        let (data_map_a, _store_a) = encrypt_file_local(file_a.path()).unwrap();

        let original_b = vec![0x77u8; 8192];
        let file_b = create_temp_file(&original_b);
        let (_data_map_b, store_b) = encrypt_file_local(file_b.path()).unwrap();

        let output_file = tempfile::NamedTempFile::new().unwrap();
        let result = decrypt_file_local(&data_map_a, &store_b, output_file.path());

        assert!(
            result.is_err(),
            "Decryption with mismatched DataMap should fail"
        );
    }

    #[test]
    #[ignore = "Requires ugly_files/kad.pdf to be present"]
    fn test_encrypt_decrypt_pdf() {
        let pdf_path = Path::new("ugly_files/kad.pdf");
        if !pdf_path.exists() {
            return;
        }
        let original = std::fs::read(pdf_path).unwrap();

        let (data_map, store) = encrypt_file_local(pdf_path).unwrap();

        let output_file = tempfile::NamedTempFile::new().unwrap();
        decrypt_file_local(&data_map, &store, output_file.path()).unwrap();

        let decrypted = std::fs::read(output_file.path()).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    #[ignore = "Requires ugly_files/pylon.mp4 to be present"]
    fn test_encrypt_decrypt_video() {
        let video_path = Path::new("ugly_files/pylon.mp4");
        if !video_path.exists() {
            return;
        }
        let original = std::fs::read(video_path).unwrap();

        let (data_map, store) = encrypt_file_local(video_path).unwrap();

        let output_file = tempfile::NamedTempFile::new().unwrap();
        decrypt_file_local(&data_map, &store, output_file.path()).unwrap();

        let decrypted = std::fs::read(output_file.path()).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_file_below_min_encryptable_bytes_fails() {
        // Files smaller than MIN_ENCRYPTABLE_BYTES (3 bytes) should fail
        let tiny = create_temp_file(&[0xAA, 0xBB]);
        let result = encrypt_file_local(tiny.path());
        assert!(
            result.is_err(),
            "Encryption of 2-byte file should fail (below MIN_ENCRYPTABLE_BYTES)"
        );
    }

    #[test]
    fn test_encrypt_at_minimum_size() {
        // Exactly MIN_ENCRYPTABLE_BYTES = 3 bytes should succeed
        let data = vec![0xAAu8; 3];
        let input_file = create_temp_file(&data);

        let (data_map, store) = encrypt_file_local(input_file.path()).unwrap();
        assert!(
            !data_map.chunk_identifiers.is_empty(),
            "DataMap should have chunk identifiers for 3-byte file"
        );

        let output_file = tempfile::NamedTempFile::new().unwrap();
        decrypt_file_local(&data_map, &store, output_file.path()).unwrap();

        let decrypted = std::fs::read(output_file.path()).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_deterministic_encryption() {
        // Same content should produce the same DataMap and chunks
        let data = vec![0xDDu8; 8192];
        let file_a = create_temp_file(&data);
        let file_b = create_temp_file(&data);

        let (data_map_a, store_a) = encrypt_file_local(file_a.path()).unwrap();
        let (data_map_b, store_b) = encrypt_file_local(file_b.path()).unwrap();

        assert_eq!(
            data_map_a.chunk_identifiers.len(),
            data_map_b.chunk_identifiers.len(),
            "Same content should produce same number of chunks"
        );

        for (a, b) in data_map_a
            .chunk_identifiers
            .iter()
            .zip(data_map_b.chunk_identifiers.iter())
        {
            assert_eq!(a.dst_hash, b.dst_hash, "Chunk addresses should match");
        }

        // Verify stores have the same keys
        for key in store_a.keys() {
            assert!(
                store_b.contains_key(key),
                "Both stores should contain the same chunk addresses"
            );
        }
    }

    #[test]
    fn test_empty_file_fails() {
        let empty = create_temp_file(&[]);
        let result = encrypt_file_local(empty.path());
        assert!(
            result.is_err(),
            "Encryption of empty file should fail (below MIN_ENCRYPTABLE_BYTES)"
        );
    }
}
