//! Content-addressed LMDB storage for chunks.
//!
//! Provides persistent storage for chunks using LMDB (via heed) for
//! memory-mapped, zero-copy reads with ACID transactions.
//!
//! ```text
//! {root}/chunks.mdb/   -- LMDB environment directory
//! ```

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};
use std::path::{Path, PathBuf};
use tokio::task::spawn_blocking;
use tracing::{debug, trace, warn};

/// Default LMDB map size: 32 GiB.
///
/// Node operators can override this via `storage.db_size_gb` in `config.toml`.
const DEFAULT_MAX_MAP_SIZE: usize = 32 * 1_073_741_824; // 32 GiB

/// Configuration for LMDB storage.
#[derive(Debug, Clone)]
pub struct LmdbStorageConfig {
    /// Root directory for storage (LMDB env lives at `{root_dir}/chunks.mdb/`).
    pub root_dir: PathBuf,
    /// Whether to verify content on read (compares hash to address).
    pub verify_on_read: bool,
    /// Maximum number of chunks to store (0 = unlimited).
    pub max_chunks: usize,
    /// Maximum LMDB map size in bytes (0 = use default of 32 GiB).
    pub max_map_size: usize,
}

impl Default for LmdbStorageConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from(".saorsa/chunks"),
            verify_on_read: true,
            max_chunks: 0,
            max_map_size: 0,
        }
    }
}

/// Statistics about storage operations.
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Total number of chunks stored.
    pub chunks_stored: u64,
    /// Total number of chunks retrieved.
    pub chunks_retrieved: u64,
    /// Total bytes stored.
    pub bytes_stored: u64,
    /// Total bytes retrieved.
    pub bytes_retrieved: u64,
    /// Number of duplicate writes (already exists).
    pub duplicates: u64,
    /// Number of verification failures on read.
    pub verification_failures: u64,
    /// Number of chunks currently persisted.
    pub current_chunks: u64,
}

/// Content-addressed LMDB storage.
///
/// Uses heed (LMDB wrapper) for memory-mapped, transactional chunk storage.
/// Keys are 32-byte `XorName` addresses, values are raw chunk bytes.
pub struct LmdbStorage {
    /// LMDB environment.
    env: Env,
    /// The unnamed default database (key=XorName bytes, value=chunk bytes).
    db: Database<Bytes, Bytes>,
    /// Storage configuration.
    config: LmdbStorageConfig,
    /// Operation statistics.
    stats: parking_lot::RwLock<StorageStats>,
}

impl LmdbStorage {
    /// Create a new LMDB storage instance.
    ///
    /// Opens (or creates) an LMDB environment at `{root_dir}/chunks.mdb/`.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB environment cannot be opened.
    #[allow(unsafe_code)]
    pub async fn new(config: LmdbStorageConfig) -> Result<Self> {
        let env_dir = config.root_dir.join("chunks.mdb");

        // Create the directory synchronously before opening LMDB
        std::fs::create_dir_all(&env_dir)
            .map_err(|e| Error::Storage(format!("Failed to create LMDB directory: {e}")))?;

        let map_size = if config.max_map_size > 0 {
            config.max_map_size
        } else {
            DEFAULT_MAX_MAP_SIZE
        };

        let env_dir_clone = env_dir.clone();
        let (env, db) = spawn_blocking(move || -> Result<(Env, Database<Bytes, Bytes>)> {
            // SAFETY: `EnvOpenOptions::open()` is unsafe because LMDB uses memory-mapped
            // I/O and relies on OS file-locking to prevent corruption from concurrent
            // access by multiple processes. We satisfy this by giving each node instance
            // a unique `root_dir` (typically a directory named by its full 64-hex peer
            // ID), ensuring no two processes open the same LMDB environment. Callers
            // who manually configure `--root-dir` must not point multiple nodes at the
            // same directory.
            let env = unsafe {
                EnvOpenOptions::new()
                    .map_size(map_size)
                    .max_dbs(1)
                    .open(&env_dir_clone)
                    .map_err(|e| Error::Storage(format!("Failed to open LMDB env: {e}")))?
            };

            let mut wtxn = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;
            let db: Database<Bytes, Bytes> = env
                .create_database(&mut wtxn, None)
                .map_err(|e| Error::Storage(format!("Failed to create database: {e}")))?;
            wtxn.commit()
                .map_err(|e| Error::Storage(format!("Failed to commit db creation: {e}")))?;

            Ok((env, db))
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB init task failed: {e}")))??;

        let storage = Self {
            env,
            db,
            config,
            stats: parking_lot::RwLock::new(StorageStats::default()),
        };

        debug!(
            "Initialized LMDB storage at {:?} ({} existing chunks)",
            env_dir,
            storage.current_chunks()?
        );

        Ok(storage)
    }

    /// Store a chunk.
    ///
    /// # Arguments
    ///
    /// * `address` - Content address (should be BLAKE3 of content)
    /// * `content` - Chunk data
    ///
    /// # Returns
    ///
    /// Returns `true` if the chunk was newly stored, `false` if it already existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails or content doesn't match address.
    pub async fn put(&self, address: &XorName, content: &[u8]) -> Result<bool> {
        // Verify content address
        let computed = Self::compute_address(content);
        if computed != *address {
            return Err(Error::Storage(format!(
                "Content address mismatch: expected {}, computed {}",
                hex::encode(address),
                hex::encode(computed)
            )));
        }

        // Fast-path duplicate check (read-only, no write lock needed).
        // This is an optimistic hint — the authoritative check happens inside
        // the write transaction below to prevent TOCTOU races.
        if self.exists(address)? {
            trace!("Chunk {} already exists", hex::encode(address));
            self.stats.write().duplicates += 1;
            return Ok(false);
        }

        let key = *address;
        let value = content.to_vec();
        let env = self.env.clone();
        let db = self.db;
        let max_chunks = self.config.max_chunks;

        // Existence check, capacity enforcement, and write all happen atomically
        // inside a single write transaction. LMDB serializes write transactions,
        // so there are no TOCTOU races or counter-drift issues.
        let was_new = spawn_blocking(move || -> Result<bool> {
            let mut wtxn = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;

            // Authoritative existence check inside the serialized write txn
            if db
                .get(&wtxn, &key)
                .map_err(|e| Error::Storage(format!("Failed to check existence: {e}")))?
                .is_some()
            {
                return Ok(false);
            }

            // Enforce capacity limit (0 = unlimited)
            if max_chunks > 0 {
                let current = db
                    .stat(&wtxn)
                    .map_err(|e| Error::Storage(format!("Failed to read db stats: {e}")))?
                    .entries;
                if current >= max_chunks {
                    return Err(Error::Storage(format!(
                        "Storage capacity reached: {current} chunks stored, max is {max_chunks}"
                    )));
                }
            }

            db.put(&mut wtxn, &key, &value)
                .map_err(|e| Error::Storage(format!("Failed to put chunk: {e}")))?;
            wtxn.commit()
                .map_err(|e| Error::Storage(format!("Failed to commit put: {e}")))?;
            Ok(true)
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB put task failed: {e}")))??;

        if !was_new {
            trace!("Chunk {} already exists", hex::encode(address));
            self.stats.write().duplicates += 1;
            return Ok(false);
        }

        {
            let mut stats = self.stats.write();
            stats.chunks_stored += 1;
            stats.bytes_stored += content.len() as u64;
        }

        debug!(
            "Stored chunk {} ({} bytes)",
            hex::encode(address),
            content.len()
        );

        Ok(true)
    }

    /// Store data at the given address without content-address verification.
    ///
    /// Use this for data types where the address is not `BLAKE3(content)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub async fn put_raw(&self, address: &XorName, data: &[u8]) -> Result<bool> {
        // Fast-path duplicate check
        if self.exists(address)? {
            trace!("Record {} already exists", hex::encode(address));
            self.stats.write().duplicates += 1;
            return Ok(false);
        }

        let key = *address;
        let value = data.to_vec();
        let env = self.env.clone();
        let db = self.db;
        let max_chunks = self.config.max_chunks;

        let was_new = spawn_blocking(move || -> Result<bool> {
            let mut wtxn = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;

            if db
                .get(&wtxn, &key)
                .map_err(|e| Error::Storage(format!("Failed to check existence: {e}")))?
                .is_some()
            {
                return Ok(false);
            }

            if max_chunks > 0 {
                let current = db
                    .stat(&wtxn)
                    .map_err(|e| Error::Storage(format!("Failed to read db stats: {e}")))?
                    .entries;
                if current >= max_chunks {
                    return Err(Error::Storage(format!(
                        "Storage capacity reached: {current} stored, max is {max_chunks}"
                    )));
                }
            }

            db.put(&mut wtxn, &key, &value)
                .map_err(|e| Error::Storage(format!("Failed to put record: {e}")))?;
            wtxn.commit()
                .map_err(|e| Error::Storage(format!("Failed to commit put: {e}")))?;
            Ok(true)
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB put_raw task failed: {e}")))??;

        if !was_new {
            // Race: fast-path missed it, txn-level check caught it.
            self.stats.write().duplicates += 1;
            return Ok(false);
        }

        {
            let mut stats = self.stats.write();
            stats.chunks_stored += 1;
            stats.bytes_stored += data.len() as u64;
        }

        debug!(
            "Stored record {} ({} bytes)",
            hex::encode(address),
            data.len()
        );

        Ok(true)
    }

    /// Overwrite a record at the given address without content-address verification.
    ///
    /// Unlike `put_raw`, this does not check for existing records and will
    /// overwrite them. Used for mutable data types where
    /// the handler has already validated the update.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub async fn put_overwrite(&self, address: &XorName, data: &[u8]) -> Result<()> {
        let key = *address;
        let value = data.to_vec();
        let env = self.env.clone();
        let db = self.db;

        // Returns the byte length of the previous value, if any.
        let old_len: Option<usize> = spawn_blocking(move || -> Result<Option<usize>> {
            let mut wtxn = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;

            let prev_len = db
                .get(&wtxn, &key)
                .map_err(|e| Error::Storage(format!("Failed to read old record: {e}")))?
                .map(<[u8]>::len);

            db.put(&mut wtxn, &key, &value)
                .map_err(|e| Error::Storage(format!("Failed to put record: {e}")))?;
            wtxn.commit()
                .map_err(|e| Error::Storage(format!("Failed to commit put: {e}")))?;
            Ok(prev_len)
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB put_overwrite task failed: {e}")))??;

        {
            let mut stats = self.stats.write();
            if let Some(prev) = old_len {
                // Update: adjust byte count, chunk count stays the same.
                stats.bytes_stored = stats
                    .bytes_stored
                    .saturating_sub(prev as u64)
                    .saturating_add(data.len() as u64);
            } else {
                // New record.
                stats.chunks_stored += 1;
                stats.bytes_stored += data.len() as u64;
            }
        }

        debug!(
            "Overwritten record {} ({} bytes)",
            hex::encode(address),
            data.len()
        );

        Ok(())
    }

    /// Retrieve a chunk.
    ///
    /// # Arguments
    ///
    /// * `address` - Content address to retrieve
    ///
    /// # Returns
    ///
    /// Returns `Some(content)` if found, `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns an error if read fails or verification fails.
    pub async fn get(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        let key = *address;
        let env = self.env.clone();
        let db = self.db;

        let content = spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let rtxn = env
                .read_txn()
                .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
            let value = db
                .get(&rtxn, &key)
                .map_err(|e| Error::Storage(format!("Failed to get chunk: {e}")))?;
            Ok(value.map(Vec::from))
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB get task failed: {e}")))??;

        let Some(content) = content else {
            trace!("Chunk {} not found", hex::encode(address));
            return Ok(None);
        };

        // Verify content if configured
        if self.config.verify_on_read {
            let computed = Self::compute_address(&content);
            if computed != *address {
                self.stats.write().verification_failures += 1;
                warn!(
                    "Chunk verification failed: expected {}, computed {}",
                    hex::encode(address),
                    hex::encode(computed)
                );
                return Err(Error::Storage(format!(
                    "Chunk verification failed for {}",
                    hex::encode(address)
                )));
            }
        }

        {
            let mut stats = self.stats.write();
            stats.chunks_retrieved += 1;
            stats.bytes_retrieved += content.len() as u64;
        }

        debug!(
            "Retrieved chunk {} ({} bytes)",
            hex::encode(address),
            content.len()
        );

        Ok(Some(content))
    }

    /// Retrieve raw data without content-address verification.
    ///
    /// Use this for non-chunk data types where the stored bytes are
    /// serialized records, not raw content.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    pub async fn get_raw(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        let key = *address;
        let env = self.env.clone();
        let db = self.db;

        let content = spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let rtxn = env
                .read_txn()
                .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
            let value = db
                .get(&rtxn, &key)
                .map_err(|e| Error::Storage(format!("Failed to get record: {e}")))?;
            Ok(value.map(Vec::from))
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB get_raw task failed: {e}")))??;

        let Some(content) = content else {
            trace!("Record {} not found", hex::encode(address));
            return Ok(None);
        };

        {
            let mut stats = self.stats.write();
            stats.chunks_retrieved += 1;
            stats.bytes_retrieved += content.len() as u64;
        }

        debug!(
            "Retrieved record {} ({} bytes)",
            hex::encode(address),
            content.len()
        );

        Ok(Some(content))
    }

    /// Check if a chunk exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub fn exists(&self, address: &XorName) -> Result<bool> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let found = self
            .db
            .get(&rtxn, address.as_ref())
            .map_err(|e| Error::Storage(format!("Failed to check existence: {e}")))?
            .is_some();
        Ok(found)
    }

    /// Delete a chunk.
    ///
    /// # Errors
    ///
    /// Returns an error if deletion fails.
    pub async fn delete(&self, address: &XorName) -> Result<bool> {
        let key = *address;
        let env = self.env.clone();
        let db = self.db;

        let deleted = spawn_blocking(move || -> Result<bool> {
            let mut wtxn = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;
            let existed = db
                .delete(&mut wtxn, &key)
                .map_err(|e| Error::Storage(format!("Failed to delete chunk: {e}")))?;
            wtxn.commit()
                .map_err(|e| Error::Storage(format!("Failed to commit delete: {e}")))?;
            Ok(existed)
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB delete task failed: {e}")))??;

        if deleted {
            debug!("Deleted chunk {}", hex::encode(address));
        }

        Ok(deleted)
    }

    /// Get storage statistics.
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        let mut stats = self.stats.read().clone();
        match self.current_chunks() {
            Ok(count) => stats.current_chunks = count,
            Err(e) => {
                warn!("Failed to read current_chunks for stats: {e}");
                stats.current_chunks = 0;
            }
        }
        stats
    }

    /// Return the number of chunks currently stored, queried from LMDB metadata.
    ///
    /// This is an O(1) read of the B-tree page header — not a full scan.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub fn current_chunks(&self) -> Result<u64> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let entries = self
            .db
            .stat(&rtxn)
            .map_err(|e| Error::Storage(format!("Failed to read db stats: {e}")))?
            .entries;
        Ok(entries as u64)
    }

    /// Compute content address (BLAKE3 hash).
    #[must_use]
    pub fn compute_address(content: &[u8]) -> XorName {
        crate::client::compute_address(content)
    }

    /// Get the root directory.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.config.root_dir
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_storage() -> (LmdbStorage, TempDir) {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = LmdbStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            verify_on_read: true,
            max_chunks: 0,
            max_map_size: 0,
        };
        let storage = LmdbStorage::new(config).await.expect("create storage");
        (storage, temp_dir)
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"hello world";
        let address = LmdbStorage::compute_address(content);

        // Store chunk
        let is_new = storage.put(&address, content).await.expect("put");
        assert!(is_new);

        // Retrieve chunk
        let retrieved = storage.get(&address).await.expect("get");
        assert_eq!(retrieved, Some(content.to_vec()));
    }

    #[tokio::test]
    async fn test_put_duplicate() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"test data";
        let address = LmdbStorage::compute_address(content);

        // First store
        let is_new1 = storage.put(&address, content).await.expect("put 1");
        assert!(is_new1);

        // Duplicate store
        let is_new2 = storage.put(&address, content).await.expect("put 2");
        assert!(!is_new2);

        // Check stats
        let stats = storage.stats();
        assert_eq!(stats.chunks_stored, 1);
        assert_eq!(stats.duplicates, 1);
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let (storage, _temp) = create_test_storage().await;

        let address = [0xAB; 32];
        let result = storage.get(&address).await.expect("get");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_exists() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"exists test";
        let address = LmdbStorage::compute_address(content);

        assert!(!storage.exists(&address).expect("exists"));

        storage.put(&address, content).await.expect("put");

        assert!(storage.exists(&address).expect("exists"));
    }

    #[tokio::test]
    async fn test_delete() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"delete test";
        let address = LmdbStorage::compute_address(content);

        // Store
        storage.put(&address, content).await.expect("put");
        assert!(storage.exists(&address).expect("exists"));

        // Delete
        let deleted = storage.delete(&address).await.expect("delete");
        assert!(deleted);
        assert!(!storage.exists(&address).expect("exists"));

        // Delete again (already deleted)
        let deleted2 = storage.delete(&address).await.expect("delete 2");
        assert!(!deleted2);
    }

    #[tokio::test]
    async fn test_max_chunks_enforced() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = LmdbStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            verify_on_read: true,
            max_chunks: 2,
            max_map_size: 0,
        };
        let storage = LmdbStorage::new(config).await.expect("create storage");

        let content1 = b"chunk one";
        let content2 = b"chunk two";
        let content3 = b"chunk three";
        let addr1 = LmdbStorage::compute_address(content1);
        let addr2 = LmdbStorage::compute_address(content2);
        let addr3 = LmdbStorage::compute_address(content3);

        // First two should succeed
        assert!(storage.put(&addr1, content1).await.is_ok());
        assert!(storage.put(&addr2, content2).await.is_ok());

        // Third should be rejected
        let result = storage.put(&addr3, content3).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("capacity reached"));
    }

    #[tokio::test]
    async fn test_address_mismatch() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"some content";
        let wrong_address = [0xFF; 32]; // Wrong address

        let result = storage.put(&wrong_address, content).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn test_compute_address() {
        // Known BLAKE3 hash of "hello world"
        let content = b"hello world";
        let address = LmdbStorage::compute_address(content);

        let expected_hex = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
        assert_eq!(hex::encode(address), expected_hex);
    }

    #[tokio::test]
    async fn test_stats() {
        let (storage, _temp) = create_test_storage().await;

        let content1 = b"content 1";
        let content2 = b"content 2";
        let address1 = LmdbStorage::compute_address(content1);
        let address2 = LmdbStorage::compute_address(content2);

        // Store two chunks
        storage.put(&address1, content1).await.expect("put 1");
        storage.put(&address2, content2).await.expect("put 2");

        // Retrieve one
        storage.get(&address1).await.expect("get");

        let stats = storage.stats();
        assert_eq!(stats.chunks_stored, 2);
        assert_eq!(stats.chunks_retrieved, 1);
        assert_eq!(
            stats.bytes_stored,
            content1.len() as u64 + content2.len() as u64
        );
        assert_eq!(stats.bytes_retrieved, content1.len() as u64);
        assert_eq!(stats.current_chunks, 2);
    }

    #[tokio::test]
    async fn test_capacity_recovers_after_delete() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = LmdbStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            verify_on_read: true,
            max_chunks: 1,
            max_map_size: 0,
        };
        let storage = LmdbStorage::new(config).await.expect("create storage");

        let first = b"first chunk";
        let second = b"second chunk";
        let addr1 = LmdbStorage::compute_address(first);
        let addr2 = LmdbStorage::compute_address(second);

        storage.put(&addr1, first).await.expect("put first");
        storage.delete(&addr1).await.expect("delete first");

        // Should succeed because delete freed capacity.
        storage.put(&addr2, second).await.expect("put second");

        let stats = storage.stats();
        assert_eq!(stats.current_chunks, 1);
    }

    #[tokio::test]
    async fn test_persistence_across_reopen() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let content = b"persistent data";
        let address = LmdbStorage::compute_address(content);

        // Store a chunk
        {
            let config = LmdbStorageConfig {
                root_dir: temp_dir.path().to_path_buf(),
                verify_on_read: true,
                max_chunks: 0,
                max_map_size: 0,
            };
            let storage = LmdbStorage::new(config).await.expect("create storage");
            storage.put(&address, content).await.expect("put");
        }

        // Re-open and verify it persisted
        {
            let config = LmdbStorageConfig {
                root_dir: temp_dir.path().to_path_buf(),
                verify_on_read: true,
                max_chunks: 0,
                max_map_size: 0,
            };
            let storage = LmdbStorage::new(config).await.expect("reopen storage");
            assert_eq!(storage.current_chunks().expect("current_chunks"), 1);
            let retrieved = storage.get(&address).await.expect("get");
            assert_eq!(retrieved, Some(content.to_vec()));
        }
    }

    #[tokio::test]
    async fn test_put_raw_and_get_raw() {
        let (storage, _temp) = create_test_storage().await;

        // put_raw uses a caller-supplied address (not BLAKE3(content))
        let address = [0xAA; 32];
        let data = b"raw record data";

        let was_new = storage.put_raw(&address, data).await.expect("put_raw");
        assert!(was_new, "first put_raw should return true");

        // get_raw retrieves without content-address verification
        let retrieved = storage.get_raw(&address).await.expect("get_raw");
        assert_eq!(retrieved, Some(data.to_vec()));

        // Duplicate put_raw returns false
        let was_new2 = storage.put_raw(&address, data).await.expect("put_raw dup");
        assert!(!was_new2, "duplicate put_raw should return false");

        // Stats: 1 stored, 1 duplicate
        let stats = storage.stats();
        assert_eq!(stats.chunks_stored, 1);
        assert_eq!(stats.duplicates, 1);
    }

    #[tokio::test]
    async fn test_get_raw_not_found() {
        let (storage, _temp) = create_test_storage().await;

        let result = storage.get_raw(&[0xBB; 32]).await.expect("get_raw");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_put_overwrite_new_record() {
        let (storage, _temp) = create_test_storage().await;

        let address = [0xCC; 32];
        let data = b"new overwrite data";

        storage
            .put_overwrite(&address, data)
            .await
            .expect("put_overwrite");

        let retrieved = storage.get_raw(&address).await.expect("get_raw");
        assert_eq!(retrieved, Some(data.to_vec()));

        let stats = storage.stats();
        assert_eq!(stats.chunks_stored, 1);
        assert_eq!(stats.bytes_stored, data.len() as u64);
    }

    #[tokio::test]
    async fn test_put_overwrite_updates_stats_correctly() {
        let (storage, _temp) = create_test_storage().await;

        let address = [0xDD; 32];
        let v1 = b"short";
        let v2 = b"much longer replacement value";

        // First write
        storage
            .put_overwrite(&address, v1)
            .await
            .expect("put_overwrite v1");
        let stats1 = storage.stats();
        assert_eq!(stats1.chunks_stored, 1);
        assert_eq!(stats1.bytes_stored, v1.len() as u64);

        // Overwrite with larger value — chunks_stored stays 1, bytes adjusts
        storage
            .put_overwrite(&address, v2)
            .await
            .expect("put_overwrite v2");
        let stats2 = storage.stats();
        assert_eq!(
            stats2.chunks_stored, 1,
            "overwrite should not increment chunk count"
        );
        assert_eq!(
            stats2.bytes_stored,
            v2.len() as u64,
            "bytes should reflect new value size"
        );

        // Verify the new value is stored
        let retrieved = storage.get_raw(&address).await.expect("get_raw");
        assert_eq!(retrieved, Some(v2.to_vec()));
    }
}
