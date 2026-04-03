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
use crate::logging::{debug, info, trace, warn};
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, MdbError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::task::spawn_blocking;

use crate::ant_protocol::XORNAME_LEN;

/// Bytes in one MiB.
pub const MIB: u64 = 1024 * 1024;

/// Bytes in one GiB.
pub const GIB: u64 = 1024 * MIB;

/// Default minimum free disk space to preserve on the storage partition.
const DEFAULT_DISK_RESERVE: u64 = 500 * MIB;

/// Convert a byte count to GiB for human-readable log messages.
#[allow(clippy::cast_precision_loss)] // display only — sub-byte precision is irrelevant
fn bytes_to_gib(bytes: u64) -> f64 {
    bytes as f64 / GIB as f64
}

/// Absolute minimum LMDB map size.
///
/// Even on a nearly-full disk the database must be able to open.
/// Set to 256 MiB — enough for millions of LMDB pages.
const MIN_MAP_SIZE: usize = 256 * 1024 * 1024;

/// How often to re-query available disk space (in seconds).
///
/// Between checks the cached result is trusted.  Disk space changes slowly
/// relative to chunk-write throughput, so a multi-second window is safe.
const DISK_CHECK_INTERVAL_SECS: u64 = 5;

/// Configuration for LMDB storage.
#[derive(Debug, Clone)]
pub struct LmdbStorageConfig {
    /// Root directory for storage (LMDB env lives at `{root_dir}/chunks.mdb/`).
    pub root_dir: PathBuf,
    /// Whether to verify content on read (compares hash to address).
    pub verify_on_read: bool,
    /// Explicit LMDB map size cap in bytes.
    ///
    /// When 0 (default), the map size is computed automatically from available
    /// disk space and grows on demand when more storage becomes available.
    pub max_map_size: usize,
    /// Minimum free disk space (in bytes) to preserve on the storage partition.
    ///
    /// Writes are refused when available space drops below this threshold.
    pub disk_reserve: u64,
}

impl Default for LmdbStorageConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from(".ant/chunks"),
            verify_on_read: true,
            max_map_size: 0,
            disk_reserve: DEFAULT_DISK_RESERVE,
        }
    }
}

impl LmdbStorageConfig {
    /// A test-friendly default with `disk_reserve` set to 0 so unit tests
    /// don't depend on the host having >= 1 GiB free disk space.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_default() -> Self {
        Self {
            disk_reserve: 0,
            ..Self::default()
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
    /// Path to the LMDB environment directory (for disk-space queries).
    env_dir: PathBuf,
    /// Operation statistics.
    stats: parking_lot::RwLock<StorageStats>,
    /// Serialises access to the LMDB environment during a map resize.
    ///
    /// Normal read/write operations acquire a **shared** lock.  The rare
    /// resize path acquires an **exclusive** lock, ensuring no transactions
    /// are active when `env.resize()` is called (an LMDB safety requirement).
    env_lock: Arc<parking_lot::RwLock<()>>,
    /// Timestamp of the last successful disk-space check.
    ///
    /// `None` means "never checked — check on next write".  Updated only
    /// after a passing check, so a low-space result is always rechecked.
    last_disk_ok: parking_lot::Mutex<Option<Instant>>,
}

impl LmdbStorage {
    /// Create a new LMDB storage instance.
    ///
    /// Opens (or creates) an LMDB environment at `{root_dir}/chunks.mdb/`.
    ///
    /// When `config.max_map_size` is 0 (the default) the map size is derived
    /// from the available disk space on the partition that hosts the database,
    /// minus `config.disk_reserve`.  This allows a node to use all available
    /// storage without a fixed cap.  If the operator adds more storage later
    /// the map is resized on demand (see [`Self::put`]).
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
            // Operator provided an explicit cap.
            config.max_map_size
        } else {
            // Auto-scale: current DB footprint + available space − reserve.
            let computed = compute_map_size(&env_dir, config.disk_reserve)?;
            info!(
                "Auto-computed LMDB map size: {:.2} GiB (available disk minus {:.2} GiB reserve)",
                bytes_to_gib(computed as u64),
                bytes_to_gib(config.disk_reserve),
            );
            computed
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
            env_dir,
            stats: parking_lot::RwLock::new(StorageStats::default()),
            env_lock: Arc::new(parking_lot::RwLock::new(())),
            last_disk_ok: parking_lot::Mutex::new(None),
        };

        debug!(
            "Initialized LMDB storage at {:?} ({} existing chunks)",
            storage.env_dir,
            storage.current_chunks()?
        );

        Ok(storage)
    }

    /// Store a chunk.
    ///
    /// Before writing, verifies that available disk space exceeds the
    /// configured reserve.  If the LMDB map is full but more disk space
    /// exists (e.g. the operator added storage), the map is resized
    /// automatically and the write is retried.
    ///
    /// # Returns
    ///
    /// Returns `true` if the chunk was newly stored, `false` if it already existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails, content doesn't match address,
    /// or the disk is too full to accept new chunks.
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

        // ── Disk-space guard (cached — at most one syscall per interval) ─
        // Placed after the duplicate check so that re-storing an existing
        // chunk remains a harmless no-op even when disk space is low.
        self.check_disk_space_cached()?;

        // ── Write (with resize-on-demand) ───────────────────────────────
        match self.try_put(address, content).await? {
            PutOutcome::New => {}
            PutOutcome::Duplicate => {
                trace!("Chunk {} already exists", hex::encode(address));
                self.stats.write().duplicates += 1;
                return Ok(false);
            }
            PutOutcome::MapFull => {
                // The map ceiling was reached but there may be more disk space
                // available (e.g. operator expanded the partition).
                self.try_resize().await?;
                // Retry once after resize.
                match self.try_put(address, content).await? {
                    PutOutcome::New => {}
                    PutOutcome::Duplicate => {
                        self.stats.write().duplicates += 1;
                        return Ok(false);
                    }
                    PutOutcome::MapFull => {
                        return Err(Error::Storage(
                            "LMDB map full after resize — disk may be at capacity".into(),
                        ));
                    }
                }
            }
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

    /// Attempt a single put inside a write transaction.
    ///
    /// Returns [`PutOutcome::MapFull`] instead of an error when the LMDB map
    /// ceiling is reached, so the caller can resize and retry.
    async fn try_put(&self, address: &XorName, content: &[u8]) -> Result<PutOutcome> {
        let key = *address;
        let value = content.to_vec();
        let env = self.env.clone();
        let db = self.db;
        let lock = Arc::clone(&self.env_lock);

        spawn_blocking(move || -> Result<PutOutcome> {
            let _guard = lock.read();

            let mut wtxn = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;

            // Authoritative existence check inside the serialized write txn
            if db
                .get(&wtxn, &key)
                .map_err(|e| Error::Storage(format!("Failed to check existence: {e}")))?
                .is_some()
            {
                return Ok(PutOutcome::Duplicate);
            }

            match db.put(&mut wtxn, &key, &value) {
                Ok(()) => {}
                Err(heed::Error::Mdb(MdbError::MapFull)) => return Ok(PutOutcome::MapFull),
                Err(e) => {
                    return Err(Error::Storage(format!("Failed to put chunk: {e}")));
                }
            }

            match wtxn.commit() {
                Ok(()) => Ok(PutOutcome::New),
                Err(heed::Error::Mdb(MdbError::MapFull)) => Ok(PutOutcome::MapFull),
                Err(e) => Err(Error::Storage(format!("Failed to commit put: {e}"))),
            }
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB put task failed: {e}")))?
    }

    /// Retrieve a chunk.
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
        let lock = Arc::clone(&self.env_lock);

        let content = spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let _guard = lock.read();
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

    /// Check if a chunk exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub fn exists(&self, address: &XorName) -> Result<bool> {
        let _guard = self.env_lock.read();
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
        let lock = Arc::clone(&self.env_lock);

        let deleted = spawn_blocking(move || -> Result<bool> {
            let _guard = lock.read();
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
        let _guard = self.env_lock.read();
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

    /// Return all stored record keys.
    ///
    /// Iterates the LMDB database in a read transaction. Used by the
    /// replication subsystem for hint construction and audit sampling.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub async fn all_keys(&self) -> Result<Vec<XorName>> {
        let env = self.env.clone();
        let db = self.db;

        let keys = spawn_blocking(move || -> Result<Vec<XorName>> {
            let rtxn = env
                .read_txn()
                .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
            let mut keys = Vec::new();
            let iter = db
                .iter(&rtxn)
                .map_err(|e| Error::Storage(format!("Failed to iterate database: {e}")))?;
            for result in iter {
                let (key_bytes, _) =
                    result.map_err(|e| Error::Storage(format!("Failed to read entry: {e}")))?;
                if key_bytes.len() == XORNAME_LEN {
                    let mut key = [0u8; XORNAME_LEN];
                    key.copy_from_slice(key_bytes);
                    keys.push(key);
                } else {
                    crate::logging::warn!(
                        "LmdbStorage: skipping entry with unexpected key length {} (expected {XORNAME_LEN})",
                        key_bytes.len()
                    );
                }
            }
            Ok(keys)
        })
        .await
        .map_err(|e| Error::Storage(format!("all_keys task failed: {e}")))?;

        keys
    }

    /// Retrieve raw chunk bytes without content-address verification.
    ///
    /// Used by the audit subsystem to compute digests over stored bytes.
    /// Unlike [`Self::get`], this does not verify `hash(content) == address`.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub async fn get_raw(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        let key = *address;
        let env = self.env.clone();
        let db = self.db;

        let value = spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let rtxn = env
                .read_txn()
                .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
            let val = db
                .get(&rtxn, key.as_ref())
                .map_err(|e| Error::Storage(format!("Failed to get chunk: {e}")))?;
            Ok(val.map(Vec::from))
        })
        .await
        .map_err(|e| Error::Storage(format!("get_raw task failed: {e}")))?;

        value
    }

    /// Check available disk space, skipping the syscall if a recent check passed.
    ///
    /// Only caches *passing* results — a low-space condition is always
    /// rechecked so we detect freed space promptly.
    fn check_disk_space_cached(&self) -> Result<()> {
        {
            let last = self.last_disk_ok.lock();
            if let Some(t) = *last {
                if t.elapsed().as_secs() < DISK_CHECK_INTERVAL_SECS {
                    return Ok(());
                }
            }
        }
        // Cache miss or stale — perform the actual statvfs check.
        check_disk_space(&self.env_dir, self.config.disk_reserve)?;
        // Passed — update the cache timestamp.
        *self.last_disk_ok.lock() = Some(Instant::now());
        Ok(())
    }

    /// Grow the LMDB map to match currently available disk space.
    ///
    /// The new size is the **larger** of:
    ///   1. the current map size (so existing data is never truncated), and
    ///   2. `current_db_file_size + available_space − reserve`
    ///      (so all reachable disk space can be used).
    ///
    /// Acquires an **exclusive** lock on `env_lock` so that no read or write
    /// transactions are active when the underlying `mdb_env_set_mapsize` is
    /// called (an LMDB safety requirement).
    #[allow(unsafe_code)]
    async fn try_resize(&self) -> Result<()> {
        let from_disk = compute_map_size(&self.env_dir, self.config.disk_reserve)?;
        let env = self.env.clone();
        let lock = Arc::clone(&self.env_lock);

        spawn_blocking(move || -> Result<()> {
            // Exclusive lock guarantees no concurrent transactions.
            let _guard = lock.write();

            // Never shrink below the current map — existing data must remain
            // addressable regardless of what the disk-space calculation says.
            let current_map = env.info().map_size;
            let new_size = from_disk.max(current_map);

            if new_size <= current_map {
                debug!("LMDB map resize skipped — no additional disk space available");
                return Ok(());
            }

            // SAFETY: We hold an exclusive lock, so no transactions are active.
            unsafe {
                env.resize(new_size)
                    .map_err(|e| Error::Storage(format!("Failed to resize LMDB map: {e}")))?;
            }

            info!(
                "Resized LMDB map to {:.2} GiB (was {:.2} GiB)",
                bytes_to_gib(new_size as u64),
                bytes_to_gib(current_map as u64),
            );
            Ok(())
        })
        .await
        .map_err(|e| Error::Storage(format!("LMDB resize task failed: {e}")))?
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Outcome of a single `try_put` attempt.
enum PutOutcome {
    /// Chunk was newly stored.
    New,
    /// Chunk already existed (idempotent).
    Duplicate,
    /// The LMDB map ceiling was reached — caller should resize and retry.
    MapFull,
}

/// Compute the LMDB map size from the disk hosting `db_dir`.
///
/// The result covers **all existing data** plus all remaining usable disk
/// space:
///
/// ```text
/// map_size = current_db_file_size + max(0, available_space − reserve)
/// ```
///
/// `available_space` (from `statvfs`) reports only the *free* bytes on the
/// partition — the DB file's own footprint is **not** included, so adding
/// it back ensures the map is always large enough for the data already
/// stored.
///
/// The result is page-aligned and never falls below [`MIN_MAP_SIZE`].
fn compute_map_size(db_dir: &Path, reserve: u64) -> Result<usize> {
    let available = fs2::available_space(db_dir)
        .map_err(|e| Error::Storage(format!("Failed to query available disk space: {e}")))?;

    // The MDB data file may not exist yet on first run.
    let mdb_file = db_dir.join("data.mdb");
    let current_db_bytes = std::fs::metadata(&mdb_file).map(|m| m.len()).unwrap_or(0);

    // available_space excludes the DB file, so we add it back to get the
    // total space the DB could occupy while still leaving `reserve` free.
    let growth_room = available.saturating_sub(reserve);
    let target = current_db_bytes.saturating_add(growth_room);

    // Align up to system page size (required by heed's resize).
    let page = page_size::get() as u64;
    let aligned = target.div_ceil(page) * page;

    let result = usize::try_from(aligned).unwrap_or(usize::MAX);
    Ok(result.max(MIN_MAP_SIZE))
}

/// Reject the write early if available disk space is below `reserve`.
fn check_disk_space(db_dir: &Path, reserve: u64) -> Result<()> {
    let available = fs2::available_space(db_dir)
        .map_err(|e| Error::Storage(format!("Failed to query available disk space: {e}")))?;

    if available < reserve {
        return Err(Error::Storage(format!(
            "Insufficient disk space: {:.2} GiB available, {:.2} GiB reserve required. \
             Free disk space or increase the partition to continue storing chunks.",
            bytes_to_gib(available),
            bytes_to_gib(reserve),
        )));
    }

    Ok(())
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
            ..LmdbStorageConfig::test_default()
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
    async fn test_persistence_across_reopen() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let content = b"persistent data";
        let address = LmdbStorage::compute_address(content);

        // Store a chunk
        {
            let config = LmdbStorageConfig {
                root_dir: temp_dir.path().to_path_buf(),
                ..LmdbStorageConfig::test_default()
            };
            let storage = LmdbStorage::new(config).await.expect("create storage");
            storage.put(&address, content).await.expect("put");
        }

        // Re-open and verify it persisted
        {
            let config = LmdbStorageConfig {
                root_dir: temp_dir.path().to_path_buf(),
                ..LmdbStorageConfig::test_default()
            };
            let storage = LmdbStorage::new(config).await.expect("reopen storage");
            assert_eq!(storage.current_chunks().expect("current_chunks"), 1);
            let retrieved = storage.get(&address).await.expect("get");
            assert_eq!(retrieved, Some(content.to_vec()));
        }
    }

    #[tokio::test]
    async fn test_all_keys() {
        let (storage, _temp) = create_test_storage().await;

        // Empty storage
        let keys = storage.all_keys().await.expect("all_keys empty");
        assert!(keys.is_empty());

        // Store some chunks
        let content1 = b"chunk one for keys";
        let content2 = b"chunk two for keys";
        let addr1 = LmdbStorage::compute_address(content1);
        let addr2 = LmdbStorage::compute_address(content2);
        storage.put(&addr1, content1).await.expect("put 1");
        storage.put(&addr2, content2).await.expect("put 2");

        let mut keys = storage.all_keys().await.expect("all_keys");
        keys.sort_unstable();
        let mut expected = vec![addr1, addr2];
        expected.sort_unstable();
        assert_eq!(keys, expected);
    }

    #[tokio::test]
    async fn test_get_raw() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"raw test data";
        let address = LmdbStorage::compute_address(content);
        storage.put(&address, content).await.expect("put");

        // get_raw returns bytes without verification
        let raw = storage.get_raw(&address).await.expect("get_raw");
        assert_eq!(raw, Some(content.to_vec()));

        // Non-existent key
        let missing = storage.get_raw(&[0xFF; 32]).await.expect("get_raw missing");
        assert!(missing.is_none());
    }
}
