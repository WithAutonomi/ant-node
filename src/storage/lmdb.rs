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
use tokio_util::task::TaskTracker;

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

/// Maximum head-room (beyond the current data footprint) to reserve for the
/// LMDB map **on Windows**.
///
/// On Windows a node's committed / private memory scales with the *mapped*
/// size rather than with the data actually stored. Measured on a live node:
/// ~7.4 GB of extra commit for a ~3.7 TiB map, versus ~181 MB for a ~55 GiB
/// map — roughly 0.2% of the mapped size, resident and attributed to *no*
/// user-space allocation. That size-proportional cost is consistent with
/// kernel page tables / section metadata for the mapping; the exact kernel
/// structure was inferred from the scaling rather than measured directly, but
/// the size-proportional *effect* is what this cap targets. Linux keeps the
/// mapping sparse, so a disk-sized map is nearly free there — the overhead is
/// Windows-specific, which is why it only surfaced in Windows reports.
///
/// Sizing the map to the whole disk therefore costs ~0.2% of *free disk* per
/// node, multiplied by every node sharing the host (e.g. a 10 TiB partition ≈
/// 20 GiB). We instead cap the head-room on Windows and lean on
/// `LmdbStorage::try_resize` to extend the map on demand as data accumulates,
/// keeping the overhead proportional to *stored data* rather than *disk
/// capacity*. At 32 GiB the extra commit is ~100 MB, and a resize happens at
/// most once per 32 GiB written.
#[cfg(windows)]
const WINDOWS_MAP_HEADROOM: u64 = 32 * GIB;

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
    /// Tracks every LMDB blocking task spawned by this storage.
    ///
    /// A `spawn_blocking` closure owns a cloned [`Env`] and keeps running
    /// even when its async awaiter is dropped (e.g. by a `select!` losing to
    /// a shutdown token).  Tracking the blocking task itself — not the async
    /// wrapper — lets [`Self::wait_idle`] wait for true quiescence before
    /// the environment may be reopened.
    blocking_tracker: TaskTracker,
    /// Test-only gate read-acquired at the top of the put blocking closure.
    ///
    /// Tests hold the write half to deterministically park an in-flight put
    /// on the blocking pool (e.g. to prove [`Self::wait_idle`] waits for a
    /// detached write).
    #[cfg(any(test, feature = "test-utils"))]
    test_put_gate: Arc<parking_lot::RwLock<()>>,
    /// Test-only gate read-acquired inside the raw-read blocking closures,
    /// immediately after the shared `env_lock` guard is taken.
    ///
    /// Tests hold the write half to deterministically park an in-flight raw
    /// read while it still holds the shared environment lock (e.g. to prove
    /// [`Self::try_resize`] waits for active raw reads before calling
    /// `env.resize()`).
    #[cfg(any(test, feature = "test-utils"))]
    test_read_gate: Arc<parking_lot::RwLock<()>>,
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
                "Auto-computed LMDB map size: {:.2} GiB (data + available disk minus {:.2} GiB \
                 reserve, head-room capped on Windows to bound page-table overhead)",
                bytes_to_gib(computed as u64),
                bytes_to_gib(config.disk_reserve),
            );
            computed
        };

        let env_dir_clone = env_dir.clone();
        // Constructor-only blocking task: it runs before `self` (and its
        // `blocking_tracker`) exists, so it is deliberately untracked.  The
        // constructor awaits it right here, so it cannot outlive this call.
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
            blocking_tracker: TaskTracker::new(),
            #[cfg(any(test, feature = "test-utils"))]
            test_put_gate: Arc::new(parking_lot::RwLock::new(())),
            #[cfg(any(test, feature = "test-utils"))]
            test_read_gate: Arc::new(parking_lot::RwLock::new(())),
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
        #[cfg(any(test, feature = "test-utils"))]
        let test_put_gate = Arc::clone(&self.test_put_gate);

        self.blocking_tracker
            .spawn_blocking(move || -> Result<PutOutcome> {
                // Test-only: parks here while a test holds the write half.
                #[cfg(any(test, feature = "test-utils"))]
                let _test_put_gate = test_put_gate.read();
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

        let content = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<Option<Vec<u8>>> {
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

        let deleted = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<bool> {
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
        let lock = Arc::clone(&self.env_lock);

        let keys = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<Vec<XorName>> {
                // Hold the shared lock for the whole read so try_resize() (which
                // takes the exclusive lock before the unsafe Env::resize()) cannot
                // unmap the environment while this txn and its cursor are live.
                let _guard = lock.read();
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
        let lock = Arc::clone(&self.env_lock);
        #[cfg(any(test, feature = "test-utils"))]
        let test_read_gate = Arc::clone(&self.test_read_gate);

        let value = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<Option<Vec<u8>>> {
                // Shared lock held until the bytes are copied out, so a concurrent
                // try_resize() cannot unmap the environment mid-read. See all_keys.
                let _guard = lock.read();
                // Test-only: parks here, still holding the shared lock, while a
                // test holds the write half — used to prove a resize waits.
                #[cfg(any(test, feature = "test-utils"))]
                let _test_read_gate = test_read_gate.read();
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

    /// Cheap capacity pre-check for callers that want to reject work *before*
    /// doing expensive setup (e.g. the PUT handler skipping payment
    /// verification on a disk-full node — see `V2-411`).
    ///
    /// Delegates to the private `check_disk_space_cached`, so it shares the same
    /// TTL cache and only ever performs an `fs2::available_space` syscall on a
    /// cache miss. Returns the same `Insufficient disk space …` error the
    /// store path raises, keeping caller behaviour identical.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] when available space is below the configured
    /// reserve, or when the disk-space query itself fails.
    pub(crate) fn check_capacity(&self) -> Result<()> {
        self.check_disk_space_cached()
    }

    /// Capacity as a three-way verdict, distinguishing a full disk from a
    /// query that failed.
    ///
    /// Shares the same TTL cache as [`Self::check_capacity`]: a passing result
    /// is cached, a failing one is always rechecked, so freed space is noticed
    /// promptly.
    pub(crate) fn capacity_verdict(&self) -> CapacityVerdict {
        {
            let last = self.last_disk_ok.lock();
            if let Some(t) = *last {
                if t.elapsed().as_secs() < DISK_CHECK_INTERVAL_SECS {
                    return CapacityVerdict::Writable;
                }
            }
        }
        let verdict = verdict_from_available_space(
            fs2::available_space(&self.env_dir),
            self.config.disk_reserve,
        );
        if verdict == CapacityVerdict::Writable {
            *self.last_disk_ok.lock() = Some(Instant::now());
        }
        verdict
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

        self.blocking_tracker
            .spawn_blocking(move || -> Result<()> {
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

    /// Wait until every tracked LMDB blocking task has finished.
    ///
    /// Dropping an async caller (e.g. a `select!` losing to a shutdown token)
    /// does not cancel an already-spawned blocking closure — the closure keeps
    /// running on the blocking pool with a cloned [`Env`].  This method waits
    /// for those detached closures too, so when it returns no blocking
    /// operation still holds the environment.
    ///
    /// Quiescence is only meaningful once callers have stopped issuing new
    /// operations; concurrent traffic can keep the tracker non-empty
    /// indefinitely.  The storage remains fully usable afterwards (the
    /// internal tracker is reopened before returning).
    pub async fn wait_idle(&self) {
        self.blocking_tracker.close();
        self.blocking_tracker.wait().await;
        self.blocking_tracker.reopen();
    }

    /// Test-only handle to the put gate.
    ///
    /// Hold the write half to deterministically park the next put inside its
    /// blocking closure (e.g. to exercise [`Self::wait_idle`] with a write
    /// still in flight).
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_put_gate(&self) -> Arc<parking_lot::RwLock<()>> {
        Arc::clone(&self.test_put_gate)
    }

    /// Test-only handle to the raw-read gate.
    ///
    /// Hold the write half to deterministically park the next raw read
    /// (`get_raw`) inside its blocking closure while it still holds the shared
    /// environment lock (e.g. to prove `try_resize` waits for active
    /// raw reads).
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_read_gate(&self) -> Arc<parking_lot::RwLock<()>> {
        Arc::clone(&self.test_read_gate)
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
/// On Windows the disk-headroom term is additionally capped at
/// `WINDOWS_MAP_HEADROOM` to bound the map-proportional commit overhead (see
/// that constant); [`LmdbStorage::try_resize`] extends the map on demand as
/// data grows.
///
/// The result is page-aligned and never falls below [`MIN_MAP_SIZE`].
fn compute_map_size(db_dir: &Path, reserve: u64) -> Result<usize> {
    let available = fs2::available_space(db_dir)
        .map_err(|e| Error::Storage(format!("Failed to query available disk space: {e}")))?;

    // The MDB data file may not exist yet on first run.
    let mdb_file = db_dir.join("data.mdb");
    let current_db_bytes = std::fs::metadata(&mdb_file).map_or(0, |m| m.len());

    let target = map_target_bytes(current_db_bytes, available, reserve);

    // Align up to system page size (required by heed's resize).
    let page = page_size::get() as u64;
    let aligned = target.div_ceil(page) * page;

    let result = usize::try_from(aligned).unwrap_or(usize::MAX);
    Ok(result.max(MIN_MAP_SIZE))
}

/// Head-room policy for the LMDB map, split out from [`compute_map_size`] so it
/// is unit-testable without touching the real filesystem.
///
/// `map = current_db_bytes + max(0, available − reserve)`, with the head-room
/// term capped at `WINDOWS_MAP_HEADROOM` on Windows. Existing data
/// (`current_db_bytes`) is always covered so a resize can never truncate the
/// database, even when the head-room cap or a nearly-full disk drives the
/// growth term to zero.
fn map_target_bytes(current_db_bytes: u64, available: u64, reserve: u64) -> u64 {
    // available_space excludes the DB file, so we add it back to get the
    // total space the DB could occupy while still leaving `reserve` free.
    let growth_room = available.saturating_sub(reserve);

    // On Windows, bound the head-room so the mapped size (and its
    // size-proportional commit overhead) stays proportional to stored data
    // rather than disk capacity. Elsewhere, use all reachable space.
    #[cfg(windows)]
    let growth_room = growth_room.min(WINDOWS_MAP_HEADROOM);

    current_db_bytes.saturating_add(growth_room)
}

/// Map the result of a space query onto a verdict.
///
/// Split out from [`LmdbStorage::capacity_verdict`] because the three-way
/// mapping is the part worth proving, and proving it through the filesystem is
/// not portable: asking for the free space of a directory that does not exist
/// fails on Unix but succeeds on Windows, which resolves it to the volume.
fn verdict_from_available_space(available: std::io::Result<u64>, reserve: u64) -> CapacityVerdict {
    match available {
        Ok(available) if available < reserve => CapacityVerdict::Full,
        Ok(_) => CapacityVerdict::Writable,
        Err(e) => {
            warn!("Could not query available disk space: {e}");
            CapacityVerdict::Unknown
        }
    }
}

/// What a capacity check concluded, when the caller needs to tell "this node is
/// full" apart from "this node could not find out".
///
/// [`LmdbStorage::check_capacity`] collapses both into `Err`, which is right for
/// a caller that only wants to know whether to attempt a write. A caller
/// deciding *how long to stand down* needs the distinction: a full disk is a
/// standing condition worth waiting minutes on, while a failed `statvfs` may
/// have cleared by the next attempt and must not be treated as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityVerdict {
    /// Available space is at or above the configured reserve. That is what the
    /// query establishes, and possibly from the TTL cache — not a promise the
    /// next write succeeds.
    Writable,
    /// Available space is below the configured reserve.
    Full,
    /// The query itself failed, so nothing is known about available space.
    Unknown,
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ant_protocol::MAX_CHUNK_SIZE;

    /// Short probe used to prove `wait_idle` is still blocked on a parked op.
    const WAIT_IDLE_BLOCKED_PROBE: std::time::Duration = std::time::Duration::from_millis(200);
    /// Generous ceiling for `wait_idle` to complete once the op is released.
    const WAIT_IDLE_COMPLETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    /// Poll interval while waiting for a parked raw read to take the shared lock.
    const RAW_READ_LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(5);
    /// Ceiling for a parked raw read to take the shared lock.
    const RAW_READ_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    /// Short probe used to prove `try_resize` is still blocked on the shared lock.
    const RESIZE_BLOCKED_PROBE: std::time::Duration = std::time::Duration::from_millis(200);
    /// Generous ceiling for `try_resize` to complete once the raw read releases.
    const RESIZE_COMPLETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    #[test]
    fn map_target_covers_existing_data_and_headroom() {
        // A partition with far more free space than any node needs.
        let huge_free = 100 * 1024 * GIB; // 100 TiB
        let reserve = 500 * MIB;

        // Fresh node, no data yet.
        let fresh = map_target_bytes(0, huge_free, reserve);
        // Node already holding 16 GiB of chunks.
        let with_data = map_target_bytes(16 * GIB, huge_free, reserve);

        #[cfg(windows)]
        {
            // Windows: head-room is capped, so the map (and thus page tables)
            // stay bounded regardless of disk size. Existing data always sits
            // on top of the capped head-room.
            assert_eq!(fresh, WINDOWS_MAP_HEADROOM);
            assert_eq!(with_data, 16 * GIB + WINDOWS_MAP_HEADROOM);
            // Sanity: page-table cost (~map/512) is tens of MiB, not tens of GiB.
            assert!(with_data / 512 < 128 * MIB);
        }

        #[cfg(not(windows))]
        {
            // Other platforms keep the disk-sized map (lazy page tables cost
            // nothing), so head-room is the full free span minus reserve.
            assert_eq!(fresh, huge_free - reserve);
            assert_eq!(with_data, 16 * GIB + (huge_free - reserve));
        }
    }

    #[test]
    fn map_target_never_truncates_data_when_disk_nearly_full() {
        // Free space below the reserve → head-room saturates to 0 on every
        // platform, but the existing 4 GiB of data must still be covered.
        assert_eq!(map_target_bytes(4 * GIB, 100 * MIB, 500 * MIB), 4 * GIB);
    }

    /// Regression (V2-620 review): `all_keys` and `get_raw` must take the shared
    /// `env_lock` so their LMDB read transaction can never run concurrently with
    /// `try_resize()`'s unsafe `Env::resize()` — which this PR turns into a
    /// routine ~per-32-GiB Windows event. We prove it by holding the exclusive
    /// lock (as a resize does) and asserting both calls block until it is freed.
    ///
    /// Holding a `parking_lot` guard across `.await` is deliberate and safe here:
    /// the guard stays on this current-thread test task while `all_keys`/`get_raw`
    /// run their blocking work on the `spawn_blocking` pool (separate threads).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn read_paths_block_while_env_is_being_resized() {
        use std::time::Duration;
        let (storage, _temp) = create_test_storage().await;

        // Store one chunk so the read paths have real work to return.
        let content = b"resize-safety";
        let address = LmdbStorage::compute_address(content);
        storage.put(&address, content).await.expect("put");

        // Simulate a resize in progress: hold the exclusive env lock.
        let write_guard = storage.env_lock.write();

        // Neither read path may complete while the exclusive lock is held —
        // before the fix they took no lock and would return immediately.
        assert!(
            tokio::time::timeout(Duration::from_millis(250), storage.all_keys())
                .await
                .is_err(),
            "all_keys completed while env_lock was held exclusively — missing shared guard"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(250), storage.get_raw(&address))
                .await
                .is_err(),
            "get_raw completed while env_lock was held exclusively — missing shared guard"
        );

        // Once the exclusive lock is released, both proceed and see the data.
        drop(write_guard);
        assert_eq!(storage.all_keys().await.expect("all_keys").len(), 1);
        assert_eq!(
            storage.get_raw(&address).await.expect("get_raw").as_deref(),
            Some(content.as_slice())
        );
    }

    async fn create_test_storage() -> (LmdbStorage, tempfile::TempDir) {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
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
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
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

    /// Dropping a put's awaiter does not cancel its `spawn_blocking` LMDB
    /// transaction; `wait_idle` must wait for that detached write, and the
    /// storage must remain usable afterwards.
    // Holding the gate's write guard across awaits is the point of the test:
    // it parks the blocking closure while we probe wait_idle.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn wait_idle_waits_for_detached_put_blocking_op() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"detached put survives its dropped awaiter";
        let address = LmdbStorage::compute_address(content);

        // Park the put's blocking closure on the test gate.
        let gate = storage.test_put_gate();
        let parked = gate.write();

        // Drop the awaiting future mid-flight: the biased select! polls the
        // put once — far enough to spawn the blocking task, which parks on
        // the gate — then completes on the ready branch, dropping the put.
        tokio::select! {
            biased;
            res = storage.put(&address, content) => {
                panic!("put must be parked on the test gate, got {res:?}")
            }
            () = std::future::ready(()) => {}
        }

        // The blocking op is still running: wait_idle must not complete.
        let blocked = tokio::time::timeout(WAIT_IDLE_BLOCKED_PROBE, storage.wait_idle()).await;
        assert!(
            blocked.is_err(),
            "wait_idle returned while the blocking op was parked"
        );

        // Release the gate: the detached closure commits and exits.
        drop(parked);
        tokio::time::timeout(WAIT_IDLE_COMPLETE_TIMEOUT, storage.wait_idle())
            .await
            .expect("wait_idle after release");

        // The dropped awaiter did not lose the write: it committed.
        assert!(storage.exists(&address).expect("exists after release"));

        // The storage remains usable after wait_idle (tracker reopened).
        let more = b"storage still usable after wait_idle";
        let more_addr = LmdbStorage::compute_address(more);
        assert!(storage
            .put(&more_addr, more)
            .await
            .expect("put after wait_idle"));
    }

    /// A map resize takes the environment's *exclusive* lock, so it must wait
    /// for in-flight raw reads (which hold the *shared* lock) to finish before
    /// calling `env.resize()`. This proves `get_raw` holds that shared lock for
    /// the whole duration of its blocking closure; `all_keys` uses the same
    /// guard.
    // Holding the gate's write guard across awaits is the point of the test:
    // it parks the raw read's blocking closure while we probe try_resize.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn resize_waits_for_in_flight_raw_read() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"raw read holds the shared env lock";
        let address = LmdbStorage::compute_address(content);
        storage.put(&address, content).await.expect("put");

        // Park the raw read's blocking closure on the test gate. It acquires
        // the shared env_lock first, then parks here still holding it.
        let gate = storage.test_read_gate();
        let parked = gate.write();

        // Drop the awaiting future mid-flight: the biased select! polls get_raw
        // once — far enough to spawn the blocking task, which takes the shared
        // lock and parks on the gate — then completes on the ready branch,
        // dropping the awaiter. The detached closure keeps holding the lock.
        tokio::select! {
            biased;
            res = storage.get_raw(&address) => {
                panic!("get_raw must be parked on the test gate, got {res:?}")
            }
            () = std::future::ready(()) => {}
        }

        // Wait until the detached read has actually taken the shared lock,
        // signalled by the exclusive half no longer being immediately available.
        tokio::time::timeout(RAW_READ_LOCK_TIMEOUT, async {
            loop {
                let free = storage.env_lock.try_write().is_some();
                if !free {
                    break;
                }
                tokio::time::sleep(RAW_READ_LOCK_POLL).await;
            }
        })
        .await
        .expect("raw read did not take the shared env lock");

        // A resize needs the exclusive lock, so it must block while the raw
        // read holds the shared lock.
        let resize = storage.try_resize();
        tokio::pin!(resize);
        let blocked = tokio::time::timeout(RESIZE_BLOCKED_PROBE, &mut resize).await;
        assert!(
            blocked.is_err(),
            "try_resize completed while a raw read held the shared env lock"
        );

        // Release the read: it drops the shared lock, letting the resize take
        // the exclusive lock and finish.
        drop(parked);
        tokio::time::timeout(RESIZE_COMPLETE_TIMEOUT, &mut resize)
            .await
            .expect("try_resize did not complete after the raw read released")
            .expect("try_resize");
    }

    /// The gate fires on `Full` and only on `Full`, so the verdict has to tell a
    /// disk below its reserve from one above it, and has to notice when that
    /// stops being true.
    ///
    /// The third call is the one that matters for recovery: the below-reserve
    /// condition clears, and the verdict has to follow it rather than stay stuck
    /// on its earlier answer. A node that remembered a refusal would stop
    /// fetching for good.
    ///
    /// What this does not show: that a changed free-space reading is re-read from
    /// the filesystem. The condition is cleared by dropping the reserve, which is
    /// the same comparison approached from the other side.
    #[tokio::test]
    async fn capacity_verdict_follows_the_reserve_and_notices_recovery() {
        let (writable, _temp) = create_test_storage().await;
        assert_eq!(writable.capacity_verdict(), CapacityVerdict::Writable);

        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let config = LmdbStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            // Far above any real free space, the same way the e2e builds a
            // write-blocked node.
            disk_reserve: u64::MAX / 2,
            ..LmdbStorageConfig::test_default()
        };
        let mut full = LmdbStorage::new(config).await.expect("create storage");
        assert_eq!(full.capacity_verdict(), CapacityVerdict::Full);

        // Still short of space, so still `Full`. A `Full` result that populated
        // the passing-result cache would answer `Writable` here.
        assert_eq!(full.capacity_verdict(), CapacityVerdict::Full);

        // Space is no longer short. Nothing cached a refusal, so the very next
        // read has to see it.
        full.config.disk_reserve = 0;
        assert_eq!(
            full.capacity_verdict(),
            CapacityVerdict::Writable,
            "a refusal must not be negatively cached: the next read has to see the \
             below-reserve condition clear"
        );
    }

    /// A space query that fails says nothing about available space, so it must
    /// not read as a full disk. The gate stands a key down for five minutes on
    /// `Full` alone, and a failed `statvfs` is not a condition worth standing
    /// down for: it may be gone by the next cycle.
    ///
    /// The two `Ok` cases pin the boundary the reserve names: equal to the
    /// reserve is writable, one byte under it is not.
    ///
    /// What this does not show: that the gate leaves `Unknown` alone. The gate
    /// tests `== Full` on a separate line inside the verification cycle, which
    /// needs a network to reach, so this covers the classification only.
    #[test]
    fn a_failed_space_query_reads_as_unknown_not_full() {
        const RESERVE: u64 = 1024;

        assert_eq!(
            verdict_from_available_space(Err(std::io::Error::other("space query failed")), RESERVE),
            CapacityVerdict::Unknown,
            "a failed query must not be reported as a full disk"
        );

        assert_eq!(
            verdict_from_available_space(Ok(RESERVE - 1), RESERVE),
            CapacityVerdict::Full
        );
        assert_eq!(
            verdict_from_available_space(Ok(RESERVE), RESERVE),
            CapacityVerdict::Writable,
            "at the reserve is not below it"
        );
    }

    /// The verdict and the pre-check have to refuse on the same condition.
    ///
    /// They are two readings of one question — can this node write? — and two
    /// callers depend on them separately: the verification cycle gates the
    /// close-group probe on the verdict, while `execute_single_fetch` gates the
    /// dial on the pre-check. A verdict stricter than the pre-check is the
    /// harmful direction. A node the pre-check would let write stops
    /// discovering holders for keys it could have stored, which is
    /// under-replication rather than a saved probe, and nothing else in the
    /// change would notice.
    ///
    /// This is a tripwire, deliberately built on the state where the two are
    /// about to part company rather than on a bare full disk. ant-node
    /// \#210 makes the pre-check a two-part predicate — below the reserve *and*
    /// out of reusable pages inside the store — and a store that has deleted
    /// more than one chunk's worth of pages fails only the first half, because
    /// LMDB returns those pages to its own free list and never to the
    /// filesystem. On a bare full disk the two predicates still agree, so a
    /// test built on one would pass straight through the divergence. Whichever
    /// of the two changes merges second has to carry the second half into the
    /// verdict, and this is what makes that a red test rather than a textual
    /// conflict resolved without it.
    ///
    /// What this does not show: which of `Full` and `Unknown` a refusal is.
    /// `a_failed_space_query_reads_as_unknown_not_full` pins that, and only
    /// `Full` reaches the gate.
    #[tokio::test]
    async fn capacity_verdict_refuses_exactly_when_check_capacity_does() {
        let (mut storage, _temp) = create_test_storage().await;
        assert_eq!(storage.capacity_verdict(), CapacityVerdict::Writable);
        assert!(
            storage.check_capacity().is_ok(),
            "a writable verdict has to mean the pre-check admits the write"
        );

        // Two chunks written and deleted, so the store sits on more than one
        // chunk of space LMDB can reuse and the filesystem will never take
        // back. This is the pruned node the two predicates disagree about.
        for fill in [1u8, 2u8] {
            let content = vec![fill; MAX_CHUNK_SIZE];
            let address = LmdbStorage::compute_address(&content);
            assert!(storage.put(&address, &content).await.expect("put"));
            assert!(storage.delete(&address).await.expect("delete"));
        }

        // Established without either function under test, so the scenario does
        // not rest on the thing being measured.
        storage.config.disk_reserve = u64::MAX / 2;
        *storage.last_disk_ok.lock() = None;
        let available = fs2::available_space(&storage.env_dir).expect("query available space");
        assert!(
            available < storage.config.disk_reserve,
            "the volume has to read as below the reserve, or neither predicate is \
             being asked the interesting question"
        );
        // Reusable bytes read the way the two-part predicate reads them: the
        // file's size less the pages still holding data. `Env::stat` rather
        // than `non_free_pages_size`, which calls `String::from_utf8(key)` and
        // unwraps, so it panics on our 32 random bytes of key.
        let stat = storage.env.stat();
        let live_pages = (stat.branch_pages as u64)
            .saturating_add(stat.leaf_pages as u64)
            .saturating_add(stat.overflow_pages as u64);
        let live_bytes = live_pages.saturating_mul(u64::from(stat.page_size));
        let file_bytes = storage.env.real_disk_size().expect("query store file size");
        let reusable = file_bytes.saturating_sub(live_bytes);
        assert!(
            reusable > MAX_CHUNK_SIZE as u64,
            "the store has to sit on more than one chunk of reusable space, or the \
             two predicates are not yet being asked to differ \
             (file_bytes={file_bytes}, live_bytes={live_bytes})"
        );

        // Neither call caches a refusal, so the order of the two does not
        // decide either answer.
        let pre_check_refuses = storage.check_capacity().is_err();
        let verdict = storage.capacity_verdict();
        assert_eq!(
            pre_check_refuses,
            verdict != CapacityVerdict::Writable,
            "the dial pre-check and the verification gate disagree about whether \
             this node can write: check_capacity refuses={pre_check_refuses}, \
             verdict={verdict:?}. A verdict of Full under a pre-check that admits \
             the write leaves a node that can store chunks refusing to look for \
             them"
        );
    }
}
