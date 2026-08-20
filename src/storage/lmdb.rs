//! Content-addressed LMDB storage for chunks.
//!
//! Provides persistent storage for chunks using LMDB (via heed) for
//! memory-mapped, zero-copy reads with ACID transactions.
//!
//! ```text
//! {root}/chunks.mdb/   -- LMDB environment directory
//! ```

use crate::ant_protocol::{XorName, MAX_CHUNK_SIZE};
use crate::error::{Error, Result};
use crate::logging::{debug, info, trace, warn};
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, MdbError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// Slack granted to a *delete* that cannot copy-on-write inside the pinned map.
///
/// A delete is itself a write: LMDB copies the B-tree path before it frees the
/// leaf pages. On a store with no free page at all, a map pinned exactly to the
/// file size leaves a delete nowhere to go, so the node could not prune its way
/// back to health.
///
/// The slack is granted **only** on the delete retry path and taken away again
/// immediately, so an ordinary store can never allocate from it. Leaving it
/// permanently in the ceiling would hand every node a little more of the very
/// reserve this mode exists to protect, which on a shared volume multiplies by
/// the number of nodes.
const DELETE_COW_SLACK: u64 = 256 * 1024;

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
    /// Whether the map is currently pinned to the file's high-water mark.
    ///
    /// Set once available disk drops below the reserve. While pinned, LMDB can
    /// still serve a write from its own free list but cannot extend
    /// `data.mdb`, so the reserve is preserved by the allocator itself rather
    /// than by refusing every write up front.
    no_growth: Arc<AtomicBool>,
    /// Serialises entering and leaving no-growth mode.
    ///
    /// Setting `no_growth` and resizing the map is one compound transition
    /// spanning an await. Without this, two callers straddling the threshold
    /// can interleave so the flag ends up describing a map size that was never
    /// applied, leaving the store unpinned while it believes it is pinned.
    growth_mode_lock: tokio::sync::Mutex<()>,
    /// Maintenance allowance already spent in this low-disk episode.
    ///
    /// A delete's copy-on-write can extend `data.mdb`, and LMDB never gives
    /// file space back, so that growth is permanent. Budgeting the grant stops
    /// repeated fill-then-delete cycles walking the file into the reserve.
    /// Reset when the store leaves no-growth mode.
    delete_slack_granted: Arc<AtomicU64>,
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
            no_growth: Arc::new(AtomicBool::new(false)),
            growth_mode_lock: tokio::sync::Mutex::new(()),
            delete_slack_granted: Arc::new(AtomicU64::new(0)),
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

        // ── Capacity guard (cached — at most one syscall per interval) ──
        // Placed after the duplicate check so that re-storing an existing
        // chunk remains a harmless no-op even when disk space is low.
        //
        // Below the reserve this pins the map instead of refusing outright, so
        // the write is still attempted and LMDB decides whether a freed page
        // can take it. A node that has pruned heavily keeps serving the network
        // from the space it already occupies.
        let no_growth = self.sync_growth_mode().await?;

        // ── Write (with resize-on-demand) ───────────────────────────────
        match self.try_put(address, content).await? {
            PutOutcome::New => {}
            PutOutcome::Duplicate => {
                trace!("Chunk {} already exists", hex::encode(address));
                self.stats.write().duplicates += 1;
                return Ok(false);
            }
            PutOutcome::MapFull if no_growth => {
                // Both halves are now true: the volume is below the reserve and
                // no free page can take *this* value. Resizing would extend the
                // file into the reserve, so refuse.
                //
                // The refusal is not remembered. `MapFull` is specific to the
                // size just attempted — a smaller value may still fit a smaller
                // run — so caching it would let one maximum-sized chunk lock out
                // every subsequent write. `check_capacity` estimates instead.
                return Err(Error::Storage(format!(
                    "Insufficient disk space: {:.2} GiB reserve required and no reusable page \
                     in the local store fits this {} B value. \
                     Free disk space or increase the partition to continue storing chunks.",
                    bytes_to_gib(self.config.disk_reserve),
                    content.len(),
                )));
            }
            PutOutcome::MapFull => {
                // The map ceiling was reached but there may be more disk space
                // available (e.g. operator expanded the partition).
                //
                // Guarded: `no_growth` was sampled before the write, so the
                // store may have entered no-growth mode since. Growing the map
                // outside the transition lock could undo a pin that a
                // concurrent `sync_growth_mode` had just applied, handing the
                // reserve back to ordinary writes.
                self.try_resize_for_growth().await?;
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

        // Establish growth mode first, exactly as `put` does. Otherwise a
        // delete arriving while the volume is low but before any write has
        // pinned the map would copy-on-write into whatever head-room the
        // ceiling still had, growing `data.mdb` into the reserve without
        // passing through the budgeted allowance below.
        self.sync_growth_mode().await?;

        let deleted = match self.try_delete(&key).await? {
            DeleteOutcome::Done(existed) => existed,
            DeleteOutcome::MapFull => {
                // A delete is a write: LMDB copies the B-tree path before it
                // frees the leaf pages, so a store with no free page at all
                // cannot delete inside a map pinned to the file size. Without a
                // way through, a node that filled up before it ever pruned
                // could never prune its way out.
                //
                // Serialised against `sync_growth_mode` so the two cannot
                // interleave their resizes.
                let _transition = self.growth_mode_lock.lock().await;
                self.delete_with_slack(&key).await?
            }
        };

        if deleted {
            debug!("Deleted chunk {}", hex::encode(address));
        }

        Ok(deleted)
    }

    /// Attempt one delete, reporting `MapFull` rather than raising it.
    async fn try_delete(&self, key: &XorName) -> Result<DeleteOutcome> {
        let key = *key;
        let env = self.env.clone();
        let db = self.db;
        let lock = Arc::clone(&self.env_lock);

        self.blocking_tracker
            .spawn_blocking(move || -> Result<DeleteOutcome> {
                let _guard = lock.read();
                delete_in_txn(&env, db, &key)
            })
            .await
            .map_err(|e| Error::Storage(format!("LMDB delete task failed: {e}")))?
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
    /// verification on a full node — see `V2-411`).
    ///
    /// A node is full only when **both** halves are true: the volume is below
    /// the reserve *and* the store has no reusable page left. Deleting a record
    /// returns its pages to LMDB's free list and never to the filesystem, so a
    /// node that has pruned heavily sits on reusable capacity while `statvfs`
    /// still reports the volume as full. Refusing on the disk half alone stops
    /// such a node from writing into space it already owns.
    ///
    /// This is a **hint**, deliberately biased towards admitting: it estimates
    /// reusable bytes and only refuses when there is not even one chunk's worth.
    /// The authority on whether a given write fits stays with LMDB's allocator
    /// in [`Self::put`], because no page count can account for the
    /// copy-on-write of the B-tree path, the contiguous run a multi-megabyte
    /// value needs, or pages still pinned by an open read transaction. An
    /// over-optimistic hint costs one refused write; an over-pessimistic one
    /// would recreate the bug this exists to fix.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] when the volume is below the reserve and the
    /// store holds less than one chunk of reusable space, or when the
    /// disk-space query itself fails.
    pub(crate) fn check_capacity(&self) -> Result<()> {
        let Some(available) = self.available_space_cached()? else {
            return Ok(());
        };

        let reusable = self.reusable_bytes()?;
        if reusable >= MAX_CHUNK_SIZE as u64 {
            return Ok(());
        }

        Err(Error::Storage(format!(
            "Insufficient disk space: {:.2} GiB available, {:.2} GiB reserve required, \
             and only {reusable} B reusable inside the local store. \
             Free disk space or increase the partition to continue storing chunks.",
            bytes_to_gib(available),
            bytes_to_gib(self.config.disk_reserve),
        )))
    }

    /// Estimated bytes inside `data.mdb` that LMDB could write without growing
    /// the file: the file size minus the pages currently holding data.
    ///
    /// Deliberately an over-estimate. `stat()` counts only the branch, leaf and
    /// overflow pages of the unnamed database, so the free-list's own pages and
    /// the environment metadata fall on the "reusable" side. Erring high keeps
    /// [`Self::check_capacity`] biased towards admitting the attempt.
    ///
    /// Uses `stat()` rather than heed's `non_free_pages_size()`, which walks the
    /// unnamed database calling `String::from_utf8(key).unwrap()` on every key
    /// without a zero byte. Our keys are 32 random bytes, so that call panics
    /// almost immediately. A single unnamed database makes `stat()` equivalent.
    fn reusable_bytes(&self) -> Result<u64> {
        // Order matters. The two samples are not atomic, so read the live pages
        // first and the file length second: a write committing in between then
        // pairs an older (smaller) live count with a newer (larger) file, which
        // over-estimates. Sampling the other way round pairs a stale file
        // length with a fresh live count and can under-estimate, which would
        // refuse a node that has room — the very bug this fixes.
        let stat = self.env.stat();
        let live_pages = (stat.branch_pages as u64)
            .saturating_add(stat.leaf_pages as u64)
            .saturating_add(stat.overflow_pages as u64);
        let live_bytes = live_pages.saturating_mul(u64::from(stat.page_size));

        let file_bytes = self
            .env
            .real_disk_size()
            .map_err(|e| Error::Storage(format!("Failed to query LMDB file size: {e}")))?;

        Ok(file_bytes.saturating_sub(live_bytes))
    }

    /// Available bytes on the storage volume, or `None` when a recent check
    /// already showed it above the reserve.
    ///
    /// Only *passing* results are cached, so a low-space condition is always
    /// re-measured and freed space is detected promptly.
    fn available_space_cached(&self) -> Result<Option<u64>> {
        {
            let last = self.last_disk_ok.lock();
            if let Some(t) = *last {
                if t.elapsed().as_secs() < DISK_CHECK_INTERVAL_SECS {
                    return Ok(None);
                }
            }
        }

        let available = fs2::available_space(&self.env_dir)
            .map_err(|e| Error::Storage(format!("Failed to query available disk space: {e}")))?;

        if available >= self.config.disk_reserve {
            *self.last_disk_ok.lock() = Some(Instant::now());
            return Ok(None);
        }

        Ok(Some(available))
    }

    /// Align the map ceiling with the current disk state, returning whether the
    /// store is in no-growth mode.
    ///
    /// Below the reserve the map is pinned to the file's high-water mark, so a
    /// put succeeds exactly when LMDB can satisfy it from the free list and
    /// returns `MapFull` the moment it would need to extend `data.mdb`. That
    /// makes the allocator the authority on "can this write fit".
    ///
    /// The whole transition runs under `growth_mode_lock`. Setting the flag and
    /// resizing the map is one compound change spanning an await, so without
    /// serialisation two callers straddling the threshold can interleave and
    /// leave the flag describing a map that was never applied.
    async fn sync_growth_mode(&self) -> Result<bool> {
        let _transition = self.growth_mode_lock.lock().await;

        // Re-measured inside the lock: a caller that queued behind a transition
        // must act on the state that transition left behind, not the one it saw
        // before waiting.
        if self.available_space_cached()?.is_none() {
            // At or above the reserve: restore normal head-room if we pinned it.
            if self.no_growth.load(Ordering::Acquire) {
                // Intent first, work second. A `spawn_blocking` body outlives a
                // cancelled awaiter, so ordering between two resizes cannot be
                // guaranteed by holding an async lock. Publishing the intent
                // before the work lets each closure re-read it under the
                // exclusive lock and decline if it has since been reversed.
                self.no_growth.store(false, Ordering::Release);
                self.try_resize().await?;
            }
            // Real disk again: the maintenance allowance is refreshed. Done on
            // every healthy pass, not just the transition, so an allowance
            // spent while the flag happened to be clear is still returned.
            self.delete_slack_granted.store(0, Ordering::Release);
            return Ok(false);
        }

        // Called unconditionally, not just on the transition. A re-pin that
        // failed, or a transition whose caller was cancelled while its detached
        // resize was still in flight, can leave the flag set while the map is
        // not actually pinned; re-asserting it here repairs that instead of
        // trusting the flag. The call is a no-op when already pinned.
        self.no_growth.store(true, Ordering::Release);
        self.pin_map_to_high_water().await?;

        Ok(true)
    }

    /// Pin the LMDB map to the size of `data.mdb` on disk.
    ///
    /// Every page already in the file stays usable, including free ones, but
    /// the file cannot grow, so the configured reserve is preserved by LMDB
    /// itself rather than by refusing writes it could have served.
    ///
    /// Deliberately leaves **no** head-room: any slack in the ceiling is
    /// ordinary put capacity, so it would be spent on the next chunk rather
    /// than kept for maintenance, and on a shared volume every node would take
    /// its own slice out of the reserve. Deletes get their copy-on-write room
    /// on demand instead, see [`Self::delete`].
    ///
    /// Takes the **exclusive** `env_lock` for the same reason
    /// [`Self::try_resize`] does: `mdb_env_set_mapsize` requires that no
    /// transaction is active. Callers hold `growth_mode_lock`.
    #[allow(unsafe_code)]
    async fn pin_map_to_high_water(&self) -> Result<()> {
        // The "is it already pinned?" test lives inside the exclusive lock
        // below, not out here. An unlocked pre-check can observe "already
        // pinned" moments before a detached resize from a cancelled transition
        // lands, after which the flag would claim a pin that no longer holds.
        // Callers invoke this on every low-disk write so the pinned state
        // repairs itself; the locked section is a few reads when nothing is to
        // be done.
        let env = self.env.clone();
        let lock = Arc::clone(&self.env_lock);
        let no_growth = Arc::clone(&self.no_growth);

        self.blocking_tracker
            .spawn_blocking(move || -> Result<()> {
                // Exclusive lock guarantees no concurrent transactions.
                let _guard = lock.write();

                // Re-read under the lock: this closure may have been queued
                // behind others, or its awaiter cancelled, and the store may
                // have left no-growth mode since it was spawned.
                if !no_growth.load(Ordering::Acquire) {
                    return Ok(());
                }

                let current_map = env.info().map_size;
                let file_bytes = env
                    .real_disk_size()
                    .map_err(|e| Error::Storage(format!("Failed to query LMDB file size: {e}")))?;

                let page = page_size::get() as u64;
                let aligned = file_bytes.div_ceil(page) * page;
                let target = usize::try_from(aligned).unwrap_or(usize::MAX);

                // Re-checked under the lock: the state may have moved between
                // the cheap check and here.
                if target >= current_map {
                    return Ok(());
                }

                // SAFETY: We hold an exclusive lock, so no transactions are active.
                unsafe {
                    env.resize(target)
                        .map_err(|e| Error::Storage(format!("Failed to pin LMDB map: {e}")))?;
                }

                info!(
                    "Disk below reserve: pinned LMDB map to {:.2} GiB (was {:.2} GiB). \
                     Writes that fit in already-freed pages still succeed; \
                     only writes that would grow the file are refused.",
                    bytes_to_gib(target as u64),
                    bytes_to_gib(current_map as u64),
                );
                Ok(())
            })
            .await
            .map_err(|e| Error::Storage(format!("LMDB map pin task failed: {e}")))?
    }

    /// Grow the map for a write, unless the store is pinned below the reserve.
    ///
    /// Serialised against [`Self::sync_growth_mode`] so a resize cannot land
    /// after a pin and quietly undo it. If the store entered no-growth mode
    /// while the write was in flight, the caller's `MapFull` is final and no
    /// growth happens.
    async fn try_resize_for_growth(&self) -> Result<()> {
        let _transition = self.growth_mode_lock.lock().await;

        if self.no_growth.load(Ordering::Acquire) {
            return Ok(());
        }

        self.try_resize().await
    }

    /// Delete `key` with [`DELETE_COW_SLACK`] of temporary map head-room, then
    /// take the head-room straight back.
    ///
    /// The raise, the delete and the re-pin all happen inside **one** exclusive
    /// `env_lock` scope. Doing them as three separate locked steps would leave
    /// windows in which an ordinary put could allocate from the raised ceiling,
    /// spending the reserve on a chunk instead of on the maintenance it was
    /// granted for, and an error or cancellation between the steps would leave
    /// the ceiling raised for good.
    ///
    /// The grant is budgeted. If the delete's copy-on-write does extend
    /// `data.mdb`, that growth is permanent — LMDB never returns file space —
    /// so an unbudgeted grant would let repeated fill-then-delete cycles walk
    /// the file into the reserve a slice at a time. In practice one grant is
    /// enough: once a delete commits there are free pages again, and later
    /// deletes reuse them. The budget resets when the store leaves no-growth
    /// mode, i.e. when there is real disk to work with again.
    #[allow(unsafe_code)]
    async fn delete_with_slack(&self, key: &XorName) -> Result<bool> {
        let key = *key;
        let env = self.env.clone();
        let db = self.db;
        let lock = Arc::clone(&self.env_lock);
        let budget = Arc::clone(&self.delete_slack_granted);

        let outcome = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<DeleteOutcome> {
                // Claim, spend and settle the allowance entirely inside the
                // closure. A `spawn_blocking` body keeps running when its
                // awaiter is dropped, so accounting split across the await could
                // claim the budget and then never release it, permanently
                // costing the node its ability to prune.
                if budget
                    .compare_exchange(0, DELETE_COW_SLACK, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return Err(Error::Storage(format!(
                        "Cannot delete: the local store is full and its {DELETE_COW_SLACK} B \
                         maintenance allowance is already spent. Free disk space to continue."
                    )));
                }

                // From here every exit settles the charge, including a panic.
                let mut allowance = DeleteAllowance {
                    budget: &budget,
                    keep: false,
                };

                // Exclusive for the whole sequence: no transaction may be
                // active across either resize, and no put may observe the
                // raised ceiling.
                let _guard = lock.write();

                let page = page_size::get() as u64;
                let previous_map = env.info().map_size;
                let raised = (previous_map as u64)
                    .saturating_add(DELETE_COW_SLACK)
                    .div_ceil(page)
                    .saturating_mul(page);

                // SAFETY: exclusive lock held, so no transactions are active.
                let granted = unsafe {
                    env.resize(usize::try_from(raised).unwrap_or(usize::MAX))
                        .map_err(|e| Error::Storage(format!("Failed to grant delete slack: {e}")))
                };
                granted?;

                // Armed across the delete so an unwind still restores the
                // ceiling; disarmed once the explicit restore below succeeds.
                let mut ceiling_guard = MapCeilingRestorer {
                    env: &env,
                    previous: previous_map,
                    armed: true,
                };

                let outcome = delete_in_txn(&env, db, &key);

                // Keep the charge the moment the delete commits: that is the
                // one outcome whose copy-on-write can have extended
                // `data.mdb`, and that growth is permanent. Deciding here
                // rather than on the combined result means a failure to restore
                // the ceiling cannot refund an allowance that was really spent.
                if matches!(outcome, Ok(DeleteOutcome::Done(_))) {
                    allowance.keep = true;
                }

                // Undo the raise before releasing the lock, on every path and
                // whatever the delete did. Restoring to the previous ceiling
                // rather than to a freshly measured file size keeps this
                // unconditional: it is exactly the inverse of the raise, needs
                // no second syscall that could itself fail, and is correct
                // whether or not the store was pinned. If the copy-on-write did
                // extend the file, LMDB clamps a request below the space in use,
                // so the map still covers the data.
                //
                // SAFETY: exclusive lock held, so no transactions are active.
                let restored = unsafe {
                    env.resize(previous_map)
                        .map_err(|e| Error::Storage(format!("Failed to restore LMDB map: {e}")))
                };
                if restored.is_ok() {
                    ceiling_guard.armed = false;
                }

                // A failed restore is reported ahead of a failed delete, so the
                // failure is not lost behind the delete's own error.
                match (outcome, restored) {
                    (Ok(outcome), Ok(())) => Ok(outcome),
                    (_, Err(e)) | (Err(e), Ok(())) => Err(e),
                }
            })
            .await
            .map_err(|e| Error::Storage(format!("LMDB delete-slack task failed: {e}")))?;

        match outcome? {
            DeleteOutcome::Done(existed) => Ok(existed),
            DeleteOutcome::MapFull => Err(Error::Storage(
                "LMDB map full during delete even with the maintenance allowance".into(),
            )),
        }
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
        let env = self.env.clone();
        let lock = Arc::clone(&self.env_lock);
        let no_growth = Arc::clone(&self.no_growth);
        let env_dir = self.env_dir.clone();
        let reserve = self.config.disk_reserve;

        self.blocking_tracker
            .spawn_blocking(move || -> Result<()> {
                // Exclusive lock guarantees no concurrent transactions.
                let _guard = lock.write();

                // Re-read under the lock. A `spawn_blocking` body outlives a
                // cancelled awaiter, so this closure may land after the store
                // entered no-growth mode. Growing then would hand back the
                // head-room a pin had just taken away, and with it the disk
                // reserve.
                if no_growth.load(Ordering::Acquire) {
                    return Ok(());
                }

                // Measured here rather than before the spawn, so a late closure
                // sizes from the disk as it is now, not as it was when queued.
                let from_disk = compute_map_size(&env_dir, reserve)?;

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

/// Restores an LMDB map ceiling when dropped, including while unwinding.
///
/// The explicit restore in [`LmdbStorage::delete_with_slack`] is the normal
/// path, because it can report a failure to the caller. This exists so a panic
/// between the raise and that restore cannot leave the ceiling raised, which
/// would quietly hand ordinary writes the disk reserve.
struct MapCeilingRestorer<'a> {
    env: &'a Env,
    previous: usize,
    armed: bool,
}

impl Drop for MapCeilingRestorer<'_> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // SAFETY: the owner holds the exclusive `env_lock` for this whole
        // scope, so no transaction is active.
        unsafe {
            if let Err(e) = self.env.resize(self.previous) {
                warn!("Failed to restore the LMDB map ceiling while unwinding: {e}");
            }
        }
    }
}

/// Settles the delete maintenance allowance when dropped, including on unwind.
///
/// The allowance is claimed before the ceiling is raised, so every exit from
/// that scope has to either keep the charge or return it. A `Drop` impl is the
/// only form that also covers a panic: a stranded charge would permanently stop
/// the node pruning for the rest of the low-disk episode.
struct DeleteAllowance<'a> {
    budget: &'a AtomicU64,
    keep: bool,
}

impl Drop for DeleteAllowance<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.budget.store(0, Ordering::Release);
        }
    }
}

/// Run one delete in its own write transaction, reporting `MapFull` rather than
/// raising it.
///
/// The caller owns the `env_lock` discipline: [`LmdbStorage::try_delete`] holds
/// the shared guard, [`LmdbStorage::delete_with_slack`] the exclusive one.
fn delete_in_txn(env: &Env, db: Database<Bytes, Bytes>, key: &XorName) -> Result<DeleteOutcome> {
    let mut wtxn = match env.write_txn() {
        Ok(wtxn) => wtxn,
        Err(heed::Error::Mdb(MdbError::MapFull)) => return Ok(DeleteOutcome::MapFull),
        Err(e) => return Err(Error::Storage(format!("Failed to create write txn: {e}"))),
    };
    let existed = match db.delete(&mut wtxn, key) {
        Ok(existed) => existed,
        Err(heed::Error::Mdb(MdbError::MapFull)) => return Ok(DeleteOutcome::MapFull),
        Err(e) => return Err(Error::Storage(format!("Failed to delete chunk: {e}"))),
    };
    match wtxn.commit() {
        Ok(()) => Ok(DeleteOutcome::Done(existed)),
        Err(heed::Error::Mdb(MdbError::MapFull)) => Ok(DeleteOutcome::MapFull),
        Err(e) => Err(Error::Storage(format!("Failed to commit delete: {e}"))),
    }
}

/// Outcome of one delete attempt.
enum DeleteOutcome {
    /// The delete committed; the flag is whether the key had existed.
    Done(bool),
    /// The map ceiling left no room for the delete's copy-on-write.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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

    // ── Capacity below the disk reserve (LMDB reuse) ────────────────────

    /// Value size for the reuse tests. A whole number of chunks' worth, so the
    /// space freed by a few deletes is unambiguously enough for one more.
    const REUSE_VALUE_LEN: usize = 1024 * 1024;

    /// Distinct filler of `REUSE_VALUE_LEN` bytes.
    fn reuse_filler(seed: u32) -> Vec<u8> {
        let mut content = seed.to_le_bytes().to_vec();
        content.resize(REUSE_VALUE_LEN, 0u8);
        content
    }

    /// A config for `dir` whose reserve exceeds any real disk, so the store
    /// always sees itself as below the reserve.
    fn below_reserve_config(dir: &Path) -> LmdbStorageConfig {
        LmdbStorageConfig {
            root_dir: dir.to_path_buf(),
            disk_reserve: u64::MAX,
            ..LmdbStorageConfig::test_default()
        }
    }

    /// Write `count` chunks with an unconstrained reserve, returning their
    /// addresses in insertion order.
    async fn seed_chunks(dir: &Path, count: u32) -> Vec<XorName> {
        let config = LmdbStorageConfig {
            root_dir: dir.to_path_buf(),
            ..LmdbStorageConfig::test_default()
        };
        let storage = LmdbStorage::new(config).await.expect("create storage");

        let mut addresses = Vec::new();
        for seed in 0..count {
            let content = reuse_filler(seed);
            let address = LmdbStorage::compute_address(&content);
            storage.put(&address, &content).await.expect("seed put");
            addresses.push(address);
        }

        storage.wait_idle().await;
        addresses
    }

    fn file_len(storage: &LmdbStorage) -> u64 {
        storage.env.real_disk_size().expect("real_disk_size")
    }

    /// The regression this change is about: a node whose volume is below the
    /// reserve must still write into pages an earlier delete freed. Before the
    /// fix the pre-check refused on the disk half alone, so a node that had
    /// pruned sat on reusable space it could not use.
    #[tokio::test]
    async fn below_reserve_put_reuses_freed_pages() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let seeded = seed_chunks(temp_dir.path(), 12).await;

        let storage = LmdbStorage::new(below_reserve_config(temp_dir.path()))
            .await
            .expect("reopen storage");

        let content = reuse_filler(u32::MAX);
        let address = LmdbStorage::compute_address(&content);

        // Nothing freed yet, so this write would have to grow the file. Below
        // the reserve that is exactly what must be refused.
        assert!(
            storage.put(&address, &content).await.is_err(),
            "a write that must grow the file was allowed below the reserve"
        );

        // Free several chunks. Their pages go on LMDB's free list, not back to
        // the filesystem, so `statvfs` still reports the volume as full.
        for seeded_address in seeded.iter().take(6) {
            assert!(storage.delete(seeded_address).await.expect("delete"));
        }

        let before = file_len(&storage);
        let stored = storage
            .put(&address, &content)
            .await
            .expect("put into freed pages was refused below the reserve");
        assert!(stored);
        assert_eq!(
            storage.get(&address).await.expect("get"),
            Some(content),
            "chunk written into reused pages did not read back"
        );

        // The whole point: it was served from inside the existing file.
        assert_eq!(
            file_len(&storage),
            before,
            "reusing freed pages grew data.mdb, consuming the reserve"
        );
    }

    /// A refused write must not have grown the file on its way to failing,
    /// which is what protects the reserve while the map is pinned.
    #[tokio::test]
    async fn below_reserve_refused_put_does_not_grow_the_file() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let _ = seed_chunks(temp_dir.path(), 6).await;

        let storage = LmdbStorage::new(below_reserve_config(temp_dir.path()))
            .await
            .expect("reopen storage");

        let content = reuse_filler(u32::MAX);
        let address = LmdbStorage::compute_address(&content);

        // Take the baseline after the first attempt, so it includes the pin.
        let refusal = storage
            .put(&address, &content)
            .await
            .expect_err("a write that must grow the file was allowed");
        assert!(
            refusal.to_string().contains("Insufficient disk space"),
            "refused for the wrong reason: {refusal}"
        );
        let before = file_len(&storage);
        let pinned_map = storage.env.info().map_size;

        for seed in 0..4u32 {
            let content = reuse_filler(u32::MAX - 1 - seed);
            let address = LmdbStorage::compute_address(&content);
            let refusal = storage
                .put(&address, &content)
                .await
                .expect_err("a write that must grow the file was allowed");
            assert!(
                refusal.to_string().contains("Insufficient disk space"),
                "refused for the wrong reason: {refusal}"
            );
        }

        assert_eq!(
            storage.env.info().map_size,
            pinned_map,
            "the map ceiling drifted while writes were being refused"
        );

        assert_eq!(
            file_len(&storage),
            before,
            "refused writes still extended data.mdb into the reserve"
        );
    }

    /// One refused maximum-sized value must not lock out smaller ones. LMDB's
    /// `MapFull` is specific to the allocation it was asked for, so remembering
    /// it store-wide would let a single large chunk deny every later write.
    #[tokio::test]
    async fn large_refusal_does_not_block_a_smaller_put() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let seeded = seed_chunks(temp_dir.path(), 10).await;

        let storage = LmdbStorage::new(below_reserve_config(temp_dir.path()))
            .await
            .expect("reopen storage");

        // Free room for a small value, but not for a large one.
        let Some(first) = seeded.first() else {
            panic!("seed_chunks returned no addresses");
        };
        assert!(storage.delete(first).await.expect("delete"));

        // A value far larger than what was freed cannot fit.
        let oversized = vec![3u8; 8 * REUSE_VALUE_LEN];
        let oversized_address = LmdbStorage::compute_address(&oversized);
        assert!(storage.put(&oversized_address, &oversized).await.is_err());

        // A small value still must, using the pages the delete released.
        let small = b"small record that fits in a freed page".to_vec();
        let small_address = LmdbStorage::compute_address(&small);
        let stored = storage
            .put(&small_address, &small)
            .await
            .expect("a large refusal blocked a small put that had room");
        assert!(stored);
    }

    /// A store with no reusable page must still be able to delete, or it can
    /// never prune its way back to health.
    #[tokio::test]
    async fn full_store_below_reserve_can_still_delete() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let seeded = seed_chunks(temp_dir.path(), 8).await;

        let storage = LmdbStorage::new(below_reserve_config(temp_dir.path()))
            .await
            .expect("reopen storage");

        // Pin the map by attempting a write that cannot fit.
        let content = reuse_filler(u32::MAX);
        let address = LmdbStorage::compute_address(&content);
        assert!(storage.put(&address, &content).await.is_err());
        assert!(storage.no_growth.load(Ordering::Acquire));

        let pinned_map = storage.env.info().map_size;

        for seeded_address in &seeded {
            assert!(
                storage.delete(seeded_address).await.expect("delete"),
                "a pinned store could not prune"
            );
        }
        assert_eq!(storage.current_chunks().expect("current_chunks"), 0);

        // Whether or not any delete needed the maintenance allowance, none of
        // it may be left in the ceiling afterwards: a raised ceiling is
        // ordinary put capacity, so leaking it hands away the reserve.
        let file_bytes = file_len(&storage);
        assert!(
            storage.env.info().map_size as u64 <= file_bytes.max(pinned_map as u64),
            "delete left maintenance slack in the map ceiling"
        );

        // And the store must still refuse a write it cannot fit, i.e. the pin
        // is still doing its job after the prune.
        let oversized = vec![9u8; 64 * REUSE_VALUE_LEN];
        let oversized_address = LmdbStorage::compute_address(&oversized);
        assert!(
            storage.put(&oversized_address, &oversized).await.is_err(),
            "pinning stopped working after a delete used the allowance"
        );
    }

    /// The pre-check must admit while reuse is plausible and refuse once it is
    /// not. Refusing on `statvfs` alone is what blinded a node to its own free
    /// pages, so being below the reserve cannot by itself be an error.
    #[tokio::test]
    async fn check_capacity_tracks_reusable_space_not_just_disk() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let seeded = seed_chunks(temp_dir.path(), 16).await;

        let storage = LmdbStorage::new(below_reserve_config(temp_dir.path()))
            .await
            .expect("reopen storage");

        // A freshly written store has almost no free page, so below the reserve
        // the pre-check refuses and the caller skips its expensive setup.
        assert!(
            storage.check_capacity().is_err(),
            "pre-check stayed open on a store with no reusable space"
        );

        // Pruning puts pages back on the free list. Nothing is returned to the
        // filesystem, so `statvfs` is unchanged and only the reusable half of
        // the predicate can reopen the node.
        for seeded_address in seeded.iter().take(10) {
            assert!(storage.delete(seeded_address).await.expect("delete"));
        }

        storage
            .check_capacity()
            .expect("pre-check stayed closed after pruning freed pages");
    }

    /// Freeing disk must lift the pin, or a node would stay clamped to its
    /// high-water mark after an operator grew the partition.
    #[tokio::test]
    async fn leaving_no_growth_restores_head_room() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let _ = seed_chunks(temp_dir.path(), 6).await;

        let mut storage = LmdbStorage::new(below_reserve_config(temp_dir.path()))
            .await
            .expect("reopen storage");

        let content = reuse_filler(u32::MAX);
        let address = LmdbStorage::compute_address(&content);
        assert!(storage.put(&address, &content).await.is_err());
        assert!(storage.no_growth.load(Ordering::Acquire));
        let pinned_map = storage.env.info().map_size;

        // Simulate the operator freeing space: the reserve is now satisfiable.
        storage.config.disk_reserve = 0;
        *storage.last_disk_ok.lock() = None;

        let stored = storage
            .put(&address, &content)
            .await
            .expect("store stayed pinned after disk was freed");
        assert!(stored);
        assert!(!storage.no_growth.load(Ordering::Acquire));
        assert!(
            storage.env.info().map_size > pinned_map,
            "map was not re-grown after leaving no-growth mode"
        );
    }

    /// Above the reserve nothing changes: no pinning, and writes grow the file
    /// on demand exactly as before.
    #[tokio::test]
    async fn above_reserve_behaviour_is_unchanged() {
        let (storage, _temp) = create_test_storage().await;

        storage
            .check_capacity()
            .expect("pre-check on a healthy node");

        let content = reuse_filler(1);
        let address = LmdbStorage::compute_address(&content);
        assert!(storage.put(&address, &content).await.expect("put"));
        assert!(!storage.no_growth.load(Ordering::Acquire));
        storage
            .check_capacity()
            .expect("pre-check after a healthy put");
    }
}
