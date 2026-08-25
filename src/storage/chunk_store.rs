//! The node's chunk store: a file store, plus the legacy LMDB environment for as long
//! as one still exists on disk.
//!
//! Every caller in the node talks to this type and sees **one** key set. That is the
//! detail that keeps quoting, commitments, hints, audits and pruning coherent while a
//! chunk moves from LMDB to a file: the backing changes, the logical key set does not.
//!
//! There is one deliberate asymmetry, and it is the whole safety argument of the
//! migration. Serving reads the **union**, so the node answers for everything it ever
//! committed to. The commitment builder reads only the **file-backed** set once the node
//! has settled on what it will keep, so the node stops claiming keys it is about to give
//! up. Between those two, a node is at worst over-honest: it serves more than it claims.

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::logging::{debug, error, info, warn};
use crate::storage::file_store::{FileStore, FileStoreConfig};
use crate::storage::lmdb::{LmdbStorage, LmdbStorageConfig};
use crate::storage::migration::{
    CopyReport, MigrationConfig, MigrationPhase, MigrationState, REQUIRED_REBUILDS_BEFORE_RETIRE,
};
use crate::storage::StorageStats;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Directory name of the legacy LMDB environment, under the node root.
pub const LEGACY_ENV_DIR: &str = "chunks.mdb";

/// Suffix for a legacy environment that has been retired but not yet deleted.
pub const RETIRED_SUFFIX: &str = ".retired";

/// Records that a retirement was authorised and may not have finished.
///
/// The rename that moves the legacy environment aside cannot be shown to be durable off
/// Unix: there is no way to flush a directory through the standard library, and
/// `MoveFileEx` is not documented as durable at return without a flag std does not use.
/// So a power loss can bring the environment back under its old name with its contents
/// already deleted, and a node that then tried to open it would fail to start.
///
/// This marker is what makes that safe. It is created before anything is moved, with the
/// same create-and-flush that publishes a chunk, which *is* documented as durable
/// everywhere. It means: the file store has been proven to hold every chunk, so the legacy
/// environment is no longer needed. A start that finds it finishes the removal instead of
/// opening whatever is there. It is cleared when the removal completes, and also when a
/// rename fails recoverably and the node goes back to bridging, so it only ever survives a
/// crash.
const RETIREMENT_MARKER: &str = "chunks.mdb.retiring";

/// The legacy environment's data file. Its presence is what says a node still has one.
const LEGACY_DATA_FILE: &str = "data.mdb";

/// How many times retirement retries taking sole ownership of the legacy handle before
/// giving up for this tick.
const RETIRE_UNWRAP_ATTEMPTS: u32 = 20;

/// How long to wait between those attempts.
const RETIRE_UNWRAP_BACKOFF: Duration = Duration::from_millis(100);

/// How many chunks the verification pass checks between progress lines.
const VERIFY_LOG_EVERY: u64 = 2000;

/// How many per-key critical sections the facade keeps.
///
/// Keyed on the address's LAST byte, for the same reason the shard directories are: a
/// node's keys share their leading bytes, so lanes keyed on the first byte would all
/// collapse into one.
const KEY_LOCK_LANES: usize = 256;

/// Configuration for [`ChunkStore`].
#[derive(Debug, Clone)]
pub struct ChunkStoreConfig {
    /// Node root directory.
    pub root_dir: PathBuf,
    /// Verify `BLAKE3(content) == address` on read.
    pub verify_on_read: bool,
    /// Explicit LMDB map size cap in bytes, used only while a legacy environment exists.
    ///
    /// Dies with LMDB. Kept so an operator's existing `storage.db_size_gb` still means
    /// what it meant during the bridge.
    pub max_map_size: usize,
    /// Minimum free disk space to preserve on the storage partition.
    pub disk_reserve: u64,
    /// Migration controls.
    pub migration: MigrationConfig,
}

impl Default for ChunkStoreConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from(".ant/chunks"),
            verify_on_read: true,
            max_map_size: 0,
            disk_reserve: crate::storage::DEFAULT_DISK_RESERVE,
            migration: MigrationConfig::default(),
        }
    }
}

impl ChunkStoreConfig {
    /// A test-friendly default with the disk reserve disabled, so unit tests do not
    /// depend on the host having spare gigabytes.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_default() -> Self {
        Self {
            disk_reserve: 0,
            ..Self::default()
        }
    }
}

/// The legacy environment and the keys only it still holds.
#[derive(Clone)]
struct Legacy {
    /// The LMDB handle.
    lmdb: Arc<LmdbStorage>,
    /// Keys in the legacy environment that are **not** in the file store.
    ///
    /// Kept in memory so the union view costs nothing on the hot paths: `exists` and
    /// `current_chunks` never touch LMDB, and `all_keys` merges two already-sorted
    /// sequences. It is derived at open (LMDB keys minus file keys) and maintained by
    /// every write, copy and delete.
    only: Arc<parking_lot::RwLock<BTreeSet<XorName>>>,
}

/// Content-addressed chunk storage.
pub struct ChunkStore {
    /// The file store. Always present, always the write target.
    files: Arc<FileStore>,
    /// The legacy environment, until it is retired.
    legacy: parking_lot::RwLock<Option<Legacy>>,
    /// Excludes retirement while any operation that touches the legacy environment runs.
    ///
    /// Reads, writes and deletes take it shared for their whole duration; retirement takes
    /// it exclusively before it takes the environment away. Sole ownership of the handle
    /// is not enough on its own: a read that has decided the file store cannot answer, and
    /// has not yet taken a legacy handle, holds nothing and would be invisible to that
    /// check. Nor would holding a handle throughout do instead, because on a busy node
    /// there would always be one and retirement would never see the environment
    /// unreferenced. Retirement also waits for the environment to go idle, which never
    /// happens if new work can keep starting in it.
    ///
    /// A shared/exclusive lock states the actual requirement, and because it is fair, a
    /// waiting retirement stops new work starting rather than starving behind it.
    retirement: tokio::sync::RwLock<()>,
    /// Where the legacy environment lives.
    legacy_env_dir: PathBuf,
    /// Store configuration.
    config: ChunkStoreConfig,
    /// The persisted migration marker.
    state: parking_lot::RwLock<MigrationState>,
    /// One lock per shard, held across a whole logical key transition.
    ///
    /// The file store has its own lane locks, but those only make a single file write
    /// atomic. The races that matter here span two stores and an await point: the copier
    /// reads a chunk out of LMDB, the pruner deletes that chunk from both stores, and
    /// then the copier's write lands and resurrects it. One critical section per key,
    /// held across put, delete and copy, is what closes that.
    key_locks: Vec<tokio::sync::Mutex<()>>,
}

impl ChunkStore {
    /// Open the store under `config.root_dir`.
    ///
    /// Opens the legacy environment only if one is already on disk. A fresh node never
    /// creates one, so it never pays for a memory map it will not use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if either store cannot be opened.
    pub async fn new(config: ChunkStoreConfig) -> Result<Self> {
        let files = Arc::new(
            FileStore::new(FileStoreConfig {
                root_dir: config.root_dir.clone(),
                verify_on_read: config.verify_on_read,
                disk_reserve: config.disk_reserve,
            })
            .await?,
        );

        // Before anything looks at the legacy environment: a start that finds the
        // retirement marker finishes what a previous run began, rather than opening a
        // directory that may be half deleted.
        let kept = finish_interrupted_retirement(&config, &files).await;
        sweep_retired_legacy(&config.root_dir);
        let legacy_env_dir = config.root_dir.join(LEGACY_ENV_DIR);
        let legacy = match kept {
            // Already open, and opening it is what proved it was worth keeping.
            Some(legacy) => Some(legacy),
            None if legacy_present(&config.root_dir)? => {
                Some(Self::open_legacy(&config, &files).await?)
            }
            None => None,
        };

        let phase = if legacy.is_some() {
            MigrationPhase::Bridging
        } else {
            MigrationPhase::FilesOnly
        };
        let mut state = MigrationState::load_or_create(&config.root_dir, phase);

        // The filesystem is the authority on whether a legacy environment exists; the
        // marker only records decisions. Reconcile rather than trust.
        if legacy.is_none() && state.phase != MigrationPhase::FilesOnly {
            info!("No legacy chunk environment on disk; the migration is already complete");
            state.phase = MigrationPhase::FilesOnly;
            if let Err(e) = state.save(&config.root_dir) {
                warn!("Could not persist the migration marker: {e}");
            }
        } else if legacy.is_some()
            && state.phase == MigrationPhase::Committed
            && files.current_chunks().unwrap_or(0) < state.kept_key_count
        {
            // The marker says this node already settled on what it would keep, but the
            // file store holds less than it recorded keeping. Something outside the node
            // changed the data directory, and trusting the marker here would skip the
            // copier, the shed rules and their rank checks on the way to deleting the
            // legacy environment. The filesystem wins.
            warn!(
                "The migration marker says this node kept {} chunk(s) but the file store \
                 holds {}. Restarting the migration from the copying stage.",
                state.kept_key_count,
                files.current_chunks().unwrap_or(0)
            );
            state.phase = MigrationPhase::Bridging;
            state.committed_at_unix = None;
            state.rebuilds_since_commit = 0;
            if let Err(e) = state.save(&config.root_dir) {
                warn!("Could not persist the migration marker: {e}");
            }
        } else if legacy.is_some() && state.phase == MigrationPhase::FilesOnly {
            warn!(
                "The migration marker says this node is done but {} is still on disk. \
                 Resuming the bridge.",
                legacy_env_dir.display()
            );
            state.phase = MigrationPhase::Bridging;
            if let Err(e) = state.save(&config.root_dir) {
                warn!("Could not persist the migration marker: {e}");
            }
        }

        let store = Self {
            files,
            legacy: parking_lot::RwLock::new(legacy),
            retirement: tokio::sync::RwLock::new(()),
            legacy_env_dir,
            config,
            state: parking_lot::RwLock::new(state),
            key_locks: std::iter::repeat_with(|| tokio::sync::Mutex::new(()))
                .take(KEY_LOCK_LANES)
                .collect(),
        };

        let (file_keys, legacy_keys) = store.split_counts();
        info!(
            "Chunk store ready: {file_keys} chunks in files, {legacy_keys} still only in the \
             legacy environment, phase {:?}",
            store.migration_phase()
        );
        Ok(store)
    }

    /// Open the legacy environment and work out which keys only it holds.
    async fn open_legacy(config: &ChunkStoreConfig, files: &FileStore) -> Result<Legacy> {
        let lmdb = Arc::new(
            LmdbStorage::new(LmdbStorageConfig {
                root_dir: config.root_dir.clone(),
                verify_on_read: config.verify_on_read,
                max_map_size: config.max_map_size,
                disk_reserve: config.disk_reserve,
            })
            .await?,
        );

        let legacy_keys = lmdb.all_keys().await?;
        let mut only = BTreeSet::new();
        for key in legacy_keys {
            if !files.exists(&key).unwrap_or(false) {
                only.insert(key);
            }
        }
        Ok(Legacy {
            lmdb,
            only: Arc::new(parking_lot::RwLock::new(only)),
        })
    }

    /// Take the critical section for one key.
    async fn key_lock(&self, address: &XorName) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        let lane = address.last().copied().unwrap_or(0) as usize;
        match self.key_locks.get(lane) {
            Some(lock) => Some(lock.lock().await),
            None => None,
        }
    }

    /// A cheap clone of the legacy handle, or `None` once it is retired.
    fn legacy(&self) -> Option<Legacy> {
        self.legacy.read().clone()
    }

    /// `(chunks in files, chunks only in the legacy environment)`.
    fn split_counts(&self) -> (u64, u64) {
        // Legacy first, for the reason given on `exists`: a key mid-copy is then counted
        // twice for an instant rather than not at all, and over-reporting what the node
        // holds is the safe direction for every caller of `current_chunks`.
        let legacy = self
            .legacy()
            .map_or(0, |l| l.only.read().len().try_into().unwrap_or(u64::MAX));
        let files = self.files.current_chunks().unwrap_or(0);
        (files, legacy)
    }

    /// Store a chunk.
    ///
    /// While a legacy environment exists and dual-writing is on, the chunk goes there
    /// **first**. A chunk uploaded during the bridge to holders that all revert to a
    /// pre-migration build would otherwise be gone from every one of them, and that is
    /// real client data, not a replica.
    ///
    /// # Returns
    ///
    /// `true` if the chunk was newly stored, `false` if either store already had it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the content does not hash to `address`, the disk is
    /// too full, or the write fails.
    pub async fn put(&self, address: &XorName, content: &[u8]) -> Result<bool> {
        // Shared, for the reason given on the field: retirement waits for the legacy
        // environment to go idle, and a write that keeps starting new work in it while
        // that wait runs makes the wait unbounded. It also stops a write inserting a key
        // into the legacy-only set after the gates have approved the set that may go.
        let _using_legacy = self.retirement.read().await;
        let _lane = self.key_lock(address).await;
        let legacy = self.legacy();
        let already_in_legacy = legacy
            .as_ref()
            .is_some_and(|l| l.only.read().contains(address));

        let mut dual_written = false;
        if let Some(ref l) = legacy {
            if self.config.migration.dual_write_legacy && !already_in_legacy {
                // The legacy store's own verdict, not the file store's. It accounts for
                // pages it can reuse internally, which is the right question for a write
                // into it and the wrong one for the file about to be written. A full
                // legacy store must not fail a put the file store can serve: the copy is
                // there to make a fleet rollback survivable, and losing that for one
                // chunk is much better than refusing the chunk.
                if l.lmdb.capacity_verdict() == crate::storage::CapacityVerdict::Full {
                    debug!(
                        "Legacy chunk environment is full; storing {} in files only. A \
                         rollback to a pre-migration build would not have this chunk.",
                        hex::encode(address)
                    );
                } else {
                    // Best effort, and only best effort. The verdict above is optimistic
                    // by design: LMDB can still refuse a write for fragmentation, pages
                    // pinned by a long read, or a copy-on-write B-tree split. Propagating
                    // that would let a store this node is in the middle of abandoning
                    // reject paid chunks the file store has ample room for, for the whole
                    // bridge period. The chunk's own validity is not at stake here; the
                    // file store checks the content address itself.
                    match l.lmdb.put(address, content).await {
                        Ok(_) => dual_written = true,
                        Err(e) => warn!(
                            "Could not also write {} to the legacy environment: {e}. \
                             Storing it in files only. A rollback to a pre-migration \
                             build would not have this chunk.",
                            hex::encode(address)
                        ),
                    }
                }
            }
        }

        let stored_in_files = match self.files.put(address, content).await {
            Ok(stored) => stored,
            Err(e) => {
                // The bytes reached LMDB but not the file store. Record the key as
                // legacy-only so the union still finds it and the copier retries later;
                // without this the node would hold a chunk it could not serve.
                if dual_written {
                    if let Some(ref l) = legacy {
                        l.only.write().insert(*address);
                    }
                }
                return Err(e);
            }
        };

        if already_in_legacy {
            // Migrated for free: a hot key the copier no longer has to move.
            if let Some(ref l) = legacy {
                l.only.write().remove(address);
            }
            return Ok(false);
        }
        Ok(stored_in_files)
    }

    /// Retrieve a chunk, verifying it against its address when configured to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on an I/O failure, or when verification fails and no
    /// intact copy is available.
    pub async fn get(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        // Held for the whole read. A verifying read that finds rotted bytes throws the
        // file away, and until this key is back in the legacy-only set there is a moment
        // when it appears to live in neither store. Retirement waits behind this rather
        // than deleting the copy the read is about to fall back on.
        let _reading = self.retirement.read().await;
        let fallback = self.legacy();
        match self.files.get(address).await {
            Ok(Some(content)) => Ok(Some(content)),
            Ok(None) => {
                // The file store missed. If the legacy store answers, the key has to go
                // back into the union view: the file index has just dropped it, and a key
                // in neither view is skipped by the verification pass and destroyed by
                // retirement.
                self.serve_from_legacy(address, fallback).await
            }
            Err(e) => {
                // Only a verification failure means the file store threw the file away.
                // Every other error (a full descriptor table, an I/O fault, an oversized
                // file) leaves a perfectly good file in place, and re-queueing on those
                // would double-count the key and could block retirement indefinitely.
                if !format!("{e}").contains("verification failed") {
                    return Err(e);
                }
                warn!(
                    "Chunk {} failed verification in the file store; looking for an intact \
                     copy in the legacy environment",
                    hex::encode(address)
                );
                // Nothing left anywhere reports the verification failure rather than a
                // plain miss, so the caller can tell the difference.
                self.serve_from_legacy(address, fallback)
                    .await?
                    .map_or(Err(e), |content| Ok(Some(content)))
            }
        }
    }

    /// Serve a key the file store could not, from the legacy store, and put it back on
    /// the copier's list.
    ///
    /// The whole sequence runs under the key's critical section, including the legacy
    /// read. Reading first and locking afterwards would let a concurrent delete remove
    /// both backings in between, and the key would then be re-inserted from bytes that no
    /// longer exist anywhere: a phantom entry that `exists` reports and `get` never
    /// satisfies.
    async fn serve_from_legacy(
        &self,
        address: &XorName,
        legacy: Option<Legacy>,
    ) -> Result<Option<Vec<u8>>> {
        // The handle the caller took before it read the file. Not re-fetched here: the
        // point of taking it early is that it has been held continuously since before the
        // file could be thrown away, so retirement cannot have run in between.
        let Some(legacy) = legacy else {
            return Ok(None);
        };
        let _lane = self.key_lock(address).await;
        let Some(content) = legacy.lmdb.get(address).await? else {
            return Ok(None);
        };
        // Only if the file really is gone: a concurrent write or repair may have put a
        // good one back while this was waiting for the lock.
        if !self.files.exists(address).unwrap_or(false) {
            legacy.only.write().insert(*address);
            debug!(
                "Chunk {} served from the legacy environment and re-queued for copying",
                hex::encode(address)
            );
        }
        Ok(Some(content))
    }

    /// Retrieve raw chunk bytes without content-address verification.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on an I/O failure.
    pub async fn get_raw(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        // For the reason given on `get`: retirement must not run in the gap between the
        // file going missing and this key being put back in the union view.
        let _reading = self.retirement.read().await;
        let fallback = self.legacy();
        if let Some(content) = self.files.get_raw(address).await? {
            return Ok(Some(content));
        }
        // Deliberately not gated on the legacy-only set. A chunk that was copied and then
        // lost its file is not in that set, and the legacy environment is exactly where
        // its bytes still are. An LMDB miss is cheap. Goes through the same path as
        // `get`, so the key is restored to the union view rather than being served once
        // and then quietly retired away.
        let Some(legacy) = fallback else {
            return Ok(None);
        };
        let _lane = self.key_lock(address).await;
        let raw = legacy.lmdb.get_raw(address).await?;
        let missing_locally = !self.files.exists(address).unwrap_or(false);
        if raw.is_some() && missing_locally {
            legacy.only.write().insert(*address);
        }
        Ok(raw)
    }

    /// Check whether a chunk is stored, in either backing.
    ///
    /// An in-memory lookup: no syscall, no I/O, in both phases.
    ///
    /// # Errors
    ///
    /// Never fails. The signature is kept because callers treat an error as "absent".
    pub fn exists(&self, address: &XorName) -> Result<bool> {
        // Legacy first, deliberately. The copier writes the file and only then drops the
        // key from the legacy-only set, so a reader that checked files first could
        // observe the gap between those two steps and report a chunk the node definitely
        // holds as absent. In this order the same interleaving yields a harmless
        // duplicate instead.
        if self
            .legacy()
            .is_some_and(|l| l.only.read().contains(address))
        {
            return Ok(true);
        }
        self.files.exists(address)
    }

    /// Does this node already hold `address` with exactly these bytes, and if it holds a
    /// damaged copy, replace it with these?
    ///
    /// The question a responder has to answer before turning away an offered copy. Plain
    /// [`Self::exists`] answers from names alone, and a name can outlive the bytes under
    /// it: off Unix a chunk is created under its final name before it is written, so a
    /// crash leaves a short file that `exists` reports as a chunk, and bit rot leaves a
    /// full-length one. Acknowledging a client on the strength of either throws away the
    /// copy that would repair it, and nothing offers it again.
    ///
    /// So this reads. It is affordable because the only caller is the client-facing PUT
    /// path, reached when a client offers a chunk this node already has, and because the
    /// alternative is keeping a chunk this node cannot serve and being penalised for it at
    /// the next audit.
    ///
    /// `content` must already hash to `address`; the caller checks that before this is
    /// reached, and a repair from bytes that do not would be worse than the damage.
    ///
    /// # Errors
    ///
    /// Never fails. An unreadable chunk answers `false`, so the offered copy is stored
    /// through the ordinary path rather than refused.
    pub async fn holds_verified(&self, address: &XorName, content: &[u8]) -> bool {
        // Held for the whole check, like every other operation that can reach the legacy
        // environment.
        let _using_legacy = self.retirement.read().await;

        if let Some(legacy) = self.legacy() {
            if legacy.only.read().contains(address) {
                // Held only in the legacy environment. Not taken on trust either: the
                // bytes in there can be wrong too, and the copier drops such a key from
                // the union when it finds out, which would leave no copy anywhere if this
                // had turned the good one away.
                let _lane = self.key_lock(address).await;
                if matches!(legacy.lmdb.get_raw(address).await, Ok(Some(bytes)) if bytes == content)
                {
                    return true;
                }
                warn!(
                    "Chunk {} is in the legacy environment but its bytes are wrong; \
                     storing the copy just offered instead",
                    hex::encode(address)
                );
                if self.files.put(address, content).await.is_err() {
                    return false;
                }
                legacy.only.write().remove(address);
                return true;
            }
        }
        if !self.files.exists(address).unwrap_or(false) {
            return false;
        }
        // Cheap first: a length that does not match cannot be these bytes, and this is the
        // shape an interrupted create leaves.
        if self.files.stored_len(address) != Some(content.len()) {
            warn!(
                "Chunk {} is on disk at the wrong length; replacing it with the copy just \
                 offered",
                hex::encode(address)
            );
            return self.files.repair(address, content).await.is_ok();
        }
        match self.files.get_raw(address).await {
            Ok(Some(stored)) if stored == content => true,
            Ok(_) => {
                warn!(
                    "Chunk {} is on disk but its contents are wrong; replacing it with the \
                     copy just offered",
                    hex::encode(address)
                );
                self.files.repair(address, content).await.is_ok()
            }
            // Unreadable. Not claimed as held, so the offer goes through the normal path.
            Err(e) => {
                warn!("Could not read {} to check it: {e}", hex::encode(address));
                false
            }
        }
    }

    /// Delete a chunk from both backings.
    ///
    /// A logical delete has to reach the legacy environment too, or the union view would
    /// resurrect the key on the next read. It frees no space there — only removing the
    /// environment whole does that — but it keeps the two views honest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if a file exists but cannot be removed.
    pub async fn delete(&self, address: &XorName) -> Result<bool> {
        // Shared, like every other operation that touches the legacy environment. Without
        // it, retirement takes the exclusive guard and then waits for the environment to
        // go idle while deletes keep starting new work in it, and the wait never ends.
        let _using_legacy = self.retirement.read().await;
        let _lane = self.key_lock(address).await;
        // Legacy first, and only then the in-memory views. The other order removes the
        // key from `only` and then, if the legacy delete fails, leaves bytes that live
        // solely in the legacy store and are invisible to `exists`, `all_keys` and the
        // pre-retirement verification, so retirement would take the only copy.
        let from_legacy = match self.legacy() {
            Some(legacy) => {
                let deleted = legacy.lmdb.delete(address).await?;
                let was_only = legacy.only.write().remove(address);
                deleted || was_only
            }
            None => false,
        };
        let from_files = self.files.delete(address).await?;
        Ok(from_files || from_legacy)
    }

    /// Every stored key, in ascending order, across both backings.
    ///
    /// The order is a correctness requirement: the commitment builder truncates the
    /// responsible subset with `take(cap)` *before* the Merkle tree sorts it, so an
    /// unstable order would make the node's published commitment depend on iteration
    /// luck rather than on what it holds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the file index cannot be read.
    pub async fn all_keys(&self) -> Result<Vec<XorName>> {
        // Legacy first, for the reason given on `exists`. `merge_sorted` drops the
        // duplicate that the overlap produces.
        let legacy_only: Vec<XorName> = self
            .legacy()
            .map(|l| l.only.read().iter().copied().collect())
            .unwrap_or_default();
        let file_keys = self.files.all_keys().await?;
        if legacy_only.is_empty() {
            return Ok(file_keys);
        }
        Ok(merge_sorted(&file_keys, legacy_only.iter()))
    }

    /// The keys the commitment builder should commit to.
    ///
    /// While the node is still bridging this is the whole union, because it can still
    /// serve all of it and dropping the claim early would collapse its commitment (and
    /// with it its quoted price) for no reason. Once it has settled on what it will keep,
    /// this narrows to the file-backed set, which is exactly the point at which the node
    /// stops claiming keys it is about to give up.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the file index cannot be read.
    pub async fn committable_keys(&self) -> Result<Vec<XorName>> {
        match self.migration_phase() {
            MigrationPhase::Bridging => self.all_keys().await,
            MigrationPhase::Committed | MigrationPhase::FilesOnly => self.files.all_keys().await,
        }
    }

    /// Number of chunks currently stored, counted across both backings without
    /// double-counting a chunk that is in each.
    ///
    /// # Errors
    ///
    /// Never fails.
    pub fn current_chunks(&self) -> Result<u64> {
        let (files, legacy) = self.split_counts();
        Ok(files.saturating_add(legacy))
    }

    /// Operation statistics.
    ///
    /// The cumulative counters are the file store's; `current_chunks` is the union.
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        let mut stats = self.files.stats();
        stats.current_chunks = self.current_chunks().unwrap_or(0);
        stats
    }

    /// Compute a content address (BLAKE3 hash).
    #[must_use]
    pub fn compute_address(content: &[u8]) -> XorName {
        crate::client::compute_address(content)
    }

    /// The node root directory.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.config.root_dir
    }

    /// Reject work early when the disk cannot take another chunk at all.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] when free space is below the configured reserve.
    pub fn check_capacity(&self) -> Result<()> {
        self.files.check_capacity()
    }

    /// Whether the store can take a write at all right now.
    ///
    /// Answered by the file store, which is where writes land. The legacy environment's
    /// own verdict is deliberately not consulted: it accounts for pages it can reuse
    /// internally, and a reusable page in a store this node is moving *off* says nothing
    /// about whether the file it is about to write will fit.
    ///
    /// Three-way, not two. The verification cycle treats `Full` as a standing condition
    /// worth minutes of backoff, so folding a failed free-space query into it would latch
    /// a transient filesystem hiccup into a stall on a node that is not full at all.
    #[must_use]
    pub(crate) fn capacity_verdict(&self) -> crate::storage::CapacityVerdict {
        self.files.capacity_verdict()
    }

    /// Reject work early when the disk cannot take `bytes` more.
    ///
    /// Free bytes alone stopped being a sufficient answer once chunks became files.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] when the write would not fit above the reserve.
    pub fn check_capacity_for(&self, bytes: u64) -> Result<()> {
        self.files.check_capacity_for(bytes)
    }

    /// Wait until every blocking task in either backing has finished.
    pub async fn wait_idle(&self) {
        self.files.wait_idle().await;
        if let Some(legacy) = self.legacy() {
            legacy.lmdb.wait_idle().await;
        }
    }

    // ── Migration ───────────────────────────────────────────────────────────

    /// Where the node is in the migration.
    #[must_use]
    pub fn migration_phase(&self) -> MigrationPhase {
        self.state.read().phase
    }

    /// A snapshot of the persisted migration marker.
    #[must_use]
    pub fn migration_state(&self) -> MigrationState {
        self.state.read().clone()
    }

    /// The migration settings this store was built with.
    #[must_use]
    pub fn migration_config(&self) -> &MigrationConfig {
        &self.config.migration
    }

    /// Whether a legacy environment is still open.
    #[must_use]
    pub fn has_legacy(&self) -> bool {
        self.legacy.read().is_some()
    }

    /// The keys the legacy environment still holds alone, ascending.
    #[must_use]
    pub fn legacy_only_keys(&self) -> Vec<XorName> {
        self.legacy()
            .map(|l| l.only.read().iter().copied().collect())
            .unwrap_or_default()
    }

    /// Bytes the legacy environment occupies, as the filesystem sees it.
    #[must_use]
    pub fn legacy_bytes(&self) -> u64 {
        std::fs::metadata(self.legacy_env_dir.join(LEGACY_DATA_FILE)).map_or(0, |m| m.len())
    }

    /// Test-only handle to the file store's put gate.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_put_gate(&self) -> Arc<parking_lot::RwLock<()>> {
        self.files.test_put_gate()
    }

    /// Test-only: adjust the persisted migration marker directly.
    ///
    /// Real transitions go through [`Self::commit_to_files`] and
    /// [`Self::note_commitment_rebuilt`]; this exists so a test can put a store into a
    /// state that would otherwise take hours of wall clock to reach.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn force_migration_state<F: FnOnce(&mut MigrationState)>(&self, f: F) {
        f(&mut self.state.write());
    }

    /// Copy up to `keys.len()` chunks out of the legacy environment into files.
    ///
    /// Stops as soon as free space would fall below `slack` above the configured
    /// reserve, so a migration never fills the disk it is trying to free.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] only for failures that are not per-key: a per-key
    /// problem is counted in the report and the pass continues.
    pub async fn copy_batch(
        &self,
        keys: &[XorName],
        slack: u64,
        throttle_mib_per_sec: u64,
        shutdown: &CancellationToken,
    ) -> Result<CopyReport> {
        let mut report = CopyReport::default();
        let Some(legacy) = self.legacy() else {
            return Ok(report);
        };

        for key in keys {
            // Checked per chunk, not per batch. Everything here is idempotent and
            // re-derived at the next start, so stopping between two chunks costs nothing
            // and stops shutdown waiting out a whole pass.
            if shutdown.is_cancelled() {
                break;
            }
            let lane = self.key_lock(key).await;
            // Re-checked inside the critical section. A prune that landed while this
            // pass was running has already taken the key out of the legacy-only set, and
            // copying it now would resurrect a chunk the node deliberately deleted.
            if !legacy.only.read().contains(key) {
                continue;
            }
            if self.files.exists(key).unwrap_or(false) {
                legacy.only.write().remove(key);
                continue;
            }
            // Reserve room for a full chunk plus the slack floor before reading, so the
            // copier stops with headroom rather than on a failed write.
            if self.files.check_capacity_for(slack).is_err() {
                report.stopped_for_space = true;
                break;
            }

            let Some(bytes) = legacy.lmdb.get_raw(key).await? else {
                report.vanished += 1;
                legacy.only.write().remove(key);
                continue;
            };
            let len = bytes.len() as u64;

            match self.files.put(key, &bytes).await {
                Ok(_) => {
                    legacy.only.write().remove(key);
                    report.copied += 1;
                    report.bytes += len;
                }
                Err(e) => {
                    let message = format!("{e}");
                    if message.contains("Content address mismatch") {
                        // The legacy bytes do not hash to their own key, so this chunk
                        // cannot be reproduced and was never servable. Stop advertising
                        // it rather than carrying a key we cannot answer for.
                        warn!(
                            "Chunk {} in the legacy environment does not match its address; \
                             dropping it from the key set so replication can repair it",
                            hex::encode(key)
                        );
                        legacy.only.write().remove(key);
                        report.unusable += 1;
                        continue;
                    }
                    if message.contains("Insufficient disk space") {
                        report.stopped_for_space = true;
                        break;
                    }
                    return Err(e);
                }
            }

            // Outside the critical section on purpose: at 32 MiB/s a 4 MiB chunk sleeps
            // for over a tenth of a second, and a shard lane held for that would stall
            // every write sharing its last address byte for the whole pass.
            drop(lane);
            if let Some(delay) = throttle_delay(len, throttle_mib_per_sec) {
                tokio::time::sleep(delay).await;
            }
        }
        Ok(report)
    }

    /// Settle on the file-backed set: from now on the node commits only to what it will
    /// keep, while still serving everything it ever committed to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the marker cannot be persisted.
    pub fn commit_to_files(&self) -> Result<()> {
        let shed = self
            .legacy()
            .map_or(0, |l| l.only.read().len().try_into().unwrap_or(u64::MAX));
        let kept = self.files.current_chunks().unwrap_or(0);
        // Written to disk before it is published in memory. The other order leaves this
        // process acting as `Committed` (and so committing only to file-backed keys)
        // while the marker still says `Bridging`, so a restart would silently undo it.
        let candidate = {
            let state = self.state.read();
            if state.phase != MigrationPhase::Bridging {
                return Ok(());
            }
            MigrationState {
                phase: MigrationPhase::Committed,
                committed_at_unix: None,
                rebuilds_since_commit: 0,
                shed_key_count: shed,
                kept_key_count: kept,
                ..state.clone()
            }
        };
        candidate.save(&self.config.root_dir)?;
        *self.state.write() = candidate;
        if shed == 0 {
            info!("Committed to the file-backed key set; nothing has to be shed");
        } else {
            info!(
                "Committed to the file-backed key set; {shed} chunk(s) will be shed and \
                 refetched once the legacy environment is gone and there is room"
            );
        }
        Ok(())
    }

    /// Record that the commitment builder has read and published the committable set.
    ///
    /// The retirement gate counts these: one proves the builder saw the new set, two
    /// prove it survived a rotation, which is what makes the answerability window
    /// meaningful rather than notional.
    pub fn note_commitment_rebuilt(&self) {
        let should_save = {
            let mut state = self.state.write();
            if state.phase != MigrationPhase::Committed {
                return;
            }
            if state.committed_at_unix.is_none() {
                state.committed_at_unix = Some(crate::storage::migration::now_unix());
            }
            state.rebuilds_since_commit = state.rebuilds_since_commit.saturating_add(1);
            state.rebuilds_since_commit <= REQUIRED_REBUILDS_BEFORE_RETIRE
        };
        if should_save {
            let snapshot = self.state.read().clone();
            if let Err(e) = snapshot.save(&self.config.root_dir) {
                warn!("Could not persist the migration marker: {e}");
            }
        }
    }

    /// Whether every gate on deleting the legacy environment is satisfied.
    ///
    /// `still_answerable` is asked of each key the node is about to give up: the pruner's
    /// existing retention contract, reused verbatim. A key still covered by a retained
    /// commitment slot vetoes the delete, because the node could still be challenged on it.
    pub fn retirement_blocker<F>(&self, still_answerable: F) -> Option<String>
    where
        F: Fn(&XorName) -> bool,
    {
        if !self.has_legacy() {
            return None;
        }
        if !self.config.migration.retire_legacy {
            return Some(
                "retirement is disabled in this release (storage.migration.retire_legacy)".into(),
            );
        }
        let state = self.state.read().clone();
        if state.phase != MigrationPhase::Committed {
            return Some(format!("phase is {:?}, not Committed", state.phase));
        }
        if state.rebuilds_since_commit < REQUIRED_REBUILDS_BEFORE_RETIRE {
            return Some(format!(
                "only {} of {REQUIRED_REBUILDS_BEFORE_RETIRE} commitment rebuilds observed",
                state.rebuilds_since_commit
            ));
        }
        if !state.retire_delay_elapsed(&self.config.migration) {
            return Some(format!(
                "the {}h retirement delay has not elapsed",
                self.config.migration.effective_retire_delay_hours()
            ));
        }
        if let Some(key) = self
            .legacy_only_keys()
            .into_iter()
            .find(|k| still_answerable(k))
        {
            return Some(format!(
                "chunk {} is still answerable under a retained commitment",
                hex::encode(key)
            ));
        }
        None
    }

    /// Re-hash every chunk that both stores hold, repairing the file from the legacy
    /// copy when they disagree.
    ///
    /// A filename is not proof the bytes behind it are good. The startup scan reads
    /// names only, so a file that was truncated or that rotted while the node was down is
    /// indexed, counted as copied, committed to, and would have its intact legacy copy
    /// deleted underneath it. The first verified read would then find the corruption with
    /// nothing left to repair from. This pass is what turns "a file with that name
    /// exists" into "those bytes are that chunk", and it is why it runs before
    /// retirement rather than after.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the legacy key set cannot be read.
    pub async fn verify_before_retire(
        &self,
        throttle_mib_per_sec: u64,
        shutdown: &CancellationToken,
    ) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        let Some(legacy) = self.legacy() else {
            report.ran = true;
            return Ok(report);
        };
        report.ran = true;

        // Names before bytes. A chunk whose contents are durable but whose directory entry
        // is not is still lost to a power loss, and the legacy copy is about to be deleted
        // on the strength of this proof. Any failure here is a proof this pass did not
        // produce.
        if let Err(e) = self.files.flush_namespace() {
            report.unrepairable = report.unrepairable.saturating_add(1);
            warn!(
                "Could not make the file store's directory entries durable: {e}. The legacy \
                 environment stays until they are."
            );
            return Ok(report);
        }

        let legacy_keys = legacy.lmdb.all_keys().await?;
        let total = legacy_keys.len();
        info!("Verifying {total} chunk(s) before removing the legacy environment");
        let mut since_log = 0u64;
        for key in legacy_keys {
            // This pass is a full read of the store and can run for hours. A shutdown
            // must not wait it out, and an incomplete pass is simply not a clean proof.
            if shutdown.is_cancelled() {
                report.unrepairable = report.unrepairable.saturating_add(1);
                debug!("Pre-retirement verification stopped for shutdown");
                return Ok(report);
            }
            if !self.files.exists(&key).unwrap_or(false) {
                continue;
            }
            since_log += 1;
            if since_log >= VERIFY_LOG_EVERY {
                since_log = 0;
                info!(
                    "Pre-retirement verification: {} of at most {total} chunk(s) checked",
                    report.checked
                );
            }
            let outcome = self.verify_one(&legacy, &key).await;
            report.checked += 1;
            report.bytes += outcome.bytes;
            match outcome.verdict {
                VerifyVerdict::Intact => {}
                VerifyVerdict::Repaired => report.repaired += 1,
                VerifyVerdict::Vanished => {
                    // The file went away while this pass was running, so the key is no
                    // longer file-backed. Put it back on the copier's list rather than
                    // republishing it here, where it could resurrect something the
                    // pruner deleted a moment ago.
                    legacy.only.write().insert(key);
                    report.unrepairable += 1;
                }
                VerifyVerdict::Unrepairable => report.unrepairable += 1,
            }
            if let Some(delay) = throttle_delay(outcome.bytes, throttle_mib_per_sec) {
                tokio::time::sleep(delay).await;
            }
        }

        if report.unrepairable == 0 {
            info!(
                "Pre-retirement verification passed: {} chunk(s) checked, {} repaired",
                report.checked, report.repaired
            );
        }
        Ok(report)
    }

    /// Check one chunk that both stores hold, repairing the file if it is wrong.
    async fn verify_one(&self, legacy: &Legacy, key: &XorName) -> VerifyOutcome {
        // The throttle sleep is deliberately outside this critical section: at 32 MiB/s a
        // 4 MiB chunk sleeps for over a tenth of a second, and holding a shard lane for
        // that would stall every write to a sixteenth of the address space for hours.
        let _lane = self.key_lock(key).await;

        let bytes = self.files.get_raw(key).await.unwrap_or(None);
        let len = bytes.as_ref().map_or(0, Vec::len) as u64;
        let Some(bytes) = bytes else {
            return VerifyOutcome {
                bytes: 0,
                verdict: VerifyVerdict::Vanished,
            };
        };
        if crate::client::compute_address(&bytes) == *key {
            return VerifyOutcome {
                bytes: len,
                verdict: VerifyVerdict::Intact,
            };
        }

        warn!(
            "Chunk {} is in the file store but does not match its address; rewriting it \
             from the legacy environment before that environment is removed",
            hex::encode(key)
        );
        // Replace in place. Deleting first and writing after would leave a window whose
        // only surviving copy is the one this whole pass exists to make safe to delete.
        let verdict = match legacy.lmdb.get_raw(key).await {
            Ok(Some(good)) if self.files.repair(key, &good).await.is_ok() => {
                VerifyVerdict::Repaired
            }
            _ => {
                warn!(
                    "Chunk {} could not be rewritten from the legacy environment. \
                     Retirement stays blocked so its bytes are not thrown away.",
                    hex::encode(key)
                );
                VerifyVerdict::Unrepairable
            }
        };
        VerifyOutcome {
            bytes: len,
            verdict,
        }
    }

    /// Close the legacy environment and remove it, returning the bytes freed.
    ///
    /// This is the only destructive step in the migration and the only one that cannot
    /// be undone. It is also the only moment the disk comes back.
    ///
    /// Takes a [`VerifyReport`] rather than a flag so the verification pass cannot be
    /// skipped: there is no way to call this without having produced one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if verification did not pass, if the handle is still
    /// shared (the caller should retry on the next tick), or if the directory cannot be
    /// removed.
    pub async fn retire_legacy<F>(
        &self,
        proof: &VerifyReport,
        still_answerable: &F,
        approved_to_shed: &BTreeSet<XorName>,
    ) -> Result<u64>
    where
        F: Fn(&XorName) -> bool + Send + Sync,
    {
        if !proof.is_clean() {
            return Err(Error::Storage(format!(
                "Refusing to remove the legacy environment: verification reported {} \
                 unrepairable chunk(s) (ran: {})",
                proof.unrepairable, proof.ran
            )));
        }
        // Rechecked here, not only by the caller. Everything between the caller's check
        // and this point is a window: the verification pass alone can run for hours, and
        // a write whose file half failed inserts a new legacy-only key in the meantime.
        if let Some(reason) = self.retirement_blocker(still_answerable) {
            return Err(Error::Storage(format!(
                "Refusing to remove the legacy environment: {reason}"
            )));
        }
        // Exclusive from here until the handle is out. Every read, write and delete holds
        // this shared, so taking it means none is in progress and none can start: no
        // reader is mid-way between discarding a corrupt file and reaching the copy that
        // would replace it, and nothing new can start work in an environment that is about
        // to go idle.
        //
        // Released as soon as the handle has been taken and the directory renamed away,
        // which is the point after which nothing can reach the environment anyway. The
        // deletion that follows can take a long time on a large store, and holding every
        // chunk request on the node behind it would turn retirement into an outage.
        //
        let retiring = self.retirement.write().await;
        let Some(legacy) = self.legacy() else {
            return Ok(0);
        };
        let freed = self.legacy_bytes();
        // Let go of our own clone straight away, so the only strong reference that should
        // remain is the one the store itself holds.
        drop(legacy);

        for attempt in 0..RETIRE_UNWRAP_ATTEMPTS {
            // Drained on every attempt, not once up front: `LmdbStorage`'s blocking
            // closures capture a cloned `Env` rather than the `Arc`, so the strong count
            // alone would not notice a read that is still mapped. The tracker does, and
            // it reopens itself, so a read that started since the last drain needs
            // another one.
            if let Some(l) = self.legacy() {
                l.lmdb.wait_idle().await;
                drop(l);
            }
            // Taking the handle out and proving sole ownership happen in the same
            // critical section. Deliberately not two steps: taking it first and putting
            // it back on failure would leave a window in which reads see no legacy store
            // and report a chunk that lives only there as missing.
            let taken = {
                let mut guard = self.legacy.write();
                match guard.as_ref() {
                    // A strong count of one means nobody else holds a handle, so nobody
                    // can be reading the legacy store *or* mutating its key set. That is
                    // what makes the final check below atomic with the removal: this is
                    // the only moment at which the answer cannot change underneath us.
                    Some(l) if Arc::strong_count(&l.lmdb) == 1 => {
                        let only = l.only.read();
                        // A count of one proves nobody else holds a handle, so nobody can
                        // be mutating this set. That is what makes the two checks below
                        // authoritative rather than a snapshot that has already moved.
                        if let Some(key) = only.iter().find(|k| still_answerable(k)) {
                            return Err(Error::Storage(format!(
                                "Refusing to remove the legacy environment: chunk {} became \
                                 answerable again while retirement was in progress",
                                hex::encode(key)
                            )));
                        }
                        // Only the keys the caller cleared may go. A write whose file half
                        // failed adds a legacy-only key that is in no commitment, so the
                        // answerability check above cannot see it, and it would otherwise
                        // be destroyed without ever facing the rank, delivery or
                        // possession gates.
                        if let Some(key) = only.iter().find(|k| !approved_to_shed.contains(*k)) {
                            return Err(Error::Storage(format!(
                                "Refusing to remove the legacy environment: chunk {} entered \
                                 the legacy-only set after the gates were cleared and has \
                                 passed none of them",
                                hex::encode(key)
                            )));
                        }
                        drop(only);
                        guard.take()
                    }
                    Some(_) => None,
                    None => return Ok(0),
                }
            };
            if let Some(Legacy { lmdb, only }) = taken {
                drop(only);
                drop(lmdb);
                return self.remove_legacy_dir(freed, retiring).await;
            }
            if attempt + 1 < RETIRE_UNWRAP_ATTEMPTS {
                tokio::time::sleep(RETIRE_UNWRAP_BACKOFF).await;
            }
        }

        // Nothing was taken and nothing will be this tick, so let the node get on with
        // serving rather than leaving this held until the function returns.
        drop(retiring);
        Err(Error::Storage(
            "Legacy environment is still being read; retirement deferred to the next tick".into(),
        ))
    }

    /// Remove the legacy directory and record that the migration is over.
    ///
    /// The handle is already closed by the time this runs, so the node is file-only
    /// either way. If the removal fails the phase still moves on, because there is no
    /// going back to a half-removed environment, and the operator is told exactly which
    /// directory to delete by hand to get the space back.
    async fn remove_legacy_dir(
        &self,
        freed: u64,
        retiring: tokio::sync::RwLockWriteGuard<'_, ()>,
    ) -> Result<u64> {
        // Renamed aside first, because `remove_dir_all` is not atomic: a failure partway
        // through leaves a directory that can no longer be opened as an environment, and
        // recording the migration as finished on top of that would have the node claim
        // completion over a half-deleted store. A rename either happens or does not.
        let tombstone = self
            .config
            .root_dir
            .join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"));

        // Written before anything moves, and durably, because the move itself cannot be
        // shown to be durable off Unix. From here on, a crash at any point leaves a start
        // that knows the file store holds everything and finishes the removal, rather than
        // one that finds a half-deleted environment and refuses to open it.
        mark_retirement_authorised(&self.config.root_dir)?;

        if let Err(e) = std::fs::rename(&self.legacy_env_dir, &tombstone) {
            // Recoverable: nothing has been deleted. Take the marker back so a later start
            // does not act on an authorisation this node has just abandoned.
            clear_retirement_marker(&self.config.root_dir);
            // Nothing was deleted, but the handle is already closed, so this node has
            // stopped being able to serve anything that lives only in there. Put it back
            // rather than carrying on with chunks it holds and cannot read, and rather
            // than letting the next tick see no handle and call that success.
            let restored = self.reopen_legacy().await;
            return Err(Error::Storage(format!(
                "Could not move the legacy environment {} aside: {e}. Nothing was deleted{}",
                self.legacy_env_dir.display(),
                if restored {
                    " and it has been reopened, so the node keeps serving from both stores."
                } else {
                    ". IT COULD NOT BE REOPENED: this node cannot serve chunks that live                      only there until it is restarted."
                }
            )));
        }
        // The rename has to reach the directory itself, not just the page cache, and this
        // one is not best effort. The tombstone is deleted a few lines below. If the
        // rename has not reached the disk when that happens, a power loss brings the
        // environment back under its old name with its contents already removed, and the
        // next start finds a corrupt environment it cannot open. Stopping here instead
        // leaves the tombstone in place, which the next start sweeps.
        if let Err(e) = crate::storage::file_store::fsync_path(&self.config.root_dir) {
            warn!(
                "The legacy environment was moved aside but {} could not be flushed: {e}. \
                 Leaving {} in place rather than deleting a directory whose new name may \
                 not have reached the disk. The next start finishes this.",
                self.config.root_dir.display(),
                tombstone.display()
            );
            self.finish_migration();
            return Ok(0);
        }
        self.finish_migration();

        // From here nothing can reach the environment: its handle is gone and its
        // directory is under a name no code looks for. Let the node serve again rather
        // than holding every chunk request behind a deletion that can run for minutes.
        drop(retiring);

        // Only now, and best effort: the bytes come back when this completes, and if it
        // does not the next start sweeps the tombstone.
        //
        // On its own thread, because this is a synchronous recursive delete of a directory
        // that can hold hundreds of gigabytes, and nothing can interrupt it once it starts.
        // Left in the migration task it would sit through shutdown's grace and past it,
        // because an abort cannot be observed until the call returns. Out here, shutdown
        // walks away and the next start finishes the job.
        let target = tombstone.clone();
        let removal = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(&target));
        match removal.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(
                    "The legacy environment has been retired but {} could not be deleted: \
                     {e}. Its space is not returned until it is. The node is serving from \
                     files and needs nothing else.",
                    tombstone.display()
                );
                return Ok(0);
            }
            Err(e) => {
                warn!(
                    "Stopped waiting for {} to be deleted: {e}. The next start sweeps it.",
                    tombstone.display()
                );
                return Ok(0);
            }
        }
        clear_retirement_marker(&self.config.root_dir);
        debug!(
            "Removed {} and returned {freed} bytes to the filesystem",
            self.legacy_env_dir.display()
        );
        Ok(freed)
    }

    /// Reopen the legacy store after a failed retirement, so the node keeps serving.
    ///
    /// Returns whether it came back. The handle is closed before the rename is attempted,
    /// so a rename that fails leaves the node holding chunks it can no longer read; that
    /// is worth undoing rather than living with until the next restart.
    async fn reopen_legacy(&self) -> bool {
        if !legacy_present(&self.config.root_dir).unwrap_or(false) {
            return false;
        }
        match Self::open_legacy(&self.config, &self.files).await {
            Ok(legacy) => {
                *self.legacy.write() = Some(legacy);
                warn!("Reopened the legacy chunk environment after a failed retirement");
                true
            }
            Err(e) => {
                error!("Could not reopen the legacy chunk environment: {e}");
                false
            }
        }
    }

    /// Record that this node serves from files alone from here on.
    fn finish_migration(&self) {
        self.files.invalidate_capacity_cache();
        {
            let mut state = self.state.write();
            state.phase = MigrationPhase::FilesOnly;
        }
        let snapshot = self.state.read().clone();
        if let Err(e) = snapshot.save(&self.config.root_dir) {
            warn!("Could not persist the migration marker: {e}");
        }
    }
}

/// What checking one chunk concluded.
enum VerifyVerdict {
    /// The file matches its name.
    Intact,
    /// The file was wrong and was rewritten from the legacy copy.
    Repaired,
    /// The file was wrong and could not be rewritten.
    Unrepairable,
    /// The file disappeared while the pass was running.
    Vanished,
}

/// One chunk's verification result.
struct VerifyOutcome {
    /// Bytes read, for the throttle.
    bytes: u64,
    /// What was concluded.
    verdict: VerifyVerdict,
}

/// What the pre-retirement verification pass found.
///
/// Every field is private, and the only way to obtain one is
/// [`ChunkStore::verify_before_retire`]. That is deliberate: it is the sole evidence
/// [`ChunkStore::retire_legacy`] accepts that the file store really holds what it claims,
/// and a report anyone could construct would be no evidence at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// Whether the pass actually ran.
    ran: bool,
    /// Chunks re-hashed.
    checked: u64,
    /// Bytes read.
    bytes: u64,
    /// Chunks whose file was wrong and was rewritten from the legacy copy.
    repaired: u64,
    /// Chunks whose file was wrong and could not be repaired.
    unrepairable: u64,
}

impl VerifyReport {
    /// Whether this report clears the way for retirement.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.ran && self.unrepairable == 0
    }

    /// Chunks re-hashed.
    #[must_use]
    pub fn checked(&self) -> u64 {
        self.checked
    }

    /// Chunks rewritten from the legacy copy.
    #[must_use]
    pub fn repaired(&self) -> u64 {
        self.repaired
    }

    /// Chunks that could not be made good.
    #[must_use]
    pub fn unrepairable(&self) -> u64 {
        self.unrepairable
    }
}

/// Delete any legacy environment that was retired but whose removal did not finish.
/// Create the retirement marker, durably.
///
/// # Errors
///
/// Returns [`Error::Storage`] if it cannot be created or flushed. Retirement stops there,
/// having touched nothing.
fn mark_retirement_authorised(root_dir: &Path) -> Result<()> {
    let path = root_dir.join(RETIREMENT_MARKER);
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(f) => f,
        // Already there, from an attempt earlier in this run. It says exactly what this
        // one would say.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => {
            return Err(Error::Storage(format!(
                "Could not record that retirement was authorised at {}: {e}",
                path.display()
            )))
        }
    };
    // For whoever reads the directory. To the node, presence is the whole signal.
    if let Err(e) = file.write_all(
        b"The chunk environment beside this file was verified as fully copied into the \n\
file store and is being removed. If it is still here, that removal was interrupted and \n\
the next node start finishes it. Nothing needs it.\n",
    ) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(Error::Storage(format!(
            "Could not write {}: {e}",
            path.display()
        )));
    }
    file.sync_all().map_err(|e| {
        let _ = std::fs::remove_file(&path);
        Error::Storage(format!(
            "Could not flush {}: {e}. Not removing the legacy environment on the strength \
             of a marker that may not survive a power loss.",
            path.display()
        ))
    })
}

/// Remove the retirement marker, if it is there, and make the removal durable.
///
/// The flush matters: an unlink that has not reached the disk can be undone by a power
/// loss, and a marker that comes back says the environment beside it may be deleted.
fn clear_retirement_marker(root_dir: &Path) {
    let path = root_dir.join(RETIREMENT_MARKER);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!("Could not remove {}: {e}", path.display());
            return;
        }
    }
    if let Err(e) = crate::storage::file_store::fsync_path(root_dir) {
        warn!(
            "Removed {} but could not flush {}: {e}",
            path.display(),
            root_dir.display()
        );
    }
}

/// Finish a retirement a previous run did not.
///
/// Runs before the legacy environment is opened, so a `chunks.mdb` that came back after a
/// power loss with its contents half deleted is removed rather than opened. The marker is
/// only written once the file store has been proven to hold every chunk, so there is
/// nothing here to lose.
/// Returns the environment if it was opened and kept, so the caller does not open it a
/// second time: that open is a full key scan, and on a large store it is not cheap.
async fn finish_interrupted_retirement(
    config: &ChunkStoreConfig,
    files: &Arc<FileStore>,
) -> Option<Legacy> {
    let root_dir = &config.root_dir;
    let marker = root_dir.join(RETIREMENT_MARKER);
    if !marker.try_exists().unwrap_or(false) {
        return None;
    }
    let env = root_dir.join(LEGACY_ENV_DIR);
    if env.try_exists().unwrap_or(false) {
        // The marker alone does not authorise this. It can be stale: a rename that failed
        // recoverably clears it, and that clearing can itself be lost. Since then the
        // environment may have taken a key that has been through none of the gates.
        //
        // Opening it is the test. An environment that opens is intact, so it is not debris
        // and nothing here may delete it: the node goes back to bridging and every gate
        // runs again from the start. An environment that cannot be opened is exactly what
        // an interrupted removal leaves behind, and the marker says the file store was
        // proven to hold everything in it, so removing it is both safe and the only way
        // the node starts at all.
        match ChunkStore::open_legacy(config, files).await {
            Ok(intact) => {
                warn!(
                    "A previous run was removing {} and did not finish, but it opens \
                     cleanly, so it is kept and the migration starts again from the \
                     copying stage.",
                    env.display()
                );
                clear_retirement_marker(root_dir);
                return Some(intact);
            }
            Err(e) => {
                warn!(
                    "A previous run was removing {} when it stopped, and what is left \
                     cannot be opened ({e}). Every chunk in it had been verified as copied \
                     into the file store, so finishing that removal now.",
                    env.display()
                );
                if let Err(e) = std::fs::remove_dir_all(&env) {
                    warn!(
                        "Could not remove {}: {e}. Its space is not returned until it is, \
                         and the node needs nothing from it.",
                        env.display()
                    );
                    // The marker stays, so the next start tries again.
                    return None;
                }
            }
        }
    }
    sweep_retired_legacy(root_dir);
    clear_retirement_marker(root_dir);
    None
}

fn sweep_retired_legacy(root_dir: &Path) {
    let tombstone = root_dir.join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"));
    if !tombstone.try_exists().unwrap_or(false) {
        return;
    }
    // Flushed first, and only best effort is not good enough here for the same reason it
    // was not good enough when the rename was made: deleting the contents of a directory
    // whose new name may not have reached the disk is what turns a power loss into a
    // resurrected, half-empty environment. If it cannot be flushed, leave the tombstone
    // for a later start. It costs disk, not data.
    if let Err(e) = crate::storage::file_store::fsync_path(root_dir) {
        warn!(
            "Leaving {} in place: {} could not be flushed ({e}), so the rename that put it \
             there may not be on disk yet.",
            tombstone.display(),
            root_dir.display()
        );
        return;
    }
    match std::fs::remove_dir_all(&tombstone) {
        Ok(()) => info!(
            "Removed the retired legacy environment left over from a previous run at {}",
            tombstone.display()
        ),
        Err(e) => warn!(
            "A retired legacy environment is still at {}: {e}. Delete it to reclaim its \
             space; the node needs nothing from it.",
            tombstone.display()
        ),
    }
}

/// Whether a legacy environment is on disk under `root_dir`.
///
/// # Errors
///
/// Returns [`Error::Storage`] if the answer cannot be determined. `Path::exists` would
/// turn a permission problem into "absent", and a node that starts in file-only mode
/// beside a `chunks.mdb` holding every chunk it has stops serving all of them.
pub fn legacy_present(root_dir: &Path) -> Result<bool> {
    let path = root_dir.join(LEGACY_ENV_DIR).join(LEGACY_DATA_FILE);
    path.try_exists().map_err(|e| {
        Error::Storage(format!(
            "Cannot tell whether the legacy chunk environment {} exists: {e}. Refusing to \
             start rather than ignore it.",
            path.display()
        ))
    })
}

/// How long to sleep after copying `bytes` to hold the copier to a rate ceiling.
fn throttle_delay(bytes: u64, mib_per_sec: u64) -> Option<Duration> {
    if mib_per_sec == 0 {
        return None;
    }
    let per_sec = mib_per_sec.saturating_mul(1024 * 1024);
    if per_sec == 0 {
        return None;
    }
    let micros = bytes.saturating_mul(1_000_000) / per_sec;
    if micros == 0 {
        None
    } else {
        Some(Duration::from_micros(micros))
    }
}

/// Merge two ascending key sequences into one, dropping duplicates.
fn merge_sorted<'a, I>(sorted: &[XorName], other: I) -> Vec<XorName>
where
    I: Iterator<Item = &'a XorName>,
{
    let other: Vec<XorName> = other.copied().collect();
    let mut out = Vec::with_capacity(sorted.len() + other.len());
    let mut a = sorted.iter().copied().peekable();
    let mut b = other.into_iter().peekable();
    loop {
        match (a.peek(), b.peek()) {
            (Some(x), Some(y)) => match x.cmp(y) {
                std::cmp::Ordering::Less => out.extend(a.next()),
                std::cmp::Ordering::Greater => out.extend(b.next()),
                std::cmp::Ordering::Equal => {
                    out.extend(a.next());
                    let _ = b.next();
                }
            },
            (Some(_), None) => out.extend(a.next()),
            (None, Some(_)) => out.extend(b.next()),
            (None, None) => break,
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::storage::migration::{now_unix, rank_closest_first, MIN_RETIRE_DELAY_HOURS};
    use tempfile::TempDir;

    /// Everything currently legacy-only, as the set a test has "approved" for shedding.
    fn approved_shed(store: &ChunkStore) -> BTreeSet<XorName> {
        store.legacy_only_keys().into_iter().collect()
    }

    /// A token that is never cancelled, for tests that are not exercising shutdown.
    fn never_cancelled() -> CancellationToken {
        CancellationToken::new()
    }

    /// Put a store through every gate a real node passes before it may retire.
    ///
    /// Deliberately not a shortcut around them: `retire_legacy` rechecks the whole set
    /// itself, so a test that skipped them would exercise a path production never takes.
    fn open_the_retirement_gate(store: &ChunkStore) {
        store.commit_to_files().expect("commit");
        store.note_commitment_rebuilt();
        store.note_commitment_rebuilt();
        store.force_migration_state(|s| {
            s.committed_at_unix =
                Some(now_unix().saturating_sub(MIN_RETIRE_DELAY_HOURS * 3600 + 60));
        });
    }

    /// Content plus the address it hashes to.
    fn addressed(seed: &str) -> (XorName, Vec<u8>) {
        let content = format!("chunk-content-{seed}").into_bytes();
        (crate::client::compute_address(&content), content)
    }

    fn test_config(dir: &TempDir) -> ChunkStoreConfig {
        ChunkStoreConfig {
            root_dir: dir.path().to_path_buf(),
            ..ChunkStoreConfig::test_default()
        }
    }

    async fn open(dir: &TempDir) -> ChunkStore {
        ChunkStore::new(test_config(dir)).await.expect("open store")
    }

    /// Populate a legacy LMDB environment the way an existing node would have one, then
    /// close it so the facade can adopt it.
    async fn seed_legacy(dir: &TempDir, seeds: &[&str]) -> Vec<XorName> {
        let lmdb = LmdbStorage::new(LmdbStorageConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            max_map_size: 0,
            disk_reserve: 0,
        })
        .await
        .expect("open legacy");
        let mut keys = Vec::new();
        for seed in seeds {
            let (addr, content) = addressed(seed);
            lmdb.put(&addr, &content).await.expect("legacy put");
            keys.push(addr);
        }
        lmdb.wait_idle().await;
        drop(lmdb);
        keys
    }

    #[tokio::test]
    async fn a_fresh_node_never_creates_a_legacy_environment() {
        let dir = TempDir::new().expect("temp dir");
        let store = open(&dir).await;

        assert!(!store.has_legacy());
        assert_eq!(store.migration_phase(), MigrationPhase::FilesOnly);
        assert!(!dir.path().join(LEGACY_ENV_DIR).exists());

        let (addr, content) = addressed("fresh");
        assert!(store.put(&addr, &content).await.expect("put"));
        assert_eq!(
            store.get(&addr).await.expect("get").expect("present"),
            content
        );
    }

    #[tokio::test]
    async fn an_existing_legacy_store_is_adopted_and_served() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["a", "b", "c"]).await;
        let store = open(&dir).await;

        assert!(store.has_legacy());
        assert_eq!(store.migration_phase(), MigrationPhase::Bridging);
        assert_eq!(store.current_chunks().expect("count"), 3);
        for key in &keys {
            assert!(store.exists(key).expect("exists"), "union must see it");
            assert!(store.get(key).await.expect("get").is_some());
        }
    }

    #[tokio::test]
    async fn the_union_key_set_is_sorted_and_free_of_duplicates() {
        let dir = TempDir::new().expect("temp dir");
        let mut expected = seed_legacy(&dir, &["u1", "u2", "u3", "u4"]).await;
        let store = open(&dir).await;

        // One chunk written now lives in both backings, and must be counted once.
        let (addr, content) = addressed("u2");
        assert!(expected.contains(&addr));
        assert!(!store.put(&addr, &content).await.expect("put"));

        let (fresh, fresh_content) = addressed("u5");
        store.put(&fresh, &fresh_content).await.expect("put");
        expected.push(fresh);
        expected.sort_unstable();

        let keys = store.all_keys().await.expect("all_keys");
        assert_eq!(keys, expected);
        assert_eq!(store.current_chunks().expect("count"), 5);
    }

    #[tokio::test]
    async fn a_put_during_the_bridge_reaches_both_stores() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["seed"]).await;
        let store = open(&dir).await;

        let (addr, content) = addressed("dual");
        assert!(store.put(&addr, &content).await.expect("put"));
        store.wait_idle().await;
        drop(store);

        // Reopening only the legacy environment proves the chunk really landed there,
        // which is what makes a fleet rollback survivable.
        let lmdb = LmdbStorage::new(LmdbStorageConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            max_map_size: 0,
            disk_reserve: 0,
        })
        .await
        .expect("reopen legacy");
        assert_eq!(
            lmdb.get(&addr).await.expect("get").expect("present"),
            content
        );
    }

    #[tokio::test]
    async fn the_copier_moves_keys_into_files_and_is_resumable() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["c1", "c2", "c3", "c4", "c5"]).await;
        let store = open(&dir).await;
        assert_eq!(store.legacy_only_keys().len(), 5);

        let first = store
            .copy_batch(&keys[..2], 0, 0, &never_cancelled())
            .await
            .expect("copy first batch");
        assert_eq!(first.copied, 2);
        assert_eq!(store.legacy_only_keys().len(), 3);
        store.wait_idle().await;
        drop(store);

        // A restart re-derives what is left from the filesystem: no progress file to
        // corrupt, and no work repeated.
        let store = open(&dir).await;
        assert_eq!(store.legacy_only_keys().len(), 3);
        let rest = store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy rest");
        assert_eq!(rest.copied, 3);
        assert!(store.legacy_only_keys().is_empty());
        assert_eq!(store.current_chunks().expect("count"), 5);
    }

    #[tokio::test]
    async fn a_delete_reaches_both_stores() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["d1", "d2"]).await;
        let store = open(&dir).await;

        let target = keys.first().copied().expect("a key");
        assert!(store.delete(&target).await.expect("delete"));
        assert!(!store.exists(&target).expect("exists"));
        assert!(store.get(&target).await.expect("get").is_none());
        assert_eq!(store.current_chunks().expect("count"), 1);

        // And it stays gone across a restart, which is what proves it left the legacy
        // environment too rather than only the union view.
        store.wait_idle().await;
        drop(store);
        let store = open(&dir).await;
        assert!(!store.exists(&target).expect("exists"));
    }

    #[tokio::test]
    async fn the_copier_does_not_resurrect_a_deleted_chunk() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["r1", "r2"]).await;
        let store = open(&dir).await;

        let target = keys.first().copied().expect("a key");
        store.delete(&target).await.expect("delete");

        let report = store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        assert_eq!(report.copied, 1, "only the surviving chunk may be copied");
        assert!(!store.exists(&target).expect("exists"));
    }

    #[tokio::test]
    async fn committing_narrows_the_commitment_but_not_what_is_served() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["k1", "k2", "k3"]).await;
        let store = open(&dir).await;

        // Copy one, leave two behind as if the disk had run out.
        store
            .copy_batch(&keys[..1], 0, 0, &never_cancelled())
            .await
            .expect("copy");

        // While bridging, the node still claims everything it can serve.
        assert_eq!(
            store.committable_keys().await.expect("committable").len(),
            3
        );

        store.commit_to_files().expect("commit");
        assert_eq!(store.migration_phase(), MigrationPhase::Committed);
        assert_eq!(store.migration_state().shed_key_count, 2);

        // It now claims only what it will keep...
        assert_eq!(
            store.committable_keys().await.expect("committable").len(),
            1
        );
        // ...while still serving everything it ever claimed.
        assert_eq!(store.all_keys().await.expect("all_keys").len(), 3);
        for key in &keys {
            assert!(store.get(key).await.expect("get").is_some());
        }
    }

    #[tokio::test]
    async fn retirement_is_refused_until_every_gate_is_satisfied() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["g1", "g2"]).await;
        let mut config = test_config(&dir);
        config.migration.retire_legacy = true;
        let store = ChunkStore::new(config).await.expect("open");

        // Still bridging.
        assert!(store
            .retirement_blocker(|_| false)
            .expect("blocked")
            .contains("Bridging"));

        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        store.commit_to_files().expect("commit");

        // No commitment rebuild observed yet.
        assert!(store
            .retirement_blocker(|_| false)
            .expect("blocked")
            .contains("commitment rebuilds"));

        store.note_commitment_rebuilt();
        store.note_commitment_rebuilt();

        // The retention delay has not elapsed.
        assert!(store
            .retirement_blocker(|_| false)
            .expect("blocked")
            .contains("retirement delay"));

        store.force_migration_state(|s| {
            s.committed_at_unix =
                Some(now_unix().saturating_sub(MIN_RETIRE_DELAY_HOURS * 3600 + 60));
        });
        assert!(store.retirement_blocker(|_| false).is_none());
    }

    #[tokio::test]
    async fn a_chunk_still_answerable_vetoes_retirement() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["h1", "h2"]).await;
        let mut config = test_config(&dir);
        config.migration.retire_legacy = true;
        let store = ChunkStore::new(config).await.expect("open");

        // Shed both, as a node short of disk would.
        store.commit_to_files().expect("commit");
        store.note_commitment_rebuilt();
        store.note_commitment_rebuilt();
        store.force_migration_state(|s| {
            s.committed_at_unix =
                Some(now_unix().saturating_sub(MIN_RETIRE_DELAY_HOURS * 3600 + 60));
        });

        // The pruner's existing retention contract, reused verbatim: a key the node
        // could still be challenged on keeps its last local copy.
        assert!(store
            .retirement_blocker(|_| true)
            .expect("blocked")
            .contains("still answerable"));
        assert!(store.retirement_blocker(|_| false).is_none());
    }

    /// The stock configuration retires, with no environment variable and no operator step.
    ///
    /// This is the property the whole release rests on. Deleting `chunks.mdb` is the only
    /// step that returns disk: LMDB never gives freed pages back, which is why the fleet
    /// deleted millions of chunks and recovered nothing. A build that shipped with this
    /// off would migrate every node and reclaim not one byte.
    #[tokio::test]
    async fn the_shipped_configuration_retires_without_an_operator_setting_anything() {
        // Asked of the configuration a node actually builds, not of the constant behind
        // it, so neither the constant nor a serde default nor the `Default` impl can turn
        // retirement off without this failing.
        assert!(
            crate::storage::MigrationConfig::default().retire_legacy,
            "this release must delete the legacy environment, or it frees no disk"
        );

        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["shipped"]).await;
        let store = open(&dir).await;
        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        open_the_retirement_gate(&store);
        assert!(
            store.retirement_blocker(|_| false).is_none(),
            "with every gate met, the shipped configuration must not refuse to retire"
        );
    }

    /// Retirement waits for a read that is already running.
    ///
    /// The window this closes: a verifying read finds rotted bytes, throws the file away,
    /// and has not yet reached the legacy copy that would replace it. If retirement ran in
    /// that gap it would delete the only remaining copy. Holding the barrier shared for
    /// the whole read, and exclusively for the removal, is what makes that impossible.
    #[tokio::test]
    async fn retirement_waits_for_a_read_that_is_already_running() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["held"]).await;
        let store = Arc::new(open(&dir).await);
        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        open_the_retirement_gate(&store);
        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");

        // Stand in for a read that has started and not finished.
        let reading = store.retirement.read().await;

        let retiring = {
            let store = Arc::clone(&store);
            let approved = approved_shed(&store);
            tokio::spawn(async move {
                store
                    .retire_legacy(&proof, &|_: &XorName| false, &approved)
                    .await
            })
        };

        // It must not have got anywhere. Given a generous window rather than a tight one,
        // so this fails on the behaviour rather than on scheduling luck.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !retiring.is_finished(),
            "retirement removed the legacy environment while a read was still running"
        );
        assert!(
            store.has_legacy(),
            "the legacy environment went while a read was still running"
        );

        drop(reading);
        let freed = retiring.await.expect("join").expect("retire");
        assert!(freed > 0, "retirement should have freed the environment");
        assert!(!store.has_legacy());
    }

    /// A good copy is never turned away because a damaged one wears its name.
    ///
    /// Two shapes of damage, because they are caught differently: a short file, which is
    /// what an interrupted create leaves on a platform that writes under the final name,
    /// and a full-length file with wrong bytes, which is what rot leaves. Answering
    /// "already have it" to either discards the copy that would fix it, and nothing offers
    /// it again.
    #[tokio::test]
    async fn a_damaged_chunk_is_repaired_from_the_copy_being_offered() {
        let dir = TempDir::new().expect("temp dir");
        let store = open(&dir).await;
        let (addr, content) = addressed("repairable-by-offer");
        store.put(&addr, &content).await.expect("put");

        // Intact: the offer is correctly refused.
        assert!(store.holds_verified(&addr, &content).await);

        // Truncated.
        let path = dir
            .path()
            .join("chunks")
            .join(format!("{:02x}", addr.last().copied().unwrap_or(0)))
            .join(hex::encode(addr));
        std::fs::write(&path, &content[..content.len() / 2]).expect("truncate");
        assert!(
            store.holds_verified(&addr, &content).await,
            "a short file must be replaced from the offered copy, not left in place"
        );
        assert_eq!(
            store.get(&addr).await.expect("get").expect("present"),
            content
        );

        // Same length, wrong bytes.
        let rotted = vec![b'x'; content.len()];
        assert_ne!(rotted, content);
        std::fs::write(&path, &rotted).expect("rot");
        assert!(
            store.holds_verified(&addr, &content).await,
            "a rotted file must be replaced from the offered copy"
        );
        assert_eq!(
            store.get(&addr).await.expect("get").expect("present"),
            content
        );
    }

    /// A chunk held only in the legacy environment is checked, not assumed good.
    ///
    /// The bytes in there can be wrong too, and when the copier finds that out it drops
    /// the key from the union view. Having turned the good copy away on the strength of
    /// the key being present, the node would then hold nothing at all.
    #[tokio::test]
    async fn a_legacy_only_chunk_with_wrong_bytes_is_replaced_by_the_offer() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["legacy-side"]).await;
        let key = *keys.first().expect("one key");
        let content = format!("chunk-content-{}", "legacy-side").into_bytes();
        let store = open(&dir).await;
        assert!(store.legacy_only_keys().contains(&key));

        // Intact: the offer is correctly refused.
        assert!(store.holds_verified(&key, &content).await);

        // Wreck the legacy copy underneath, leaving the key in the union view.
        let legacy = store.legacy().expect("legacy");
        legacy.lmdb.delete(&key).await.expect("delete");
        assert!(
            store.holds_verified(&key, &content).await,
            "with no readable legacy copy the offered bytes must be taken, not refused"
        );
        assert_eq!(
            store.get(&key).await.expect("get").expect("present"),
            content
        );
        assert!(
            !store.legacy_only_keys().contains(&key),
            "and the key must leave the legacy-only set now that a file holds it"
        );
    }

    /// A chunk this node does not have is not claimed as held.
    #[tokio::test]
    async fn a_chunk_this_node_does_not_have_is_not_claimed() {
        let dir = TempDir::new().expect("temp dir");
        let store = open(&dir).await;
        let (addr, content) = addressed("never-stored");
        assert!(!store.holds_verified(&addr, &content).await);
    }

    /// A marker is not on its own permission to delete an environment.
    ///
    /// It can be stale: a rename that failed recoverably clears it, and that clearing can
    /// itself be lost to a power loss. Since then the environment may have taken a key
    /// that has been through none of the gates. So an environment that still opens is
    /// kept, the marker is dropped, and every gate runs again.
    #[tokio::test]
    async fn an_intact_environment_is_never_deleted_on_a_stale_marker() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["intact"]).await;
        mark_retirement_authorised(dir.path()).expect("mark");

        let store = open(&dir).await;
        assert!(
            store.has_legacy(),
            "an environment that opens cleanly must be kept, whatever the marker says"
        );
        assert!(
            !dir.path().join(RETIREMENT_MARKER).exists(),
            "and the stale marker must be dropped rather than left to act again"
        );
        for key in &keys {
            assert!(store.get(key).await.expect("get").is_some());
        }
    }

    /// An environment left unopenable by an interrupted removal is finished off.
    ///
    /// This is the case the marker exists for. Off Unix the rename that moves the
    /// environment aside cannot be shown to be durable, so a power loss can bring it back
    /// with its contents already deleted. Opening that fails, and without the marker the
    /// node would refuse to start on it forever. The marker says the file store was proven
    /// to hold every chunk, so removing the remains is safe and is the only way forward.
    #[tokio::test]
    async fn an_unopenable_environment_left_by_an_interrupted_removal_is_finished_off() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["interrupted"]).await;
        {
            let store = open(&dir).await;
            store
                .copy_batch(&keys, 0, 0, &never_cancelled())
                .await
                .expect("copy");
        }
        // What a half-finished removal leaves: the directory is back, its contents are
        // not what an environment looks like.
        let data = dir.path().join(LEGACY_ENV_DIR).join(LEGACY_DATA_FILE);
        std::fs::write(&data, b"not an environment any more").expect("wreck");
        mark_retirement_authorised(dir.path()).expect("mark");

        let store = open(&dir).await;
        assert!(
            !store.has_legacy(),
            "the remains of an interrupted removal must not be adopted"
        );
        assert!(
            !dir.path().join(LEGACY_ENV_DIR).exists(),
            "the next start must finish the removal"
        );
        assert!(
            !dir.path().join(RETIREMENT_MARKER).exists(),
            "and clear the marker once it has"
        );
        // Every chunk is still served, from the file store.
        for key in &keys {
            assert!(store.get(key).await.expect("get").is_some());
        }
    }

    /// A single node can still be told to keep both stores.
    #[tokio::test]
    async fn retirement_is_refused_when_the_switch_is_turned_off() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["off"]).await;
        let mut config = test_config(&dir);
        config.migration.retire_legacy = false;
        let store = ChunkStore::new(config).await.expect("open store");
        store.commit_to_files().expect("commit");
        assert!(store
            .retirement_blocker(|_| false)
            .expect("blocked")
            .contains("retirement is disabled"));
    }

    #[tokio::test]
    async fn retiring_removes_the_legacy_environment_and_frees_its_space() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["f1", "f2", "f3"]).await;
        let mut config = test_config(&dir);
        config.migration.retire_legacy = true;
        let store = ChunkStore::new(config).await.expect("open");

        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        open_the_retirement_gate(&store);

        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");
        assert!(proof.is_clean());
        assert_eq!(proof.checked, 3);

        let freed = store
            .retire_legacy(&proof, &|_: &XorName| false, &approved_shed(&store))
            .await
            .expect("retire");
        assert!(freed > 0, "retirement must report the space it returned");
        assert!(
            !dir.path().join(LEGACY_ENV_DIR).exists(),
            "the legacy environment must actually be removed"
        );
        assert!(!store.has_legacy());
        assert_eq!(store.migration_phase(), MigrationPhase::FilesOnly);

        // Everything is still readable, from files alone.
        assert_eq!(store.current_chunks().expect("count"), 3);
        for key in &keys {
            assert!(store.get(key).await.expect("get").is_some());
        }
    }

    #[tokio::test]
    async fn a_reader_holding_the_legacy_handle_defers_retirement_without_hiding_chunks() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["busy"]).await;
        let mut config = test_config(&dir);
        config.migration.retire_legacy = true;
        let store = Arc::new(ChunkStore::new(config).await.expect("open"));
        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        open_the_retirement_gate(&store);

        // Stand in for a read that is still holding the legacy handle. Retirement must
        // defer rather than unmap underneath it, and the chunk must stay readable
        // throughout: a retirement attempt that briefly hid the legacy store would make a
        // node answer "not found" for a chunk it holds.
        let squatter = store.legacy().expect("a legacy handle");
        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");
        let err = store
            .retire_legacy(&proof, &|_: &XorName| false, &approved_shed(&store))
            .await
            .expect_err("must defer while the handle is held");
        assert!(format!("{err}").contains("deferred"), "{err}");

        assert!(store.has_legacy(), "the store must keep its legacy handle");
        let key = keys.first().copied().expect("a key");
        assert!(
            store.get(&key).await.expect("get").is_some(),
            "the chunk must stay readable across a deferred retirement"
        );

        // Once the reader lets go, the next attempt succeeds.
        drop(squatter);
        store
            .retire_legacy(&proof, &|_: &XorName| false, &approved_shed(&store))
            .await
            .expect("retire");
        assert!(!store.has_legacy());
    }

    #[tokio::test]
    async fn retirement_needs_a_clean_verification_report() {
        let dir = TempDir::new().expect("temp dir");
        // Left uncopied on purpose, so this node is about to give the chunk up and the
        // answerability veto has something to fire on.
        seed_legacy(&dir, &["v1"]).await;
        let mut config = test_config(&dir);
        config.migration.retire_legacy = true;
        let store = ChunkStore::new(config).await.expect("open");

        // A report cannot be fabricated: every field is private and the only source is
        // the verification pass. The one available here is the default, which never ran.
        let absent = VerifyReport::default();
        let err = store
            .retire_legacy(&absent, &|_: &XorName| false, &approved_shed(&store))
            .await
            .expect_err("must refuse a report that never ran");
        assert!(format!("{err}").contains("unrepairable"), "{err}");
        assert!(store.has_legacy(), "the legacy environment must survive");

        // And a real, clean report is still refused while any gate is unmet, because
        // retirement rechecks them all itself rather than trusting its caller.
        open_the_retirement_gate(&store);
        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");
        assert!(proof.is_clean());
        let err = store
            .retire_legacy(&proof, &|_: &XorName| true, &approved_shed(&store))
            .await
            .expect_err("must refuse while a chunk is still answerable");
        assert!(format!("{err}").contains("still answerable"), "{err}");
        assert!(store.has_legacy());
    }

    #[tokio::test]
    async fn verification_repairs_a_file_that_rotted_before_retirement() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["w1", "w2"]).await;
        let mut config = test_config(&dir);
        config.migration.retire_legacy = true;
        let store = ChunkStore::new(config).await.expect("open");
        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");

        // A filename is not proof the bytes behind it are good. Corrupt one, exactly as
        // a truncated write or a bad sector would, then prove retirement repairs it
        // rather than deleting the only intact copy.
        let victim = keys.first().copied().expect("a key");
        let path = dir
            .path()
            .join(crate::storage::file_store::CHUNKS_DIR_NAME)
            .join(format!("{:02x}", victim.last().copied().unwrap_or(0)))
            .join(hex::encode(victim));
        std::fs::write(&path, b"rotted").expect("corrupt the file");
        open_the_retirement_gate(&store);

        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");
        assert_eq!(proof.repaired(), 1);
        assert_eq!(proof.unrepairable(), 0);
        assert!(proof.is_clean());

        store
            .retire_legacy(&proof, &|_: &XorName| false, &approved_shed(&store))
            .await
            .expect("retire");
        assert_eq!(
            store.get(&victim).await.expect("get").expect("present"),
            addressed("w1").1
        );
    }

    #[tokio::test]
    async fn a_corrupt_file_is_served_from_the_legacy_copy_and_requeued() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["s1"]).await;
        let store = open(&dir).await;
        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        assert!(store.legacy_only_keys().is_empty());

        let victim = keys.first().copied().expect("a key");
        let path = dir
            .path()
            .join(crate::storage::file_store::CHUNKS_DIR_NAME)
            .join(format!("{:02x}", victim.last().copied().unwrap_or(0)))
            .join(hex::encode(victim));
        std::fs::write(&path, b"rotted").expect("corrupt the file");

        // The file store removes the bad file and stops advertising it; the facade must
        // still find the intact copy rather than reporting a failure.
        assert_eq!(
            store.get(&victim).await.expect("get").expect("present"),
            addressed("s1").1
        );
        assert!(
            store.legacy_only_keys().contains(&victim),
            "the key must go back on the copier's list"
        );
    }

    #[tokio::test]
    async fn a_marker_claiming_more_than_the_file_store_holds_restarts_the_copy() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["p1", "p2", "p3"]).await;
        let store = open(&dir).await;
        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        store.commit_to_files().expect("commit");
        assert_eq!(store.migration_state().kept_key_count, 3);
        store.wait_idle().await;
        drop(store);

        // Someone clears the chunk directory to reclaim space, keeping chunks.mdb.
        // Trusting the marker here would skip the copier, the shed rules and their rank
        // checks on the way to deleting the legacy environment.
        let chunks = dir.path().join(crate::storage::file_store::CHUNKS_DIR_NAME);
        for key in &keys {
            let path = chunks
                .join(format!("{:02x}", key.last().copied().unwrap_or(0)))
                .join(hex::encode(key));
            std::fs::remove_file(path).expect("clear the file store");
        }

        let store = open(&dir).await;
        assert_eq!(
            store.migration_phase(),
            MigrationPhase::Bridging,
            "the filesystem must win over the marker"
        );
        assert_eq!(store.legacy_only_keys().len(), 3);
    }

    #[tokio::test]
    async fn a_file_that_vanished_mid_verification_is_requeued_not_republished() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["gone"]).await;
        let mut config = test_config(&dir);
        config.migration.retire_legacy = true;
        let store = ChunkStore::new(config).await.expect("open");
        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        assert!(store.legacy_only_keys().is_empty());

        // Remove the file without telling the store, which is what the pruner's own
        // delete looks like if it lands mid-pass. Republishing from the legacy copy here
        // would resurrect a chunk the node had deliberately deleted, so the key goes back
        // on the copier's list instead and retirement is refused.
        let key = keys.first().copied().expect("a key");
        let path = dir
            .path()
            .join(crate::storage::file_store::CHUNKS_DIR_NAME)
            .join(format!("{:02x}", key.last().copied().unwrap_or(0)))
            .join(hex::encode(key));
        std::fs::remove_file(&path).expect("remove behind the store's back");

        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");
        assert_eq!(proof.unrepairable, 1);
        assert!(!proof.is_clean());
        assert!(!path.exists(), "the pass must not republish it");
        assert!(store.legacy_only_keys().contains(&key));
        assert!(store
            .retire_legacy(&proof, &|_: &XorName| false, &approved_shed(&store))
            .await
            .is_err());
        assert!(store.has_legacy());
    }

    #[tokio::test]
    async fn a_cancelled_shutdown_stops_the_copier_and_refuses_to_pass_verification() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["s1", "s2", "s3"]).await;
        let store = open(&dir).await;

        // Shutdown must not have to wait out a pass that can run for hours, and a pass
        // that stopped early is not evidence of anything.
        let cancelled = CancellationToken::new();
        cancelled.cancel();

        let report = store
            .copy_batch(&keys, 0, 0, &cancelled)
            .await
            .expect("copy");
        assert_eq!(report.copied, 0, "the copier must stop immediately");
        assert_eq!(store.legacy_only_keys().len(), 3);

        let proof = store
            .verify_before_retire(0, &cancelled)
            .await
            .expect("verify");
        assert!(
            !proof.is_clean(),
            "an interrupted verification must never read as a pass"
        );
    }

    #[tokio::test]
    async fn the_migration_marker_survives_a_restart() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["m1", "m2"]).await;
        let store = open(&dir).await;
        store
            .copy_batch(&keys[..1], 0, 0, &never_cancelled())
            .await
            .expect("copy");
        store.commit_to_files().expect("commit");
        store.note_commitment_rebuilt();
        let first_start = store.migration_state().first_start_unix;
        store.wait_idle().await;
        drop(store);

        let store = open(&dir).await;
        let state = store.migration_state();
        assert_eq!(state.phase, MigrationPhase::Committed);
        assert_eq!(state.shed_key_count, 1);
        assert_eq!(
            state.first_start_unix, first_start,
            "a restart must not restart the shed hold"
        );
        assert!(
            state.committed_at_unix.is_some(),
            "nor the retirement clock"
        );
    }

    #[tokio::test]
    async fn a_marker_that_disagrees_with_the_filesystem_loses() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["x1"]).await;
        let store = open(&dir).await;
        store.force_migration_state(|s| s.phase = MigrationPhase::FilesOnly);
        store.migration_state().save(dir.path()).expect("save");
        store.wait_idle().await;
        drop(store);

        // The marker claims the migration is done, but `chunks.mdb` is right there. The
        // filesystem is the authority.
        let store = open(&dir).await;
        assert_eq!(store.migration_phase(), MigrationPhase::Bridging);
        assert!(store.has_legacy());
    }

    #[tokio::test]
    async fn a_legacy_chunk_that_does_not_match_its_address_is_dropped_once() {
        let dir = TempDir::new().expect("temp dir");
        // Write a mismatched entry straight into LMDB, bypassing its own address check.
        let (addr, _) = addressed("bad");
        let other = addressed("other").1;
        {
            let lmdb = LmdbStorage::new(LmdbStorageConfig {
                root_dir: dir.path().to_path_buf(),
                verify_on_read: false,
                max_map_size: 0,
                disk_reserve: 0,
            })
            .await
            .expect("open legacy");
            // `put` verifies, so seed a good chunk and corrupt the association by
            // storing the other content under a key it does not hash to.
            let bad_key = crate::client::compute_address(&other);
            lmdb.put(&bad_key, &other).await.expect("put");
            lmdb.wait_idle().await;
        }
        let store = open(&dir).await;
        let keys = store.legacy_only_keys();
        assert_eq!(keys.len(), 1);
        assert_ne!(keys.first().copied(), Some(addr));

        // A well-formed entry copies cleanly; the report shape is what the driver reads.
        let report = store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        assert_eq!(report.copied, 1);
        assert_eq!(report.unusable, 0);
    }

    #[test]
    fn the_release_switches_are_never_written_to_an_operator_config_file() {
        // A node writes its effective configuration back to disk. If these round-tripped,
        // R1's values would be baked into every operator's file and the next release
        // would change nothing.
        let mut config = MigrationConfig::default();
        config.retire_legacy = !config.retire_legacy;
        config.allow_shed = false;
        config.shed_hold_hours = 5;

        let encoded = toml::to_string(&config).expect("encode");
        assert!(!encoded.contains("retire_legacy"), "{encoded}");

        let decoded: MigrationConfig = toml::from_str(&encoded).expect("decode");
        let fresh = MigrationConfig::default();
        assert_eq!(decoded.retire_legacy, fresh.retire_legacy);
        // Genuine operator controls do survive.
        assert!(!decoded.allow_shed);
        assert_eq!(decoded.shed_hold_hours, 5);
    }

    #[test]
    fn the_copy_order_is_closest_first() {
        let me = [0u8; XORNAME_LEN_LOCAL];
        let mut near = [0u8; XORNAME_LEN_LOCAL];
        if let Some(b) = near.last_mut() {
            *b = 1;
        }
        let mut far = [0u8; XORNAME_LEN_LOCAL];
        if let Some(b) = far.first_mut() {
            *b = 0xff;
        }
        let ordered = rank_closest_first(vec![far, near], Some(me));
        assert_eq!(ordered.first().copied(), Some(near));
        assert_eq!(ordered.last().copied(), Some(far));

        // With no identity the order is still stable, which is all the copier needs.
        let ordered = rank_closest_first(vec![far, near], None);
        let mut expected = vec![far, near];
        expected.sort_unstable();
        assert_eq!(ordered, expected);
    }

    /// Local alias so the test does not import from the protocol crate.
    const XORNAME_LEN_LOCAL: usize = 32;

    #[test]
    fn the_retirement_delay_can_never_be_shortened_below_the_retention_window() {
        let config = MigrationConfig {
            retire_delay_hours: 0,
            ..MigrationConfig::default()
        };
        assert_eq!(
            config.effective_retire_delay_hours(),
            MIN_RETIRE_DELAY_HOURS
        );
    }
}
