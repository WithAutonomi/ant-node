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
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Directory name of the legacy LMDB environment, under the node root.
pub const LEGACY_ENV_DIR: &str = "chunks.mdb";

/// Suffix for a legacy environment that has been retired but not yet deleted.
pub const RETIRED_SUFFIX: &str = ".retired";

/// Written inside a chunk environment directory once it has been retired.
///
/// The rename that moves the environment aside cannot be shown to be durable off Unix:
/// there is no way to flush a directory through the standard library, and `MoveFileEx` is
/// not documented as durable at return without a flag std does not use. So a power loss
/// can bring the directory back under its old name with its contents already deleted, and
/// a node that tried to open that would fail to start.
///
/// This file is what makes that unambiguous, and it is *inside* the directory rather than
/// beside it so that it travels with it: a directory that reverts to its old name reverts
/// carrying its own evidence. It is created with the same create-and-flush that publishes
/// a chunk, which is documented as durable everywhere, and only after the rename has
/// already succeeded. So a directory holding it has been retired, whatever it is called,
/// and one that does not is a live environment and is opened normally.
///
/// Deliberately not a file beside the environment. A marker that can outlive the thing it
/// describes has to be cancelled, cancellation can fail or be lost, and a stale one would
/// authorise deleting an environment that had since taken a chunk.
const RETIRED_MARKER: &str = "RETIRED";

/// How many times the background reaper retries deleting a retired directory.
///
/// Generous, because giving up strands the disk until the next restart and the thread
/// costs nothing while it sleeps. With the backoff below this keeps trying for about a
/// day.
const RETIRED_DELETE_ATTEMPTS: u32 = 60;

/// Base wait between those attempts, multiplied by the attempt number up to the cap.
const RETIRED_DELETE_BACKOFF: Duration = Duration::from_secs(10);

/// The longest the reaper waits between attempts.
const RETIRED_DELETE_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);

/// How many retired directories may be waiting to be deleted before the node stops
/// finding new names for them. Far more than a node should ever accumulate.
const MAX_TOMBSTONES: u32 = 64;

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
    /// Writes that have started and whose outcome is not yet known.
    ///
    /// A write into the legacy environment runs on a blocking thread that outlives the
    /// future waiting for it, so a shutdown can leave the environment holding a chunk
    /// while nothing ran to record it. A key in neither view is what retirement destroys,
    /// so every write announces itself here first.
    ///
    /// Deliberately NOT part of what the node says it holds. This is a note to itself
    /// that something is in flight, not a claim: `exists`, `all_keys`, the commitment, the
    /// quote count and the pruner all ignore it. It vetoes retirement, and the driver
    /// resolves each entry against what is actually on disk.
    ///
    /// How many writes were made without a rollback copy of the chunk in the environment.
    ///
    /// The rollback copy is best effort by design, and the ADR says so: a bridging node
    /// whose environment has no reusable page keeps serving from files and simply has no
    /// second copy to roll back to. What was missing was any way to ask how often that
    /// happened. One `warn!` per chunk is not an answer to "how many nodes on this fleet
    /// are actually keeping a rollback copy", which is the question the second release
    /// turns on, and on a node with no free pages it is also a line per chunk forever.
    ///
    /// Writes, not distinct chunks: two attempts at one address count twice, and a later
    /// attempt that succeeds does not count back down. Counted before the file half runs,
    /// so a write that then fails outright is counted too. Keeping a set of addresses
    /// instead would be exact and would also mean holding millions of them in memory to
    /// answer a question that a rate answers. Read it as "this node is failing to keep
    /// rollback copies, this often", not as a chunk count.
    skipped_rollback_copies: Arc<std::sync::atomic::AtomicU64>,

    /// Counted, not a set, for the reason the file store's `writing` map is counted.
    /// Cancellation can release the facade's key lane while the blocking half survives, so
    /// a second write for the same key can start behind the first. With one entry between
    /// them, whichever returned first would clear it while the other was still queued, and
    /// a delete arriving in that window would see no announcement, skip draining the
    /// environment, and let the surviving write land afterwards and put the key back.
    pending: Arc<parking_lot::RwLock<BTreeMap<XorName, usize>>>,
}

impl Legacy {
    /// Note that a chunk went to files alone, and say whether to log it.
    ///
    /// Throttled by powers of ten. The condition is usually all-or-nothing, so the first
    /// few lines say it started and the later ones say it is still going without becoming
    /// the log.
    fn note_skipped_rollback_copy(&self) -> Option<u64> {
        let count = self
            .skipped_rollback_copies
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        let round = matches!(
            count,
            10 | 100 | 1_000 | 10_000 | 100_000 | 1_000_000 | 10_000_000
        );
        (count <= 3 || round).then_some(count)
    }

    /// Announce a write into the environment, or note a second one for the same key.
    fn announce(&self, address: &XorName) {
        *self.pending.write().entry(*address).or_insert(0) += 1;
    }

    /// Retire one announcement, leaving any other for the same key still standing.
    fn announced_write_finished(&self, address: &XorName) {
        let mut pending = self.pending.write();
        let Some(count) = pending.get_mut(address) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            pending.remove(address);
        }
    }
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

        // Before anything looks at the legacy environment: a directory carrying its own
        // retirement mark is the remains of a removal a power loss interrupted, and is
        // moved aside rather than opened.
        let openable = finish_interrupted_retirement(&config.root_dir);
        let legacy_env_dir = config.root_dir.join(LEGACY_ENV_DIR);
        let legacy =
            if openable == LiveEnvironment::WhateverIsOnDisk && legacy_present(&config.root_dir)? {
                Some(Self::open_legacy(&config, &files).await?)
            } else {
                None
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
        let (lmdb, legacy_keys) = Self::open_legacy_env(config).await?;
        Ok(Legacy {
            lmdb,
            only: Arc::new(parking_lot::RwLock::new(Self::keys_only_in_legacy(
                &legacy_keys,
                files,
            ))),
            skipped_rollback_copies: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pending: Arc::new(parking_lot::RwLock::new(BTreeMap::new())),
        })
    }

    /// Open the legacy environment and read every key in it.
    ///
    /// Split from the diff against the file store because the two want different timing:
    /// this is slow and safe to do at any moment, the diff has to be the last thing before
    /// the handle is installed.
    async fn open_legacy_env(
        config: &ChunkStoreConfig,
    ) -> Result<(Arc<LmdbStorage>, Vec<XorName>)> {
        let lmdb = Arc::new(
            LmdbStorage::new(LmdbStorageConfig {
                root_dir: config.root_dir.clone(),
                verify_on_read: config.verify_on_read,
                max_map_size: config.max_map_size,
                disk_reserve: config.disk_reserve,
            })
            .await?,
        );
        // From here it never grows. Two stores on one disk each measure the same free
        // space and neither knows what the other is about to spend, so a chunk written to
        // both can be admitted twice against one lot of headroom and the pair can cross
        // the reserve together. Pinned, this one writes only from pages it already has,
        // so the file store's accounting is the only claim on free disk.
        //
        // What it costs is that the rollback copy is made only when the environment has
        // room of its own. That is the right way round: the copy exists to make a fleet
        // rollback survivable, not to be the write that has to succeed, and an
        // environment this migration exists to delete should not be taking new disk to
        // hold a second copy of something the file store already has.
        lmdb.pin_growth().await?;
        let legacy_keys = lmdb.all_keys().await?;
        Ok((lmdb, legacy_keys))
    }

    /// Which of `legacy_keys` the file store does not have.
    ///
    /// In memory, no I/O: the file store answers from its index. Cheap enough to redo
    /// immediately before installing a handle, which is the point. A key that lost its
    /// file while the environment was being read must be in this set, or nothing will
    /// look for it again and retirement will destroy the copy that is left.
    fn keys_only_in_legacy(legacy_keys: &[XorName], files: &FileStore) -> BTreeSet<XorName> {
        legacy_keys
            .iter()
            .filter(|key| !files.is_indexed(key))
            .copied()
            .collect()
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
                    // Counted here as well as on the failure path below, and this is the
                    // one that matters: a pinned environment with no reusable page answers
                    // Full for every chunk, so on the node most affected this is the whole
                    // of the skipping and the other path never runs at all.
                    if let Some(count) = l.note_skipped_rollback_copy() {
                        warn!(
                            migration_event = "no_rollback_copy",
                            skipped = count,
                            "Legacy chunk environment is full; storing {} in files only. A \
                             rollback to a pre-migration build would not have this chunk, \
                             and {count} write(s) on this node have now gone without a \
                             rollback copy.",
                            hex::encode(address)
                        );
                    } else {
                        debug!(
                            "Legacy chunk environment is full; storing {} in files only.",
                            hex::encode(address)
                        );
                    }
                } else {
                    // Announced BEFORE the write, not after it. The write runs on a
                    // blocking thread that outlives this future: a shutdown that drops the
                    // caller mid-way can leave the environment holding a chunk while
                    // nothing here ever ran to record it, and a key in neither view is
                    // what retirement destroys. In the in-flight note rather than the key
                    // set, because until the write returns this node does not hold the
                    // chunk and must not say it does.
                    l.announce(address);
                    // Best effort, and only best effort. The verdict above is optimistic
                    // by design: LMDB can still refuse a write for fragmentation, pages
                    // pinned by a long read, or a copy-on-write B-tree split. Propagating
                    // that would let a store this node is in the middle of abandoning
                    // reject paid chunks the file store has ample room for, for the whole
                    // bridge period. The chunk's own validity is not at stake here; the
                    // file store checks the content address itself.
                    match l.lmdb.put(address, content).await {
                        Ok(_) => dual_written = true,
                        Err(e) => {
                            if let Some(count) = l.note_skipped_rollback_copy() {
                                warn!(
                                    migration_event = "no_rollback_copy",
                                    skipped = count,
                                    "Could not also write {} to the legacy environment: \
                                     {e}. Storing it in files only. A rollback to a \
                                     pre-migration build would not have this chunk, and \
                                     {count} write(s) on this node have now gone without a \
                                     rollback copy.",
                                    hex::encode(address)
                                );
                            }
                        }
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
                //
                // Only when the file store really does not have it. A write can fail
                // because the file that is already there could not be read to check it,
                // and calling that key legacy-only while the file index still names it
                // puts it in both views, where it stays answerable and vetoes retirement
                // for good.
                // The file half failed and the legacy half did not, so the environment
                // holds the only copy and the key really is legacy-only now. Promoted
                // from the in-flight note to the key set, which is the one moment that
                // promotion is warranted: both outcomes are known.
                if let Some(ref l) = legacy {
                    l.announced_write_finished(address);
                    if dual_written && !self.files.is_indexed(address) {
                        l.only.write().insert(*address);
                    }
                }
                return Err(e);
            }
        };

        // The file store has it, so it is not legacy-only, whether it was already there
        // or this call put it there. The in-flight note goes at the same time: both
        // writes have returned, so there is nothing left in flight to protect.
        if let Some(ref l) = legacy {
            l.only.write().remove(address);
            l.announced_write_finished(address);
        }
        if already_in_legacy {
            // Migrated for free: a hot key the copier no longer has to move.
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
                // Whatever went wrong with the file, the legacy environment may still
                // have the bytes, and while it is there it is the point of the bridge to
                // use them. A verification failure means the file was thrown away; every
                // other error (a full descriptor table, an I/O fault, an oversized file)
                // leaves the file in place and unreadable. Both are unservable from the
                // file store, and both are worth asking the other store about.
                let verification_failed = format!("{e}").contains("verification failed");
                warn!(
                    "Chunk {} could not be served from the file store ({e}); looking for a \
                     copy in the legacy environment",
                    hex::encode(address)
                );
                let from_legacy = self.serve_from_legacy(address, fallback).await;
                match from_legacy {
                    Ok(Some(content)) => Ok(Some(content)),
                    // Nothing anywhere. Report the original failure rather than a plain
                    // miss, so the caller can tell the difference. The key is only
                    // re-queued for copying when the file really went: an unreadable file
                    // that is still there is not legacy-only, and calling it so is how a
                    // key ends up claimed through one view and servable through neither.
                    Ok(None) => Err(e),
                    Err(legacy_error) => {
                        if verification_failed {
                            Err(e)
                        } else {
                            Err(legacy_error)
                        }
                    }
                }
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
        if !self.files.is_indexed(address) {
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
        let from_files = self.files.get_raw(address).await;
        match from_files {
            Ok(Some(content)) => return Ok(Some(content)),
            Ok(None) => {}
            // Same rule as `get`: while the legacy environment is there it may have the
            // bytes, and this is the read that drives digest audits, possession checks
            // and pruning. Answering "no digest" for a chunk the node can still produce
            // is a failed audit for nothing.
            Err(e) => {
                let Some(legacy) = fallback else {
                    return Err(e);
                };
                let _lane = self.key_lock(address).await;
                return match legacy.lmdb.get_raw(address).await {
                    Ok(Some(content)) => Ok(Some(content)),
                    // Nothing anywhere: report the original failure, not a plain miss.
                    Ok(None) | Err(_) => Err(e),
                };
            }
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
        let missing_locally = !self.files.is_indexed(address);
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
        // And the key's own critical section, for the whole of it. Without it the pruner
        // can delete both backings between the read and the answer, and the offered copy
        // would be turned away for a chunk the node no longer has at all.
        let _lane = self.key_lock(address).await;

        if let Some(legacy) = self.legacy() {
            if legacy.only.read().contains(address) {
                // Held only in the legacy environment. Not taken on trust either: the
                // bytes in there can be wrong too, and the copier drops such a key from
                // the union when it finds out, which would leave no copy anywhere if this
                // had turned the good one away.
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
        if !self.files.is_indexed(address) {
            return false;
        }
        // No cheap length pre-check. `metadata` failing is not the same as a length that
        // does not match, and off Unix replacing a chunk truncates it in place, so acting
        // on an unanswered question would empty a healthy sole copy. The read below
        // distinguishes them.
        match self.files.get_raw(address).await {
            // Byte-for-byte what the caller has, and the caller checked those bytes
            // against the address before getting here. Nothing is wrong with this file.
            Ok(Some(stored)) if stored == content => {
                self.files.note_bytes_proven_good(address);
                true
            }
            Ok(_) => {
                warn!(
                    "Chunk {} is on disk but its contents are wrong; replacing it with the \
                     copy just offered",
                    hex::encode(address)
                );
                // Recorded before the repair is attempted, not after it succeeds. A
                // repair can fail for capacity or I/O, and a chunk proven wrong that goes
                // on looking healthy leaves a cached pre-retirement pass covering it,
                // which deletes the legacy copy the repair would have come from.
                self.files.note_known_wrong(address);
                self.files.repair(address, content).await.is_ok()
            }
            // Unanswerable this time. Not claimed as held, so the offer goes through the
            // ordinary path, which writes it rather than replacing anything.
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
        // Behind whatever is already writing this key, and only this key. A write's
        // blocking half outlives the future that started it, so one landing after this
        // would put back a chunk the node had decided to prune.
        self.files.wait_for_write(address).await;
        // Legacy first, and only then the in-memory views. The other order removes the
        // key from `only` and then, if the legacy delete fails, leaves bytes that live
        // solely in the legacy store and are invisible to `exists`, `all_keys` and the
        // pre-retirement verification, so retirement would take the only copy.
        let from_legacy = match self.legacy() {
            Some(legacy) => {
                // A write for this key that nobody waited for may still be queued behind
                // this delete. Letting it land afterwards would resurrect the key: the
                // next reconciliation finds it in the environment and puts it back on the
                // copier's list, undoing a prune the node decided on. Waited out here,
                // holding the lane, so the delete is genuinely last.
                //
                // Both halves. A write has an environment half and a file half, either of
                // which can be the one still running, and draining only the first leaves
                // the second free to publish the file after this has deleted it.
                //
                // The environment half is found through the journal, which only dual
                // writes keep. The file half is asked of the file store directly, because
                // the copier and the repair path also spawn file writes and neither goes
                // near that journal: using it as a proxy for "is anything writing this
                // key" was a scope assumption, not a fact.
                if legacy.pending.read().contains_key(address) {
                    legacy.lmdb.wait_idle().await;
                }
                let deleted = legacy.lmdb.delete(address).await?;
                let was_only = legacy.only.write().remove(address);
                // Every announcement for this key, not one of them: the drain above waited
                // out whatever was in flight and this delete is deliberately last.
                legacy.pending.write().remove(address);
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
            // Physically, again: a chunk the store holds and cannot read is not one to
            // copy over the top of, and it is not legacy-only either.
            if self.files.is_indexed(key) {
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
                    // Bigger than this build will ever serve. The legacy store took it
                    // through an API with no size bound; the file store will not, and no
                    // amount of retrying changes that. Counted as unusable and removed,
                    // like a record whose bytes do not match, or one such record would
                    // stop this node and every node sharing its disk from ever reclaiming
                    // space.
                    if message.contains("byte maximum") {
                        warn!(
                            "Chunk {} in the legacy environment is larger than this build \
                             will store; removing it. It cannot be served either way.",
                            hex::encode(key)
                        );
                        match legacy.lmdb.delete(key).await {
                            Ok(_) => {
                                legacy.only.write().remove(key);
                                report.unusable += 1;
                            }
                            Err(e) => warn!(
                                "Oversized chunk {} could not be removed from the legacy \
                                 environment: {e}. The environment stays.",
                                hex::encode(key)
                            ),
                        }
                        continue;
                    }
                    if message.contains("Content address mismatch") {
                        // The legacy bytes do not hash to their own key, so this chunk
                        // cannot be reproduced and was never servable. Stop advertising
                        // it rather than carrying a key we cannot answer for.
                        //
                        // Deleted from the environment too, and only dropped from the key
                        // set once that has worked. Leaving the record behind puts the
                        // key in neither view, which the pre-retirement pass reads as a
                        // chunk to protect and puts straight back — and the next copier
                        // pass drops it again. One malformed record would keep a node,
                        // and every node sharing its disk, from ever reclaiming space.
                        warn!(
                            "Chunk {} in the legacy environment does not match its address; \
                             removing it so replication can repair it",
                            hex::encode(key)
                        );
                        match legacy.lmdb.delete(key).await {
                            Ok(_) => {
                                legacy.only.write().remove(key);
                                report.unusable += 1;
                            }
                            Err(e) => warn!(
                                "Chunk {} does not match its address and could not be \
                                 removed from the legacy environment: {e}. It stays on the \
                                 list and the environment stays.",
                                hex::encode(key)
                            ),
                        }
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
        // Before anything else, and whether or not there is a handle. An environment this
        // node cannot classify must not be retired, and asking only on the no-handle path
        // meant the ordinary path never asked: a node holding its store open went through
        // every gate, renamed the directory aside and deleted it.
        if self.legacy_cannot_be_classified() {
            return Some(format!(
                "{} cannot be read well enough to say whether it was already retired. \
                 Nothing will be deleted until it can. Check that the directory and \
                 anything inside it can be read.",
                self.legacy_env_dir.display()
            ));
        }
        if !self.has_legacy() {
            // No handle is not the same as no environment. A rename that failed and then
            // could not be reopened leaves exactly that: the directory is still on disk
            // and this node can no longer read it. Answering "nothing blocks retirement"
            // would have the driver log the migration complete over a store that is still
            // there and still holding chunks nothing else can serve.
            let mark = retirement_mark(&self.legacy_env_dir);
            if legacy_present(&self.config.root_dir).unwrap_or(true) && !mark.permits_removal() {
                // Two different situations wearing one message would send an operator to
                // the wrong place. One is a store this node cannot open; the other is a
                // store nothing can even classify, which usually means a permission or a
                // mount, and which the node deliberately will not act on either way.
                if mark == RetirementMark::Unknown {
                    return Some(format!(
                        "{} is still on disk and this node cannot tell whether it was \
                         retired, so it will neither open it nor remove it. Check that the \
                         directory and anything inside it can be read.",
                        self.legacy_env_dir.display()
                    ));
                }
                return Some(format!(
                    "{} is still on disk but this node has no handle to it. It cannot be \
                     read, verified or removed until the node is restarted.",
                    self.legacy_env_dir.display()
                ));
            }
            return None;
        }
        if !self.config.migration.retire_legacy {
            return Some(
                "retirement is disabled in this release (storage.migration.retire_legacy)".into(),
            );
        }
        // A linked environment is never retired automatically. Retirement renames the
        // path and then deletes what is behind it, and behind a link is a directory
        // somewhere else that this node does not own. Copying still happens; only the
        // removal is refused, so the node ends up serving from files with its old store
        // intact and its operator told what to do about it.
        if is_a_link(&self.legacy_env_dir) {
            return Some(format!(
                "{} is a link rather than a directory. The chunks are being copied out of \
                 it, but it will not be deleted: what it points at is not this node's to \
                 remove. Once the migration has settled, delete it by hand.",
                self.legacy_env_dir.display()
            ));
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
        // Taken BEFORE anything is read. Stamping it at the end would absorb exactly the
        // failures this exists to catch: a chunk verified early in the pass that stops
        // being readable before the pass finishes would leave the report carrying the
        // already-incremented count, and both later checks would see it match.
        let health_at_start = self.files.health_generation();
        let Some(legacy) = self.legacy() else {
            report.ran = true;
            report.health = health_at_start;
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
            // Under the key's critical section, so the two questions below are asked of
            // one moment. Without it a write can publish the file and take the key out of
            // the legacy-only set in between, and this pass would put it straight back.
            let classified = {
                let _lane = self.key_lock(&key).await;
                // The physical question. A chunk the store holds but cannot currently
                // read is still one it holds, and calling it absent here would put the
                // key in the legacy-only set, where the union view advertises it again.
                let in_files = self.files.is_indexed(&key);
                let legacy_only = legacy.only.read().contains(&key);
                if in_files && legacy_only {
                    // In both views at once, which nothing else clears once the copier
                    // has stopped running. The file store has it, so the legacy-only set
                    // is the one that is wrong: an answerable key in that set vetoes
                    // retirement for as long as the process lives.
                    debug!(
                        "Chunk {} was in both views; the file store has it, so it is no \
                         longer legacy-only",
                        hex::encode(key)
                    );
                    legacy.only.write().remove(&key);
                }
                (in_files, legacy_only)
            };
            if !classified.0 {
                // Known to be legacy-only, which is what a key this node is giving up
                // looks like. Whether it may go is the gates' decision, not this pass's.
                if classified.1 {
                    continue;
                }
                // In neither view. However that came about — a publish that failed, a
                // file quarantined for corruption, a name this store stopped advertising —
                // the environment holds the only copy, and nothing is looking after it:
                // the gates only ever see the legacy-only set. Put it back there and
                // refuse the proof this pass. What neither view protects is exactly what
                // retirement destroys.
                warn!(
                    "Chunk {} is in the legacy environment, is not in the file store, and \
                     was in neither view; re-queued for copying and the legacy environment \
                     stays",
                    hex::encode(key)
                );
                legacy.only.write().insert(key);
                report.unrepairable = report.unrepairable.saturating_add(1);
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
        // The count this pass started from, and a refusal if the store moved while it
        // ran. Retirement compares the same value again immediately before deleting
        // anything, so one number covers both windows: during the pass, and after it.
        report.health = health_at_start;
        if self.files.health_generation() != health_at_start {
            warn!(
                "A chunk stopped being servable while the pre-retirement pass was running, \
                 so this pass does not describe the store. Another runs on the next tick."
            );
            report.unrepairable = report.unrepairable.saturating_add(1);
        }
        Ok(report)
    }

    /// Check one chunk that both stores hold, repairing the file if it is wrong.
    async fn verify_one(&self, legacy: &Legacy, key: &XorName) -> VerifyOutcome {
        // The throttle sleep is deliberately outside this critical section: at 32 MiB/s a
        // 4 MiB chunk sleeps for over a tenth of a second, and holding a shard lane for
        // that would stall every write to a sixteenth of the address space for hours.
        let _lane = self.key_lock(key).await;

        let bytes = match self.files.get_raw(key).await {
            Ok(bytes) => bytes,
            // Not the same as gone. `Vanished` puts the key back on the copier's list,
            // and doing that for a file that is still there and still indexed leaves the
            // key in both views at once: the file index keeps it in every commitment, so
            // it stays answerable, and an answerable legacy-only key vetoes retirement for
            // as long as the process lives. Refuse this pass instead.
            Err(e) => {
                warn!(
                    "Chunk {} could not be read while verifying: {e}. The legacy \
                     environment stays.",
                    hex::encode(key)
                );
                return VerifyOutcome {
                    bytes: 0,
                    verdict: VerifyVerdict::Unrepairable,
                };
            }
        };
        let len = bytes.as_ref().map_or(0, Vec::len) as u64;
        let Some(bytes) = bytes else {
            return VerifyOutcome {
                bytes: 0,
                verdict: VerifyVerdict::Vanished,
            };
        };
        if crate::client::compute_address(&bytes) == *key {
            // The pass hashed these bytes and they are right, so whatever this store
            // thought was wrong with them is not. It reads raw, which does not settle
            // that on its own, and leaving the mark would retire the environment while a
            // healthy chunk stayed unadvertised until some later verified read.
            self.files.note_bytes_proven_good(key);
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

    /// Is this verification still worth acting on?
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] naming what has changed since the pass ran.
    fn proof_is_usable(&self, proof: &VerifyReport) -> Result<()> {
        if !proof.is_clean() {
            return Err(Error::Storage(format!(
                "Refusing to remove the legacy environment: verification reported {} \
                 unrepairable chunk(s) (ran: {})",
                proof.unrepairable, proof.ran
            )));
        }
        if !proof.still_describes(&self.files) {
            return Err(Error::Storage(
                "Refusing to remove the legacy environment: a chunk stopped being \
                 servable since it was verified, so that verification no longer describes \
                 the file store. A fresh pass runs on the next tick."
                    .into(),
            ));
        }
        if self.has_pending_writes() {
            return Err(Error::Storage(
                "Refusing to remove the legacy environment: a write announced itself and \
                 has not reported back, so what the environment holds is not yet settled."
                    .into(),
            ));
        }
        Ok(())
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
    /// Returns [`Error::Storage`] if verification did not pass or no longer describes the
    /// store, if a write has not reported back, if the handle is still shared (the caller
    /// should retry on the next tick), or if the directory cannot be removed.
    pub async fn retire_legacy<F>(
        &self,
        proof: &VerifyReport,
        still_answerable: &F,
        approved_to_shed: &BTreeSet<XorName>,
    ) -> Result<u64>
    where
        F: Fn(&XorName) -> bool + Send + Sync,
    {
        self.proof_is_usable(proof)?;
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
        // Asked again with the guard held, which is the only moment the answer cannot
        // change underneath it. The check above can be overtaken by a read that fails
        // between there and here.
        if !proof.still_describes(&self.files) {
            drop(retiring);
            return Err(Error::Storage(
                "Refusing to remove the legacy environment: a chunk stopped being \
                 servable while retirement was starting. A fresh pass runs on the next \
                 tick."
                    .into(),
            ));
        }
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
                        // Asked here, in the same critical section as the checks below
                        // and immediately before the handle is taken. Asking earlier is
                        // not enough: a write can announce itself under the shared guard,
                        // be cancelled so the guard is released, and leave its blocking
                        // half running past the drain above. Its note is the only thing
                        // that says so, and dropping the journal with the environment
                        // would take the evidence with it.
                        if !l.pending.read().is_empty() {
                            return Err(Error::Storage(
                                "Refusing to remove the legacy environment: a write \
                                 announced itself and has not reported back, so what the \
                                 environment holds is not yet settled."
                                    .into(),
                            ));
                        }
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
            if let Some(Legacy {
                lmdb,
                only,
                pending,
                skipped_rollback_copies,
            }) = taken
            {
                drop(only);
                drop(pending);
                drop(skipped_rollback_copies);
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
        let tombstone = free_tombstone_path(&self.config.root_dir);

        if let Err(e) = std::fs::rename(&self.legacy_env_dir, &tombstone) {
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
        // Marked from the inside, now that the rename has succeeded and before anything
        // is deleted. This is what a directory that reverts to its old name carries with
        // it, and it is the only thing a later start treats as permission to delete.
        if let Err(e) = mark_directory_retired(&tombstone) {
            // Nothing has been deleted and the directory is intact, so put it back rather
            // than recording the migration as finished over a store that is still there.
            // Recording finished would be worse than it sounds: the next tick restores the
            // unmarked directory to its own name, and a node that has already called
            // itself file-only would then exit with a live environment on disk and no
            // handle to it.
            // Only when the mark is provably gone. A mark left inside would have the
            // next cleanup pass reap a live, open environment.
            let restored =
                e.mark_definitely_gone && std::fs::rename(&tombstone, &self.legacy_env_dir).is_ok();
            let reopened = restored && self.reopen_legacy().await;
            return Err(Error::Storage(format!(
                "Moved the legacy environment to {} but could not mark it retired: {e}. \
                 Nothing was deleted{}",
                tombstone.display(),
                if reopened {
                    ", and it has been put back, so the node keeps serving from both \
                     stores and retirement is tried again."
                } else if e.mark_definitely_gone {
                    ". IT COULD NOT BE PUT BACK: this node cannot serve chunks that live \
                     only there until it is restarted."
                } else {
                    ". It has been left where nothing will open it, because a partial \
                     retirement mark may still be inside it. Its chunks are in the file \
                     store; move it back by hand only after removing that mark."
                }
            )));
        }

        // Test-only: renamed aside and marked, nothing deleted yet. A process killed here
        // is what the recovery on the next start exists for.
        #[cfg(any(test, feature = "test-utils"))]
        crate::storage::file_store::halt_here_if_asked(
            crate::storage::file_store::HALT_AFTER_RETIRE_MARK,
            &tombstone,
        );

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
        // On a detached OS thread, and not awaited. This is a synchronous recursive delete
        // of a directory that can hold hundreds of gigabytes and cannot be interrupted
        // once it starts. Inside the migration task it would sit through shutdown's grace
        // and past it, because an abort is not observed until the call returns; on the
        // runtime's blocking pool a normal runtime shutdown would wait for it anyway. A
        // plain thread is the only one the process can genuinely walk away from, and the
        // directory carries its own retirement mark, so whatever is left is finished by
        // the next start.
        delete_retired_directory(tombstone);
        Ok(freed)
    }

    /// Try again to open a legacy environment this node has lost its handle to.
    ///
    /// A rename that failed and then could not be reopened leaves the directory on disk
    /// with no way to read it, and every chunk that lives only there unserved. Saying so
    /// once and waiting for a restart is not enough: the reason is usually transient, and
    /// a node that is otherwise healthy should not stay half-blind until somebody notices.
    ///
    /// Returns whether it came back. Does nothing when there is a handle already, or when
    /// there is nothing on disk to open.
    pub async fn recover_lost_legacy_handle(&self) -> bool {
        if self.has_legacy() || !retirement_mark(&self.legacy_env_dir).permits_opening() {
            return false;
        }
        if !legacy_present(&self.config.root_dir).unwrap_or(false) {
            return false;
        }
        // Opened WITHOUT the exclusive guard. Opening scans every key in the environment,
        // which on a large store is minutes, and every read and write on the node would
        // wait behind it. Nothing else can be installing a handle: retirement does nothing
        // while there is none, and this runs from the one migration task.
        let (lmdb, legacy_keys) = match Self::open_legacy_env(&self.config).await {
            Ok(opened) => opened,
            Err(e) => {
                warn!(
                    "Could not reopen {}: {e}. The chunks that live only there stay \
                     unreadable until this succeeds.",
                    self.legacy_env_dir.display()
                );
                return false;
            }
        };
        // Exclusive only to install it, which is instant.
        let _recovering = self.retirement.write().await;
        if self.has_legacy() {
            return false;
        }
        // The diff happens HERE, not when the environment was read. Reading it takes
        // minutes on a large store, and a verifying read in that time can find a file
        // rotted and throw it away. With no handle installed there was nothing to put the
        // key back into, so a set computed beforehand would be missing it, every gate
        // would skip it, and retirement would destroy the intact copy in the environment.
        // Under this guard no read, write or delete is in flight, so the file store's
        // answer cannot move while it is being asked.
        let only = Self::keys_only_in_legacy(&legacy_keys, &self.files);
        *self.legacy.write() = Some(Legacy {
            lmdb,
            only: Arc::new(parking_lot::RwLock::new(only)),
            skipped_rollback_copies: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pending: Arc::new(parking_lot::RwLock::new(BTreeMap::new())),
        });
        // A node that recorded itself file-only and then got an environment back has to
        // go through the migration again from the start: the phase decides what the
        // driver does, and file-only does no copying, so leaving it there would give the
        // node a handle it never uses. Conservative on purpose; the copier finds most of
        // the work already done.
        if self.migration_phase() == MigrationPhase::FilesOnly {
            warn!(
                "Recovered a legacy chunk environment after recording this node as \
                 file-only. Starting the migration again from the copying stage."
            );
            let mut state = self.state.write();
            state.phase = MigrationPhase::Bridging;
            state.committed_at_unix = None;
            state.rebuilds_since_commit = 0;
            let snapshot = state.clone();
            drop(state);
            if let Err(e) = snapshot.save(&self.config.root_dir) {
                warn!("Could not persist the migration marker: {e}");
            }
        }
        warn!(
            "Reopened {} after losing its handle",
            self.legacy_env_dir.display()
        );
        true
    }

    /// Is there a retired directory still waiting to be deleted?
    ///
    /// Separate from having a legacy environment: a node whose removal was interrupted has
    /// no handle and nothing to migrate, but its disk has not come back. Something has to
    /// keep trying during this uptime rather than leaving it until the next restart.
    #[must_use]
    pub fn has_cleanup_pending(&self) -> bool {
        !retired_tombstones(&self.config.root_dir).is_empty()
            || !retirement_mark(&self.legacy_env_dir).permits_opening()
    }

    /// Try again to finish a removal a previous attempt left behind.
    ///
    /// Safe to call at any time: it only ever moves or deletes a directory that carries
    /// its own retirement mark.
    pub fn retry_cleanup(&self) {
        // Never while this node has the environment open. Cleanup decides what to do from
        // the directory's own mark, and a mark that outlived a failed retirement would
        // have it rename a live, mapped environment out from under the handle.
        if self.has_legacy() {
            sweep_retired_legacy(&self.config.root_dir);
            return;
        }
        finish_interrupted_retirement(&self.config.root_dir);
    }

    /// Resolve writes whose outcome was never recorded.
    ///
    /// A write announces itself before it starts and clears the note when both halves
    /// have returned. A note still there afterwards belongs to a write nobody waited for,
    /// and only the disk can say what became of it: the file store has the chunk, or the
    /// environment does and nothing else, or neither and there was never anything to
    /// protect.
    pub async fn reconcile_pending_writes(&self) {
        if !self.has_pending_writes() {
            return;
        }
        // Exclusively, and before the snapshot. Draining is not a barrier on its own:
        // writes hold this shared, and a new one for the same key could announce itself,
        // be cancelled, and leave its blocking half running while this decided the older
        // one's fate and removed the single entry they share. Held here, nothing new can
        // start, so what the disk says once the drain returns is final.
        //
        // Only reached when something is waiting, which after a clean run is never, so
        // this is not a stall on the ordinary path.
        let _settling = self.retirement.write().await;
        let Some(legacy) = self.legacy() else {
            return;
        };
        let waiting: Vec<XorName> = legacy.pending.read().keys().copied().collect();
        if waiting.is_empty() {
            return;
        }
        legacy.lmdb.wait_idle().await;
        self.files.wait_idle().await;
        for key in waiting {
            let _lane = self.key_lock(&key).await;
            if self.files.is_indexed(&key) {
                legacy.only.write().remove(&key);
                legacy.pending.write().remove(&key);
                continue;
            }
            match legacy.lmdb.get_raw(&key).await {
                Ok(Some(_)) => {
                    debug!(
                        "Chunk {} was written to the legacy environment by a call that \
                         never returned; recording it so the copier picks it up",
                        hex::encode(key)
                    );
                    legacy.only.write().insert(key);
                    legacy.pending.write().remove(&key);
                }
                // Nothing behind it: there was never anything to protect.
                Ok(None) => {
                    legacy.pending.write().remove(&key);
                }
                // NOT the same as nothing behind it. Dropping the note on a read that
                // failed would leave a committed write with no protection at all, which
                // is the case this journal exists for. Keep it and ask again next tick;
                // retirement stays vetoed meanwhile.
                Err(e) => warn!(
                    "Could not tell what became of the write for {}: {e}. Asking again on \
                     the next tick.",
                    hex::encode(key)
                ),
            }
        }
    }

    /// Are there writes in flight whose outcome nothing has recorded?
    #[must_use]
    pub fn has_pending_writes(&self) -> bool {
        self.legacy().is_some_and(|l| !l.pending.read().is_empty())
    }

    /// Is there anything at the legacy environment's path at all?
    ///
    /// Asked without a handle, and answered conservatively: a path this node cannot even
    /// look at counts as present. The migration is not finished while something is there,
    /// whether or not this node can currently read it.
    #[must_use]
    pub fn legacy_dir_is_on_disk(&self) -> bool {
        // `symlink_metadata`, not `try_exists`, which follows links. An operator's link to
        // storage that is not mounted right now reads as nothing at all through the
        // second, and the node would call its migration finished and go file-only, blind
        // to every chunk that lives only there until somebody restarts it.
        match std::fs::symlink_metadata(&self.legacy_env_dir) {
            Ok(_) => true,
            // Only "it is not there" means it is not there. A permission change or a
            // transient fault is an unanswered question, and answering it with "nothing
            // here" is how the driver declares the migration finished over a store it has
            // merely lost sight of.
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        }
    }

    /// Is the legacy environment a link this node must not delete?
    ///
    /// Copying out of it works; only the removal is refused. Callers use this to stop
    /// waiting for a retirement that is never going to happen.
    #[must_use]
    pub fn legacy_is_a_link(&self) -> bool {
        self.has_legacy() && is_a_link(&self.legacy_env_dir)
    }

    /// How many writes this node made without a rollback copy, cumulatively.
    ///
    /// Zero on a node that is not bridging, and zero on a bridging node whose environment
    /// has room. A number that is climbing says this node would lose those chunks on a
    /// rollback to a pre-migration build, which is a fleet question the second release
    /// turns on and which a per-chunk log line cannot answer.
    ///
    /// Attempts rather than distinct chunks, for the reason given on the field: it is a
    /// rate, not an inventory.
    #[must_use]
    pub fn writes_without_a_rollback_copy(&self) -> u64 {
        self.legacy().map_or(0, |l| {
            l.skipped_rollback_copies
                .load(std::sync::atomic::Ordering::Relaxed)
        })
    }

    /// Is there an environment on disk this node cannot classify at all?
    ///
    /// Neither removable nor openable, which is not a state waiting will clear: something
    /// about the path has to change first, and until it does the node will refuse to touch
    /// it in either direction. The driver treats this the way it treats a lost handle or a
    /// link, by standing down from the shared volume and saying so where an operator looks,
    /// because holding a disk exclusively to wait for a person is a disk nobody else can
    /// use.
    #[must_use]
    pub fn legacy_cannot_be_classified(&self) -> bool {
        retirement_mark(&self.legacy_env_dir) == RetirementMark::Unknown
    }

    /// Is there an environment on disk this node can no longer read?
    #[must_use]
    pub fn has_lost_its_legacy_handle(&self) -> bool {
        !self.has_legacy()
            && retirement_mark(&self.legacy_env_dir).permits_opening()
            // Conservative in the same direction as the retirement blocker, which reads the
            // same failure as "there is one". A question that cannot be answered is not an
            // answer of no, and answering no here left the node holding the shared volume
            // for the six-hour cap over work no amount of disk will finish.
            && legacy_present(&self.config.root_dir).unwrap_or(true)
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
    /// What the file store's health looked like when this pass finished.
    ///
    /// A clean report is reused for a while rather than re-read on every tick, and a lot
    /// can happen in that window: a kept file can start failing to read while ordinary
    /// requests are served from the legacy copy, and the node would then delete the
    /// legacy copy on the strength of a pass that no longer describes the store. This is
    /// how retirement tells, immediately before it deletes anything.
    health: u64,
}

impl VerifyReport {
    /// Whether this report clears the way for retirement.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.ran && self.unrepairable == 0
    }

    /// Does this report still describe the store?
    #[must_use]
    fn still_describes(&self, files: &FileStore) -> bool {
        self.health == files.health_generation()
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

/// Mark a retired environment directory as retired, from the inside, durably.
///
/// Called only after the directory has already been renamed aside, so it can never land
/// inside a live environment. See [`RETIRED_MARKER`] for why it goes inside.
///
/// # Errors
///
/// Returns [`Error::Storage`] if it cannot be created or flushed.
fn mark_directory_retired(dir: &Path) -> std::result::Result<(), MarkFailure> {
    match write_retirement_mark(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.pre_existing => {
            // Nothing here was created by this attempt, so there is nothing to take back.
            // Removing a mark that was already there because re-flushing it failed is how
            // a correctly retired directory comes to look unmarked, and an unmarked
            // directory is restored as a live environment.
            Err(MarkFailure {
                pre_existing: true,
                ..e
            })
        }
        Err(e) => {
            // A half-written mark is worse than none: the caller puts the directory back
            // under the live name and reopens it, and a mark left inside would have the
            // next cleanup pass reap a live, open environment. If it cannot be taken away,
            // say so, and the caller keeps the directory where nothing will open it.
            let path = dir.join(RETIRED_MARKER);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(gone) if gone.kind() == std::io::ErrorKind::NotFound => {}
                Err(stuck) => {
                    return Err(MarkFailure {
                        reason: format!(
                            "{e}. The partial mark at {} could not be removed either \
                             ({stuck})",
                            path.display()
                        ),
                        mark_definitely_gone: false,
                        pre_existing: false,
                    })
                }
            }
            if let Err(flush) = crate::storage::file_store::fsync_path(dir) {
                return Err(MarkFailure {
                    reason: format!(
                        "{e}. Removing the partial mark at {} could not be flushed \
                         ({flush})",
                        path.display()
                    ),
                    mark_definitely_gone: false,
                    pre_existing: false,
                });
            }
            Err(MarkFailure {
                reason: format!("{e}"),
                mark_definitely_gone: true,
                pre_existing: false,
            })
        }
    }
}

/// Why a directory could not be marked retired, and whether it is safe to reopen.
#[derive(Debug)]
struct MarkFailure {
    /// What went wrong, for the operator.
    reason: String,
    /// Is the directory provably free of a partial mark?
    ///
    /// Only then may the caller put it back under the live name. A mark left inside would
    /// have the next cleanup pass reap a live, open environment.
    mark_definitely_gone: bool,
    /// Was the mark already there before this attempt?
    ///
    /// Then this attempt created nothing and must take nothing away. Removing a mark that
    /// was already there because re-flushing it failed is how a correctly retired
    /// directory comes to look unmarked, and an unmarked directory is restored as a live
    /// environment.
    pre_existing: bool,
}

impl std::fmt::Display for MarkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// Create the mark. See [`mark_directory_retired`], which owns the failure handling.
fn write_retirement_mark(dir: &Path) -> std::result::Result<(), MarkFailure> {
    let path = dir.join(RETIRED_MARKER);
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(f) => f,
        // Already there, from an attempt that got this far and no further. Flushed
        // again rather than taken on trust: the attempt that wrote it may have been the
        // one that could not flush it.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Something is already at that name. That it could not be created is not the
            // same as its being a mark this node can read, and everything downstream
            // deletes an environment on the strength of it. The rest of this file insists
            // the name is not the evidence; this is the one place that was taking it.
            if retirement_mark(dir) != RetirementMark::Present {
                return Err(MarkFailure {
                    reason: format!(
                        "{} already exists but cannot be read as a retirement mark, so it \
                         is not one this node will delete on. Check what is at that path.",
                        path.display()
                    ),
                    mark_definitely_gone: false,
                    pre_existing: true,
                });
            }
            return crate::storage::file_store::fsync_path(dir).map_err(|flush| MarkFailure {
                reason: format!(
                    "{} is already there but could not be flushed: {flush}",
                    path.display()
                ),
                mark_definitely_gone: false,
                pre_existing: true,
            });
        }
        Err(e) => {
            return Err(MarkFailure {
                reason: format!("Could not mark {} as retired: {e}", path.display()),
                mark_definitely_gone: true,
                pre_existing: false,
            })
        }
    };
    // For whoever reads the directory. To the node, presence is the whole signal.
    if let Err(e) = file.write_all(
        b"This chunk environment was verified as fully copied into the file store and \n\
retired. It is being deleted; if it is still here, that was interrupted and the next \n\
node start finishes it. Nothing needs it.\n",
    ) {
        drop(file);
        return Err(MarkFailure {
            reason: format!("Could not write {}: {e}", path.display()),
            mark_definitely_gone: false,
            pre_existing: false,
        });
    }
    file.sync_all().map_err(|e| MarkFailure {
        reason: format!(
            "Could not flush {}: {e}. Not deleting on the strength of a mark that may not \
             survive a power loss.",
            path.display()
        ),
        mark_definitely_gone: false,
        pre_existing: false,
    })?;
    // And the directory that now contains it. Flushing the file makes its contents
    // durable; the entry naming it is in the directory, and on Unix that needs its own
    // flush. Without this the mark can be missing after a crash from a directory that
    // was in fact retired, which is the whole question this file answers.
    crate::storage::file_store::fsync_path(dir).map_err(|e| MarkFailure {
        reason: format!(
            "Marked {} retired but could not flush {}: {e}. Not deleting on the strength \
             of a mark that may not survive a power loss.",
            path.display(),
            dir.display()
        ),
        mark_definitely_gone: false,
        pre_existing: false,
    })
}

/// Delete a retired directory in the background, without anything waiting for it.
///
/// The caller is finished with it either way: the environment is closed, the directory is
/// under a name nothing looks for, and it carries its own mark, so an interrupted deletion
/// is finished by the next start. What matters is that neither shutdown nor startup ever
/// blocks on a recursive delete that can run for minutes.
fn delete_retired_directory(dir: PathBuf) {
    // One at a time per directory. The driver asks for cleanup on every tick while
    // anything is pending, and starting a fresh thread each time would leave hundreds of
    // them asleep on the same path, all retrying the same failure.
    if !REAPING.lock().insert(dir.clone()) {
        return;
    }
    let named = dir.clone();
    let started = std::thread::Builder::new()
        .name("chunk-store-retire".into())
        .spawn(move || {
            let _done = ReapingGuard(dir.clone());
            for attempt in 1..=RETIRED_DELETE_ATTEMPTS {
                match remove_marked_directory(&dir) {
                    Ok(()) => {
                        info!(
                            migration_event = "space_returned",
                            "Removed the retired chunk environment {} and returned its \
                             space",
                            dir.display()
                        );
                        return;
                    }
                    // Worth another go: on Windows a scanner or an antivirus can hold a
                    // handle inside it for a moment, and a partial delete leaves less to
                    // do next time.
                    Err(e) if attempt < RETIRED_DELETE_ATTEMPTS => {
                        debug!(
                            "Could not delete {} (attempt {attempt}): {e}. Trying again.",
                            dir.display()
                        );
                        std::thread::sleep(
                            (RETIRED_DELETE_BACKOFF * attempt).min(RETIRED_DELETE_BACKOFF_MAX),
                        );
                    }
                    Err(e) => warn!(
                        "The chunk environment has been retired but {} could not be \
                         deleted: {e}. Its space is not returned until it is, and the node \
                         needs nothing from it. The next start tries again.",
                        dir.display()
                    ),
                }
            }
        });
    if let Err(e) = started {
        REAPING.lock().remove(&named);
        warn!(
            "Could not start the thread to delete the retired chunk environment {}: {e}. \
             The next start sweeps it.",
            named.display()
        );
    }
}

/// Directories a reaper thread is already working on.
static REAPING: parking_lot::Mutex<BTreeSet<PathBuf>> = parking_lot::Mutex::new(BTreeSet::new());

/// Releases a directory from [`REAPING`] however its thread ends.
struct ReapingGuard(PathBuf);

impl Drop for ReapingGuard {
    fn drop(&mut self) {
        REAPING.lock().remove(&self.0);
    }
}

/// Delete a retired directory, taking its mark away last of all.
///
/// `remove_dir_all` walks in whatever order the filesystem hands back, so it can unlink
/// the mark and then fail on the next entry, which is exactly what a Windows sharing
/// violation on the data file produces. What is left is a genuinely retired, partly
/// deleted directory carrying no evidence that it was retired, and the next start would
/// read that as an intact environment and restore it.
///
/// Emptying it first and removing the mark last means the mark is only ever absent from a
/// directory that has nothing else left in it.
///
/// # Errors
///
/// Returns the underlying I/O error. The directory is left with its mark intact on every
/// failure that happens before the mark is reached.
fn remove_marked_directory(dir: &Path) -> std::io::Result<()> {
    // Never through a link. An operator who points the chunk environment at another
    // volume leaves a symlink here, and walking it would delete the contents of a
    // directory that is not this node's to delete. Retirement refuses such a root before
    // it gets this far; this is the second line, because the check and the walk are not
    // one operation.
    if std::fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(std::io::Error::other(format!(
            "{} is a link, not a directory. Refusing to delete through it.",
            dir.display()
        )));
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name() == RETIRED_MARKER {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    match std::fs::remove_file(dir.join(RETIRED_MARKER)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) => {
            // The mark is gone and the directory is not, which is the one state the whole
            // scheme says cannot happen: a start that found it would read an unmarked
            // directory as an intact environment. Put the mark back before giving up.
            if let Err(remark) = mark_directory_retired(dir) {
                error!(
                    "Could not remove {} ({e}) and could not restore its retirement mark \
                     ({remark}). It is empty and nothing needs it; delete it by hand.",
                    dir.display()
                );
            }
            Err(e)
        }
    }
}

/// What a directory's own contents say about whether it was retired.
///
/// Three answers, not two. Reading the mark can fail for reasons that are neither yes nor
/// no: a permission change, a descriptor limit, a filesystem that has gone away underneath
/// the node. Folding that into "no" is the failure mode the rest of this file exists to
/// avoid, and it fails in the worst direction: a retired environment that reads as unmarked
/// is put back under the live name and reopened, and its keys re-enter a commitment they
/// have already left.
///
/// So an unreadable answer is its own answer, and the two questions callers actually ask
/// are asked separately. Neither of them treats "cannot tell" as permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetirementMark {
    /// The directory carries its mark. It is the remains of a removal.
    Present,
    /// The directory carries no mark, and that is known rather than assumed.
    Absent,
    /// Whether it carries one could not be determined.
    Unknown,
}

impl RetirementMark {
    /// May this directory be deleted, or treated as already gone?
    ///
    /// Only a mark actually read says yes. Deleting on a guess destroys chunks.
    const fn permits_removal(self) -> bool {
        matches!(self, Self::Present)
    }

    /// May this directory be opened and served from?
    ///
    /// Only a mark known to be absent says yes. Opening a retired environment puts keys
    /// back into a commitment they have already left.
    const fn permits_opening(self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// Has this directory been retired?
///
/// A link is never treated as retired, whatever it points at: the mark would have been
/// written through it into somebody else's directory, and acting on it would delete
/// somebody else's data. A path whose kind cannot be determined is not a link either way,
/// and is reported as unknown rather than as a link, so that neither question gets a yes.
fn retirement_mark(dir: &Path) -> RetirementMark {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => return RetirementMark::Absent,
        Ok(_) => {}
        // Nothing here at all, which is the ordinary case on a node that has already
        // finished or never had a legacy store. There is no mark because there is nothing
        // to carry one, and that is known rather than undetermined.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RetirementMark::Absent,
        Err(e) => {
            // Debug, not warn: this is asked on every tick, so a warn here would be a
            // wall of the same line. The operator-facing version is the retirement
            // blocker, which says what it means for the node.
            debug!(
                "Could not tell what {} is ({e}); treating it as neither removable nor \
                 openable until it can be read",
                dir.display()
            );
            return RetirementMark::Unknown;
        }
    }
    match dir.join(RETIRED_MARKER).try_exists() {
        Ok(true) => RetirementMark::Present,
        Ok(false) => RetirementMark::Absent,
        Err(e) => {
            debug!(
                "Could not read the retirement mark in {} ({e}); treating it as neither \
                 removable nor openable until it can be read",
                dir.display()
            );
            RetirementMark::Unknown
        }
    }
}

/// Is this path a symbolic link, or something whose kind cannot be determined?
///
/// Unknown counts as yes. Every caller is deciding whether it is safe to delete through
/// the path, and a question that cannot be answered is not a yes to that.
fn is_a_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).map_or(true, |m| m.file_type().is_symlink())
}

/// Finish a removal a previous run did not, before anything tries to open the environment.
///
/// The only thing that counts as evidence is the directory's own mark. An open that fails
/// is not: `open_legacy` queries free space, maps the file, takes a write transaction and
/// scans every key, so a full disk, a permission change, a mapping limit or a transient
/// I/O fault all look identical to corruption, and deleting on any of those would destroy
/// a perfectly good environment.
fn finish_interrupted_retirement(root_dir: &Path) -> LiveEnvironment {
    let env = root_dir.join(LEGACY_ENV_DIR);
    // Three answers, three branches. Asking only whether it may be removed and letting
    // everything else fall through would put "cannot tell" back on the opening path, which
    // is the whole failure this is three states to avoid: the mark check can fail for a
    // moment and succeed the next, and the open in between would resurrect a store that
    // really had been retired.
    //
    // Asked of the mark alone, with no separate "is it there" first. A `try_exists` that
    // could not answer would have folded straight back into "nothing here" and skipped both
    // branches below, which is the same fold one level up. The mark already tells the three
    // apart: a path that is not there carries no mark and says so, and a path that cannot be
    // reached at all says it cannot be reached.
    // Asked once. Asking twice is asking two different questions: the answer can change
    // between them, and a second answer of "cannot tell" after a first of "retired" fell
    // through to opening the very directory the first answer said not to open.
    let mark = retirement_mark(&env);
    if mark == RetirementMark::Unknown {
        error!(
            "{} is under the live name and this node cannot tell whether it was retired. \
             It will NOT be opened and it will NOT be removed. The node serves from files \
             alone. Check that the directory and anything inside it can be read.",
            env.display()
        );
        return LiveEnvironment::None;
    }
    if mark.permits_removal() {
        // Its own contents say it was retired, so whatever name it is wearing now, it is
        // the remains of a removal that a power loss undid the rename of.
        warn!(
            "{} carries its own retirement mark, so it is what an interrupted removal left \
             behind rather than a live environment. Finishing that removal.",
            env.display()
        );
        // Renamed rather than deleted here, so the node can get on with starting: the
        // deletion itself is detached below and can take minutes on a large store. Under a
        // name nothing else is using, so a tombstone whose deletion is still running does
        // not force a synchronous delete first.
        let tombstone = free_tombstone_path(root_dir);
        if let Err(e) = std::fs::rename(&env, &tombstone) {
            error!(
                "{} carries its own retirement mark but could not be moved aside: {e}. It \
                 will NOT be opened: it says it has been retired, so it may be partly \
                 deleted, and its chunks are in the file store. The node serves from files \
                 alone and the next start tries again.",
                env.display()
            );
            sweep_retired_legacy(root_dir);
            return LiveEnvironment::None;
        }
    }
    sweep_retired_legacy(root_dir);
    LiveEnvironment::WhateverIsOnDisk
}

/// Whether the ordinary open may look at what is under the live environment name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveEnvironment {
    /// Nothing is claiming it should not be opened.
    WhateverIsOnDisk,
    /// A directory under the live name says it has been retired, and could not be moved
    /// out of the way. It must not be opened: a retired directory may be partly deleted,
    /// and opening it would put its keys back into a commitment they have left.
    None,
}

fn sweep_retired_legacy(root_dir: &Path) {
    let tombstones = retired_tombstones(root_dir);
    if tombstones.is_empty() {
        return;
    }
    // Flushed first, and only best effort is not good enough here for the same reason it
    // was not good enough when the rename was made: deleting the contents of a directory
    // whose new name may not have reached the disk is what turns a power loss into a
    // resurrected, half-empty environment. If it cannot be flushed, leave them for a later
    // start. It costs disk, not data.
    if let Err(e) = crate::storage::file_store::fsync_path(root_dir) {
        warn!(
            "Leaving {} retired chunk environment(s) in place: {} could not be flushed \
             ({e}), so the rename that put them there may not be on disk yet.",
            tombstones.len(),
            root_dir.display()
        );
        return;
    }
    for tombstone in tombstones {
        // The name is not the evidence. Only the directory's own mark is: a crash between
        // the rename and the mark leaves an intact environment sitting under the retired
        // name, and deleting that because of what it is called would destroy every chunk
        // in it.
        let mark = retirement_mark(&tombstone);
        if mark == RetirementMark::Unknown {
            // Neither restored nor deleted. Restoring would put a directory that may be
            // half-deleted back under the live name for the next start to open, and
            // deleting would destroy an intact one. It costs disk until somebody looks,
            // which is the right price for not knowing.
            warn!(
                "{} cannot be classified: this node cannot tell whether it carries a \
                 retirement mark, so it will be neither restored nor deleted. Check that \
                 the directory and anything inside it can be read.",
                tombstone.display()
            );
            continue;
        }
        if mark.permits_removal() {
            // The mark is re-established before anything is deleted on the strength of
            // it. A retirement that failed part-way can leave one that was never flushed,
            // and this is the pass that would otherwise act on it thirty seconds after
            // the failure that said it would be left alone.
            if let Err(e) = mark_directory_retired(&tombstone) {
                warn!(
                    "{} says it was retired but that could not be confirmed ({e}). \
                     Leaving it.",
                    tombstone.display()
                );
                continue;
            }
            // Detached, so a node starting beside a large leftover directory serves
            // immediately rather than waiting out a recursive delete before it opens its
            // store.
            delete_retired_directory(tombstone);
            continue;
        }
        restore_unmarked_environment(root_dir, &tombstone);
    }
}

/// Put an intact environment back under its own name.
///
/// An environment under the retired name with no mark inside it was renamed and then
/// interrupted before it could be marked. Nothing was deleted, so it is whole, and the
/// answer is to give it its name back and let the migration run again from the beginning:
/// every gate is re-derived, and a second retirement costs a pass, not data.
fn restore_unmarked_environment(root_dir: &Path, tombstone: &Path) {
    // An empty one is what a deletion that removed the contents and the mark and then
    // could not remove the directory leaves. There is nothing in it to restore, and
    // putting it back under the live name would strand an empty path the node then tries
    // to open.
    if std::fs::read_dir(tombstone).is_ok_and(|mut entries| entries.next().is_none()) {
        if let Err(e) = std::fs::remove_dir(tombstone) {
            warn!("Could not remove the empty {}: {e}", tombstone.display());
        }
        return;
    }
    let env = root_dir.join(LEGACY_ENV_DIR);
    if env.try_exists().unwrap_or(true) {
        // Both names are taken, so which one the node should serve is not this code's
        // decision to make.
        error!(
            "{} and {} both exist, and {} carries no retirement mark, so it may hold \
             chunks. Neither has been touched. Move or remove one by hand: the node is \
             using {}.",
            env.display(),
            tombstone.display(),
            tombstone.display(),
            env.display()
        );
        return;
    }
    match std::fs::rename(tombstone, &env) {
        Ok(()) => {
            let _ = crate::storage::file_store::fsync_path(root_dir);
            warn!(
                "{} was moved aside for retirement but never marked retired, so it is \
                 intact. It has been restored to {} and the migration starts again.",
                tombstone.display(),
                env.display()
            );
        }
        Err(e) => error!(
            "{} carries no retirement mark, so it may hold chunks, but it could not be \
             restored to {}: {e}. It has not been deleted.",
            tombstone.display(),
            env.display()
        ),
    }
}

/// Every retired environment directory under `root_dir`.
///
/// More than one can be there: a node that retires, is restarted before the deletion
/// finishes, and somehow acquires another environment would leave the first behind. Each
/// is named so it cannot collide with the next.
fn retired_tombstones(root_dir: &Path) -> Vec<PathBuf> {
    let prefix = format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}");
    let entries = match std::fs::read_dir(root_dir) {
        Ok(entries) => entries,
        Err(e) => {
            // Cannot tell. Not the same as nothing here, and the caller uses this to
            // decide whether cleanup is finished, so answer with the one that keeps it
            // looking rather than the one that declares victory.
            warn!(
                "Could not list {} to look for retired chunk environments: {e}",
                root_dir.display()
            );
            return vec![root_dir.join(&prefix)];
        }
    };
    let mut found = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(&prefix))
                {
                    found.push(entry.path());
                }
            }
            // One unreadable entry is not evidence there is nothing here, and the caller
            // uses this to decide whether cleanup is finished. Answer with the one that
            // keeps it looking.
            Err(e) => {
                warn!(
                    "Could not read an entry of {} while looking for retired chunk \
                     environments: {e}",
                    root_dir.display()
                );
                found.push(root_dir.join(&prefix));
            }
        }
    }
    found
}

/// A directory name to retire the environment under that nothing else is using.
///
/// A fixed name would collide with a tombstone whose deletion is still running, and
/// clearing that one first would put a synchronous recursive delete back on the path this
/// is trying to keep clear.
fn free_tombstone_path(root_dir: &Path) -> PathBuf {
    let base = root_dir.join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"));
    if !base.try_exists().unwrap_or(true) {
        return base;
    }
    for n in 1..=MAX_TOMBSTONES {
        let candidate = root_dir.join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}.{n}"));
        if !candidate.try_exists().unwrap_or(true) {
            return candidate;
        }
    }
    // Every name taken, which means many retirements have been interrupted without their
    // deletions finishing. Reuse the base: the rename fails, retirement defers, and the
    // operator sees a directory full of them.
    base
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

    /// The legacy environment takes no new disk during the bridge.
    ///
    /// Both stores sit on one disk, each measures the same free space, and neither knows
    /// what the other is about to spend. A chunk written to both could be admitted twice
    /// against one lot of headroom, and enough of them could cross the reserve together
    /// and fill the volume this migration exists to free.
    ///
    /// So the environment is pinned to what it already occupies. It still takes the
    /// rollback copy when it has room of its own, which on a real node it usually does:
    /// this migration exists because deleting millions of chunks left the free list full
    /// and returned nothing to the filesystem. What it will not do is grow.
    #[tokio::test]
    async fn the_legacy_environment_takes_no_new_disk_during_the_bridge() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["seed"]).await;
        let store = open(&dir).await;

        let data_file = dir.path().join(LEGACY_ENV_DIR).join(LEGACY_DATA_FILE);
        let before = std::fs::metadata(&data_file).expect("meta").len();

        for seed in ["dual-1", "dual-2", "dual-3", "dual-4"] {
            let (addr, content) = addressed(seed);
            assert!(store.put(&addr, &content).await.expect("put"));
            assert!(
                store.exists(&addr).expect("exists"),
                "the file store is the one that has to have it"
            );
        }
        store.wait_idle().await;

        let after = std::fs::metadata(&data_file).expect("meta").len();
        assert_eq!(
            after, before,
            "the environment must not claim disk the file store is also counting on"
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

    /// An environment is never deleted because it failed to open.
    ///
    /// Opening is not a corruption test. It queries free space, maps the file, takes a
    /// write transaction and scans every key, so a full disk, a permission change or a
    /// transient fault all look identical to corruption. The only thing that counts is the
    /// directory's own mark.
    #[tokio::test]
    async fn an_unmarked_environment_is_kept_however_badly_it_reads() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["unmarked"]).await;
        let env = dir.path().join(LEGACY_ENV_DIR);
        assert_eq!(retirement_mark(&env), RetirementMark::Absent);

        finish_interrupted_retirement(dir.path());
        assert!(
            env.exists(),
            "an environment carrying no retirement mark must never be removed"
        );
    }

    /// A directory carrying its own retirement mark is finished off, whatever it is named.
    ///
    /// This is the case the mark exists for. Off Unix the rename that moves the
    /// environment aside cannot be shown to be durable, so a power loss can bring it back
    /// under its old name with its contents already deleted. Without the mark the node
    /// would refuse to start on it forever; with it, the directory says what it is.
    #[tokio::test]
    async fn a_directory_that_says_it_was_retired_is_removed_under_any_name() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["reverted"]).await;
        {
            let store = open(&dir).await;
            store
                .copy_batch(&keys, 0, 0, &never_cancelled())
                .await
                .expect("copy");
        }
        // What a reverted rename leaves: the old name, the retirement mark inside it.
        let env = dir.path().join(LEGACY_ENV_DIR);
        mark_directory_retired(&env).expect("mark");

        let store = open(&dir).await;
        assert!(
            !store.has_legacy(),
            "the remains of an interrupted removal must not be adopted"
        );
        assert!(!env.exists(), "and the next start must finish the removal");
        // Every chunk is still served, from the file store.
        for key in &keys {
            assert!(store.get(key).await.expect("get").is_some());
        }
    }

    /// The mark goes inside the directory, so a rename cannot separate them.
    ///
    /// A mark beside the environment would have to be cancelled when a retirement is
    /// abandoned, cancellation can fail or be lost, and a stale one would then authorise
    /// deleting an environment that had since taken a chunk.
    #[test]
    fn the_retirement_mark_travels_with_the_directory() {
        let dir = TempDir::new().expect("temp dir");
        let original = dir.path().join("chunks.mdb");
        std::fs::create_dir_all(&original).expect("mkdir");
        mark_directory_retired(&original).expect("mark");
        assert_eq!(retirement_mark(&original), RetirementMark::Present);

        let renamed = dir.path().join("chunks.mdb.retired");
        std::fs::rename(&original, &renamed).expect("rename");
        assert!(
            retirement_mark(&renamed) == RetirementMark::Present,
            "the mark must survive the rename it exists to outlive"
        );
        // And back again, which is what a power loss undoing the rename looks like.
        std::fs::rename(&renamed, &original).expect("rename back");
        assert_eq!(retirement_mark(&original), RetirementMark::Present);
    }

    /// Losing the handle to an environment that is still there is not completion.
    ///
    /// A rename that failed and then could not be reopened leaves the directory on disk
    /// with no way to read it. Treating the missing handle as "nothing left to migrate"
    /// would have the driver log the migration finished over a store still holding chunks
    /// nothing else can serve.
    #[tokio::test]
    async fn a_lost_handle_beside_a_live_environment_blocks_retirement() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["orphaned"]).await;
        let store = open(&dir).await;
        assert!(store.has_legacy());

        // Stand in for a failed rename followed by a failed reopen.
        *store.legacy.write() = None;
        assert!(!store.has_legacy());
        assert!(dir.path().join(LEGACY_ENV_DIR).exists());

        let blocker = store
            .retirement_blocker(|_| false)
            .expect("a live environment with no handle must block");
        assert!(
            blocker.contains("no handle"),
            "the reason must name the actual problem, got: {blocker}"
        );
    }

    /// A node that still holds its store open is gated too.
    ///
    /// The classification used to be asked only when there was no handle, which meant the
    /// ordinary path never asked it: a node holding its environment open went through every
    /// gate, renamed the directory aside and deleted it, whatever the mark said or failed to
    /// say. Retirement deletes the last other copy of these chunks, so it is not a question
    /// to skip because a different question already had an answer.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_environment_that_cannot_be_classified_blocks_retirement_even_with_a_handle() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["still-open"]).await;
        let store = open(&dir).await;
        assert!(
            store.has_legacy(),
            "this one keeps its handle, deliberately"
        );
        // Whatever else is in the way at this point, it is not this. Compared rather than
        // required to be nothing, because the other gates have their own tests and their
        // own reasons to be unmet here.
        let before = store.retirement_blocker(|_| false).unwrap_or_default();
        assert!(
            !before.contains("already retired"),
            "a readable environment must not be blocked for being unclassifiable: {before}"
        );

        make_the_mark_unreadable(&dir.path().join(LEGACY_ENV_DIR));

        let blocker = store
            .retirement_blocker(|_| false)
            .expect("an environment that cannot be classified must block retirement");
        assert!(
            blocker.contains("already retired"),
            "the reason must name the actual problem, got: {blocker}"
        );
        assert!(
            store.legacy_cannot_be_classified(),
            "and the driver must see it as work only a person can finish, so that it \
             gives the shared volume back"
        );
    }

    /// A directory under the retired name with no mark inside it is an intact store.
    ///
    /// It got that name from a rename, and the rename happens after every gate; the mark
    /// is written straight afterwards. A crash in between leaves a whole environment
    /// wearing a name that says otherwise, and deleting it because of what it is called
    /// would destroy every chunk in it. It is put back instead.
    #[tokio::test]
    async fn an_unmarked_retired_directory_is_restored_rather_than_deleted() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["not-really-retired"]).await;
        let env = dir.path().join(LEGACY_ENV_DIR);
        let tombstone = dir.path().join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"));
        std::fs::rename(&env, &tombstone).expect("rename");
        assert_eq!(retirement_mark(&tombstone), RetirementMark::Absent);

        let store = open(&dir).await;
        assert!(
            store.has_legacy(),
            "an unmarked environment must be restored and served, not deleted"
        );
        assert!(env.exists(), "it must be back under its own name");
        for key in &keys {
            assert!(store.get(key).await.expect("get").is_some());
        }
    }

    /// A mark already at that name is not a mark until it can be read.
    ///
    /// The one place in this file that was taking the name as the evidence, which is the
    /// thing every other part of it refuses to do. Retirement writes the mark with
    /// `create_new`, and a failure saying something is already there was accepted as "the
    /// mark is present" and the environment deleted on the strength of it. What is at that
    /// name might be anything.
    ///
    /// It matters most for a node that already has its store open. That path never
    /// consulted the mark at all until this round, so an unreadable one would have gone
    /// through every gate and been deleted.
    #[cfg(unix)]
    #[test]
    fn a_mark_already_at_that_name_is_not_accepted_until_it_can_be_read() {
        let dir = TempDir::new().expect("temp dir");
        let env = dir.path().join(LEGACY_ENV_DIR);
        std::fs::create_dir_all(&env).expect("mkdir");
        make_the_mark_unreadable(&env);

        let refused = mark_directory_retired(&env).expect_err("an unreadable mark is not a mark");
        assert!(
            !refused.mark_definitely_gone,
            "something is at that name, so the caller must not treat it as absent and put \
             the directory back under a name that will be opened"
        );
        assert_eq!(retirement_mark(&env), RetirementMark::Unknown);

        // And a real one is still accepted, so the refusal above is about being unable to
        // read it rather than about there being something there at all.
        std::fs::remove_file(env.join(RETIRED_MARKER)).expect("clear the link");
        mark_directory_retired(&env).expect("a first mark");
        mark_directory_retired(&env).expect("and the same mark again, which is readable");
        assert_eq!(retirement_mark(&env), RetirementMark::Present);
    }

    /// A directory nothing can classify is neither restored nor deleted.
    ///
    /// The half of the three-state answer that a first attempt at this got wrong. Asking
    /// only "may it be removed" and letting everything else fall through puts "cannot tell"
    /// straight back on the restoring path, which is the resurrection this exists to
    /// prevent: the mark check can fail for a moment and succeed the next, and the restore
    /// in between brings back a store that really had been retired.
    ///
    /// Unix only: the state is staged with a symbolic link, which Windows does not offer
    /// on the same terms.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_tombstone_that_cannot_be_classified_is_left_where_it_is() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["unclassifiable"]).await;
        let env = dir.path().join(LEGACY_ENV_DIR);
        let tombstone = dir.path().join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"));
        std::fs::rename(&env, &tombstone).expect("rename");
        make_the_mark_unreadable(&tombstone);
        assert_eq!(retirement_mark(&tombstone), RetirementMark::Unknown);

        sweep_retired_legacy(dir.path());
        let still_there = tombstone.exists();
        let restored = env.exists();

        assert!(
            still_there,
            "a directory that cannot be classified must not be deleted: it may be intact"
        );
        assert!(
            !restored,
            "a directory that cannot be classified must not be put back under the live \
             name: it may be half deleted"
        );
    }

    /// The same directory under the live name is not opened either.
    ///
    /// Opening it would put keys back into a commitment they may already have left, and
    /// this node cannot tell whether they have. Serving from files alone is the answer that
    /// is right either way.
    #[cfg(unix)]
    #[test]
    fn a_live_environment_that_cannot_be_classified_is_not_opened() {
        let dir = TempDir::new().expect("temp dir");
        let env = dir.path().join(LEGACY_ENV_DIR);
        std::fs::create_dir_all(&env).expect("mkdir");
        std::fs::write(env.join("data.mdb"), b"not really an environment").expect("seed");
        assert_eq!(
            finish_interrupted_retirement(dir.path()),
            LiveEnvironment::WhateverIsOnDisk,
            "a readable directory with no mark is ordinary and may be opened"
        );

        make_the_mark_unreadable(&env);
        assert_eq!(retirement_mark(&env), RetirementMark::Unknown);

        let verdict = finish_interrupted_retirement(dir.path());
        let still_there = env.exists();

        assert_eq!(
            verdict,
            LiveEnvironment::None,
            "a directory that cannot be classified must not be opened"
        );
        assert!(
            still_there,
            "and it must not be deleted either: it may be a live environment"
        );
    }

    /// Make the retirement mark in `dir` unreadable without touching the directory itself.
    ///
    /// A symbolic link pointing at itself. Looking for the mark follows it, gets
    /// `FilesystemLoop` back, and the answer is neither "there" nor "not there", which is
    /// the state under test.
    ///
    /// Taking the directory's permissions away instead was the first attempt and staged too
    /// much: at mode 000 the operating system refuses the rename as well, so the code being
    /// tested was never reached and the test passed with its own protection removed. Root
    /// can also read a mode-000 directory, which would have made it fail on any CI that
    /// runs as root. A link loop is neither: everything else about the directory keeps
    /// working, for every user.
    #[cfg(unix)]
    fn make_the_mark_unreadable(dir: &Path) {
        let link = dir.join(RETIRED_MARKER);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&link, &link).expect("a link to itself");
    }

    /// Both names taken is not a decision this code makes.
    #[tokio::test]
    async fn an_unmarked_retired_directory_beside_a_live_one_is_left_alone() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["live"]).await;
        let tombstone = dir.path().join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"));
        std::fs::create_dir_all(&tombstone).expect("mkdir");
        std::fs::write(tombstone.join("data.mdb"), b"something").expect("write");

        let store = open(&dir).await;
        assert!(store.has_legacy());
        assert!(
            tombstone.exists(),
            "an unmarked directory must never be deleted, even beside a live one"
        );
        assert!(dir.path().join(LEGACY_ENV_DIR).exists());
    }

    /// The mark is the last thing a deletion takes away.
    ///
    /// A recursive delete walks in whatever order the filesystem gives, so it can unlink
    /// the mark and then fail on the next entry, which is what a sharing violation on the
    /// data file looks like. That leaves a genuinely retired, partly deleted directory
    /// carrying no evidence of it, and the next start would read that as intact and
    /// restore it.
    /// Unix only: the failure is provoked with directory permissions, which is not how
    /// the same thing happens on Windows. The behaviour under test is platform-neutral.
    #[cfg(unix)]
    #[test]
    fn a_failed_deletion_leaves_the_mark_in_place() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir");
        let retired = dir.path().join("chunks.mdb.retired");
        std::fs::create_dir_all(&retired).expect("mkdir");
        std::fs::write(retired.join(LEGACY_DATA_FILE), b"payload").expect("write");
        mark_directory_retired(&retired).expect("mark");

        // An entry that cannot be removed, standing in for whatever the filesystem
        // refuses on the day.
        std::fs::create_dir_all(retired.join("stuck")).expect("mkdir");
        let mut perms = std::fs::metadata(&retired).expect("meta").permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&retired, perms.clone()).expect("chmod");

        let failed = remove_marked_directory(&retired).is_err();

        perms.set_mode(0o700);
        std::fs::set_permissions(&retired, perms).expect("chmod back");

        assert!(failed, "the deletion was supposed to fail");
        assert!(
            retirement_mark(&retired) == RetirementMark::Present,
            "a deletion that failed must leave the mark, or the directory stops saying \
             what it is"
        );
    }

    /// A mark that cannot be read is not permission to do anything.
    ///
    /// The reason this is three states and not two. Reading the mark can fail for reasons
    /// that are neither yes nor no, and the old answer for those was "no mark", which is
    /// the worst of the three: a retired environment reads as live, goes back under its own
    /// name, and its keys re-enter a commitment they have already left. Deleting on an
    /// unreadable answer would be just as wrong in the other direction.
    ///
    /// Unix only: the state is staged with a symbolic link, which Windows does not offer
    /// on the same terms.
    #[cfg(unix)]
    #[test]
    fn a_mark_that_cannot_be_read_permits_nothing() {
        let dir = TempDir::new().expect("temp dir");
        let env = dir.path().join(LEGACY_ENV_DIR);

        // Nothing there is not the same as cannot tell, and it is the ordinary case: every
        // node that never had a legacy store, and every node that has finished with one,
        // asks this question on every tick. Answering "cannot tell" for those would have a
        // fresh node run a migration driver forever over a store it does not have.
        assert_eq!(
            retirement_mark(&env),
            RetirementMark::Absent,
            "a directory that is not there carries no mark, and that is known"
        );
        assert!(retirement_mark(&env).permits_opening());

        std::fs::create_dir_all(&env).expect("mkdir");
        std::fs::write(env.join(RETIRED_MARKER), b"retired").expect("mark");
        assert_eq!(retirement_mark(&env), RetirementMark::Present);

        // Looking for the mark now goes round in a circle, so the answer is neither there
        // nor not there.
        make_the_mark_unreadable(&env);
        let unreadable = retirement_mark(&env);

        assert_eq!(
            unreadable,
            RetirementMark::Unknown,
            "a mark that cannot be read must not report as absent"
        );
        assert!(
            !unreadable.permits_removal(),
            "an unreadable mark must not authorise deleting the environment"
        );
        assert!(
            !unreadable.permits_opening(),
            "an unreadable mark must not authorise reopening the environment"
        );
    }

    /// A directory under the live name that says it was retired is never opened.
    ///
    /// It may be partly deleted, and opening it would put keys back into a commitment
    /// they have already left. Its chunks are in the file store, which is what the mark
    /// records, so serving from files alone is correct.
    #[tokio::test]
    async fn a_marked_directory_under_the_live_name_is_not_served_from() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["marked-live"]).await;
        {
            let store = open(&dir).await;
            store
                .copy_batch(&keys, 0, 0, &never_cancelled())
                .await
                .expect("copy");
        }
        let env = dir.path().join(LEGACY_ENV_DIR);
        mark_directory_retired(&env).expect("mark");

        // Every name it could be moved to is taken by something that is not empty, so the
        // rename fails and the marked directory stays under the live name. That is the
        // case this is about: it must be left alone rather than opened.
        for n in 0..=MAX_TOMBSTONES {
            let taken = if n == 0 {
                dir.path().join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}"))
            } else {
                dir.path()
                    .join(format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}.{n}"))
            };
            std::fs::create_dir_all(&taken).expect("mkdir");
            std::fs::write(taken.join("occupied"), b"x").expect("write");
        }

        let store = open(&dir).await;
        assert!(
            env.exists(),
            "the rename was supposed to fail, leaving the marked directory in place"
        );
        assert!(
            !store.has_legacy(),
            "a directory that says it was retired must never be opened as live"
        );
        for key in &keys {
            assert!(store.get(key).await.expect("get").is_some());
        }
    }

    /// A linked environment is copied out of but never deleted.
    ///
    /// An operator who points the chunk store at another volume leaves a link here.
    /// Retirement renames the path and then deletes what is behind it, and behind a link
    /// is a directory somewhere else that this node does not own.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_environment_is_never_retired() {
        let outside = TempDir::new().expect("temp dir");
        let dir = TempDir::new().expect("temp dir");
        // A real environment that lives in `outside`; the node root only links to it.
        seed_legacy(&outside, &["someone-elses"]).await;
        let real = outside.path().join(LEGACY_ENV_DIR);
        let bystander = outside.path().join("unrelated");
        std::fs::create_dir_all(&bystander).expect("mkdir");
        std::os::unix::fs::symlink(&real, dir.path().join(LEGACY_ENV_DIR)).expect("symlink");

        let store = open(&dir).await;
        let blocker = store
            .retirement_blocker(|_| false)
            .expect("a linked environment must block retirement");
        assert!(
            blocker.contains("link"),
            "the reason must name the actual problem, got: {blocker}"
        );

        // And nothing walks through it, whatever it is marked with.
        std::fs::write(real.join(RETIRED_MARKER), b"x").expect("mark through the link");
        assert!(
            retirement_mark(&dir.path().join(LEGACY_ENV_DIR)) != RetirementMark::Present,
            "a link must never be treated as a retired directory"
        );
        assert!(
            remove_marked_directory(&dir.path().join(LEGACY_ENV_DIR)).is_err(),
            "deleting through a link must be refused"
        );
        assert!(
            real.join(LEGACY_DATA_FILE).exists(),
            "and must delete nothing"
        );
        assert!(bystander.exists());
    }

    /// A deletion that cannot remove the directory itself puts the mark back.
    ///
    /// An unmarked directory that still exists is the one state the scheme says cannot
    /// happen: the next start would read it as an intact environment.
    ///
    /// Unix only: the failure is provoked with directory permissions, which is not how
    /// the same thing happens on Windows. The behaviour under test is platform-neutral.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_removed_keeps_saying_it_was_retired() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir");
        let retired = dir.path().join("chunks.mdb.retired");
        std::fs::create_dir_all(&retired).expect("mkdir");
        std::fs::write(retired.join(LEGACY_DATA_FILE), b"payload").expect("write");
        mark_directory_retired(&retired).expect("mark");

        // The parent read-only, so the directory cannot be unlinked from it while its own
        // contents still can be. That is the shape that leaves an emptied, unmarked
        // directory behind.
        let mut perms = std::fs::metadata(dir.path()).expect("meta").permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(dir.path(), perms).expect("chmod");

        let failed = remove_marked_directory(&retired).is_err();

        let mut perms = std::fs::metadata(dir.path()).expect("meta").permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir.path(), perms).expect("chmod back");

        assert!(failed, "the removal was supposed to fail");
        assert!(retired.exists(), "and to leave the directory behind");
        assert!(
            retirement_mark(&retired) == RetirementMark::Present,
            "a directory that outlived its deletion must still say what it is"
        );
    }

    /// A key the environment holds that is in neither view stops retirement.
    ///
    /// The gates only ever see the legacy-only set, so a key that has fallen out of both
    /// the file index and that set has been through nothing and is protected by nothing.
    /// It is the environment's only copy, and retirement would take it.
    #[tokio::test]
    async fn a_legacy_key_in_neither_view_refuses_the_proof_and_is_re_queued() {
        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["orphan"]).await;
        let key = *keys.first().expect("one key");
        let store = open(&dir).await;
        store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        assert!(!store.legacy_only_keys().contains(&key));

        // Stand in for whatever takes the file out from under the index: a quarantine, a
        // publish that failed, an operator. The key is now in neither view.
        let path = dir
            .path()
            .join("chunks")
            .join(format!("{:02x}", key.last().copied().unwrap_or(0)))
            .join(hex::encode(key));
        std::fs::remove_file(&path).expect("remove the file");
        store.files.forget_for_test(&key);
        assert!(!store.files.exists(&key).unwrap_or(false));
        assert!(!store.legacy_only_keys().contains(&key));

        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");
        assert!(
            !proof.is_clean(),
            "a key protected by neither view must refuse the proof"
        );
        assert!(
            store.legacy_only_keys().contains(&key),
            "and must be put back where the gates can see it"
        );
    }

    /// A verification that no longer describes the store does not authorise a deletion.
    ///
    /// The pass reads every chunk and its result is reused for a while rather than re-read
    /// on every tick. Retirement is often deferred in that window by a gate that has
    /// nothing to do with the files. If a kept chunk stops being readable meanwhile,
    /// ordinary requests are still served from the legacy copy, and deleting that copy on
    /// the strength of the older pass leaves the node holding only the unreadable one.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_verification_overtaken_by_a_failing_file_does_not_authorise_retirement() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("temp dir");
        let keys = seed_legacy(&dir, &["kept-then-unreadable"]).await;
        let key = *keys.first().expect("one key");
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

        // The window: the file stops being readable after the pass and before the
        // deletion it authorised.
        let path = dir
            .path()
            .join("chunks")
            .join(format!("{:02x}", key.last().copied().unwrap_or(0)))
            .join(hex::encode(key));
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&path, perms).expect("chmod");
        assert!(
            store.get(&key).await.is_ok(),
            "the legacy copy still serves it, which is what hides the problem"
        );

        let err = store
            .retire_legacy(&proof, &|_: &XorName| false, &approved_shed(&store))
            .await
            .expect_err("a verification the store has outrun must not authorise a delete");
        assert!(format!("{err}").contains("no longer describes"), "{err}");
        assert!(
            store.has_legacy(),
            "and the legacy environment must survive"
        );

        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).expect("chmod back");
    }

    /// A write with no rollback copy is counted, on the path that actually skips.
    ///
    /// The environment is pinned to its current size for the whole bridge, so one with no
    /// reusable page answers `Full` to every write and the node stores in files alone. That
    /// is accepted, and the ADR says so. What was missing was any way to ask how often it
    /// happens: the second release turns on knowing how many nodes are really keeping a
    /// rollback copy, and a log line per chunk does not answer it.
    ///
    /// The first version of this counter missed exactly this path and counted only the
    /// other one, the write that is attempted and refused. On the node most affected the
    /// other path never runs, so the counter stayed at zero on precisely the nodes it was
    /// added for.
    #[tokio::test]
    async fn a_write_with_no_rollback_copy_is_counted() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["settled"]).await;
        let store = open(&dir).await;
        assert_eq!(
            store.writes_without_a_rollback_copy(),
            0,
            "nothing has been skipped yet"
        );

        let legacy = store.legacy().expect("legacy");
        let before = legacy
            .skipped_rollback_copies
            .load(std::sync::atomic::Ordering::Relaxed);

        // Whichever way the environment refuses, the count moves. Driven through the
        // counter itself rather than by filling a real environment, because what is under
        // test is that the skip is recorded, and staging a genuinely unwritable LMDB from
        // here would be testing LMDB.
        for _ in 0..12 {
            let _ = legacy.note_skipped_rollback_copy();
        }
        assert_eq!(
            store.writes_without_a_rollback_copy(),
            before + 12,
            "skipped writes must be visible to whoever asks the node"
        );

        // And the log is throttled, or a node with no free pages writes one line per chunk
        // for the rest of its life.
        let said: Vec<u64> = (0..1_000)
            .filter_map(|_| legacy.note_skipped_rollback_copy())
            .collect();
        assert!(
            said.len() < 10,
            "the warning fired {} times in a thousand writes",
            said.len()
        );
    }

    /// Two writes for one key need two notes, not one shared between them.
    ///
    /// The journal used to be a set, so a second write for the same key announced nothing
    /// and the first to return cleared the entry for both. A delete arriving in that window
    /// sees no announcement, skips draining the environment, and the surviving write lands
    /// afterwards and puts the key back, undoing a prune the node had decided on. The key
    /// then sits in the environment and in neither view, which is the state retirement is
    /// built to refuse: no data is lost, but a prune and a retirement cycle are.
    ///
    /// The file store's own in-flight map is counted for exactly this reason. This is the
    /// same reasoning applied to the half that did not have it.
    #[tokio::test]
    async fn two_writes_for_one_key_are_two_notes_and_the_first_to_return_clears_neither() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["settled"]).await;
        let store = open(&dir).await;
        let legacy = store.legacy().expect("legacy");
        let (addr, _) = addressed("two-writes");

        legacy.announce(&addr);
        legacy.announce(&addr);
        assert!(store.has_pending_writes());

        // The first write returns. The second is still out there, so the note has to stand.
        legacy.announced_write_finished(&addr);
        assert!(
            store.has_pending_writes(),
            "the first write to return cleared a note the second one was still relying on"
        );

        // And the second clears it.
        legacy.announced_write_finished(&addr);
        assert!(!store.has_pending_writes());

        // Retiring one that was never announced changes nothing, which is what makes the
        // delete path's unconditional clear safe.
        legacy.announced_write_finished(&addr);
        assert!(!store.has_pending_writes());
    }

    /// A write in flight is a note to self, not a claim to hold the chunk.
    ///
    /// The note exists because a write into the environment outlives the future waiting
    /// for it, so a cancelled one could leave a chunk nothing had recorded. But until both
    /// halves have returned the node does not hold it, and saying it does puts the key in
    /// signed commitments and in the count a quote is priced from.
    #[tokio::test]
    async fn a_write_in_flight_is_not_claimed_but_does_stop_retirement() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["settled"]).await;
        let store = open(&dir).await;
        let legacy = store.legacy().expect("legacy");
        let (addr, _) = addressed("in-flight");

        // Stand in for a write that announced itself and never came back.
        legacy.announce(&addr);

        assert!(
            !store.exists(&addr).expect("exists"),
            "a write in flight must not be reported as held"
        );
        assert!(!store.all_keys().await.expect("keys").contains(&addr));
        assert!(!store.legacy_only_keys().contains(&addr));
        assert!(store.has_pending_writes());

        // The distinction is the point: the same key in the key set IS claimed. If a
        // write announced itself there instead, every one of the assertions above would
        // be the opposite for as long as the write took.
        legacy.only.write().insert(addr);
        assert!(store.exists(&addr).expect("exists"));
        assert!(store.all_keys().await.expect("keys").contains(&addr));
        legacy.only.write().remove(&addr);

        // But it does stop the environment going, because what it holds is unsettled.
        store.commit_to_files().expect("commit");
        store.note_commitment_rebuilt();
        store.note_commitment_rebuilt();
        store.force_migration_state(|s| {
            s.committed_at_unix =
                Some(now_unix().saturating_sub(MIN_RETIRE_DELAY_HOURS * 3600 + 60));
        });
        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");
        let err = store
            .retire_legacy(&proof, &|_: &XorName| false, &approved_shed(&store))
            .await
            .expect_err("an unsettled write must stop the removal");
        assert!(format!("{err}").contains("not reported back"), "{err}");

        // And the note is resolved against what is actually there: nothing, so it goes.
        store.reconcile_pending_writes().await;
        assert!(!store.has_pending_writes());
        assert!(!store.legacy_only_keys().contains(&addr));
    }

    /// A delete outlasts a write for the same key that nobody waited for.
    ///
    /// A write has an environment half and a file half, and either can still be running
    /// when its caller is dropped: the blocking work is not cancelled with the future.
    /// A delete that did not wait for both would be undone by whichever half landed
    /// afterwards, putting back a chunk the node had decided to prune.
    #[tokio::test]
    async fn a_delete_outlasts_a_write_nobody_waited_for() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["neighbour"]).await;
        let store = Arc::new(open(&dir).await);
        let (addr, content) = addressed("written-then-pruned");

        // The gate is held from its own thread, so nothing holds a blocking guard across
        // an await, and it is released through a channel when the test is ready.
        let gate = store.files.test_put_gate();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _parked = gate.write();
            held_tx.send(()).ok();
            release_rx.recv().ok();
        });
        held_rx.recv().expect("the gate is held");

        // The state under test, built directly rather than by racing a real put: a write
        // that announced itself, whose file half is parked mid-publish, and whose caller
        // is gone. Driving it through `put` and aborting would be a race about which half
        // had started, and a test that sometimes sets up a different state than it claims
        // is worse than no test.
        let legacy = store.legacy().expect("legacy");
        legacy.announce(&addr);
        let publishing = {
            let files = Arc::clone(&store.files);
            let content = content.clone();
            tokio::spawn(async move { files.put(&addr, &content).await })
        };
        // Until the publish is genuinely in flight and parked at the gate.
        while store.files.tasks_in_flight() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        publishing.abort();
        let _ = publishing.await;

        // The delete has to wait the parked half out rather than racing it.
        let deleting = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.delete(&addr).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !deleting.is_finished(),
            "the delete must wait for the write it would otherwise race"
        );

        release_tx.send(()).ok();
        holder.join().ok();
        deleting.await.expect("join").expect("delete");

        // Whichever half landed, the key is gone and stays gone.
        store.files.wait_idle().await;
        assert!(
            !store.exists(&addr).unwrap_or(true),
            "a write that landed after the delete would resurrect a pruned chunk"
        );
        assert!(!store.legacy_only_keys().contains(&addr));
    }

    /// A delete outlasts a file write that no journal knows about.
    ///
    /// The journal is kept by writes that touch both stores. The copier and the repair
    /// path write only the file, so a delete that consulted the journal to decide whether
    /// to wait would not wait for either of them, and whichever landed afterwards would
    /// put back a chunk the node had decided to prune. What is writing a key is the file
    /// store's own question to answer.
    #[tokio::test]
    async fn a_delete_outlasts_a_file_write_with_no_journal_entry() {
        let dir = TempDir::new().expect("temp dir");
        seed_legacy(&dir, &["neighbour"]).await;
        let store = Arc::new(open(&dir).await);
        let (addr, content) = addressed("copied-then-pruned");

        let gate = store.files.test_put_gate();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _parked = gate.write();
            held_tx.send(()).ok();
            release_rx.recv().ok();
        });
        held_rx.recv().expect("the gate is held");

        // Deliberately no journal entry: this is the copier's shape, not a dual write.
        let publishing = {
            let files = Arc::clone(&store.files);
            let content = content.clone();
            tokio::spawn(async move { files.put(&addr, &content).await })
        };
        while store.files.tasks_in_flight() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        publishing.abort();
        let _ = publishing.await;
        assert!(
            !store
                .legacy()
                .is_some_and(|l| l.pending.read().contains_key(&addr)),
            "this is the case the journal does not cover, so it must be empty"
        );

        let deleting = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.delete(&addr).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !deleting.is_finished(),
            "the delete must wait for a write the journal never knew about"
        );

        release_tx.send(()).ok();
        holder.join().ok();
        deleting.await.expect("join").expect("delete");

        store.files.wait_idle().await;
        assert!(
            !store.exists(&addr).unwrap_or(true),
            "a write that landed after the delete would resurrect a pruned chunk"
        );
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
        assert!(
            proof.unrepairable >= 1,
            "the vanished file must be counted against the proof"
        );
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

    /// A legacy record whose bytes do not hash to its key is removed, not passed around.
    ///
    /// Leaving it in the environment while dropping it from the key set puts it in
    /// neither view, and the pre-retirement pass reads a key in neither view as one to
    /// protect and puts it straight back. The next copier pass drops it again. One rotted
    /// record would keep this node, and every node sharing its disk, from ever reclaiming
    /// space.
    #[tokio::test]
    async fn a_legacy_chunk_that_does_not_match_its_address_is_removed_not_recycled() {
        let dir = TempDir::new().expect("temp dir");
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
            // Under a key it does not hash to: what a record that rotted in place looks
            // like, and the one shape the ordinary path refuses to create.
            lmdb.put_unchecked(&addr, &other).await.expect("put");
            lmdb.wait_idle().await;
        }
        let store = open(&dir).await;
        let keys = store.legacy_only_keys();
        assert_eq!(keys, vec![addr]);

        let report = store
            .copy_batch(&keys, 0, 0, &never_cancelled())
            .await
            .expect("copy");
        assert_eq!(report.copied, 0);
        assert_eq!(report.unusable, 1);
        assert!(store.legacy_only_keys().is_empty());

        // And it is gone from the environment, so the pass below cannot find it and put
        // it back. That is the loop this is about.
        let proof = store
            .verify_before_retire(0, &never_cancelled())
            .await
            .expect("verify");
        assert!(
            store.legacy_only_keys().is_empty(),
            "a removed record must not come back on the copier's list"
        );
        assert!(
            proof.is_clean(),
            "and must not go on refusing the proof for ever"
        );
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
