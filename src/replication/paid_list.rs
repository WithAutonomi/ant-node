//! Persistent `PaidForList` backed by LMDB.
//!
//! Tracks keys this node believes are paid-authorized. Survives restarts
//! (Invariant 15). Bounded by `PaidCloseGroup` membership with
//! hysteresis-based pruning.
//!
//! ## Storage layout
//!
//! ```text
//! {root}/paid_list.mdb/   -- LMDB environment directory
//! ```
//!
//! One unnamed database stores set membership: key = 32-byte `XorName`,
//! value = empty byte slice, or one marker byte for a key whose
//! payment the price floor contested here (ADR-0006). Releases before that
//! marker only ever test presence, so they read a marked key as paid. The
//! marked keys are also held in memory, so hint construction never scans the
//! database for them.
//!
//! ## Out-of-range timestamps
//!
//! Per-key `PaidOutOfRangeFirstSeen` and `RecordOutOfRangeFirstSeen`
//! timestamps live in memory only. On restart the hysteresis clock
//! restarts from zero, which is safe: the prune timer simply starts
//! fresh.

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::logging::{debug, info, trace, warn};
use heed::types::Bytes;
#[cfg(test)]
use heed::WithTls;
use heed::{Database, Env, EnvOpenOptions, RoTxn};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::task::spawn_blocking;
use tokio_util::task::TaskTracker;

use crate::ant_protocol::XORNAME_LEN;

/// Value stored for a key whose payment the price floor contested here (see
/// `fresh::record_paid_key`).
const PRICE_CONTESTED_VALUE: &[u8] = &[1];

/// Default LMDB map size for the paid list: 256 MiB.
///
/// The paid list stores only 32-byte keys with empty or one-byte values, so
/// this is generous even for very large close-group memberships.
const DEFAULT_MAP_SIZE: usize = 256 * 1_024 * 1_024;

/// What the open task returns: the environment, the database and the keys
/// marked price-contested in it, if they could be read.
type OpenedPaidList = (Env, Database<Bytes, Bytes>, Result<HashSet<XorName>>);

/// Every key whose entry in `db` carries the price-contested mark.
fn read_price_contested_keys(db: &Database<Bytes, Bytes>, txn: &RoTxn) -> Result<HashSet<XorName>> {
    let mut keys = HashSet::new();
    for result in db
        .iter(txn)
        .map_err(|e| Error::Storage(format!("Failed to iterate paid-list: {e}")))?
    {
        let (key_bytes, value) =
            result.map_err(|e| Error::Storage(format!("Failed to read paid-list entry: {e}")))?;
        if value.is_empty() {
            continue;
        }
        if let Ok(key) = XorName::try_from(key_bytes) {
            keys.insert(key);
        }
    }
    Ok(keys)
}

/// Drop `keys` from the in-memory marks, after a commit that left none of
/// them marked in the database. The set is copied only if one of them is in
/// it.
fn unmark_in_memory(marks: &RwLock<Option<Arc<HashSet<XorName>>>>, keys: &[XorName]) {
    if let Some(marked) = marks.write().as_mut() {
        if keys.iter().any(|key| marked.contains(key)) {
            let marked = Arc::make_mut(marked);
            for key in keys {
                marked.remove(key);
            }
        }
    }
}

/// Persistent paid-for-list backed by LMDB.
///
/// Tracks which keys this node believes are paid-authorized.
/// Survives node restarts via LMDB persistence.
pub struct PaidList {
    /// LMDB environment.
    env: Env,
    /// The unnamed default database (key = `XorName` bytes, value = empty, or
    /// the price-contested marker).
    db: Database<Bytes, Bytes>,
    /// In-memory copy of the keys whose entry carries the price-contested
    /// mark, or `None` if they could not be read on open. Changed only by the
    /// blocking task that writes the database, under `write_order`, so a
    /// cancelled caller cannot leave it stale. Readers clone the `Arc` and
    /// filter outside the lock; a write while such a snapshot is alive
    /// copies the set first (`Arc::make_mut`).
    price_contested: Arc<RwLock<Option<Arc<HashSet<XorName>>>>>,
    /// Held by every database write from before its write transaction until
    /// it has updated `price_contested`, so the copy changes in commit order.
    /// A new mark goes in just before its commit and a removed one just after,
    /// so the copy never lacks a committed mark. A mark whose commit fails
    /// stays, since that commit may still have reached the disk: when in
    /// doubt, judge no one. Any later write that commits the key unmarked, a
    /// plain insert that adds it or a removal, drops that mark.
    write_order: Arc<Mutex<()>>,
    /// Mark reads that have failed since the last one that succeeded, so a
    /// run of failures is logged once (see `counts_as_price_contested`).
    failed_mark_reads: AtomicU64,
    /// In-memory: when each paid key first went out of `PaidCloseGroup` range.
    /// Cleared on restart (safe: hysteresis clock restarts from zero).
    paid_out_of_range: RwLock<HashMap<XorName, Instant>>,
    /// In-memory: when each stored record first went out of
    /// storage-responsibility range.
    record_out_of_range: RwLock<HashMap<XorName, Instant>>,
    /// Cursor used by paid-list pruning to rotate through expired entries when
    /// the per-pass remote confirmation cap is exhausted.
    paid_prune_cursor: RwLock<usize>,
    /// Tracks every paid-list LMDB blocking task.
    ///
    /// Same rationale as `ChunkStore::blocking_tracker`: a `spawn_blocking`
    /// closure owns a cloned [`Env`] and keeps running when its async awaiter
    /// is dropped, so [`Self::wait_idle`] waits on the blocking tasks
    /// themselves before the environment may be reopened.
    blocking_tracker: TaskTracker,
}

impl PaidList {
    /// Open or create a `PaidList` backed by LMDB at `{root_dir}/paid_list.mdb/`.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB environment cannot be opened or the
    /// database cannot be created.
    #[allow(unsafe_code)]
    pub async fn new(root_dir: &Path) -> Result<Self> {
        let env_dir = root_dir.join("paid_list.mdb");

        std::fs::create_dir_all(&env_dir)
            .map_err(|e| Error::Storage(format!("Failed to create paid-list directory: {e}")))?;

        let env_dir_clone = env_dir.clone();
        // Constructor-only blocking task: it runs before `self` (and its
        // `blocking_tracker`) exists, so it is deliberately untracked.  The
        // constructor awaits it right here, so it cannot outlive this call.
        let (env, db, price_contested) = spawn_blocking(move || -> Result<OpenedPaidList> {
            // SAFETY: `EnvOpenOptions::open()` is unsafe because LMDB uses
            // memory-mapped I/O and relies on OS file-locking to prevent
            // corruption from concurrent access by multiple processes. We
            // satisfy this by giving each node instance a unique `root_dir`
            // (typically named by its full 64-hex peer ID), ensuring no two
            // processes open the same LMDB environment.
            let env = unsafe {
                EnvOpenOptions::new()
                    .map_size(DEFAULT_MAP_SIZE)
                    .max_dbs(1)
                    .open(&env_dir_clone)
                    .map_err(|e| {
                        Error::Storage(format!("Failed to open paid-list LMDB env: {e}"))
                    })?
            };

            let mut wtxn = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;
            let db: Database<Bytes, Bytes> = env
                .create_database(&mut wtxn, None)
                .map_err(|e| Error::Storage(format!("Failed to create paid-list database: {e}")))?;
            wtxn.commit()
                .map_err(|e| Error::Storage(format!("Failed to commit db creation: {e}")))?;
            // A failed read leaves its transaction unable to commit, so the
            // scan gets one of its own, dropped uncommitted. A write
            // transaction takes no reader slot on this thread.
            let price_contested = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))
                .and_then(|scan| read_price_contested_keys(&db, &scan));

            Ok((env, db, price_contested))
        })
        .await
        .map_err(|e| Error::Storage(format!("Paid-list init task failed: {e}")))??;
        // A paid list whose marks cannot be read still opens; the node then
        // sends no replica hints until it restarts (see `retain_unmarked`).
        let price_contested = price_contested
            .inspect_err(|e| {
                warn!(
                    "Cannot read the paid list's price-contested marks; sending no replica \
                     hints until restart: {e}"
                );
            })
            .ok()
            .map(Arc::new);

        let paid_list = Self {
            env,
            db,
            price_contested: Arc::new(RwLock::new(price_contested)),
            write_order: Arc::new(Mutex::new(())),
            failed_mark_reads: AtomicU64::new(0),
            paid_out_of_range: RwLock::new(HashMap::new()),
            record_out_of_range: RwLock::new(HashMap::new()),
            paid_prune_cursor: RwLock::new(0),
            blocking_tracker: TaskTracker::new(),
        };

        let count = paid_list.count()?;
        debug!("Initialized paid-list at {env_dir:?} ({count} existing keys)");

        Ok(paid_list)
    }

    /// Insert a key into the paid-for set.
    ///
    /// Returns `true` if the key was newly added, `false` if it already existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB write transaction fails.
    pub async fn insert(&self, key: &XorName) -> Result<bool> {
        self.insert_with_value(key, &[]).await
    }

    /// Insert `key` as paid at a price the floor contested here (see
    /// `fresh::record_paid_key`). Like [`Self::insert`], an existing entry is
    /// left exactly as it is, so a key already recorded can never gain the
    /// mark later. The mark survives restarts and later inserts, and goes
    /// with the entry on [`Self::remove`].
    ///
    /// Returns `true` if the key was newly added, `false` if it already existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB write transaction fails.
    pub async fn insert_price_contested(&self, key: &XorName) -> Result<bool> {
        self.insert_with_value(key, PRICE_CONTESTED_VALUE).await
    }

    async fn insert_with_value(&self, key: &XorName, value: &'static [u8]) -> Result<bool> {
        // Fast-path: avoid write transaction if key already present.
        if self.contains(key)? {
            trace!("Paid-list key {} already present", hex::encode(key));
            return Ok(false);
        }

        let key_owned = *key;
        let env = self.env.clone();
        let db = self.db;
        let price_contested = Arc::clone(&self.price_contested);
        let write_order = Arc::clone(&self.write_order);

        let was_new = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<bool> {
                let ordered = write_order.lock();
                let mut wtxn = env
                    .write_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;

                // Authoritative existence check inside the serialized write txn.
                if db
                    .get(&wtxn, &key_owned)
                    .map_err(|e| {
                        Error::Storage(format!("Failed to check paid-list existence: {e}"))
                    })?
                    .is_some()
                {
                    return Ok(false);
                }

                db.put(&mut wtxn, &key_owned, value)
                    .map_err(|e| Error::Storage(format!("Failed to insert into paid-list: {e}")))?;
                if !value.is_empty() {
                    if let Some(keys) = price_contested.write().as_mut() {
                        Arc::make_mut(keys).insert(key_owned);
                    }
                }
                wtxn.commit().map_err(|e| {
                    Error::Storage(format!("Failed to commit paid-list insert: {e}"))
                })?;
                if value.is_empty() {
                    unmark_in_memory(&price_contested, slice::from_ref(&key_owned));
                }
                drop(ordered);

                Ok(true)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list insert task failed: {e}")))??;

        if was_new {
            debug!(
                "Added key {} to paid-list{}",
                hex::encode(key),
                if value.is_empty() {
                    ""
                } else {
                    " as price-contested"
                }
            );
        }

        Ok(was_new)
    }

    /// Whether `key` is paid at a price the floor contested here (see
    /// [`Self::insert_price_contested`]).
    ///
    /// Reads the database, which is authoritative: the in-memory copy behind
    /// [`Self::retain_unmarked`] can hold a mark whose commit is under way or
    /// failed, or be missing. A caller that has just seen a racing write's
    /// entry sees its mark here as well (see `fresh::record_paid_key`).
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub fn is_price_contested(&self, key: &XorName) -> Result<bool> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let marked = self
            .db
            .get(&rtxn, key.as_ref())
            .map_err(|e| Error::Storage(format!("Failed to read paid-list entry: {e}")))?
            .is_some_and(|value| !value.is_empty());
        Ok(marked)
    }

    /// Whether `key` must be treated as price-contested: its entry carries the
    /// mark, or the mark cannot be read (when in doubt, judge no one). While
    /// reads fail no peer is judged on any key they hit, so the first failure
    /// of a run is a warning, and the read that ends the run reports how many
    /// failed.
    pub fn counts_as_price_contested(&self, key: &XorName) -> bool {
        match self.is_price_contested(key) {
            Ok(marked) => {
                let failed = self.failed_mark_reads.swap(0, Ordering::Relaxed);
                if failed > 0 {
                    info!("Price-contested marks are readable again, after {failed} failed reads");
                }
                marked
            }
            Err(e) => {
                if self.failed_mark_reads.fetch_add(1, Ordering::Relaxed) == 0 {
                    warn!(
                        "Cannot read the price-contested mark of key {}; counting unreadable \
                         marks as set until a read succeeds: {e}",
                        hex::encode(key)
                    );
                } else {
                    debug!(
                        "Price-contested mark of key {} still unreadable: {e}",
                        hex::encode(key)
                    );
                }
                true
            }
        }
    }

    /// Drop from `keys` every key marked price-contested, using the in-memory
    /// copy rather than the database. If the marks could not be read on open,
    /// no key is known to be unmarked, so every key is dropped.
    pub fn retain_unmarked(&self, keys: &mut Vec<XorName>) {
        let snapshot = self.price_contested.read().clone();
        match snapshot {
            Some(marked) => keys.retain(|key| !marked.contains(key)),
            None => keys.clear(),
        }
    }

    /// Remove a key from the paid-for set.
    ///
    /// Also clears any in-memory out-of-range timestamps for this key.
    ///
    /// Returns `true` if the key existed and was removed, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB write transaction fails.
    pub async fn remove(&self, key: &XorName) -> Result<bool> {
        let key_owned = *key;
        let env = self.env.clone();
        let db = self.db;
        let price_contested = Arc::clone(&self.price_contested);
        let write_order = Arc::clone(&self.write_order);

        let existed = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<bool> {
                let ordered = write_order.lock();
                let mut wtxn = env
                    .write_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;
                let deleted = db
                    .delete(&mut wtxn, &key_owned)
                    .map_err(|e| Error::Storage(format!("Failed to delete from paid-list: {e}")))?;
                wtxn.commit().map_err(|e| {
                    Error::Storage(format!("Failed to commit paid-list delete: {e}"))
                })?;
                unmark_in_memory(&price_contested, slice::from_ref(&key_owned));
                drop(ordered);
                Ok(deleted)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list remove task failed: {e}")))??;

        if existed {
            self.paid_out_of_range.write().remove(key);
            self.record_out_of_range.write().remove(key);
            debug!("Removed key {} from paid-list", hex::encode(key));
        }

        Ok(existed)
    }

    /// Check whether a key is in the paid-for set.
    ///
    /// This is a synchronous read-only operation (no write transaction needed).
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub fn contains(&self, key: &XorName) -> Result<bool> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let found = self
            .db
            .get(&rtxn, key.as_ref())
            .map_err(|e| Error::Storage(format!("Failed to check paid-list membership: {e}")))?
            .is_some();
        Ok(found)
    }

    /// Return the number of keys in the paid-for set.
    ///
    /// This is an O(1) read of the B-tree page header, not a full scan.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub fn count(&self) -> Result<u64> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let entries = self
            .db
            .stat(&rtxn)
            .map_err(|e| Error::Storage(format!("Failed to read paid-list stats: {e}")))?
            .entries;
        Ok(entries as u64)
    }

    /// Return all keys in the paid-for set.
    ///
    /// Used during hint construction to advertise which keys this node holds.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction or iteration fails.
    pub fn all_keys(&self) -> Result<Vec<XorName>> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let mut keys = Vec::new();
        let iter = self
            .db
            .iter(&rtxn)
            .map_err(|e| Error::Storage(format!("Failed to iterate paid-list: {e}")))?;
        for result in iter {
            let (key_bytes, _) = result
                .map_err(|e| Error::Storage(format!("Failed to read paid-list entry: {e}")))?;
            if key_bytes.len() == XORNAME_LEN {
                let mut key = [0u8; XORNAME_LEN];
                key.copy_from_slice(key_bytes);
                keys.push(key);
            } else {
                warn!(
                    "PaidList: skipping entry with unexpected key length {} (expected {XORNAME_LEN})",
                    key_bytes.len()
                );
            }
        }
        Ok(keys)
    }

    /// Record the `PaidOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Only sets the timestamp if one is not already recorded (first
    /// observation wins).
    pub fn set_paid_out_of_range(&self, key: &XorName) {
        self.paid_out_of_range
            .write()
            .entry(*key)
            .or_insert_with(Instant::now);
    }

    /// Clear the `PaidOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Called when the key moves back into `PaidCloseGroup` range.
    pub fn clear_paid_out_of_range(&self, key: &XorName) {
        self.paid_out_of_range.write().remove(key);
    }

    /// Get the `PaidOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Returns `None` if the key is currently in range (no timestamp set).
    pub fn paid_out_of_range_since(&self, key: &XorName) -> Option<Instant> {
        self.paid_out_of_range.read().get(key).copied()
    }

    /// Record the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Only sets the timestamp if one is not already recorded (first
    /// observation wins).
    pub fn set_record_out_of_range(&self, key: &XorName) {
        self.record_out_of_range
            .write()
            .entry(*key)
            .or_insert_with(Instant::now);
    }

    /// Clear the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Called when the record moves back into storage-responsibility range.
    pub fn clear_record_out_of_range(&self, key: &XorName) {
        self.record_out_of_range.write().remove(key);
    }

    /// Get the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Returns `None` if the record is currently in range (no timestamp set).
    pub fn record_out_of_range_since(&self, key: &XorName) -> Option<Instant> {
        self.record_out_of_range.read().get(key).copied()
    }

    /// Starting offset for the next paid-list prune scan.
    ///
    /// LMDB iteration order is stable, so a bounded prune pass must rotate its
    /// verification window or later expired entries can be starved behind
    /// earlier unconfirmed entries.
    pub(crate) fn paid_prune_scan_start(&self, paid_key_count: usize) -> usize {
        if paid_key_count == 0 {
            return 0;
        }

        *self.paid_prune_cursor.read() % paid_key_count
    }

    /// Advance the paid-list prune cursor after one pass.
    pub(crate) fn advance_paid_prune_cursor(
        &self,
        paid_key_count: usize,
        scan_start: usize,
        last_selected_offset: Option<usize>,
    ) {
        let mut cursor = self.paid_prune_cursor.write();
        if paid_key_count == 0 {
            *cursor = 0;
            return;
        }

        let advance_by = last_selected_offset.map_or(1, |offset| offset.saturating_add(1));
        *cursor = (scan_start + advance_by) % paid_key_count;
    }

    /// Remove multiple keys in a single write transaction.
    ///
    /// Also clears any in-memory out-of-range timestamps for removed keys.
    ///
    /// Returns the number of keys that were actually present and removed.
    ///
    /// # Cancellation
    ///
    /// The delete commits inside `spawn_blocking`, which cancellation cannot
    /// reach; the timestamp clear below happens only after that await resumes.
    /// Dropping this future in between therefore leaves keys deleted on disk
    /// with their `paid_out_of_range` entries still set.
    ///
    /// That window is deliberately left open. The only caller is the prune pass
    /// (`pruning::prune_paid_entries`), reached from `run_neighbor_sync_round`,
    /// which is awaited inside a `select!` racing the engine's shutdown token —
    /// so shutdown is the only way to hit it. `paid_out_of_range` is in-memory
    /// only (never persisted), so the stale entries die with the process that
    /// cancelled the prune, and a reopened `PaidList` starts with an empty map.
    ///
    /// Do NOT "fix" this by clearing the timestamps before the commit: a failed
    /// commit would then leave a live key with a cleared hysteresis clock,
    /// restarting its prune countdown from zero. That is a real correctness
    /// regression in exchange for a window with no observable effect.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB write transaction fails.
    pub async fn remove_batch(&self, keys: &[XorName]) -> Result<usize> {
        if keys.is_empty() {
            return Ok(0);
        }

        let keys_owned: Vec<XorName> = keys.to_vec();
        let env = self.env.clone();
        let db = self.db;
        let price_contested = Arc::clone(&self.price_contested);
        let write_order = Arc::clone(&self.write_order);

        let removed_keys = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<Vec<XorName>> {
                let ordered = write_order.lock();
                let mut wtxn = env
                    .write_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;

                let mut removed = Vec::new();
                for key in &keys_owned {
                    let deleted = db.delete(&mut wtxn, key.as_ref()).map_err(|e| {
                        Error::Storage(format!("Failed to delete from paid-list: {e}"))
                    })?;
                    if deleted {
                        removed.push(*key);
                    }
                }

                wtxn.commit()
                    .map_err(|e| Error::Storage(format!("Failed to commit batch remove: {e}")))?;
                // Every key of the batch, not only those the database held: a
                // mark whose commit failed can be in memory alone.
                unmark_in_memory(&price_contested, &keys_owned);
                drop(ordered);

                Ok(removed)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list batch remove task failed: {e}")))??;

        // Clear in-memory timestamps for all removed keys.
        // Acquire and release each lock separately to minimize hold time.
        if !removed_keys.is_empty() {
            {
                let mut paid_oor = self.paid_out_of_range.write();
                for key in &removed_keys {
                    paid_oor.remove(key);
                }
            }
            {
                let mut record_oor = self.record_out_of_range.write();
                for key in &removed_keys {
                    record_oor.remove(key);
                }
            }
        }

        let count = removed_keys.len();
        debug!("Batch-removed {count} keys from paid-list");
        Ok(count)
    }

    /// Wait until every tracked paid-list LMDB blocking task has finished.
    ///
    /// Dropping an async caller (e.g. a `select!` losing to a shutdown token)
    /// does not cancel an already-spawned blocking closure — the closure keeps
    /// running on the blocking pool with a cloned [`Env`].  This method waits
    /// for those detached closures too, so when it returns no blocking
    /// operation still holds the environment.
    ///
    /// Quiescence is only meaningful once callers have stopped issuing new
    /// operations; concurrent traffic can keep the tracker non-empty
    /// indefinitely.  The paid list remains fully usable afterwards (the
    /// internal tracker is reopened before returning).
    pub async fn wait_idle(&self) {
        self.blocking_tracker.close();
        self.blocking_tracker.wait().await;
        self.blocking_tracker.reopen();
    }

    /// Hold a read transaction on the calling thread. LMDB gives each thread
    /// one reader slot, so until it is dropped every paid-list read on this
    /// thread fails, which lets a test drive the paths a mark that cannot be
    /// read takes.
    #[cfg(test)]
    pub(crate) fn hold_reader_for_tests(&self) -> Result<RoTxn<'_, WithTls>> {
        self.env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    #[cfg(target_pointer_width = "64")]
    use std::fs::OpenOptions;
    #[cfg(target_pointer_width = "64")]
    use std::io::{Read, Seek, SeekFrom, Write};
    #[cfg(feature = "logging")]
    use tracing::subscriber::with_default;
    #[cfg(feature = "logging")]
    use tracing_subscriber::fmt::writer::{MakeWriter, MutexGuardWriter};

    /// Short probe used to prove `wait_idle` is still blocked on a parked op.
    const WAIT_IDLE_BLOCKED_PROBE: std::time::Duration = std::time::Duration::from_millis(200);
    /// Generous ceiling for `wait_idle` to complete once the op is released.
    const WAIT_IDLE_COMPLETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// The in-memory copy of the marks, which must have been read on open.
    fn marked_in_memory(pl: &PaidList) -> HashSet<XorName> {
        pl.price_contested
            .read()
            .as_deref()
            .cloned()
            .expect("marks read on open")
    }

    async fn create_test_paid_list() -> (PaidList, tempfile::TempDir) {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let paid_list = PaidList::new(temp_dir.path())
            .await
            .expect("create paid list");
        (paid_list, temp_dir)
    }

    #[tokio::test]
    async fn test_insert_and_contains() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xAA; 32];
        assert!(!pl.contains(&key).expect("contains before insert"));

        let was_new = pl.insert(&key).await.expect("insert");
        assert!(was_new);

        assert!(pl.contains(&key).expect("contains after insert"));
    }

    #[tokio::test]
    async fn test_insert_duplicate_returns_false() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xBB; 32];

        let first = pl.insert(&key).await.expect("first insert");
        assert!(first);

        let second = pl.insert(&key).await.expect("second insert");
        assert!(!second);
    }

    #[tokio::test]
    async fn test_remove_existing() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xCC; 32];
        pl.insert(&key).await.expect("insert");
        assert!(pl.contains(&key).expect("contains"));

        let removed = pl.remove(&key).await.expect("remove");
        assert!(removed);
        assert!(!pl.contains(&key).expect("contains after remove"));
    }

    #[tokio::test]
    async fn test_remove_nonexistent() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xDD; 32];
        let removed = pl.remove(&key).await.expect("remove nonexistent");
        assert!(!removed);
    }

    #[tokio::test]
    async fn test_persistence_across_reopen() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let key: XorName = [0xEE; 32];

        // Insert a key, then drop the PaidList.
        {
            let pl = PaidList::new(temp_dir.path())
                .await
                .expect("create paid list");
            pl.insert(&key).await.expect("insert");
            assert_eq!(pl.count().expect("count"), 1);
        }

        // Re-open and verify the key persisted.
        {
            let pl = PaidList::new(temp_dir.path())
                .await
                .expect("reopen paid list");
            assert_eq!(pl.count().expect("count"), 1);
            assert!(pl.contains(&key).expect("contains after reopen"));
        }
    }

    /// ADR-0006: the price-contested mark is written only with a new entry, so
    /// an already recorded key can never gain it. It survives a restart and a
    /// later plain insert, and goes with the entry on removal.
    #[tokio::test]
    async fn price_contested_mark_persists_until_the_key_is_removed() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let marked: XorName = [0x51; 32];
        let recorded_first: XorName = [0x52; 32];

        {
            let pl = PaidList::new(temp_dir.path())
                .await
                .expect("create paid list");
            assert!(pl.insert(&recorded_first).await.expect("insert"));
            assert!(pl.insert_price_contested(&marked).await.expect("mark"));
            assert!(!pl
                .insert_price_contested(&recorded_first)
                .await
                .expect("mark an existing key"));
            assert!(!pl.insert(&marked).await.expect("re-insert"));
        }

        let pl = PaidList::new(temp_dir.path())
            .await
            .expect("reopen paid list");
        assert_eq!(pl.count().expect("count"), 2);
        assert!(pl.contains(&marked).expect("contains"));
        assert!(pl.is_price_contested(&marked).expect("read mark"));
        assert!(!pl.is_price_contested(&recorded_first).expect("read mark"));
        assert_eq!(marked_in_memory(&pl), HashSet::from([marked]));

        pl.remove(&marked).await.expect("remove");
        pl.insert(&marked).await.expect("insert again");
        assert!(!pl.is_price_contested(&marked).expect("read mark"));
        assert!(marked_in_memory(&pl).is_empty());
    }

    /// ADR-0006: the in-memory marks follow every insert, removal and batch
    /// removal.
    #[tokio::test]
    async fn the_in_memory_marks_follow_every_write() {
        let (pl, _temp) = create_test_paid_list().await;
        let first: XorName = [0x61; 32];
        let second: XorName = [0x62; 32];
        let plain: XorName = [0x63; 32];
        pl.insert_price_contested(&first).await.expect("mark");
        pl.insert_price_contested(&second).await.expect("mark");
        pl.insert(&plain).await.expect("insert");
        assert_eq!(marked_in_memory(&pl), HashSet::from([first, second]));
        let mut keys = vec![first, plain, second];
        pl.retain_unmarked(&mut keys);
        assert_eq!(keys, vec![plain]);
        pl.remove(&first).await.expect("remove");
        assert_eq!(marked_in_memory(&pl), HashSet::from([second]));
        pl.remove_batch(&[second, plain])
            .await
            .expect("remove batch");
        assert!(marked_in_memory(&pl).is_empty());
    }

    /// ADR-0006: while a database write holds the write order, a marked
    /// insert or a batch removal neither commits nor changes the in-memory
    /// copy, so writes and the copy move in one order.
    #[tokio::test]
    async fn the_in_memory_marks_change_in_commit_order() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x6B; 32];
        let (release_tx, holder) = hold_write_order(&pl).await;

        let insert = pl.insert_price_contested(&key);
        tokio::pin!(insert);
        let blocked = tokio::time::timeout(WAIT_IDLE_BLOCKED_PROBE, &mut insert).await;
        assert!(blocked.is_err(), "the insert must wait for the write order");
        assert!(!pl.contains(&key).expect("contains"));
        assert!(marked_in_memory(&pl).is_empty());

        drop(release_tx);
        holder.await.expect("holder task");
        assert!(insert.await.expect("insert"));
        assert_eq!(marked_in_memory(&pl), HashSet::from([key]));

        let (release_tx, holder) = hold_write_order(&pl).await;

        let batch = [key];
        let removal = pl.remove_batch(&batch);
        tokio::pin!(removal);
        let blocked = tokio::time::timeout(WAIT_IDLE_BLOCKED_PROBE, &mut removal).await;
        assert!(
            blocked.is_err(),
            "the removal must wait for the write order"
        );
        assert!(pl.contains(&key).expect("contains"));
        assert_eq!(marked_in_memory(&pl), HashSet::from([key]));

        drop(release_tx);
        holder.await.expect("holder task");
        assert_eq!(removal.await.expect("remove batch"), 1);
        assert!(marked_in_memory(&pl).is_empty());
    }

    /// Mark `key` in memory only, with no entry in the database: what a marked
    /// insert whose commit failed before reaching the disk leaves.
    fn mark_in_memory_only(pl: &PaidList, key: XorName) {
        let mut marks = pl.price_contested.write();
        let marks = marks.as_mut().expect("marks read on open");
        Arc::make_mut(marks).insert(key);
    }

    /// ADR-0006: a mark left in memory alone by a failed commit goes with a
    /// later plain insert that adds the key, so the copy agrees with the
    /// database again and the key is hinted as a replica. A plain insert of a
    /// key whose entry carries the mark leaves both as they are.
    #[tokio::test]
    async fn a_plain_insert_drops_a_mark_held_in_memory_only() {
        let (pl, _temp) = create_test_paid_list().await;
        let stale: XorName = [0x71; 32];
        let marked: XorName = [0x72; 32];
        pl.insert_price_contested(&marked).await.expect("mark");
        mark_in_memory_only(&pl, stale);
        let mut keys = vec![stale];
        pl.retain_unmarked(&mut keys);
        assert_eq!(keys, Vec::<XorName>::new());

        assert!(pl.insert(&stale).await.expect("insert"));
        assert!(!pl.insert(&marked).await.expect("insert"));
        assert!(!pl.is_price_contested(&stale).expect("read mark"));
        assert!(pl.is_price_contested(&marked).expect("read mark"));
        assert_eq!(marked_in_memory(&pl), HashSet::from([marked]));
        let mut keys = vec![stale, marked];
        pl.retain_unmarked(&mut keys);
        assert_eq!(keys, vec![stale]);
    }

    /// ADR-0006: a mark left in memory alone by a failed commit goes with a
    /// later removal of the key, single or batched, although the database
    /// holds no entry to delete. A mark the removal does not name stays.
    #[tokio::test]
    async fn a_removal_drops_a_mark_held_in_memory_only() {
        let (pl, _temp) = create_test_paid_list().await;
        let batched: XorName = [0x73; 32];
        let single: XorName = [0x74; 32];
        let marked: XorName = [0x75; 32];
        pl.insert_price_contested(&marked).await.expect("mark");
        mark_in_memory_only(&pl, batched);
        mark_in_memory_only(&pl, single);

        assert_eq!(pl.remove_batch(&[batched]).await.expect("remove batch"), 0);
        assert_eq!(marked_in_memory(&pl), HashSet::from([single, marked]));
        assert!(!pl.remove(&single).await.expect("remove"));
        assert_eq!(marked_in_memory(&pl), HashSet::from([marked]));
        assert!(pl.is_price_contested(&marked).expect("read mark"));
    }

    /// Byte offsets in an LMDB meta page on a 64-bit target: the magic number
    /// follows the 16-byte page header, the free list's record keeps the page
    /// size at 40, and the main database's root page number sits at 128.
    #[cfg(target_pointer_width = "64")]
    const LMDB_MAGIC_AT: u64 = 16;
    #[cfg(target_pointer_width = "64")]
    const LMDB_PAGE_SIZE_AT: u64 = 40;
    #[cfg(target_pointer_width = "64")]
    const LMDB_MAIN_ROOT_AT: u64 = 128;

    /// ADR-0006: a paid list whose marks cannot be read still opens, with no
    /// marks in memory, so the node hints no key as a replica. Both meta pages
    /// point the database's root past the end of the file, so the scan for
    /// the marks fails as it would on a lost page.
    #[cfg(target_pointer_width = "64")]
    #[tokio::test]
    async fn a_paid_list_whose_marks_cannot_be_read_still_opens() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let marked: XorName = [0x70; 32];
        {
            let pl = PaidList::new(temp_dir.path())
                .await
                .expect("create paid list");
            pl.insert_price_contested(&marked).await.expect("mark");
        }

        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp_dir.path().join("paid_list.mdb").join("data.mdb"))
            .expect("open data file");
        let mut read_u32 = |at: u64| {
            let mut word = [0u8; 4];
            data.seek(SeekFrom::Start(at)).expect("seek");
            data.read_exact(&mut word).expect("read");
            u32::from_ne_bytes(word)
        };
        let page_size = u64::from(read_u32(LMDB_PAGE_SIZE_AT));
        for meta in [0, page_size] {
            assert_eq!(
                read_u32(meta + LMDB_MAGIC_AT),
                0xBEEF_C0DE,
                "LMDB meta page"
            );
        }
        for meta in [0, page_size] {
            data.seek(SeekFrom::Start(meta + LMDB_MAIN_ROOT_AT))
                .expect("seek");
            data.write_all(&(1u64 << 40).to_ne_bytes()).expect("write");
        }
        data.sync_all().expect("sync");
        drop(data);

        let pl = PaidList::new(temp_dir.path())
            .await
            .expect("a paid list whose marks cannot be read must open");
        assert!(pl.price_contested.read().is_none());
        assert!(pl.is_price_contested(&marked).is_err());
        let mut keys = vec![marked];
        pl.retain_unmarked(&mut keys);
        assert_eq!(keys, Vec::<XorName>::new());
    }

    /// ADR-0006: a paid list whose marks could not be read on open shows no
    /// key as unmarked, so the node hints no key as a replica, while writes and
    /// point reads of the marks still work.
    #[tokio::test]
    async fn marks_unread_on_open_hint_no_replicas() {
        let (pl, _temp) = create_test_paid_list().await;
        let marked: XorName = [0x6C; 32];
        let plain: XorName = [0x6D; 32];
        *pl.price_contested.write() = None;

        let mut keys = vec![plain];
        pl.retain_unmarked(&mut keys);
        assert_eq!(keys, Vec::<XorName>::new());
        pl.insert_price_contested(&marked).await.expect("mark");
        pl.insert(&plain).await.expect("insert");
        pl.remove_batch(&[plain]).await.expect("remove batch");
        assert!(pl.price_contested.read().is_none());
        assert!(pl.counts_as_price_contested(&marked));
        assert!(!pl.counts_as_price_contested(&plain));
    }

    /// ADR-0006: a key counts as price-contested when it is marked, or when
    /// its mark cannot be read; an unmarked or unpaid key that reads fine
    /// does not.
    #[tokio::test]
    async fn an_unreadable_mark_counts_as_price_contested() {
        let (pl, _temp) = create_test_paid_list().await;
        let marked: XorName = [0x64; 32];
        let plain: XorName = [0x65; 32];
        let unpaid: XorName = [0x66; 32];
        pl.insert_price_contested(&marked).await.expect("mark");
        pl.insert(&plain).await.expect("insert");

        assert!(pl.counts_as_price_contested(&marked));
        assert!(!pl.counts_as_price_contested(&plain));
        assert!(!pl.counts_as_price_contested(&unpaid));

        let _reader = pl.hold_reader_for_tests().expect("hold reader");
        assert!(pl.counts_as_price_contested(&plain));
        assert!(pl.counts_as_price_contested(&unpaid));
    }

    /// In-memory sink a test subscriber writes its lines to.
    #[cfg(feature = "logging")]
    #[derive(Clone, Default)]
    struct LogSink(Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(feature = "logging")]
    impl<'a> MakeWriter<'a> for LogSink {
        type Writer = MutexGuardWriter<'a, Vec<u8>>;

        fn make_writer(&'a self) -> Self::Writer {
            self.0.make_writer()
        }
    }

    /// ADR-0006: a run of mark reads that fail logs one warning, not one per
    /// key, and the read that ends the run reports how many failed.
    #[cfg(feature = "logging")]
    #[tokio::test]
    async fn a_run_of_unreadable_marks_warns_once() {
        let (pl, _temp) = create_test_paid_list().await;
        let first: XorName = [0x6E; 32];
        let second: XorName = [0x6F; 32];
        pl.insert(&first).await.expect("insert");
        let sink = LogSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .finish();

        with_default(subscriber, || {
            {
                let _reader = pl.hold_reader_for_tests().expect("hold reader");
                for key in [first, second, first] {
                    assert!(pl.counts_as_price_contested(&key));
                }
            }
            assert!(!pl.counts_as_price_contested(&first));
            assert!(!pl.counts_as_price_contested(&second));
        });

        let logs = String::from_utf8(sink.0.lock().expect("sink").clone()).expect("utf-8");
        assert_eq!(
            logs.matches("Cannot read the price-contested mark").count(),
            1,
            "{logs}"
        );
        assert_eq!(
            logs.matches("readable again, after 3 failed reads").count(),
            1,
            "{logs}"
        );
    }

    #[tokio::test]
    async fn test_all_keys() {
        let (pl, _temp) = create_test_paid_list().await;

        let key_a: XorName = [0x01; 32];
        let key_b: XorName = [0x02; 32];
        let key_c: XorName = [0x03; 32];

        pl.insert(&key_a).await.expect("insert 1");
        pl.insert(&key_b).await.expect("insert 2");
        pl.insert(&key_c).await.expect("insert 3");

        let mut keys = pl.all_keys().expect("all_keys");
        keys.sort_unstable();

        let mut expected = vec![key_a, key_b, key_c];
        expected.sort_unstable();

        assert_eq!(keys, expected);
    }

    #[tokio::test]
    async fn test_count() {
        let (pl, _temp) = create_test_paid_list().await;

        assert_eq!(pl.count().expect("count empty"), 0);

        let key1: XorName = [0x10; 32];
        let key2: XorName = [0x20; 32];

        pl.insert(&key1).await.expect("insert 1");
        assert_eq!(pl.count().expect("count after 1"), 1);

        pl.insert(&key2).await.expect("insert 2");
        assert_eq!(pl.count().expect("count after 2"), 2);

        pl.remove(&key1).await.expect("remove 1");
        assert_eq!(pl.count().expect("count after remove"), 1);
    }

    #[tokio::test]
    async fn test_paid_out_of_range_timestamps() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xF0; 32];

        // Initially no timestamp.
        assert!(pl.paid_out_of_range_since(&key).is_none());

        // Set timestamp.
        let before = Instant::now();
        pl.set_paid_out_of_range(&key);
        let after = Instant::now();

        let ts = pl
            .paid_out_of_range_since(&key)
            .expect("timestamp should exist");
        assert!(ts >= before);
        assert!(ts <= after);

        // Setting again should not update (first observation wins).
        std::thread::sleep(std::time::Duration::from_millis(10));
        pl.set_paid_out_of_range(&key);
        let ts2 = pl
            .paid_out_of_range_since(&key)
            .expect("timestamp should still exist");
        assert_eq!(ts, ts2);

        // Clear.
        pl.clear_paid_out_of_range(&key);
        assert!(pl.paid_out_of_range_since(&key).is_none());
    }

    #[tokio::test]
    async fn test_record_out_of_range_timestamps() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xF1; 32];

        assert!(pl.record_out_of_range_since(&key).is_none());

        let before = Instant::now();
        pl.set_record_out_of_range(&key);
        let after = Instant::now();

        let ts = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should exist");
        assert!(ts >= before);
        assert!(ts <= after);

        // Setting again should not update.
        std::thread::sleep(std::time::Duration::from_millis(10));
        pl.set_record_out_of_range(&key);
        let ts2 = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should still exist");
        assert_eq!(ts, ts2);

        // Clear.
        pl.clear_record_out_of_range(&key);
        assert!(pl.record_out_of_range_since(&key).is_none());
    }

    #[tokio::test]
    async fn test_remove_clears_timestamps() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xA0; 32];
        pl.insert(&key).await.expect("insert");

        pl.set_paid_out_of_range(&key);
        pl.set_record_out_of_range(&key);
        assert!(pl.paid_out_of_range_since(&key).is_some());
        assert!(pl.record_out_of_range_since(&key).is_some());

        pl.remove(&key).await.expect("remove");
        assert!(pl.paid_out_of_range_since(&key).is_none());
        assert!(pl.record_out_of_range_since(&key).is_none());
    }

    #[tokio::test]
    async fn test_remove_batch() {
        let (pl, _temp) = create_test_paid_list().await;

        let key1: XorName = [0x01; 32];
        let key2: XorName = [0x02; 32];
        let key3: XorName = [0x03; 32];
        let key4: XorName = [0x04; 32]; // not inserted

        pl.insert(&key1).await.expect("insert 1");
        pl.insert(&key2).await.expect("insert 2");
        pl.insert(&key3).await.expect("insert 3");

        // Set timestamps to verify they get cleared.
        pl.set_paid_out_of_range(&key1);
        pl.set_record_out_of_range(&key2);

        let removed = pl
            .remove_batch(&[key1, key2, key4])
            .await
            .expect("remove_batch");
        assert_eq!(removed, 2); // key1 and key2 existed; key4 did not

        assert!(!pl.contains(&key1).expect("key1 gone"));
        assert!(!pl.contains(&key2).expect("key2 gone"));
        assert!(pl.contains(&key3).expect("key3 still present"));
        assert_eq!(pl.count().expect("count"), 1);

        // Timestamps should be cleared for removed keys.
        assert!(pl.paid_out_of_range_since(&key1).is_none());
        assert!(pl.record_out_of_range_since(&key2).is_none());
    }

    #[tokio::test]
    async fn test_remove_batch_empty() {
        let (pl, _temp) = create_test_paid_list().await;

        let removed = pl.remove_batch(&[]).await.expect("remove_batch empty");
        assert_eq!(removed, 0);
    }

    /// Park the paid-list env's single LMDB writer slot on a test-held write
    /// transaction, so the next tracked write blocks inside its closure.
    ///
    /// Returns once the transaction is open. Dropping the returned sender
    /// releases the slot.
    async fn hold_write_txn(
        pl: &PaidList,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let env = pl.env.clone();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (opened_tx, opened_rx) = tokio::sync::oneshot::channel::<()>();
        let holder = tokio::task::spawn_blocking(move || {
            let _wtxn = env.write_txn().expect("open holder write txn");
            let _ = opened_tx.send(());
            let _ = release_rx.blocking_recv();
        });
        opened_rx.await.expect("holder txn opened");
        (release_tx, holder)
    }

    /// Hold the paid list's write order on a blocking thread, so the next
    /// write waits before its write transaction.
    ///
    /// Returns once the order is held. Dropping the returned sender releases
    /// it.
    async fn hold_write_order(
        pl: &PaidList,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let write_order = Arc::clone(&pl.write_order);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();
        let holder = tokio::task::spawn_blocking(move || {
            let _ordered = write_order.lock();
            let _ = held_tx.send(());
            let _ = release_rx.blocking_recv();
        });
        held_rx.await.expect("write order held");
        (release_tx, holder)
    }

    /// Dropping an `insert` awaiter does not cancel its `spawn_blocking` LMDB
    /// transaction; `wait_idle` must wait for that detached write, and the
    /// paid list must remain usable afterwards.
    #[tokio::test]
    async fn wait_idle_waits_for_detached_insert_blocking_op() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x77; 32];

        let (release, holder) = hold_write_txn(&pl).await;

        // Drop the awaiting future mid-flight: the biased select! polls the
        // insert once — far enough to spawn the blocking task, which parks on
        // the held writer slot — then completes on the ready branch.
        tokio::select! {
            biased;
            res = pl.insert(&key) => {
                panic!("insert must be parked on the writer slot, got {res:?}")
            }
            () = std::future::ready(()) => {}
        }

        // The blocking op is still running: wait_idle must not complete.
        let blocked = tokio::time::timeout(WAIT_IDLE_BLOCKED_PROBE, pl.wait_idle()).await;
        assert!(
            blocked.is_err(),
            "wait_idle returned while the insert blocking op was parked"
        );

        // Release the writer slot: the detached closure commits and exits.
        drop(release);
        holder.await.expect("holder task");
        tokio::time::timeout(WAIT_IDLE_COMPLETE_TIMEOUT, pl.wait_idle())
            .await
            .expect("wait_idle after release");

        // The dropped awaiter did not lose the write: it committed.
        assert!(pl.contains(&key).expect("contains after release"));

        // The paid list remains usable after wait_idle (tracker reopened).
        let key2: XorName = [0x78; 32];
        assert!(pl.insert(&key2).await.expect("insert after wait_idle"));
    }

    /// Same shape as the insert test, for `remove_batch`: a detached batch
    /// removal must hold `wait_idle` open until its transaction commits.
    #[tokio::test]
    async fn wait_idle_waits_for_detached_remove_batch_blocking_op() {
        let (pl, _temp) = create_test_paid_list().await;
        let key_a: XorName = [0x79; 32];
        let key_b: XorName = [0x7A; 32];
        pl.insert(&key_a).await.expect("insert a");
        pl.insert(&key_b).await.expect("insert b");

        let (release, holder) = hold_write_txn(&pl).await;

        let batch = [key_a, key_b];
        tokio::select! {
            biased;
            res = pl.remove_batch(&batch) => {
                panic!("remove_batch must be parked on the writer slot, got {res:?}")
            }
            () = std::future::ready(()) => {}
        }

        let blocked = tokio::time::timeout(WAIT_IDLE_BLOCKED_PROBE, pl.wait_idle()).await;
        assert!(
            blocked.is_err(),
            "wait_idle returned while the remove_batch blocking op was parked"
        );

        drop(release);
        holder.await.expect("holder task");
        tokio::time::timeout(WAIT_IDLE_COMPLETE_TIMEOUT, pl.wait_idle())
            .await
            .expect("wait_idle after release");

        // The dropped awaiter did not lose the batch removal: it committed.
        assert!(!pl.contains(&key_a).expect("key_a removed"));
        assert!(!pl.contains(&key_b).expect("key_b removed"));

        // The paid list remains usable after wait_idle (tracker reopened).
        assert!(pl.insert(&key_a).await.expect("insert after wait_idle"));
    }

    #[tokio::test]
    async fn paid_prune_cursor_advances_past_selected_window() {
        const PAID_KEY_COUNT: usize = 10;
        const START_CURSOR: usize = 2;
        const LAST_SELECTED_OFFSET: usize = 3;
        const EXPECTED_CURSOR: usize = 6;

        let (pl, _temp) = create_test_paid_list().await;
        *pl.paid_prune_cursor.write() = START_CURSOR;

        let scan_start = pl.paid_prune_scan_start(PAID_KEY_COUNT);
        pl.advance_paid_prune_cursor(PAID_KEY_COUNT, scan_start, Some(LAST_SELECTED_OFFSET));

        assert_eq!(*pl.paid_prune_cursor.read(), EXPECTED_CURSOR);
    }

    #[tokio::test]
    async fn paid_prune_cursor_advances_even_without_selected_entry() {
        const PAID_KEY_COUNT: usize = 10;
        const START_CURSOR: usize = 9;
        const EXPECTED_CURSOR: usize = 0;

        let (pl, _temp) = create_test_paid_list().await;
        *pl.paid_prune_cursor.write() = START_CURSOR;

        let scan_start = pl.paid_prune_scan_start(PAID_KEY_COUNT);
        pl.advance_paid_prune_cursor(PAID_KEY_COUNT, scan_start, None);

        assert_eq!(*pl.paid_prune_cursor.read(), EXPECTED_CURSOR);
    }

    #[tokio::test]
    async fn paid_prune_cursor_resets_for_empty_paid_list() {
        const STALE_CURSOR: usize = 7;
        const EMPTY_PAID_KEY_COUNT: usize = 0;
        const EXPECTED_CURSOR: usize = 0;

        let (pl, _temp) = create_test_paid_list().await;
        *pl.paid_prune_cursor.write() = STALE_CURSOR;

        let scan_start = pl.paid_prune_scan_start(EMPTY_PAID_KEY_COUNT);
        pl.advance_paid_prune_cursor(EMPTY_PAID_KEY_COUNT, scan_start, Some(STALE_CURSOR));

        assert_eq!(*pl.paid_prune_cursor.read(), EXPECTED_CURSOR);
    }

    // -- Scenario tests -------------------------------------------------------

    /// #50: Key goes out of range. `set_record_out_of_range` called.
    /// Immediately the elapsed time is less than `PRUNE_HYSTERESIS_DURATION`,
    /// so a prune pass should NOT delete it. We verify the timestamp is
    /// present but recent.
    #[tokio::test]
    async fn scenario_50_hysteresis_prevents_premature_deletion() {
        let hysteresis = crate::replication::config::PRUNE_HYSTERESIS_DURATION;
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x50; 32];

        // Key goes out of range — record the timestamp.
        pl.set_record_out_of_range(&key);

        // Timestamp must be present.
        let since = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should exist after set");

        // Elapsed time is effectively zero — well below hysteresis threshold.
        let elapsed = since.elapsed();
        assert!(
            elapsed < hysteresis,
            "elapsed ({elapsed:?}) should be far below PRUNE_HYSTERESIS_DURATION ({hysteresis:?})",
        );
    }

    /// #51: Key goes out of range, then comes back. Timestamp is cleared.
    /// If the key leaves again, the clock restarts from now.
    #[tokio::test]
    async fn scenario_51_timestamp_reset_on_heal() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x51; 32];

        // Key goes out of range.
        pl.set_record_out_of_range(&key);
        assert!(
            pl.record_out_of_range_since(&key).is_some(),
            "timestamp should exist after going out of range"
        );

        // Partition heals — key comes back in range.
        pl.clear_record_out_of_range(&key);
        assert!(
            pl.record_out_of_range_since(&key).is_none(),
            "timestamp should be cleared after heal"
        );

        // Key goes out of range again — clock must restart.
        let before_second = Instant::now();
        pl.set_record_out_of_range(&key);
        let second_ts = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should exist after second out-of-range");
        assert!(
            second_ts >= before_second,
            "new timestamp should be >= the instant before second set call"
        );
    }

    /// #52: Paid and record out-of-range timestamps are independent.
    /// Clearing one must not affect the other.
    #[tokio::test]
    async fn scenario_52_paid_and_record_timestamps_independent() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x52; 32];

        // Set both timestamps.
        pl.set_paid_out_of_range(&key);
        pl.set_record_out_of_range(&key);
        assert!(pl.paid_out_of_range_since(&key).is_some());
        assert!(pl.record_out_of_range_since(&key).is_some());

        // Clear record — paid must survive.
        pl.clear_record_out_of_range(&key);
        assert!(
            pl.paid_out_of_range_since(&key).is_some(),
            "paid timestamp should survive clearing record timestamp"
        );
        assert!(pl.record_out_of_range_since(&key).is_none());

        // Re-set record, then clear paid — record must survive.
        pl.set_record_out_of_range(&key);
        pl.clear_paid_out_of_range(&key);
        assert!(
            pl.record_out_of_range_since(&key).is_some(),
            "record timestamp should survive clearing paid timestamp"
        );
        assert!(pl.paid_out_of_range_since(&key).is_none());
    }

    /// #23: Inserting then removing a key from the paid list clears both
    /// the persistence entry and any in-memory out-of-range timestamps.
    #[tokio::test]
    async fn scenario_23_paid_list_entry_removed() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x23; 32];

        // Insert key and attach out-of-range timestamps.
        pl.insert(&key).await.expect("insert");
        pl.set_paid_out_of_range(&key);
        pl.set_record_out_of_range(&key);

        // Remove — should clear everything.
        let removed = pl.remove(&key).await.expect("remove");
        assert!(removed, "key should have existed");
        assert!(
            !pl.contains(&key).expect("contains check"),
            "key should be gone from paid list"
        );
        assert!(
            pl.paid_out_of_range_since(&key).is_none(),
            "paid timestamp should be cleaned up on remove"
        );
        assert!(
            pl.record_out_of_range_since(&key).is_none(),
            "record timestamp should be cleaned up on remove"
        );
    }

    /// #13: Responsible range shrink — out-of-range records have their
    /// timestamp recorded, are NOT pruned before `PRUNE_HYSTERESIS_DURATION`,
    /// and new in-range keys are still accepted while out-of-range keys
    /// await expiry.
    #[tokio::test]
    async fn scenario_13_responsible_range_shrink() {
        let hysteresis = crate::replication::config::PRUNE_HYSTERESIS_DURATION;
        let (pl, _temp) = create_test_paid_list().await;

        let out_of_range_key: XorName = [0x13; 32];
        let in_range_key: XorName = [0x14; 32];

        // Insert both keys initially (simulating they were once in range).
        pl.insert(&out_of_range_key)
            .await
            .expect("insert out-of-range");
        pl.insert(&in_range_key).await.expect("insert in-range");

        // Range shrinks: out_of_range_key is no longer in responsibility range.
        // Record RecordOutOfRangeFirstSeen.
        pl.set_record_out_of_range(&out_of_range_key);
        let first_seen = pl
            .record_out_of_range_since(&out_of_range_key)
            .expect("timestamp should be recorded for out-of-range key");

        // Key must NOT be pruned yet — elapsed time is far below hysteresis.
        let elapsed = first_seen.elapsed();
        assert!(
            elapsed < hysteresis,
            "elapsed {elapsed:?} should be below PRUNE_HYSTERESIS_DURATION \
             ({hysteresis:?}) — key must not be pruned yet"
        );

        // The key should still exist in the paid list (not deleted).
        assert!(
            pl.contains(&out_of_range_key).expect("contains"),
            "out-of-range key should still be retained within hysteresis window"
        );

        // In-range key is unaffected — no out-of-range timestamp set.
        assert!(
            pl.record_out_of_range_since(&in_range_key).is_none(),
            "in-range key should have no out-of-range timestamp"
        );

        // New in-range keys are still accepted during this period.
        let new_key: XorName = [0x15; 32];
        let was_new = pl.insert(&new_key).await.expect("insert new key");
        assert!(
            was_new,
            "new in-range keys should still be accepted while out-of-range keys await expiry"
        );
        assert!(
            pl.contains(&new_key).expect("contains new"),
            "newly inserted in-range key should be present"
        );
    }

    /// #46: Bootstrap claim first-seen is recorded and follows
    /// first-observation-wins semantics.
    #[test]
    fn scenario_46_bootstrap_claim_first_seen_recorded() {
        let grace_period = crate::replication::config::BOOTSTRAP_CLAIM_GRACE_PERIOD;
        let peer = saorsa_core::identity::PeerId::from_bytes([0x46; 32]);
        let mut state = crate::replication::types::NeighborSyncState::new_cycle(vec![peer]);

        let first_ts = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3))
            .unwrap_or_else(Instant::now);
        let observed = state.observe_bootstrap_claim(peer, first_ts, grace_period);
        assert_eq!(
            observed,
            crate::replication::types::BootstrapClaimObservation::WithinGrace {
                first_seen: first_ts
            }
        );

        // Verify recorded.
        assert_eq!(
            state.bootstrap_claims.get(&peer),
            Some(&first_ts),
            "first-seen timestamp should be recorded"
        );
        assert_eq!(
            state.bootstrap_claim_history.get(&peer),
            Some(&first_ts),
            "first-ever timestamp should be retained"
        );

        // Observe again while still active — must NOT overwrite
        // (first-observation-wins).
        let later_ts = Instant::now();
        let observed = state.observe_bootstrap_claim(peer, later_ts, grace_period);
        assert_eq!(
            observed,
            crate::replication::types::BootstrapClaimObservation::WithinGrace {
                first_seen: first_ts
            }
        );
        assert_eq!(
            state.bootstrap_claims.get(&peer),
            Some(&first_ts),
            "second insert must not overwrite the original timestamp"
        );
    }

    /// #48: Peer P first claimed bootstrapping >24 h ago.  On next interaction
    /// the claim age exceeds `BOOTSTRAP_CLAIM_GRACE_PERIOD` and the node emits
    /// `BootstrapClaimAbuse` evidence.
    #[test]
    fn scenario_48_bootstrap_claim_abuse_after_grace_period() {
        let grace_period = crate::replication::config::BOOTSTRAP_CLAIM_GRACE_PERIOD;
        let peer = saorsa_core::identity::PeerId::from_bytes([0x48; 32]);
        let mut state = crate::replication::types::NeighborSyncState::new_cycle(vec![peer]);

        // Record a first-seen timestamp >24 h ago.
        // `Instant::checked_sub` can fail on Windows where the epoch is
        // process-start, so fall back to a recent instant when the platform
        // cannot represent the backdated time (the claim-age assertion is
        // skipped in that case since the subtraction itself proves nothing
        // about production behaviour).
        let grace_plus_margin = grace_period + std::time::Duration::from_hours(1);
        let first_seen = Instant::now()
            .checked_sub(grace_plus_margin)
            .unwrap_or_else(Instant::now);
        state.bootstrap_claims.insert(peer, first_seen);
        state.bootstrap_claim_history.insert(peer, first_seen);

        // On platforms that support the backdated instant, verify claim age.
        let claim_age = Instant::now().duration_since(first_seen);
        if claim_age > std::time::Duration::from_secs(1) {
            assert!(
                claim_age > grace_period,
                "claim age {claim_age:?} should exceed grace period {grace_period:?}",
            );
        }

        // Caller constructs BootstrapClaimAbuse evidence.
        let evidence =
            crate::replication::types::FailureEvidence::BootstrapClaimAbuse { peer, first_seen };

        let crate::replication::types::FailureEvidence::BootstrapClaimAbuse {
            peer: p,
            first_seen: fs,
        } = evidence
        else {
            unreachable!("evidence was just constructed as BootstrapClaimAbuse");
        };
        assert_eq!(p, peer);
        assert_eq!(fs, first_seen);
    }

    /// #49: Bootstrap claim is cleared when a peer responds normally.
    #[test]
    fn scenario_49_bootstrap_claim_cleared() {
        let grace_period = crate::replication::config::BOOTSTRAP_CLAIM_GRACE_PERIOD;
        let peer = saorsa_core::identity::PeerId::from_bytes([0x49; 32]);
        let mut state = crate::replication::types::NeighborSyncState::new_cycle(vec![peer]);

        // Record a bootstrap claim.
        let first_seen = Instant::now();
        let _ = state.observe_bootstrap_claim(peer, first_seen, grace_period);
        assert!(
            state.bootstrap_claims.contains_key(&peer),
            "claim should exist after insert"
        );

        // Peer responded normally — clear only the active claim.
        state.clear_active_bootstrap_claim(&peer);
        assert!(
            !state.bootstrap_claims.contains_key(&peer),
            "claim should be gone after normal response"
        );
        assert!(
            state.bootstrap_claim_history.contains_key(&peer),
            "claim history should remain so the peer cannot claim bootstrapping again"
        );

        let repeated = state.observe_bootstrap_claim(peer, Instant::now(), grace_period);
        assert_eq!(
            repeated,
            crate::replication::types::BootstrapClaimObservation::Repeated { first_seen },
            "a second bootstrap claim should be classified as repeated abuse"
        );
    }
}
