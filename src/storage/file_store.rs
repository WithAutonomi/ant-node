//! One immutable file per chunk, content-addressed, with the filesystem as the
//! only authority.
//!
//! ```text
//! {root}/chunks/                     store root
//! {root}/chunks/layout.json          versioned layout marker
//! {root}/chunks/.lock                advisory single-process guard
//! {root}/chunks/<xy>/<64-hex>        xy = the LAST two hex characters of the address
//! {root}/chunks/<xy>/.tmp.<pid>.<n>  an in-flight write, in the destination directory
//! ```
//!
//! # Why the *last* two hex characters
//!
//! A node holds keys for which it is among the [`CLOSE_GROUP_SIZE`] closest, so its
//! holdings share roughly `log2(N / CLOSE_GROUP_SIZE)` leading bits with its own node
//! ID, and that shared prefix grows as the network grows. Sharding on a prefix therefore
//! does not degrade, it collapses: at ~800 nodes a two-hex prefix already resolves to
//! about two distinct directories, and past a million nodes even a four-hex prefix
//! resolves to one. Close-group membership constrains the leading bits and places no
//! constraint at all on the trailing ones, and the address is a BLAKE3 output, so the
//! last byte is uniform by construction at every network size.
//!
//! 256 shards keeps a 24 GiB node at ~23 files per directory and a 1 TiB node at ~977,
//! for 1 MiB of directory inodes. The scheme and depth are recorded in `layout.json` at
//! creation so a future layout can be detected rather than silently misread.
//!
//! # Why lowercase hex names
//!
//! NTFS and default APFS fold case. Under an encoding with both cases (base64url,
//! base58) two distinct 32-byte keys can share one case-folded filename, which is a
//! silent overwrite. Hex has one case-folded form per key, and no hex string can ever
//! spell a reserved Windows device name (`CON`, `NUL`, `AUX`, `COM1`, ...) because none
//! of those letters is in `0-9a-f`. The full 64-character key stays in the filename, so
//! a `find` over the tree recovers the whole store even if the directory layer is lost.
//!
//! [`CLOSE_GROUP_SIZE`]: crate::ant_protocol::CLOSE_GROUP_SIZE

use crate::ant_protocol::{XorName, MAX_CHUNK_SIZE, XORNAME_LEN};
use crate::error::{Error, Result};
use crate::logging::{debug, info, trace, warn};
use crate::storage::StorageStats;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::spawn_blocking;
use tokio_util::task::TaskTracker;

/// Directory under the node root that holds the chunk files.
pub const CHUNKS_DIR_NAME: &str = "chunks";

/// Name of the layout marker written once at store creation.
pub const LAYOUT_FILE_NAME: &str = "layout.json";

/// Name of the advisory single-process lock file.
const LOCK_FILE_NAME: &str = ".lock";

/// Prefix that marks an in-flight write. Never a valid chunk name (chunk names are
/// exactly [`CHUNK_NAME_LEN`] lowercase hex characters, and `.` is not hex).
const TEMP_PREFIX: &str = ".tmp.";

/// Number of shard directories. One level, `00` through `ff`.
const SHARD_COUNT: usize = 256;

/// Length of a chunk filename: the full address in lowercase hex.
const CHUNK_NAME_LEN: usize = XORNAME_LEN * 2;

/// How often to re-query available disk space, in seconds.
///
/// Matches the LMDB store's cadence so the capacity predicate behaves identically
/// for callers that only ask "is there room at all".
const DISK_CHECK_INTERVAL_SECS: u64 = 5;

/// Allocation granularity assumed when charging a pending write against free space.
///
/// Every filesystem we support allocates in units of at least 4 KiB, so a write of
/// `n` bytes consumes at least `ceil(n / 4096) * 4096`. One extra unit covers the
/// directory entry and inode.
const ALLOC_UNIT: u64 = 4096;

/// How many times a publish retries a transient Windows sharing violation.
const RENAME_RETRY_ATTEMPTS: u32 = 5;

/// Base backoff between those retries; the wait grows linearly with the attempt.
const RENAME_RETRY_BACKOFF: Duration = Duration::from_millis(20);

/// Minimum age before an orphaned temp file is swept when this process could not take
/// the store lock, i.e. when another process might legitimately own that temp.
const UNLOCKED_TEMP_SWEEP_MIN_AGE: Duration = Duration::from_secs(3600);

/// Longest absolute path a chunk file may need, checked once at open.
///
/// Windows caps a non-verbatim path at `MAX_PATH` (260) including the terminating NUL.
/// Rust's standard library transparently switches to the `\\?\` verbatim form for long
/// absolute paths, so this is a warning rather than a hard failure, but an operator who
/// buries the node root ten directories deep should hear about it before the first write
/// fails rather than after.
#[cfg(windows)]
const WINDOWS_PATH_WARN_LEN: usize = 240;

/// The on-disk layout marker.
///
/// Written once when the store directory is created and read on every subsequent open.
/// Nothing in this survey of comparable stores (IPFS flatfs, Storj, borgbackup) shipped
/// an in-place re-sharder, and all three paid for it. Recording the scheme costs one
/// small file and is the difference between changing the default later and never being
/// able to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreLayout {
    /// Marker schema version. A store written by a newer schema is refused.
    pub schema: u32,
    /// How a chunk address maps to a shard directory.
    pub scheme: String,
    /// How many hex characters of the address name the shard directory.
    pub shard_chars: u8,
    /// How many directory levels of sharding.
    pub depth: u8,
    /// How a chunk address maps to a filename.
    pub name_encoding: String,
}

/// Marker schema this build writes and understands.
const LAYOUT_SCHEMA: u32 = 1;
/// Shard scheme this build implements: the trailing hex characters of the address.
const LAYOUT_SCHEME_SUFFIX_HEX: &str = "suffix-hex";
/// Filename encoding this build implements.
const LAYOUT_NAME_LOWER_HEX: &str = "lower-hex";

impl Default for StoreLayout {
    fn default() -> Self {
        Self {
            schema: LAYOUT_SCHEMA,
            scheme: LAYOUT_SCHEME_SUFFIX_HEX.to_string(),
            shard_chars: 2,
            depth: 1,
            name_encoding: LAYOUT_NAME_LOWER_HEX.to_string(),
        }
    }
}

impl StoreLayout {
    /// Return an error unless this build can read a store written with this layout.
    fn check_supported(&self) -> Result<()> {
        if self.schema > LAYOUT_SCHEMA {
            return Err(Error::Storage(format!(
                "Chunk store layout schema {} is newer than this build understands ({LAYOUT_SCHEMA}). \
                 Refusing to open rather than misread the store.",
                self.schema
            )));
        }
        if self.scheme != LAYOUT_SCHEME_SUFFIX_HEX {
            return Err(Error::Storage(format!(
                "Chunk store uses shard scheme '{}', this build implements '{LAYOUT_SCHEME_SUFFIX_HEX}'",
                self.scheme
            )));
        }
        if self.shard_chars != 2 || self.depth != 1 {
            return Err(Error::Storage(format!(
                "Chunk store uses {} shard characters at depth {}, this build implements 2 at depth 1",
                self.shard_chars, self.depth
            )));
        }
        if self.name_encoding != LAYOUT_NAME_LOWER_HEX {
            return Err(Error::Storage(format!(
                "Chunk store names files with '{}', this build implements '{LAYOUT_NAME_LOWER_HEX}'",
                self.name_encoding
            )));
        }
        Ok(())
    }
}

/// Configuration for [`FileStore`].
#[derive(Debug, Clone)]
pub struct FileStoreConfig {
    /// Node root directory. The store lives at `{root_dir}/chunks/`.
    pub root_dir: PathBuf,
    /// Verify `BLAKE3(content) == address` on read.
    pub verify_on_read: bool,
    /// Free bytes to keep on the storage partition. Writes are refused below this.
    pub disk_reserve: u64,
}

/// Outcome of a single write attempt, used to keep the duplicate accounting honest.
enum PutOutcome {
    /// The chunk was newly published.
    New,
    /// The chunk was already on disk.
    Duplicate,
}

/// Snapshot of free space, plus what has been written since it was taken.
#[derive(Debug)]
struct CapacitySnapshot {
    /// When `available` was measured. `None` means never.
    measured_at: Option<Instant>,
    /// Free bytes reported by the filesystem at `measured_at`.
    available: u64,
    /// Bytes published since `measured_at`, charged against `available`.
    ///
    /// Cleared by a fresh measurement, which already accounts for them.
    written_since: u64,
    /// Bytes reserved by writes that have not landed yet.
    ///
    /// Deliberately **not** cleared by a measurement: a `statvfs` taken while writes are
    /// in flight reports space those writes are about to consume, so forgetting their
    /// reservations at that moment would hand the same bytes out twice. That is precisely
    /// the over-admission the reservation exists to prevent.
    in_flight: u64,
}

/// Size-aware free-space predicate with a short-lived cache.
///
/// Free bytes alone stopped being a sufficient answer the moment chunks became files:
/// a caller wants to know whether *this* write fits, not whether the disk is non-empty.
/// The cache keeps the common case at one `statvfs` per interval while staying correct
/// under a burst, because bytes written since the measurement are charged against it.
#[derive(Debug)]
struct CapacityGuard {
    /// Directory whose partition is measured.
    dir: PathBuf,
    /// Free bytes to keep unused.
    reserve: u64,
    /// The cached measurement.
    snapshot: parking_lot::Mutex<CapacitySnapshot>,
}

impl CapacitySnapshot {
    /// Free bytes, less everything written or promised since the measurement.
    fn free_estimate(&self) -> u64 {
        self.available
            .saturating_sub(self.written_since)
            .saturating_sub(self.in_flight)
    }
}

impl CapacityGuard {
    /// Create a guard over the partition hosting `dir`.
    fn new(dir: PathBuf, reserve: u64) -> Self {
        Self {
            dir,
            reserve,
            snapshot: parking_lot::Mutex::new(CapacitySnapshot {
                measured_at: None,
                available: 0,
                written_since: 0,
                in_flight: 0,
            }),
        }
    }

    /// Bytes actually consumed on disk by a payload of `len` bytes.
    fn charge(len: u64) -> u64 {
        // Round the payload up to the allocation unit, then add one unit for the
        // directory entry and inode.
        len.div_ceil(ALLOC_UNIT)
            .saturating_mul(ALLOC_UNIT)
            .saturating_add(ALLOC_UNIT)
    }

    /// Free bytes right now, or `None` if the question could not be answered.
    ///
    /// Deliberately separate from [`Self::measure`], which folds a failure into an error
    /// the caller cannot tell from "below the reserve".
    fn measure_available(&self) -> Option<u64> {
        let mut snapshot = self.snapshot.lock();
        match self.measure(&mut snapshot) {
            Ok(()) => Some(snapshot.free_estimate()),
            Err(_) => None,
        }
    }

    /// Query the filesystem and refresh the snapshot.
    fn measure(&self, snapshot: &mut CapacitySnapshot) -> Result<()> {
        let available = fs2::available_space(&self.dir)
            .map_err(|e| Error::Storage(format!("Failed to query available disk space: {e}")))?;
        snapshot.available = available;
        // Reservations survive: their bytes are not on the platter yet, so the fresh
        // measurement does not include them.
        snapshot.written_since = 0;
        snapshot.measured_at = Some(Instant::now());
        Ok(())
    }

    /// Test `needed` against the snapshot, refreshing it if it is stale or short.
    ///
    /// Only *passing* results are cached, so a low-space condition is rechecked on every
    /// call and freed space is noticed promptly.
    fn admit(&self, snapshot: &mut CapacitySnapshot, needed: u64) -> Result<()> {
        let want = self.reserve.saturating_add(Self::charge(needed));

        let cache_fresh = snapshot
            .measured_at
            .is_some_and(|t| t.elapsed().as_secs() < DISK_CHECK_INTERVAL_SECS);
        if cache_fresh && snapshot.free_estimate() >= want {
            return Ok(());
        }

        self.measure(snapshot)?;
        if snapshot.free_estimate() < want {
            // Do not cache a failing result: `measured_at` is left set so the next call
            // still re-measures, because the branch above only short-circuits a pass.
            return Err(Error::Storage(format!(
                "Insufficient disk space: {:.2} GiB available, {:.2} GiB reserve required. \
                 Free disk space or increase the partition to continue storing chunks.",
                bytes_to_gib(snapshot.free_estimate()),
                bytes_to_gib(self.reserve),
            )));
        }
        Ok(())
    }

    /// Drop the cached measurement so the next question hits the filesystem.
    fn invalidate(&self) {
        let mut snapshot = self.snapshot.lock();
        snapshot.measured_at = None;
        snapshot.written_since = 0;
    }

    /// Return `Ok(())` if a write of `needed` bytes would fit. Charges nothing.
    fn check(&self, needed: u64) -> Result<()> {
        let mut snapshot = self.snapshot.lock();
        self.admit(&mut snapshot, needed)
    }

    /// Admit a write of `needed` bytes and charge it in the same critical section.
    ///
    /// Checking and charging separately is the bug this exists to prevent: dozens of
    /// protocol handlers can each pass against the same cached measurement before any of
    /// them has written a byte, and collectively cross the reserve.
    ///
    /// The returned [`Reservation`] settles itself when dropped, so a caller whose future
    /// is dropped mid-write cannot strand it. Nothing else ever decrements the in-flight
    /// count, so a stranded reservation would be permanent, and enough of them would make
    /// an empty disk look full until the process restarted.
    fn reserve(self: &Arc<Self>, needed: u64) -> Result<Reservation> {
        {
            let mut snapshot = self.snapshot.lock();
            self.admit(&mut snapshot, needed)?;
            snapshot.in_flight = snapshot.in_flight.saturating_add(Self::charge(needed));
        }
        Ok(Reservation {
            capacity: Arc::clone(self),
            bytes: needed,
            settled: false,
        })
    }

    /// Give back a reservation whose write did not happen.
    fn release(&self, needed: u64) {
        let mut snapshot = self.snapshot.lock();
        snapshot.in_flight = snapshot.in_flight.saturating_sub(Self::charge(needed));
    }

    /// Turn a reservation into bytes that are now on disk.
    fn commit_reservation(&self, needed: u64) {
        let charge = Self::charge(needed);
        let mut snapshot = self.snapshot.lock();
        snapshot.in_flight = snapshot.in_flight.saturating_sub(charge);
        snapshot.written_since = snapshot.written_since.saturating_add(charge);
    }

    /// Credit a completed delete back to the cached measurement.
    fn record_removed(&self, len: u64) {
        let mut snapshot = self.snapshot.lock();
        snapshot.written_since = snapshot.written_since.saturating_sub(Self::charge(len));
    }
}

/// A charged, unsettled write.
///
/// Held by whatever is actually doing the write, so the charge is released even if the
/// caller's future is dropped and only the blocking closure survives.
struct Reservation {
    /// The guard this was taken from.
    capacity: Arc<CapacityGuard>,
    /// Payload size, before rounding.
    bytes: u64,
    /// Whether it has already been accounted for.
    settled: bool,
}

impl Reservation {
    /// The write landed: move the charge from in-flight to written.
    fn commit(mut self) {
        self.capacity.commit_reservation(self.bytes);
        self.settled = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.settled {
            self.capacity.release(self.bytes);
        }
    }
}

/// What is behind a chunk's name on disk.
///
/// Four answers, not two, because "could not read it" must never be treated as "wrong":
/// replacing a chunk is destructive, and off Unix it truncates the file in place, so a
/// transient fault would turn a healthy sole copy into an empty one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredBytes {
    /// The bytes are there and hash to the name.
    Good,
    /// The bytes are there and do not.
    Wrong,
    /// There is nothing behind the name.
    Absent,
    /// The question could not be answered this time.
    Unreadable,
}

/// Convert a byte count to GiB for human-readable log messages.
#[allow(clippy::cast_precision_loss)] // display only — sub-byte precision is irrelevant
fn bytes_to_gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

/// Content-addressed store holding one immutable file per chunk.
///
/// The filesystem is the sole authority. The in-memory index is a cache of what the
/// directory tree already contains, rebuilt from directory entries at every open, and
/// every mutation of it mirrors a filesystem operation that has *already* completed.
/// Bitcask's issue #114 is the cautionary tale for the opposite order: an index that is
/// rebuilt at startup and then mutated in anticipation drifts, and the drift is silent.
#[derive(Debug)]
pub struct FileStore {
    /// Store configuration.
    config: FileStoreConfig,
    /// `{root_dir}/chunks`.
    chunks_dir: PathBuf,
    /// Every address whose file is published, in ascending order.
    ///
    /// `BTreeSet` rather than a hash set because `all_keys()` must be sorted (the
    /// commitment builder truncates with `take(cap)` *before* the Merkle tree sorts, so
    /// an unstable order would make the node's published commitment depend on iteration
    /// luck), and because it never spikes memory while growing.
    index: Arc<parking_lot::RwLock<BTreeSet<XorName>>>,
    /// One mutex per shard, serialising writers of the same address.
    ///
    /// LMDB gave exactly-once `put` semantics for free: the duplicate test happened
    /// inside the write transaction. Two threads publishing the same address here would
    /// otherwise both see an absent file, both rename, and both report "newly stored",
    /// double-counting the chunk. The lane is indexed by the address's LAST byte for the
    /// same reason the shard is: a node's keys share their leading bytes, so lanes keyed
    /// on the first byte would all collapse into one.
    write_lanes: Arc<Vec<parking_lot::Mutex<()>>>,
    /// Operation counters, same shape as the LMDB store reported.
    stats: parking_lot::RwLock<StorageStats>,
    /// Which of the 256 shard directories are known to exist, so a steady-state write
    /// does not pay a `create_dir_all` syscall.
    shards_present: Arc<parking_lot::Mutex<[bool; SHARD_COUNT]>>,
    /// Size-aware free-space predicate.
    capacity: Arc<CapacityGuard>,
    /// Monotonic counter that makes temp filenames unique within this store.
    temp_seq: AtomicU64,
    /// Random per-instance discriminator for temp filenames.
    nonce: u32,
    /// Held for the store's lifetime when this process owns the directory.
    ///
    /// `None` means another process holds it. The store still opens (LMDB allowed
    /// multi-process access, so refusing here would be a new failure mode), but the
    /// startup temp sweep becomes age-gated so it can never delete a live write.
    _lock: Option<File>,
    /// Tracks every blocking task, so [`FileStore::wait_idle`] can wait for writes that
    /// outlived their awaiting future.
    blocking_tracker: TaskTracker,
    /// Test-only gate read-acquired at the top of the put blocking closure.
    ///
    /// Tests hold the write half to park an in-flight write on the blocking pool, which
    /// is the shape a `select!` losing to a shutdown token leaves behind.
    #[cfg(any(test, feature = "test-utils"))]
    test_put_gate: Arc<parking_lot::RwLock<()>>,
}

impl FileStore {
    /// Open (or create) the store at `{root_dir}/chunks/`.
    ///
    /// Sweeps orphaned temp files, then rebuilds the index from directory entries.
    /// The scan reads names only: it never `stat`s an entry and never reads a chunk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the directory cannot be created, the layout marker
    /// is unreadable or describes a layout this build does not implement, or the scan
    /// fails.
    pub async fn new(config: FileStoreConfig) -> Result<Self> {
        let chunks_dir = config.root_dir.join(CHUNKS_DIR_NAME);
        std::fs::create_dir_all(&chunks_dir).map_err(|e| {
            Error::Storage(format!(
                "Failed to create chunk store directory {}: {e}",
                chunks_dir.display()
            ))
        })?;

        check_path_budget(&chunks_dir);

        let layout = read_or_write_layout(&chunks_dir)?;
        layout.check_supported()?;

        let lock = acquire_store_lock(&chunks_dir)?;
        let locked = lock.is_some();

        let scan_dir = chunks_dir.clone();
        let scan = spawn_blocking(move || scan_store(&scan_dir, locked))
            .await
            .map_err(|e| Error::Storage(format!("Chunk store scan task failed: {e}")))??;

        let ScanResult {
            keys,
            shards_present,
            swept_temps,
            skipped,
        } = scan;

        let key_count = keys.len();
        // Build from a sorted vector: bulk-building packs every B-tree node to its
        // capacity, where repeated `insert` converges on ~68% fill for the same keys.
        let index: BTreeSet<XorName> = keys.into_iter().collect();

        if swept_temps > 0 {
            info!("Chunk store: removed {swept_temps} orphaned temporary file(s) from interrupted writes");
        }
        if skipped > 0 {
            warn!("Chunk store: ignored {skipped} directory entr(ies) that are not chunk files");
        }
        info!(
            "Chunk store open at {} ({key_count} chunks)",
            chunks_dir.display()
        );

        let capacity = Arc::new(CapacityGuard::new(chunks_dir.clone(), config.disk_reserve));

        Ok(Self {
            config,
            chunks_dir,
            index: Arc::new(parking_lot::RwLock::new(index)),
            write_lanes: Arc::new(
                std::iter::repeat_with(|| parking_lot::Mutex::new(()))
                    .take(SHARD_COUNT)
                    .collect(),
            ),
            stats: parking_lot::RwLock::new(StorageStats::default()),
            shards_present: Arc::new(parking_lot::Mutex::new(shards_present)),
            capacity,
            temp_seq: AtomicU64::new(0),
            nonce: rand::random(),
            _lock: lock,
            blocking_tracker: TaskTracker::new(),
            #[cfg(any(test, feature = "test-utils"))]
            test_put_gate: Arc::new(parking_lot::RwLock::new(())),
        })
    }

    /// Store a chunk.
    ///
    /// Publishing is a rename within the destination directory, so the final name can
    /// never appear on partial content: the name *is* the hash, and the content is
    /// fully written and flushed before the name exists.
    ///
    /// # Returns
    ///
    /// `true` if the chunk was newly stored, `false` if it was already present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the content does not hash to `address`, the disk
    /// is too full, or the write fails.
    pub async fn put(&self, address: &XorName, content: &[u8]) -> Result<bool> {
        let computed = crate::client::compute_address(content);
        if computed != *address {
            return Err(Error::Storage(format!(
                "Content address mismatch: expected {}, computed {}",
                hex::encode(address),
                hex::encode(computed)
            )));
        }
        // The read path refuses anything over the ceiling, so writing one would create a
        // file the store could never read back and could never repair.
        if content.len() > MAX_CHUNK_SIZE {
            return Err(Error::Storage(format!(
                "Chunk {} is {} bytes, over the {MAX_CHUNK_SIZE} byte maximum",
                hex::encode(address),
                content.len()
            )));
        }

        // An indexed name is not proof of the bytes under it. The index is built from
        // names, by the startup scan and by a completed publish, and a name can outlive
        // what it points at: off Unix a chunk is created under its final name before its
        // bytes are written, so a crash leaves a short file wearing a real name, and rot
        // leaves a full-length one. Answering "already have it" to the copy that would fix
        // either is how a node discards its own repair and is never offered another.
        //
        // So the bytes decide. Checked before the reservation below, so re-storing a chunk
        // this node already holds stays a no-op on a full disk.
        if self.index.read().contains(address) {
            if let Some(answer) = self.settle_indexed_duplicate(address, content).await {
                return answer;
            }
        }

        let len = content.len() as u64;
        // Reserved after the duplicate test so re-storing an existing chunk stays a
        // harmless no-op on a full disk, matching the LMDB store's ordering.
        let reservation = self.capacity.reserve(len)?;

        let shard = self.chunks_dir.join(shard_name(address));
        let final_path = shard.join(hex::encode(address));
        let temp_path = shard.join(self.next_temp_name());
        let payload = content.to_vec();
        let lanes = Arc::clone(&self.write_lanes);
        let index = Arc::clone(&self.index);
        let shards_present = Arc::clone(&self.shards_present);
        let chunks_dir = self.chunks_dir.clone();
        let lane = shard_index(address);
        let key = *address;
        #[cfg(any(test, feature = "test-utils"))]
        let test_put_gate = Arc::clone(&self.test_put_gate);

        let outcome = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<PutOutcome> {
                // Test-only: parks here while a test holds the write half.
                #[cfg(any(test, feature = "test-utils"))]
                let _test_put_gate = test_put_gate.read();
                let _lane = lanes.get(lane).map(parking_lot::Mutex::lock);
                // `mkdir` plus a directory flush are syscalls, so they belong here and
                // not on a runtime worker.
                ensure_shard_dir(&chunks_dir, &shard, lane, &shards_present)?;
                let outcome = publish(&temp_path, &final_path, &payload, &shard)?;
                // Index inside the lane, and only after the rename has returned. A
                // concurrent delete of the same address therefore cannot interleave
                // between publishing the file and admitting the key.
                index.write().insert(key);
                // Settled here, inside the work, so a dropped awaiter cannot strand it.
                if matches!(outcome, PutOutcome::New) {
                    reservation.commit();
                }
                Ok(outcome)
            })
            .await
            .map_err(|e| Error::Storage(format!("Chunk store put task failed: {e}")))??;

        match outcome {
            PutOutcome::Duplicate => {
                // The file was already on disk, and its name is not evidence its contents
                // are right. The startup scan indexes by name without reading anything,
                // and on Windows a crash mid-write leaves a partial file under a real
                // chunk name. Trusting the name here would acknowledge a chunk that was
                // never stored, and then discard the good copy arriving to repair it.
                // Every answer handled, because three of the four must not report the
                // chunk as stored. A caller that hears success acts on it: a client drops
                // its own copy, replication marks the key held, and the copier takes it
                // out of the legacy-only set.
                match self.stored_bytes_match(address).await {
                    StoredBytes::Good => {
                        {
                            let mut stats = self.stats.write();
                            stats.duplicates = stats.duplicates.saturating_add(1);
                        }
                        Ok(false)
                    }
                    StoredBytes::Wrong => {
                        warn!(
                            "Chunk {} was already on disk but its contents are wrong; \
                             replacing it with the copy just offered",
                            hex::encode(address)
                        );
                        self.repair(address, content).await.map(|()| true)
                    }
                    // The name was taken a moment ago and is not now, or was never a
                    // readable chunk file. Either way nothing holds these bytes, so say so
                    // rather than reporting a chunk that is not there.
                    StoredBytes::Absent => Err(Error::Storage(format!(
                        "Chunk {} was reported already on disk but nothing is there. Not \
                         reporting it as stored.",
                        hex::encode(address)
                    ))),
                    // Replacing on an unanswered question would destroy a healthy copy,
                    // and reporting success would discard the offered one.
                    StoredBytes::Unreadable => Err(Error::Storage(format!(
                        "Chunk {} is on disk but could not be read to check it. Not \
                         replacing it, and not reporting it as stored.",
                        hex::encode(address)
                    ))),
                }
            }
            PutOutcome::New => {
                let mut stats = self.stats.write();
                stats.chunks_stored = stats.chunks_stored.saturating_add(1);
                stats.bytes_stored = stats.bytes_stored.saturating_add(len);
                drop(stats);
                debug!("Stored chunk {} ({len} bytes)", hex::encode(address));
                Ok(true)
            }
        }
    }

    /// Flush every directory a chunk can live in, so the names in them are durable.
    ///
    /// Byte integrity is not the whole of what the pre-retirement proof has to establish.
    /// A chunk whose contents are on the platter but whose *name* is not is still lost to
    /// a power loss, and a publish whose rename landed and whose directory flush failed
    /// leaves exactly that: the next attempt sees the name, the next verification reads
    /// the right bytes, and nothing goes back to retry the flush. So the proof flushes
    /// them itself rather than trusting that each publish did.
    ///
    /// Cheap: at most 257 directory flushes for a store of any size, and nothing off Unix,
    /// where directories cannot be flushed and the retirement marker covers the same
    /// ground instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on the first directory that cannot be flushed. The
    /// caller must treat that as a proof it did not get.
    pub fn flush_namespace(&self) -> Result<()> {
        fsync_dir(&self.chunks_dir).map_err(|e| {
            Error::Storage(format!(
                "Could not flush {}: {e}",
                self.chunks_dir.display()
            ))
        })?;
        let present = *self.shards_present.lock();
        for (shard, _) in present.iter().enumerate().filter(|(_, here)| **here) {
            let dir = self.chunks_dir.join(format!("{shard:02x}"));
            fsync_dir(&dir)
                .map_err(|e| Error::Storage(format!("Could not flush {}: {e}", dir.display())))?;
        }
        Ok(())
    }

    /// Decide what to do about a write of a chunk the index already names.
    ///
    /// `None` means the index was wrong and there is nothing on disk, so the caller
    /// publishes it as new. Everything else is the answer.
    async fn settle_indexed_duplicate(
        &self,
        address: &XorName,
        content: &[u8],
    ) -> Option<Result<bool>> {
        match self.stored_bytes_match(address).await {
            StoredBytes::Good => {
                trace!("Chunk {} already exists", hex::encode(address));
                {
                    let mut stats = self.stats.write();
                    stats.duplicates = stats.duplicates.saturating_add(1);
                }
                Some(Ok(false))
            }
            StoredBytes::Wrong => {
                warn!(
                    "Chunk {} is indexed but its bytes are wrong; replacing it with the \
                     copy just offered",
                    hex::encode(address)
                );
                Some(self.repair(address, content).await.map(|()| true))
            }
            // Indexed but gone: publish it fresh rather than replacing something that is
            // not there.
            StoredBytes::Absent => None,
            // Unanswerable this time. Do not touch what is there, and do not tell the
            // caller the chunk is safely stored either: a client would take that as an
            // acknowledgement and drop the only other copy.
            StoredBytes::Unreadable => Some(Err(Error::Storage(format!(
                "Chunk {} is indexed but could not be read to check it. Not replacing it, \
                 and not reporting it as stored.",
                hex::encode(address)
            )))),
        }
    }

    /// The size of the file behind `address`, if there is one.
    ///
    /// One `metadata` call, no read. Used where an indexed name has to be checked against
    /// what a caller is offering before that offer is turned away.
    #[must_use]
    pub fn stored_len(&self, address: &XorName) -> Option<usize> {
        std::fs::metadata(self.chunk_path(address))
            .ok()
            .filter(std::fs::Metadata::is_file)
            .and_then(|m| usize::try_from(m.len()).ok())
    }

    /// Whether the file already stored under `address` really hashes to it.
    async fn stored_bytes_match(&self, address: &XorName) -> StoredBytes {
        match self.get_raw(address).await {
            Ok(Some(bytes)) if crate::client::compute_address(&bytes) == *address => {
                StoredBytes::Good
            }
            Ok(Some(_)) => StoredBytes::Wrong,
            Ok(None) => StoredBytes::Absent,
            // NOT the same as wrong. A file that could not be read this once may be
            // perfectly good, and off Unix replacing it means opening it with `truncate`,
            // which would destroy a healthy sole copy on the strength of a transient
            // fault. Say so and let the caller leave it alone.
            Err(e) => {
                debug!("Could not read {} to check it: {e}", hex::encode(address));
                StoredBytes::Unreadable
            }
        }
    }

    /// Replace the file behind an address with known-good bytes, atomically.
    ///
    /// Unlike [`Self::put`], this deliberately publishes **over** an existing name. It
    /// exists for one caller: repairing a file whose bytes no longer hash to their own
    /// name, from a copy held elsewhere, before that copy is destroyed. Doing it as
    /// delete-then-put would leave a window where the only remaining copy is the one
    /// about to be deleted, and any failure in that window is unrecoverable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if `content` does not hash to `address`, or the write
    /// fails. The old file is left untouched on every error path.
    pub async fn repair(&self, address: &XorName, content: &[u8]) -> Result<()> {
        let computed = crate::client::compute_address(content);
        if computed != *address {
            return Err(Error::Storage(format!(
                "Refusing to repair {} with content that hashes to {}",
                hex::encode(address),
                hex::encode(computed)
            )));
        }
        // The replacement exists alongside the original until the rename, so the room for
        // it has to be there first. Reserved rather than merely checked: a plain check
        // passes against a cached measurement, so concurrent repairs and PUTs can each be
        // admitted against the same headroom and cross the reserve together.
        let reservation = self.capacity.reserve(content.len() as u64)?;

        let shard = self.chunks_dir.join(shard_name(address));
        let final_path = shard.join(hex::encode(address));
        let temp_path = shard.join(self.next_temp_name());
        let payload = content.to_vec();
        let lanes = Arc::clone(&self.write_lanes);
        let index = Arc::clone(&self.index);
        let shards_present = Arc::clone(&self.shards_present);
        let chunks_dir = self.chunks_dir.clone();
        let lane = shard_index(address);
        let key = *address;

        self.blocking_tracker
            .spawn_blocking(move || -> Result<()> {
                let _lane = lanes.get(lane).map(parking_lot::Mutex::lock);
                ensure_shard_dir(&chunks_dir, &shard, lane, &shards_present)?;
                write_and_replace(&temp_path, &final_path, &payload, &shard)?;
                index.write().insert(key);
                Ok(())
            })
            .await
            .map_err(|e| Error::Storage(format!("Chunk store repair task failed: {e}")))??;

        // Released rather than committed, because a repair is not a new chunk: it took the
        // place of one that was already there, and charging it again would make the guard
        // believe the store is larger than it is.
        //
        // But it is not free either. The file it replaced may have been shorter, which is
        // exactly the case a repair fixes, so the difference is real bytes the cached
        // measurement does not know about. Rather than guess at the net, throw the
        // measurement away: the next admission takes a fresh one.
        drop(reservation);
        self.invalidate_capacity_cache();

        debug!("Repaired chunk {}", hex::encode(address));
        Ok(())
    }

    /// Retrieve a chunk, verifying it against its address when configured to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on an I/O failure, or when verification fails. A
    /// chunk whose bytes do not hash to its name is removed and dropped from the index
    /// before the error is returned, so it leaves `all_keys()` and ordinary replication
    /// repairs it.
    pub async fn get(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        let Some(content) = self.read_file(address).await? else {
            trace!("Chunk {} not found", hex::encode(address));
            return Ok(None);
        };

        if self.config.verify_on_read {
            let computed = crate::client::compute_address(&content);
            if computed != *address {
                {
                    let mut stats = self.stats.write();
                    stats.verification_failures = stats.verification_failures.saturating_add(1);
                }
                warn!(
                    "Chunk verification failed: expected {}, computed {}",
                    hex::encode(address),
                    hex::encode(computed)
                );
                self.quarantine_corrupt(address).await;
                return Err(Error::Storage(format!(
                    "Chunk verification failed for {}",
                    hex::encode(address)
                )));
            }
        }

        let len = content.len() as u64;
        {
            let mut stats = self.stats.write();
            stats.chunks_retrieved = stats.chunks_retrieved.saturating_add(1);
            stats.bytes_retrieved = stats.bytes_retrieved.saturating_add(len);
        }
        debug!("Retrieved chunk {} ({len} bytes)", hex::encode(address));
        Ok(Some(content))
    }

    /// Retrieve raw chunk bytes without content-address verification.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on an I/O failure.
    pub async fn get_raw(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        self.read_file(address).await
    }

    /// Check whether a chunk is stored.
    ///
    /// An in-memory lookup: no syscall, no I/O.
    ///
    /// # Errors
    ///
    /// Never fails. The signature keeps the shape the LMDB store had, because callers
    /// treat the error as "assume absent".
    pub fn exists(&self, address: &XorName) -> Result<bool> {
        Ok(self.index.read().contains(address))
    }

    /// Delete a chunk, returning whether it was present.
    ///
    /// `unlink` returns the blocks to the filesystem immediately. That is the whole
    /// point of this store: no free list, no compaction, no free space required to
    /// reclaim space.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the file exists but cannot be removed. The index
    /// keeps the key in that case, because the bytes are still on disk.
    pub async fn delete(&self, address: &XorName) -> Result<bool> {
        let path = self.chunk_path(address);
        let lanes = Arc::clone(&self.write_lanes);
        let index = Arc::clone(&self.index);
        let lane = shard_index(address);
        let key = *address;

        let (existed, freed) = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<(bool, u64)> {
                let _lane = lanes.get(lane).map(parking_lot::Mutex::lock);
                let len = std::fs::metadata(&path).map_or(0, |m| m.len());
                let removed = match std::fs::remove_file(&path) {
                    Ok(()) => {
                        // Without this a crash can resurrect the entry on ext4, XFS,
                        // btrfs and APFS: the unlink is in the page cache, the directory
                        // is not.
                        if let Some(shard) = path.parent() {
                            fsync_dir_best_effort(shard);
                        }
                        true
                    }
                    // Already gone: the index was stale. Still a successful delete as
                    // far as the caller is concerned.
                    Err(e) if e.kind() == ErrorKind::NotFound => false,
                    Err(e) => {
                        return Err(Error::Storage(format!(
                            "Failed to delete chunk file {}: {e}",
                            path.display()
                        )))
                    }
                };
                // Index only after the filesystem operation has succeeded. On the error
                // path above the entry stays, because the bytes are still on disk.
                let was_indexed = index.write().remove(&key);
                Ok((removed || was_indexed, if removed { len } else { 0 }))
            })
            .await
            .map_err(|e| Error::Storage(format!("Chunk store delete task failed: {e}")))??;

        if freed > 0 {
            self.capacity.record_removed(freed);
            debug!("Deleted chunk {}", hex::encode(address));
        }
        Ok(existed)
    }

    /// Return every stored key, in ascending order.
    ///
    /// The order is a correctness requirement, not a convenience: the commitment
    /// builder truncates the responsible subset with `take(cap)` before the Merkle tree
    /// sorts it, so an unstable order would make the node's published commitment depend
    /// on iteration luck.
    ///
    /// # Errors
    ///
    /// Never fails. The signature matches the LMDB store's.
    // Async without awaiting anything, deliberately: the whole point of this store is
    // that the key set is already in memory. Callers are spread across the replication
    // engine and cannot all be de-async'd in this change.
    //
    // Two lint names because they were renamed between toolchains, and `unknown_lints`
    // so whichever one the compiler in use has never heard of stays quiet.
    #[allow(unknown_lints)]
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn all_keys(&self) -> Result<Vec<XorName>> {
        Ok(self.index.read().iter().copied().collect())
    }

    /// Number of chunks currently stored.
    ///
    /// # Errors
    ///
    /// Never fails. The signature matches the LMDB store's.
    pub fn current_chunks(&self) -> Result<u64> {
        Ok(self.index.read().len() as u64)
    }

    /// Operation statistics, with the live chunk count filled in.
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        let mut stats = self.stats.read().clone();
        stats.current_chunks = self.index.read().len() as u64;
        stats
    }

    /// The node root directory this store was configured with.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.config.root_dir
    }

    /// The directory holding the shard tree.
    #[must_use]
    pub fn chunks_dir(&self) -> &Path {
        &self.chunks_dir
    }

    /// Reject work early when the disk cannot take another chunk at all.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] when free space is below the configured reserve.
    pub fn check_capacity(&self) -> Result<()> {
        self.capacity.check(0)
    }

    /// Three-way answer to "can this store take a write right now".
    ///
    /// Kept distinct from [`Self::check_capacity`] because a failed free-space query and a
    /// genuinely full disk are not the same thing, and the replication verification cycle
    /// depends on the difference: a full disk is a standing condition worth minutes of
    /// backoff, while a `statvfs` that failed says nothing about available space and may
    /// well succeed on the next pass.
    #[must_use]
    pub fn capacity_verdict(&self) -> crate::storage::CapacityVerdict {
        match self.capacity.measure_available() {
            Some(available) if available < self.capacity.reserve => {
                crate::storage::CapacityVerdict::Full
            }
            Some(_) => crate::storage::CapacityVerdict::Writable,
            None => crate::storage::CapacityVerdict::Unknown,
        }
    }

    /// Reject work early when the disk cannot take `bytes` more.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] when the write would not fit above the reserve.
    pub fn check_capacity_for(&self, bytes: u64) -> Result<()> {
        self.capacity.check(bytes)
    }

    /// Force the next capacity question to re-measure the filesystem.
    ///
    /// Called after the legacy environment is removed, because that is a step change in
    /// free space that the short-lived cache would otherwise hide for a few seconds.
    pub fn invalidate_capacity_cache(&self) {
        self.capacity.invalidate();
    }

    /// Test-only handle to the put gate.
    ///
    /// Hold the write half to park the next write inside its blocking closure, for
    /// example to prove that shutdown waits for a write whose awaiter was dropped.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_put_gate(&self) -> Arc<parking_lot::RwLock<()>> {
        Arc::clone(&self.test_put_gate)
    }

    /// Wait until every blocking task this store spawned has finished.
    ///
    /// Dropping the awaiting future does not cancel a `spawn_blocking` closure, so
    /// shutdown has to wait for the closure itself.
    pub async fn wait_idle(&self) {
        self.blocking_tracker.close();
        self.blocking_tracker.wait().await;
        self.blocking_tracker.reopen();
    }

    /// Absolute path of a chunk file.
    fn chunk_path(&self, address: &XorName) -> PathBuf {
        self.chunks_dir
            .join(shard_name(address))
            .join(hex::encode(address))
    }

    /// A temp name unique to this store instance, and distinguishable from a chunk name.
    ///
    /// The nonce matters: two `FileStore`s on one root in one process share a PID, and a
    /// recycled PID collides with an age-gated leftover. Either way `create_new` would
    /// fail and surface as a spurious write error.
    fn next_temp_name(&self) -> String {
        let seq = self.temp_seq.fetch_add(1, Ordering::Relaxed);
        format!(
            "{TEMP_PREFIX}{}.{:08x}.{seq}",
            std::process::id(),
            self.nonce
        )
    }

    /// Read a chunk file, dropping the index entry if the file has vanished.
    async fn read_file(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        let path = self.chunk_path(address);
        let read = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<Option<Vec<u8>>> {
                match open_regular(&path) {
                    Ok(Some(f)) => read_bounded(f, &path).map(Some),
                    Ok(None) => Ok(None),
                    Err(e) => Err(e),
                }
            })
            .await
            .map_err(|e| Error::Storage(format!("Chunk store read task failed: {e}")))??;

        if read.is_none() && self.forget_if_absent(address).await {
            // The file went away underneath us. Stop advertising the key so the close
            // group notices the shortfall and replication puts it back.
            warn!(
                "Chunk {} is indexed but its file is missing; dropped from the index so \
                 replication can repair it",
                hex::encode(address)
            );
        }
        Ok(read)
    }

    /// Drop an index entry whose file is genuinely gone.
    ///
    /// Re-checks under the address's write lane, so a chunk republished between the
    /// failing read and this call keeps its entry.
    async fn forget_if_absent(&self, address: &XorName) -> bool {
        let path = self.chunk_path(address);
        let lanes = Arc::clone(&self.write_lanes);
        let index = Arc::clone(&self.index);
        let lane = shard_index(address);
        let key = *address;
        self.blocking_tracker
            .spawn_blocking(move || {
                let _lane = lanes.get(lane).map(parking_lot::Mutex::lock);
                if path.exists() {
                    return false;
                }
                index.write().remove(&key)
            })
            .await
            .unwrap_or(false)
    }

    /// Remove a chunk whose bytes do not match its name, and stop advertising it.
    ///
    /// Re-reads and re-verifies under the address's write lane first. A read that failed
    /// verification is rare enough that paying for one extra read is worth never
    /// discarding a chunk that a concurrent write had already repaired.
    async fn quarantine_corrupt(&self, address: &XorName) {
        let path = self.chunk_path(address);
        let lanes = Arc::clone(&self.write_lanes);
        let index = Arc::clone(&self.index);
        let lane = shard_index(address);
        let key = *address;
        let outcome =
            self.blocking_tracker
                .spawn_blocking(move || -> std::io::Result<bool> {
                    let _lane = lanes.get(lane).map(parking_lot::Mutex::lock);
                    // Nothing is thrown away without proof. A re-read that fails says the
                    // question could not be answered this time, not that the bytes are wrong,
                    // and a repair may have published a good copy since the read that brought
                    // us here. Treating either as corruption deletes a chunk this node has.
                    let buf = match open_regular(&path) {
                        Ok(Some(f)) => read_bounded(f, &path)
                            .map_err(|e| std::io::Error::other(e.to_string()))?,
                        Ok(None) => {
                            index.write().remove(&key);
                            return Ok(true);
                        }
                        Err(e) => return Err(std::io::Error::other(e.to_string())),
                    };
                    if crate::client::compute_address(&buf) == key {
                        // Repaired between the failing read and now. Leave it alone.
                        return Ok(false);
                    }
                    std::fs::remove_file(&path)?;
                    index.write().remove(&key);
                    Ok(true)
                })
                .await;
        match outcome {
            Ok(Ok(true)) => warn!(
                "Removed corrupt chunk file {}; replication will repair it",
                hex::encode(address)
            ),
            Ok(Ok(false)) => debug!(
                "Chunk {} verified on re-read; leaving it in place",
                hex::encode(address)
            ),
            Ok(Err(e)) => warn!(
                "Corrupt chunk {} could not be removed: {e}. It stays indexed and will \
                 keep failing verification until the operator intervenes",
                hex::encode(address)
            ),
            Err(e) => warn!("Corrupt-chunk removal task failed: {e}"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Free functions
// ────────────────────────────────────────────────────────────────────────────

/// Create the destination shard directory if this store has not seen it yet.
///
/// A newly created directory entry is only durable once its parent is flushed; without
/// that a crash could take the directory and the chunk inside it together.
fn ensure_shard_dir(
    chunks_dir: &Path,
    dir: &Path,
    shard: usize,
    present: &parking_lot::Mutex<[bool; SHARD_COUNT]>,
) -> Result<()> {
    if present.lock().get(shard).copied().unwrap_or(false) {
        return Ok(());
    }
    std::fs::create_dir_all(dir).map_err(|e| {
        Error::Storage(format!(
            "Failed to create shard directory {}: {e}",
            dir.display()
        ))
    })?;
    // Load-bearing, like the flush that publishes a chunk into this directory. Until the
    // parent is flushed the shard's own entry can be lost, and losing it loses every chunk
    // inside it. Reporting the shard present anyway would let the very first chunk written
    // into it count as durably stored.
    fsync_dir(chunks_dir).map_err(|e| {
        Error::Storage(format!(
            "Created shard directory {} but could not flush {}: {e}. Not marking the shard \
             usable, because a directory that is not durable cannot hold a chunk that is.",
            dir.display(),
            chunks_dir.display()
        ))
    })?;
    if let Some(slot) = present.lock().get_mut(shard) {
        *slot = true;
    }
    Ok(())
}

/// Shard directory index for an address: its last byte.
fn shard_index(address: &XorName) -> usize {
    address.last().copied().unwrap_or(0) as usize
}

/// Shard directory name for an address: the last two characters of its hex form.
fn shard_name(address: &XorName) -> String {
    format!("{:02x}", shard_index(address))
}

/// True for a string of hex digits in either case.
fn is_hex_any_case(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Move an entry aside under a name that can never be read as a chunk.
fn quarantine_entry(path: &Path) {
    let aside = path.with_extension("not-a-chunk");
    match std::fs::rename(path, &aside) {
        Ok(()) => warn!(
            "Chunk store: moved {} aside to {}; a name that differs from a chunk name only \
             by case collides with it on Windows and macOS",
            path.display(),
            aside.display()
        ),
        Err(e) => warn!(
            "Chunk store: {} collides with a chunk name by case folding and could not be \
             moved aside: {e}. Rename or delete it.",
            path.display()
        ),
    }
}

/// True for a string of lowercase hex digits only.
fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Decode a filename back into the address it names, or `None` if it is not one.
///
/// Rejects uppercase deliberately. On a case-folding filesystem (NTFS, default APFS)
/// accepting both cases would let one file answer to two index entries.
fn decode_chunk_name(name: &str) -> Option<XorName> {
    if name.len() != CHUNK_NAME_LEN || !is_lower_hex(name) {
        return None;
    }
    let bytes = hex::decode(name).ok()?;
    XorName::try_from(bytes.as_slice()).ok()
}

/// Flush a directory and report whether it worked, for callers outside this module.
///
/// For the one caller whose next step is destructive: retirement moves the legacy
/// environment aside and then deletes it under its new name, so if the rename has not
/// reached the disk when the delete lands, a power loss brings the environment back under
/// its old name with its contents gone.
///
/// # Errors
///
/// Returns the underlying I/O error. Off Unix there is no way to flush a directory through
/// the standard library, so this reports success without being able to promise anything;
/// see [`fsync_dir`].
pub fn fsync_path(path: &Path) -> std::io::Result<()> {
    fsync_dir(path)
}

/// Flush a directory so a rename or creation inside it survives power loss.
///
/// Best effort by design. Linux and XFS require it, macOS accepts it with undocumented
/// effect, and Windows offers no way to do it at all through the standard library. The
/// content is content-addressed and re-replicable, so a lost directory entry costs a
/// refetch rather than data. Pretending otherwise in the code would be dishonest.
#[cfg(unix)]
fn fsync_dir_best_effort(path: &Path) {
    if let Err(e) = fsync_dir(path) {
        debug!("Directory flush of {} failed: {e}", path.display());
    }
}

/// Flush a directory, reporting whether it worked.
///
/// Used where the answer is load-bearing: a chunk copied out of the legacy store is only
/// durable once its directory entry is, and that copy is what permits the legacy store to
/// be deleted.
#[cfg(unix)]
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

/// Off Unix there is no way to flush a directory through the standard library, so this
/// reports success without being able to promise anything.
///
/// That is why the publish path off Unix does not use a rename at all: it creates the
/// chunk under its final name and flushes the file, which Microsoft documents as flushing
/// the creation metadata with it. Directory creation has no equivalent, so the guarantee
/// there rests on the pre-retirement pass, which re-reads every chunk before the legacy
/// store is deleted, and on the operator gate that keeps retirement off a platform until
/// forced power loss has been shown to hold old-or-new on it.
///
/// Returns a `Result` so the callers that must handle a flush failure on Unix read the
/// same on every platform.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn fsync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// No-op on platforms with no way to flush a directory handle.
#[cfg(not(unix))]
fn fsync_dir_best_effort(_path: &Path) {}

/// Warn if the deepest chunk path this store can produce is close to `MAX_PATH`.
#[cfg(windows)]
fn check_path_budget(chunks_dir: &Path) {
    // Measured absolute, because that is what the filesystem sees. A relative root is the
    // case that still fails hard at MAX_PATH, since the standard library's long-path
    // handling only applies to paths it resolves as absolute.
    let absolute = if chunks_dir.is_absolute() {
        chunks_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_or_else(|_| chunks_dir.to_path_buf(), |cwd| cwd.join(chunks_dir))
    };
    // `{chunks_dir}\{xy}\{64 hex}` — two separators, two shard characters, 64 name
    // characters.
    let deepest = absolute.as_os_str().len() + 1 + 2 + 1 + CHUNK_NAME_LEN;
    if deepest > WINDOWS_PATH_WARN_LEN {
        warn!(
            "Chunk file paths will be {deepest} characters, close to the {} character \
             Windows limit. Move the node root closer to the drive letter if writes start \
             failing.",
            WINDOWS_PATH_WARN_LEN
        );
    }
}

/// No-op where path length is not a practical constraint.
#[cfg(not(windows))]
fn check_path_budget(_chunks_dir: &Path) {}

/// Write `bytes` to `path` durably, for small metadata files outside the shard tree.
///
/// # Errors
///
/// Returns [`Error::Storage`] if the file cannot be written or published.
pub fn write_file_durably(path: &Path, bytes: &[u8]) -> Result<()> {
    write_file_atomic(path, bytes)
}

/// Write `bytes` to `path` so a reader sees either the old content or the new.
fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let Some(dir) = path.parent() else {
        return Err(Error::Storage(format!(
            "Refusing to write {} — it has no parent directory",
            path.display()
        )));
    };
    let temp = dir.join(format!(
        "{TEMP_PREFIX}{}.{:08x}.marker",
        std::process::id(),
        rand::random::<u32>()
    ));
    write_temp(&temp, bytes)?;
    // Through the retry, because these small files (the layout marker, the migration
    // state) are rewritten while the node runs, and on Windows a scanner holding a handle
    // for a few milliseconds turns an ordinary rewrite into a hard failure.
    rename_with_retry(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        Error::Storage(format!("Failed to publish {}: {e}", path.display()))
    })?;
    fsync_dir_best_effort(dir);
    Ok(())
}

/// Read the layout marker, writing the current one if the store is new.
fn read_or_write_layout(chunks_dir: &Path) -> Result<StoreLayout> {
    let path = chunks_dir.join(LAYOUT_FILE_NAME);
    match read_small_file(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            Error::Storage(format!(
                "Chunk store layout marker {} is unreadable: {e}. Refusing to open rather \
                 than guess the layout.",
                path.display()
            ))
        }),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if store_has_entries(chunks_dir) {
                warn!(
                    "Chunk store at {} has data but no layout marker. Adopting it under \
                     the current scheme, which is the only one this build implements. If \
                     it was written by a build with a different layout its chunks will \
                     appear to be missing.",
                    chunks_dir.display()
                );
            }
            let layout = StoreLayout::default();
            let bytes = serde_json::to_vec_pretty(&layout)
                .map_err(|e| Error::Storage(format!("Failed to encode chunk store layout: {e}")))?;
            write_file_atomic(&path, &bytes)?;
            debug!("Wrote chunk store layout marker to {}", path.display());
            Ok(layout)
        }
        Err(e) => Err(Error::Storage(format!(
            "Failed to read chunk store layout marker {}: {e}",
            path.display()
        ))),
    }
}

/// Whether the store directory already holds at least one shard.
fn store_has_entries(chunks_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(chunks_dir) else {
        return false;
    };
    entries.filter_map(std::result::Result::ok).any(|e| {
        e.file_name()
            .to_str()
            .is_some_and(|n| n.len() == 2 && is_lower_hex(n))
    })
}

/// Largest a metadata marker may be before it is treated as corrupt.
const MAX_MARKER_BYTES: u64 = 64 * 1024;

/// Read a small metadata file, refusing an implausibly large one.
///
/// The chunk path is bounded for exactly this reason; the markers live in the same data
/// directory and deserve the same ceiling.
///
/// # Errors
///
/// Returns an I/O error, including `NotFound`, so callers can distinguish "no marker yet".
pub fn read_small_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    let read = file.take(MAX_MARKER_BYTES + 1).read_to_end(&mut bytes)?;
    if read as u64 > MAX_MARKER_BYTES {
        return Err(std::io::Error::other(format!(
            "{} is larger than the {MAX_MARKER_BYTES} byte limit for a marker file",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Take the store lock.
///
/// `Ok(None)` means no lock file could be created at all, which is not a concurrency
/// hazard and is tolerated (the startup temp sweep then becomes age-gated). Another
/// process actually holding the lock **is** refused: unlike LMDB, which was genuinely
/// multi-process safe, two of these stores on one directory keep independent in-memory
/// indices, so both would report the same write as new and each would keep serving keys
/// the other had deleted.
///
/// # Errors
///
/// Returns [`Error::Storage`] when another process owns the directory.
fn acquire_store_lock(chunks_dir: &Path) -> Result<Option<File>> {
    let path = chunks_dir.join(LOCK_FILE_NAME);
    let file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            warn!(
                "Could not create the chunk store lock {}: {e}. Startup will only sweep \
                 clearly abandoned interrupted writes.",
                path.display()
            );
            return Ok(None);
        }
    };
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(e) => Err(Error::Storage(format!(
            "Another process already has the chunk store at {} open ({e}). Two nodes \
             cannot share one data directory: each keeps its own index and they would \
             disagree about what is stored. Stop the other node first.",
            chunks_dir.display()
        ))),
    }
}

/// What a startup scan found.
struct ScanResult {
    /// Every published address, ascending.
    keys: Vec<XorName>,
    /// Which shard directories already exist.
    shards_present: [bool; SHARD_COUNT],
    /// Orphaned temp files removed.
    swept_temps: usize,
    /// Entries that were neither a chunk nor one of ours.
    skipped: usize,
}

/// Rebuild the key set from directory entries.
///
/// Reads names only. A `stat` per entry costs about ten times the enumeration on Linux
/// and macOS and fifty to sixty times on Windows, and buys nothing: the filename is the
/// key, and the content is verified on read.
fn scan_store(chunks_dir: &Path, locked: bool) -> Result<ScanResult> {
    let mut result = ScanResult {
        keys: Vec::new(),
        shards_present: [false; SHARD_COUNT],
        swept_temps: 0,
        skipped: 0,
    };

    let top = std::fs::read_dir(chunks_dir).map_err(|e| {
        Error::Storage(format!(
            "Failed to enumerate chunk store {}: {e}",
            chunks_dir.display()
        ))
    })?;

    for entry in top {
        let entry = entry.map_err(|e| {
            Error::Storage(format!(
                "Failed to read an entry of {}: {e}",
                chunks_dir.display()
            ))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            result.skipped = result.skipped.saturating_add(1);
            continue;
        };
        if name == LAYOUT_FILE_NAME || name == LOCK_FILE_NAME {
            continue;
        }
        if name.starts_with(TEMP_PREFIX) {
            if sweep_temp(&entry.path(), locked) {
                result.swept_temps = result.swept_temps.saturating_add(1);
            }
            continue;
        }
        if name.len() != 2 || !is_lower_hex(name) {
            warn!(
                "Chunk store: ignoring unexpected entry {name} in {}",
                chunks_dir.display()
            );
            result.skipped = result.skipped.saturating_add(1);
            continue;
        }
        let Ok(shard) = u8::from_str_radix(name, 16) else {
            result.skipped = result.skipped.saturating_add(1);
            continue;
        };
        // `shards_present` is set inside `scan_shard`, on success only. Setting it from
        // the name alone would make a stray regular file called `ab` look like a shard
        // that already exists, and every write to that shard would then fail with a
        // misleading error until the node was restarted.
        scan_shard(&entry.path(), shard, locked, &mut result)?;
    }

    result.keys.sort_unstable();
    result.keys.dedup();
    Ok(result)
}

/// Scan one shard directory into `result`.
fn scan_shard(dir: &Path, shard: u8, locked: bool, result: &mut ScanResult) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // A stray file named like a shard, or a directory removed between the two reads.
        // Neither is fatal, and neither marks the shard as present.
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            warn!(
                "Chunk store: {} is not a shard directory ({e}); ignoring it",
                dir.display()
            );
            result.skipped = result.skipped.saturating_add(1);
            return Ok(());
        }
        // Anything else is a real fault: a permission problem, exhausted descriptors, or
        // failing hardware. Opening with a shard's worth of keys silently missing would
        // make the node under-claim in its published commitment and stop serving chunks
        // it still holds and is answerable for, so refuse to open at all.
        Err(e) => {
            return Err(Error::Storage(format!(
                "Failed to enumerate shard {}: {e}. Refusing to open with an incomplete \
                 key set.",
                dir.display()
            )))
        }
    };
    if let Some(slot) = result.shards_present.get_mut(shard as usize) {
        *slot = true;
    }

    for entry in entries {
        let entry =
            entry.map_err(|e| Error::Storage(format!("Failed to read {}: {e}", dir.display())))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            result.skipped = result.skipped.saturating_add(1);
            continue;
        };
        if name.starts_with(TEMP_PREFIX) {
            if sweep_temp(&entry.path(), locked) {
                result.swept_temps = result.swept_temps.saturating_add(1);
            }
            continue;
        }
        let Some(key) = decode_chunk_name(name) else {
            if name.len() == CHUNK_NAME_LEN && is_hex_any_case(name) {
                // A case-folded twin of a real chunk name. On NTFS and default APFS the
                // existence check in the write path folds onto it, so a paid write would
                // be answered "already stored" and its bytes dropped. Move it aside.
                quarantine_entry(&entry.path());
            } else {
                warn!(
                    "Chunk store: ignoring non-chunk entry {name} in {}",
                    dir.display()
                );
            }
            result.skipped = result.skipped.saturating_add(1);
            continue;
        };
        // `file_type` comes from the directory entry itself on Linux and macOS and from
        // the enumeration on Windows, so this is not the per-entry `stat` the scan
        // deliberately avoids. A pipe, socket, device or directory wearing a chunk name
        // must never enter the index: nothing downstream can read it, and it would sit in
        // the published commitment forever.
        match entry.file_type() {
            Ok(kind) if kind.is_file() => {}
            Ok(_) => {
                warn!(
                    "Chunk store: {name} in {} is not a regular file; ignoring it",
                    dir.display()
                );
                result.skipped = result.skipped.saturating_add(1);
                continue;
            }
            // Not the same as knowing it is not a file. Treating an unanswered question
            // as a no would drop a real chunk from the index and from the commitment
            // while its bytes sit on disk, and the node would not serve it again until
            // some later restart happened to succeed. Fail the scan instead: an index
            // that is missing keys must never be published as this node's key set.
            Err(e) => {
                return Err(Error::Storage(format!(
                    "Could not tell what {name} in {} is: {e}. Refusing to publish an \
                     index that may be missing chunks.",
                    dir.display()
                )));
            }
        }
        // A file in the wrong shard is unreachable through `chunk_path`, so indexing it
        // would make the index claim a key the read path cannot find.
        if shard_index(&key) != shard as usize {
            warn!(
                "Chunk store: {name} is filed under shard {shard:02x} but belongs in {:02x}; \
                 ignoring it. Move it or delete it.",
                shard_index(&key)
            );
            result.skipped = result.skipped.saturating_add(1);
            continue;
        }
        result.keys.push(key);
    }
    Ok(())
}

/// Remove one orphaned temp file. Returns whether it went.
///
/// When this process owns the store lock, any temp file is by definition an interrupted
/// write of a previous run and goes immediately. When it does not, another process may
/// legitimately be writing it, so only clearly abandoned ones are swept.
fn sweep_temp(path: &Path, force: bool) -> bool {
    if !force {
        let abandoned = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .and_then(|t| {
                std::time::SystemTime::now()
                    .duration_since(t)
                    .map_err(|e| std::io::Error::other(e.to_string()))
            })
            .is_ok_and(|age| age >= UNLOCKED_TEMP_SWEEP_MIN_AGE);
        if !abandoned {
            return false;
        }
    }
    match std::fs::remove_file(path) {
        Ok(()) => {
            debug!("Removed orphaned temporary file {}", path.display());
            true
        }
        Err(e) => {
            debug!("Could not remove {}: {e}", path.display());
            false
        }
    }
}

/// Open a chunk file, refusing anything that is not a regular file.
///
/// `Ok(None)` means the file is not there. A named pipe wearing a valid chunk name would
/// otherwise block the opening thread forever: `open` on a FIFO with no writer does not
/// return, and enough of them would exhaust the blocking pool and stall every file and
/// database operation in the process. `O_NOFOLLOW` refuses a symlink for the same reason,
/// and both are checked on the handle rather than the path, so nothing can be swapped
/// underneath between the check and the open.
fn open_regular(path: &Path) -> Result<Option<File>> {
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = OpenOptions::new().read(true).open(path);

    let file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::Storage(format!(
                "Failed to open chunk file {}: {e}",
                path.display()
            )))
        }
    };
    let is_regular = file.metadata().is_ok_and(|m| m.file_type().is_file());
    if !is_regular {
        return Err(Error::Storage(format!(
            "{} is not a regular file; refusing to read it as a chunk",
            path.display()
        )));
    }
    Ok(Some(file))
}

/// Read a chunk file, refusing anything larger than a chunk can legitimately be.
///
/// A corrupt, sparse, or locally planted file wearing a valid 64-hex name would
/// otherwise be read straight into memory, so a single bad entry could exhaust the node
/// during an ordinary GET or an audit response.
fn read_bounded(file: File, path: &Path) -> Result<Vec<u8>> {
    let ceiling = MAX_CHUNK_SIZE as u64;
    let mut buf = Vec::new();
    let read = file.take(ceiling + 1).read_to_end(&mut buf).map_err(|e| {
        Error::Storage(format!("Failed to read chunk file {}: {e}", path.display()))
    })?;
    if read as u64 > ceiling {
        return Err(Error::Storage(format!(
            "Chunk file {} is larger than the {ceiling} byte maximum; refusing to read it",
            path.display()
        )));
    }
    Ok(buf)
}

/// Whether a Windows error is one a scanner or indexer holding a handle would produce.
///
/// `ERROR_ACCESS_DENIED`, `ERROR_SHARING_VIOLATION`, `ERROR_LOCK_VIOLATION`. Every other
/// failure is deterministic and retrying it only burns a blocking thread.
fn is_windows_sharing_violation(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

/// Publish `temp_path` as `final_path`, retrying a transient sharing violation.
///
/// On Windows an antivirus scanner or the search indexer can hold a handle to either
/// file for a few milliseconds after it is created, and `MoveFileEx` fails outright
/// rather than queueing. Retrying a bounded number of times turns that from a failed
/// write into a short pause. Every other error returns immediately.
fn rename_with_retry(temp_path: &Path, final_path: &Path) -> std::io::Result<()> {
    let mut last = match std::fs::rename(temp_path, final_path) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    if !cfg!(windows) || !is_windows_sharing_violation(&last) {
        return Err(last);
    }
    for attempt in 1..=RENAME_RETRY_ATTEMPTS {
        std::thread::sleep(RENAME_RETRY_BACKOFF * attempt);
        match std::fs::rename(temp_path, final_path) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Write `payload` and publish it as `final_path`, replacing whatever is there.
///
/// Success here means the bytes are durable, not merely written. The repair path this
/// serves runs during the pre-retirement pass, where a chunk that fails to match its
/// address is rewritten from the legacy store and the legacy store is then deleted. A
/// replacement that a power loss can undo would leave that chunk with the wrong bytes and
/// no other copy.
fn write_and_replace(
    temp_path: &Path,
    final_path: &Path,
    payload: &[u8],
    shard: &Path,
) -> Result<()> {
    // Unix: an intra-directory rename is atomic, so a reader sees the old content or the
    // new one and never an absence, and the directory flush is what makes it durable.
    #[cfg(unix)]
    {
        write_temp(temp_path, payload)?;
        if let Err(e) = rename_with_retry(temp_path, final_path) {
            let _ = std::fs::remove_file(temp_path);
            return Err(Error::Storage(format!(
                "Failed to replace chunk {}: {e}",
                final_path.display()
            )));
        }
        fsync_dir(shard).map_err(|e| {
            Error::Storage(format!(
                "Replaced {} but could not flush {}: {e}. Not reporting the repair as \
                 done, because a rewrite that is not durable must not authorise deleting \
                 the copy it was rewritten from.",
                final_path.display(),
                shard.display()
            ))
        })?;
        Ok(())
    }
    // Everywhere else, Windows included: there is no way to flush a directory through the
    // standard library, so a rename cannot be shown to be durable at return. Overwriting
    // the existing file changes no directory entry at all, and `sync_all` (FlushFileBuffers
    // on Windows) is documented to flush the file's data, so a successful return is
    // durable under a documented contract.
    //
    // The cost is that this is not atomic: a crash part-way leaves the file holding a mix
    // of old and new bytes. That is safe here and only here, because the only caller that
    // matters runs before the legacy store is deleted, and a crash means no report was
    // produced and nothing was deleted. The next start re-reads the file, sees it does not
    // match its address, and repairs it again from the store that is still there.
    #[cfg(not(unix))]
    {
        let _ = temp_path;
        let _ = shard;
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(final_path)
            .map_err(|e| {
                Error::Storage(format!(
                    "Failed to open {} for replacement: {e}",
                    final_path.display()
                ))
            })?;
        file.write_all(payload).map_err(|e| {
            Error::Storage(format!("Failed to rewrite {}: {e}", final_path.display()))
        })?;
        file.sync_all().map_err(|e| {
            Error::Storage(format!(
                "Rewrote {} but could not flush it: {e}. Not reporting the repair as \
                 done, because a rewrite that is not durable must not authorise deleting \
                 the copy it was rewritten from.",
                final_path.display()
            ))
        })?;
        Ok(())
    }
}

/// Create `temp_path`, write `payload` into it, and flush it.
///
/// Flushed before any rename. On ext4 `auto_da_alloc` only orders the data before the
/// rename's own commit; it does not make the data durable, and btrfs has been observed
/// reordering. A name must never become visible on bytes that are not on the platter.
fn write_temp(temp_path: &Path, payload: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp_path)
        .map_err(|e| {
            Error::Storage(format!(
                "Failed to create temporary file {}: {e}",
                temp_path.display()
            ))
        })?;
    if let Err(e) = f.write_all(payload) {
        let _ = std::fs::remove_file(temp_path);
        return Err(Error::Storage(format!(
            "Failed to write {}: {e}",
            temp_path.display()
        )));
    }
    if let Err(e) = f.sync_all() {
        let _ = std::fs::remove_file(temp_path);
        return Err(Error::Storage(format!(
            "Failed to flush {}: {e}",
            temp_path.display()
        )));
    }
    Ok(())
}

/// Write `payload` and publish it under `final_path`.
///
/// The temp lives in the destination directory, so the publish is an intra-directory
/// rename: atomic on every filesystem we support, and needing only that one directory
/// Put `payload` on disk as `final_path`, durably.
///
/// Returns [`PutOutcome::Duplicate`] when the name is already taken. The name is a hash
/// of the content, so that is not treated as proof the bytes are right: the caller
/// re-reads and verifies them.
#[cfg(unix)]
fn publish(
    temp_path: &Path,
    final_path: &Path,
    payload: &[u8],
    shard: &Path,
) -> Result<PutOutcome> {
    publish_via_rename(temp_path, final_path, payload, shard)
}

/// Put `payload` on disk as `final_path`, durably. See [`publish_in_place`] for why this
/// takes a different route off Unix.
#[cfg(not(unix))]
fn publish(
    temp_path: &Path,
    final_path: &Path,
    payload: &[u8],
    shard: &Path,
) -> Result<PutOutcome> {
    let _ = temp_path;
    let _ = shard;
    publish_in_place(final_path, payload)
}

/// Create the chunk under its final name and flush it. Everywhere but Unix.
///
/// There is no way to flush a directory through the standard library, and Microsoft does
/// not document `MoveFileEx` as durable at return unless it is called with
/// `MOVEFILE_WRITE_THROUGH`, which std does not use. So off Unix a rename cannot be
/// relied on to have reached the disk before the legacy store is deleted.
///
/// Creating the file under its final name sidesteps the rename entirely. Microsoft
/// documents that creation metadata is cached and that `FlushFileBuffers`, which
/// `sync_all` calls on Windows, is the way to flush it. So a successful create, write and
/// flush is a durable publication under a documented contract, with no directory flush
/// and no rename involved.
///
/// The cost is that a crash mid-write leaves a partial file wearing a real chunk name.
/// That is why a duplicate re-reads and verifies rather than trusting the name, and why
/// the pre-retirement pass re-hashes everything before anything is deleted.
#[cfg(not(unix))]
fn publish_in_place(final_path: &Path, payload: &[u8]) -> Result<PutOutcome> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(final_path)
    {
        Ok(f) => f,
        // Someone got there first. Immutable content under a content-addressed name, so
        // the caller verifies what is already there rather than assuming it is right.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok(PutOutcome::Duplicate),
        Err(e) => {
            return Err(Error::Storage(format!(
                "Failed to create chunk {}: {e}",
                final_path.display()
            )))
        }
    };
    if let Err(e) = file.write_all(payload) {
        drop(file);
        let _ = std::fs::remove_file(final_path);
        return Err(Error::Storage(format!(
            "Failed to write {}: {e}",
            final_path.display()
        )));
    }
    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = std::fs::remove_file(final_path);
        return Err(Error::Storage(format!(
            "Failed to flush {}: {e}",
            final_path.display()
        )));
    }
    Ok(PutOutcome::New)
}

/// Write a temp beside the target and rename it into place. Unix only.
#[cfg(unix)]
fn publish_via_rename(
    temp_path: &Path,
    final_path: &Path,
    payload: &[u8],
    shard: &Path,
) -> Result<PutOutcome> {
    // Content is immutable and the name is its hash, so an existing file already holds
    // exactly these bytes. Skipping the write is both cheaper and safer than replacing
    // it: on Windows a rename over a file another thread has open fails outright.
    //
    // The flush still happens. A name that is already there is not proof it is durable:
    // the write that put it there may have been this store's own previous attempt, whose
    // rename landed and whose directory flush then failed. That attempt returned an
    // error, so nothing was retired on the strength of it, but if this call reported a
    // durable duplicate without flushing, the retry would silently launder an unflushed
    // rename into a copy that authorises deleting the last other one.
    let outcome = if final_path.exists() {
        PutOutcome::Duplicate
    } else {
        write_temp(temp_path, payload)?;
        match rename_with_retry(temp_path, final_path) {
            Ok(()) => PutOutcome::New,
            Err(e) => {
                let _ = std::fs::remove_file(temp_path);
                // Another writer of the same address won the race, or the destination was
                // open. Either way the bytes are already published.
                if !final_path.exists() {
                    return Err(Error::Storage(format!(
                        "Failed to publish chunk {}: {e}",
                        final_path.display()
                    )));
                }
                PutOutcome::Duplicate
            }
        }
    };

    // NOT best effort. The directory flush is what makes the rename durable, and a copy
    // reported successful is what authorises deleting the only other copy. Swallowing the
    // failure would let a power loss discard the directory entry after the legacy store
    // had already been removed.
    fsync_dir(shard).map_err(|e| {
        Error::Storage(format!(
            "Published {} but could not flush {}: {e}. Not reporting this chunk as stored, \
             because a copy that is not durable must not authorise deleting another.",
            final_path.display(),
            shard.display()
        ))
    })?;
    Ok(outcome)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A directory flush that fails must say so.
    ///
    /// The quiet version of this function is only used where the answer does not change
    /// what happens next. On the publish path it does.
    #[cfg(unix)]
    #[test]
    fn flushing_a_directory_that_is_not_there_reports_the_failure() {
        let dir = TempDir::new().expect("temp dir");
        assert!(fsync_dir(dir.path()).is_ok());
        assert!(fsync_dir(&dir.path().join("no-such-shard")).is_err());
    }

    /// A chunk whose directory entry was never flushed is not reported as stored.
    ///
    /// This is the whole safety argument for retirement: the legacy store is deleted
    /// because every chunk was copied durably. A published file whose directory flush
    /// failed can vanish on power loss, so counting it as copied would lose data. The
    /// file staying on disk afterwards is fine, the next pass republishes it.
    #[cfg(unix)]
    #[test]
    fn a_publish_whose_directory_flush_fails_is_not_reported_as_stored() {
        let dir = TempDir::new().expect("temp dir");
        let temp_path = dir.path().join("chunk.tmp");
        let final_path = dir.path().join("chunk");
        let unflushable = dir.path().join("shard-that-does-not-exist");

        let outcome = publish_via_rename(&temp_path, &final_path, b"payload", &unflushable);

        assert!(
            outcome.is_err(),
            "an unflushed publication must not be reported as stored"
        );
        assert!(
            !temp_path.exists(),
            "the temp file must not be left behind either way"
        );
    }

    use tempfile::TempDir;

    /// Open a store on a fresh temp directory with the disk reserve disabled.
    async fn test_store() -> (FileStore, TempDir) {
        let dir = TempDir::new().expect("temp dir");
        let store = FileStore::new(FileStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            disk_reserve: 0,
        })
        .await
        .expect("open store");
        (store, dir)
    }

    /// Open a store on an existing directory, as a restart would.
    async fn reopen(dir: &TempDir) -> FileStore {
        FileStore::new(FileStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            disk_reserve: 0,
        })
        .await
        .expect("reopen store")
    }

    /// Content plus the address it hashes to.
    fn addressed(seed: &str) -> (XorName, Vec<u8>) {
        let content = format!("chunk-content-{seed}").into_bytes();
        (crate::client::compute_address(&content), content)
    }

    #[tokio::test]
    async fn put_then_get_returns_the_same_bytes() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("a");

        assert!(store.put(&addr, &content).await.expect("put"));
        let got = store.get(&addr).await.expect("get").expect("present");
        assert_eq!(got, content);
    }

    #[tokio::test]
    async fn a_second_put_of_the_same_chunk_reports_not_new() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("b");

        assert!(store.put(&addr, &content).await.expect("first put"));
        assert!(!store.put(&addr, &content).await.expect("second put"));
        assert_eq!(store.current_chunks().expect("count"), 1);
        assert_eq!(store.stats().duplicates, 1);
    }

    #[tokio::test]
    async fn get_of_an_unknown_address_is_none() {
        let (store, _dir) = test_store().await;
        let (addr, _) = addressed("missing");
        assert!(store.get(&addr).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn exists_tracks_the_store() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("c");

        assert!(!store.exists(&addr).expect("exists"));
        store.put(&addr, &content).await.expect("put");
        assert!(store.exists(&addr).expect("exists"));
        store.delete(&addr).await.expect("delete");
        assert!(!store.exists(&addr).expect("exists"));
    }

    #[tokio::test]
    async fn delete_unlinks_the_file_and_returns_the_space() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("d");
        store.put(&addr, &content).await.expect("put");

        let path = store.chunk_path(&addr);
        assert!(path.exists(), "the chunk file should be on disk");

        assert!(store.delete(&addr).await.expect("delete"));
        assert!(!path.exists(), "delete must actually unlink the file");
        assert_eq!(store.current_chunks().expect("count"), 0);

        // Deleting again is a no-op that reports nothing was there.
        assert!(!store.delete(&addr).await.expect("second delete"));
    }

    #[tokio::test]
    async fn content_that_does_not_hash_to_its_address_is_rejected() {
        let (store, _dir) = test_store().await;
        let (addr, _) = addressed("e");
        let err = store
            .put(&addr, b"different content")
            .await
            .expect_err("must reject");
        assert!(
            format!("{err}").contains("Content address mismatch"),
            "unexpected error: {err}"
        );
        assert_eq!(store.current_chunks().expect("count"), 0);
    }

    #[tokio::test]
    async fn a_chunk_is_filed_under_the_last_two_hex_characters_of_its_address() {
        let (store, dir) = test_store().await;
        let (addr, content) = addressed("f");
        store.put(&addr, &content).await.expect("put");

        let name = hex::encode(addr);
        let expected_shard = name
            .get(name.len() - 2..)
            .expect("64-character name")
            .to_string();
        let path = dir
            .path()
            .join(CHUNKS_DIR_NAME)
            .join(&expected_shard)
            .join(&name);
        assert!(path.exists(), "expected the chunk at {}", path.display());
    }

    #[tokio::test]
    async fn the_index_is_rebuilt_from_the_filesystem_on_restart() {
        let (store, dir) = test_store().await;
        let mut written = Vec::new();
        for i in 0..64 {
            let (addr, content) = addressed(&format!("restart-{i}"));
            store.put(&addr, &content).await.expect("put");
            written.push(addr);
        }
        drop(store);

        let reopened = reopen(&dir).await;
        assert_eq!(reopened.current_chunks().expect("count"), 64);
        for addr in &written {
            assert!(reopened.exists(addr).expect("exists"), "lost a key");
        }
    }

    #[tokio::test]
    async fn all_keys_is_sorted_ascending() {
        let (store, dir) = test_store().await;
        for i in 0..128 {
            let (addr, content) = addressed(&format!("sorted-{i}"));
            store.put(&addr, &content).await.expect("put");
        }

        let keys = store.all_keys().await.expect("all_keys");
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "all_keys() must be ordered");

        // And the order has to survive a restart, because the commitment builder
        // truncates the responsible subset before the Merkle tree sorts it.
        drop(store);
        let reopened = reopen(&dir).await;
        assert_eq!(reopened.all_keys().await.expect("all_keys"), keys);
    }

    #[tokio::test]
    async fn get_raw_skips_verification() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("raw");
        store.put(&addr, &content).await.expect("put");

        // Corrupt the file behind the store's back.
        std::fs::write(store.chunk_path(&addr), b"tampered").expect("tamper");

        let raw = store.get_raw(&addr).await.expect("get_raw").expect("bytes");
        assert_eq!(raw, b"tampered");
    }

    #[tokio::test]
    async fn a_corrupt_chunk_is_removed_so_replication_can_repair_it() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("corrupt");
        store.put(&addr, &content).await.expect("put");
        std::fs::write(store.chunk_path(&addr), b"tampered").expect("tamper");

        let err = store.get(&addr).await.expect_err("verification must fail");
        assert!(format!("{err}").contains("verification failed"), "{err}");

        assert!(!store.chunk_path(&addr).exists(), "corrupt file must go");
        assert!(!store.exists(&addr).expect("exists"));
        assert!(
            !store.all_keys().await.expect("all_keys").contains(&addr),
            "a corrupt chunk must stop being advertised"
        );
        assert_eq!(store.stats().verification_failures, 1);
    }

    #[tokio::test]
    async fn a_file_removed_underneath_the_store_drops_out_of_the_index() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("vanished");
        store.put(&addr, &content).await.expect("put");

        std::fs::remove_file(store.chunk_path(&addr)).expect("remove behind our back");

        assert!(store.get(&addr).await.expect("get").is_none());
        assert!(!store.exists(&addr).expect("exists"));
        assert_eq!(store.current_chunks().expect("count"), 0);
    }

    #[tokio::test]
    async fn interrupted_writes_are_swept_at_startup() {
        let (store, dir) = test_store().await;
        let (addr, content) = addressed("sweep");
        store.put(&addr, &content).await.expect("put");
        let shard = store
            .chunk_path(&addr)
            .parent()
            .expect("shard")
            .to_path_buf();
        drop(store);

        let orphan = shard.join(format!("{TEMP_PREFIX}999.7"));
        std::fs::write(&orphan, b"half a chunk").expect("write orphan");
        let stray_root = dir
            .path()
            .join(CHUNKS_DIR_NAME)
            .join(format!("{TEMP_PREFIX}999.8"));
        std::fs::write(&stray_root, b"half a marker").expect("write stray");

        let reopened = reopen(&dir).await;
        assert!(!orphan.exists(), "an interrupted write must not survive");
        assert!(!stray_root.exists(), "nor one at the store root");
        assert_eq!(reopened.current_chunks().expect("count"), 1);
    }

    #[tokio::test]
    async fn concurrent_writers_of_one_address_store_it_exactly_once() {
        let (store, _dir) = test_store().await;
        let store = Arc::new(store);
        let (addr, content) = addressed("racing");

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            let content = content.clone();
            tasks.push(tokio::spawn(
                async move { store.put(&addr, &content).await },
            ));
        }

        let mut new_count = 0;
        for task in tasks {
            if task.await.expect("join").expect("put") {
                new_count += 1;
            }
        }
        assert_eq!(new_count, 1, "exactly one writer may report a new chunk");
        assert_eq!(store.current_chunks().expect("count"), 1);
        assert_eq!(
            store.get(&addr).await.expect("get").expect("present"),
            content
        );
    }

    #[tokio::test]
    async fn names_that_are_not_lowercase_hex_are_ignored_by_the_scan() {
        let (store, dir) = test_store().await;
        let (addr, content) = addressed("scan");
        store.put(&addr, &content).await.expect("put");
        let shard = store
            .chunk_path(&addr)
            .parent()
            .expect("shard")
            .to_path_buf();
        drop(store);

        // Uppercase is deliberately rejected: on a case-folding filesystem accepting it
        // would let one file answer to two index entries.
        let upper = shard.join(hex::encode_upper(addressed("upper").0));
        std::fs::write(&upper, b"x").expect("write upper");
        std::fs::write(shard.join("not-a-chunk"), b"x").expect("write junk");
        std::fs::write(shard.join("deadbeef"), b"x").expect("write short");

        let reopened = reopen(&dir).await;
        assert_eq!(reopened.current_chunks().expect("count"), 1);
    }

    #[tokio::test]
    async fn a_chunk_filed_in_the_wrong_shard_is_not_indexed() {
        let (store, dir) = test_store().await;
        let (addr, content) = addressed("misfiled");
        store.put(&addr, &content).await.expect("put");
        drop(store);

        // Move it one shard over: the read path would never find it there, so indexing
        // it would make the store advertise a key it cannot serve.
        let correct = dir
            .path()
            .join(CHUNKS_DIR_NAME)
            .join(shard_name(&addr))
            .join(hex::encode(addr));
        let wrong_shard_index = (shard_index(&addr) + 1) % SHARD_COUNT;
        let wrong_dir = dir
            .path()
            .join(CHUNKS_DIR_NAME)
            .join(format!("{wrong_shard_index:02x}"));
        std::fs::create_dir_all(&wrong_dir).expect("mkdir");
        std::fs::rename(&correct, wrong_dir.join(hex::encode(addr))).expect("misfile");

        let reopened = reopen(&dir).await;
        assert_eq!(reopened.current_chunks().expect("count"), 0);
        assert!(!reopened.exists(&addr).expect("exists"));
    }

    #[tokio::test]
    async fn the_layout_marker_is_written_once_and_checked_on_reopen() {
        let (store, dir) = test_store().await;
        drop(store);

        let marker = dir.path().join(CHUNKS_DIR_NAME).join(LAYOUT_FILE_NAME);
        let layout: StoreLayout =
            serde_json::from_slice(&std::fs::read(&marker).expect("read marker"))
                .expect("parse marker");
        assert_eq!(layout, StoreLayout::default());

        // A store written by a future build must be refused, not misread.
        let future = StoreLayout {
            schema: LAYOUT_SCHEMA + 1,
            ..StoreLayout::default()
        };
        std::fs::write(&marker, serde_json::to_vec(&future).expect("encode")).expect("write");
        let err = FileStore::new(FileStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            disk_reserve: 0,
        })
        .await
        .expect_err("must refuse a newer layout");
        assert!(format!("{err}").contains("newer than this build"), "{err}");
    }

    #[tokio::test]
    async fn an_unknown_shard_scheme_is_refused() {
        let (store, dir) = test_store().await;
        drop(store);
        let marker = dir.path().join(CHUNKS_DIR_NAME).join(LAYOUT_FILE_NAME);
        let other = StoreLayout {
            scheme: "prefix-hex".to_string(),
            ..StoreLayout::default()
        };
        std::fs::write(&marker, serde_json::to_vec(&other).expect("encode")).expect("write");
        let err = FileStore::new(FileStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            disk_reserve: 0,
        })
        .await
        .expect_err("must refuse an unknown scheme");
        assert!(format!("{err}").contains("shard scheme"), "{err}");
    }

    #[tokio::test]
    async fn writes_are_refused_when_the_disk_reserve_cannot_be_met() {
        let dir = TempDir::new().expect("temp dir");
        let store = FileStore::new(FileStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            disk_reserve: u64::MAX / 2,
        })
        .await
        .expect("open store");

        let (addr, content) = addressed("full");
        let err = store.put(&addr, &content).await.expect_err("must refuse");
        assert!(
            format!("{err}").contains("Insufficient disk space"),
            "{err}"
        );
        assert!(store.check_capacity().is_err());
    }

    #[tokio::test]
    async fn capacity_is_size_aware() {
        // Wide enough that a test running alongside this one cannot move the answer.
        const MARGIN: u64 = 512 * 1024 * 1024;

        let dir = TempDir::new().expect("temp dir");
        let available = fs2::available_space(dir.path()).expect("free space");
        // A reserve that leaves room for a small write but not a huge one. This is the
        // whole reason the predicate takes a size: free bytes alone stopped being a
        // sufficient answer once chunks became files.
        let store = FileStore::new(FileStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            disk_reserve: available.saturating_sub(MARGIN),
        })
        .await
        .expect("open store");

        assert!(store.check_capacity_for(1024).is_ok());
        assert!(store.check_capacity_for(4 * MARGIN).is_err());
    }

    #[test]
    fn suffix_shards_stay_uniform_for_a_close_group_of_keys() {
        // The real distribution: a node holds keys it is closest to, so they share a
        // long leading prefix with its own ID. Sharding on that prefix collapses to one
        // directory. The trailing byte is untouched by close-group membership.
        let mut prefix_dirs = HashSet::new();
        let mut suffix_dirs = HashSet::new();
        for i in 0u32..4096 {
            let mut key = [0u8; XORNAME_LEN];
            // 20 shared leading bits, as a ~1M-node network would impose.
            let tail = crate::client::compute_address(&i.to_le_bytes());
            key.copy_from_slice(&tail);
            if let Some(b) = key.first_mut() {
                *b = 0xab;
            }
            if let Some(b) = key.get_mut(1) {
                *b = 0xcd;
            }
            if let Some(b) = key.get_mut(2) {
                *b &= 0x0f;
            }
            prefix_dirs.insert(key.first().copied().unwrap_or(0));
            suffix_dirs.insert(shard_index(&key));
        }
        assert_eq!(
            prefix_dirs.len(),
            1,
            "prefix sharding collapses for a node's own holdings"
        );
        assert!(
            suffix_dirs.len() > 250,
            "suffix sharding must stay uniform, got {} of 256 directories",
            suffix_dirs.len()
        );
    }

    #[test]
    fn no_chunk_filename_can_spell_a_reserved_windows_device_name() {
        // Hex has no `n`, `u`, `x`, `p`, `r`, `l`, `t`, `o` or `s`, so `CON`, `NUL`,
        // `AUX`, `PRN`, `COM1` and `LPT1` are all unspellable at any length. This is why
        // the encoding is hex and not base32 or base64url.
        for reserved in ["con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"] {
            assert!(
                !is_lower_hex(reserved),
                "{reserved} must not be a valid chunk or shard name"
            );
        }
    }

    #[test]
    fn only_full_length_lowercase_hex_decodes_to_an_address() {
        // 0xab so the hex form actually contains letters, which is where case matters.
        assert!(decode_chunk_name(&hex::encode([0xabu8; XORNAME_LEN])).is_some());
        assert!(decode_chunk_name(&hex::encode_upper([0xabu8; XORNAME_LEN])).is_none());
        assert!(decode_chunk_name("deadbeef").is_none());
        assert!(decode_chunk_name("").is_none());
        assert!(decode_chunk_name(&"g".repeat(CHUNK_NAME_LEN)).is_none());
    }

    #[tokio::test]
    async fn repair_replaces_bad_bytes_without_the_file_ever_being_absent() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("repairable");
        store.put(&addr, &content).await.expect("put");
        let path = store.chunk_path(&addr);

        std::fs::write(&path, b"rotted").expect("corrupt");
        store.repair(&addr, &content).await.expect("repair");

        assert_eq!(
            store.get(&addr).await.expect("get").expect("present"),
            content
        );
        assert!(store.exists(&addr).expect("exists"));
    }

    #[tokio::test]
    async fn a_repair_with_the_wrong_bytes_is_refused_and_changes_nothing() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("guarded");
        store.put(&addr, &content).await.expect("put");
        let path = store.chunk_path(&addr);

        // The whole point of repairing in place is that a failure must leave the old file
        // where it was. Deleting first and writing after would open a window whose only
        // surviving copy is the one the caller is about to destroy.
        let err = store
            .repair(&addr, b"not this chunk")
            .await
            .expect_err("must refuse");
        assert!(format!("{err}").contains("Refusing to repair"), "{err}");
        assert!(
            path.exists(),
            "the existing file must survive a refused repair"
        );
        assert_eq!(
            store.get(&addr).await.expect("get").expect("present"),
            content
        );
    }

    #[tokio::test]
    async fn a_chunk_can_be_deleted_and_stored_again() {
        let (store, _dir) = test_store().await;
        let (addr, content) = addressed("cycle");

        assert!(store.put(&addr, &content).await.expect("put"));
        assert!(store.delete(&addr).await.expect("delete"));
        assert!(
            store.put(&addr, &content).await.expect("re-put"),
            "a re-stored chunk is new again"
        );
        assert_eq!(
            store.get(&addr).await.expect("get").expect("present"),
            content
        );
    }

    /// Write a chunk file straight into its shard, the way an existing store already
    /// contains thousands of them. Bypasses the write path deliberately: this exercises
    /// the startup scan, not `put`.
    fn plant(chunks_dir: &Path, key: &XorName) {
        let dir = chunks_dir.join(shard_name(key));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(hex::encode(key)), key).expect("plant");
    }

    #[tokio::test]
    async fn a_populated_and_churned_store_scans_correctly_at_scale() {
        // Every shard populated, then aged the way a long-lived node ages: some keys
        // deleted, others added in their place, so the directories carry holes rather
        // than being freshly written. APFS enumeration is known to degrade with churn
        // rather than with size, so a fresh corpus is not a realistic one.
        const PLANTED: u32 = 20_000;
        const CHURN: u32 = 1_000;

        let dir = TempDir::new().expect("temp dir");
        let chunks_dir = dir.path().join(CHUNKS_DIR_NAME);
        std::fs::create_dir_all(&chunks_dir).expect("mkdir");

        let mut expected: Vec<XorName> = Vec::new();
        for i in 0..PLANTED {
            let key = crate::client::compute_address(&i.to_le_bytes());
            plant(&chunks_dir, &key);
            expected.push(key);
        }
        for i in 0..CHURN {
            let key = crate::client::compute_address(&i.to_le_bytes());
            std::fs::remove_file(chunks_dir.join(shard_name(&key)).join(hex::encode(key)))
                .expect("churn out");
            let replacement = crate::client::compute_address(&(PLANTED + i).to_le_bytes());
            plant(&chunks_dir, &replacement);
        }
        expected.retain(|k| chunks_dir.join(shard_name(k)).join(hex::encode(k)).exists());
        for i in 0..CHURN {
            expected.push(crate::client::compute_address(&(PLANTED + i).to_le_bytes()));
        }
        expected.sort_unstable();
        expected.dedup();

        let started = std::time::Instant::now();
        let store = reopen(&dir).await;
        let scan = started.elapsed();

        assert_eq!(
            store.current_chunks().expect("count"),
            expected.len() as u64
        );
        assert_eq!(store.all_keys().await.expect("all_keys"), expected);

        // Every shard should be in use at this size: 20,000 keys over 256 directories is
        // about 78 each, and the last byte of a BLAKE3 output is uniform.
        let occupied = std::fs::read_dir(&chunks_dir)
            .expect("read store root")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_str().is_some_and(|n| n.len() == 2))
            .count();
        assert_eq!(occupied, SHARD_COUNT, "the suffix must reach every shard");

        println!(
            "scan of {} keys across {SHARD_COUNT} shards took {scan:?}",
            expected.len()
        );
    }

    #[tokio::test]
    async fn wait_idle_returns_once_writes_have_drained() {
        let (store, _dir) = test_store().await;
        let store = Arc::new(store);
        for i in 0..32 {
            let store = Arc::clone(&store);
            let (addr, content) = addressed(&format!("drain-{i}"));
            tokio::spawn(async move { store.put(&addr, &content).await });
        }
        // Not a synchronisation point for tasks that have not been spawned yet, but it
        // must not hang and it must leave the store usable.
        store.wait_idle().await;
        let (addr, content) = addressed("after-drain");
        assert!(store.put(&addr, &content).await.expect("put after drain"));
    }
}
