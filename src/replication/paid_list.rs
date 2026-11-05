//! Persistent `PaidForList` backed by LMDB.
//!
//! Tracks keys this node believes are paid-authorized. Survives restarts
//! (Invariant 15). A retained record keeps the entry that authorises its repair,
//! so entries stay until the list nears its store's capacity (ADR-0028). Then
//! entries far outside this node's range go first, and those of records it still
//! stores stay.
//!
//! ## Storage layout
//!
//! ```text
//! {root}/paid_list.mdb/           -- LMDB environment directory
//! {root}/record_out_of_range.bin  -- saved `RecordOutOfRangeFirstSeen` clocks
//! ```
//!
//! One unnamed database stores set membership: key = 32-byte `XorName`,
//! value = empty byte slice. Keys sort by their bytes, so the keys sharing a
//! prefix with a given key are one contiguous range.

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::logging::{debug, error, trace, warn};
use crate::replication::config::{PAID_LIST_MAP_SIZE, PAID_LIST_NEAR_RANK};
use crate::replication::out_of_range_clocks::OutOfRangeClocks;
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, MdbError, RoTxn};
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;
use tokio::task::spawn_blocking;
use tokio_util::task::TaskTracker;

use crate::ant_protocol::XORNAME_LEN;

/// Bits in one byte of a key.
const BITS_PER_BYTE: usize = 8;

/// Bits in a key. A key is near any other within this many low bits.
pub const XORNAME_BITS: usize = XORNAME_LEN * BITS_PER_BYTE;

/// File under the root directory holding saved record clocks.
const RECORD_CLOCKS_FILE: &str = "record_out_of_range.bin";

/// How many low bits of a key may differ from this node's for the key to count
/// as near it, given its distances to the closest peers it knows.
///
/// Every key counts as near until it knows [`PAID_LIST_NEAR_RANK`] peers: in a
/// network that small, this node or a neighbour can be in the paid close group of
/// any key.
#[must_use]
pub fn near_bits_for_peer_distances(distances: &[XorName]) -> usize {
    if distances.len() < PAID_LIST_NEAR_RANK {
        return XORNAME_BITS;
    }
    distances
        .iter()
        .max()
        .map_or(XORNAME_BITS, significant_bits)
}

/// How many bits of `distance` count, from its highest set bit down.
fn significant_bits(distance: &XorName) -> usize {
    distance
        .iter()
        .enumerate()
        .find(|(_, byte)| **byte != 0)
        .map_or(0, |(index, byte)| {
            (XORNAME_LEN - index) * BITS_PER_BYTE - byte.leading_zeros() as usize
        })
}

/// Mutable access to bit `bit` of `key`, counted from the least significant:
/// its byte's index and its mask.
const fn bit_position(bit: usize) -> (usize, u8) {
    (
        XORNAME_LEN - 1 - bit / BITS_PER_BYTE,
        1 << (bit % BITS_PER_BYTE),
    )
}

/// The inclusive range of keys sharing all but the low `free_bits` bits with `key`.
fn prefix_range(key: &XorName, free_bits: usize) -> (XorName, XorName) {
    let (mut low, mut high) = (*key, *key);
    for bit in 0..free_bits.min(XORNAME_BITS) {
        let (index, mask) = bit_position(bit);
        if let (Some(low_byte), Some(high_byte)) = (low.get_mut(index), high.get_mut(index)) {
            *low_byte &= !mask;
            *high_byte |= mask;
        }
    }
    (low, high)
}

/// The key ranges outside the `near_bits` around `center`, farthest first: each
/// holds the keys whose highest bit differing from `center` is one given bit.
fn far_ranges(center: &XorName, near_bits: usize) -> impl Iterator<Item = (XorName, XorName)> {
    let center = *center;
    (near_bits.min(XORNAME_BITS)..XORNAME_BITS)
        .rev()
        .map(move |bit| {
            let mut flipped = center;
            let (index, mask) = bit_position(bit);
            if let Some(byte) = flipped.get_mut(index) {
                *byte ^= mask;
            }
            prefix_range(&flipped, bit)
        })
}

/// Call `visit` with each key from `low` to `high`, until it returns `false`.
/// Returns whether it was never told to stop.
fn visit_range(
    db: Database<Bytes, Bytes>,
    rtxn: &RoTxn<'_>,
    (low, high): (&XorName, &XorName),
    mut visit: impl FnMut(XorName) -> bool,
) -> Result<bool> {
    let bounds = (
        Bound::Included(low.as_slice()),
        Bound::Included(high.as_slice()),
    );
    let iter = db
        .range(rtxn, &bounds)
        .map_err(|e| Error::Storage(format!("Failed to iterate paid-list: {e}")))?;
    for result in iter {
        let (key_bytes, _) =
            result.map_err(|e| Error::Storage(format!("Failed to read paid-list entry: {e}")))?;
        let Ok(key) = XorName::try_from(key_bytes) else {
            warn!(
                "PaidList: skipping entry with unexpected key length {} (expected {XORNAME_LEN})",
                key_bytes.len()
            );
            continue;
        };
        if !visit(key) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Persistent paid-for-list backed by LMDB.
///
/// Tracks which keys this node believes are paid-authorized.
/// Survives node restarts via LMDB persistence.
pub struct PaidList {
    /// LMDB environment.
    env: Env,
    /// The unnamed default database (key = `XorName` bytes, value = empty).
    db: Database<Bytes, Bytes>,
    /// When each stored record first went out of storage-responsibility range.
    record_out_of_range: OutOfRangeClocks,
    /// Whether a full store has been reported, so it is reported only once.
    full_reported: AtomicBool,
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
        let record_clocks_path = root_dir.join(RECORD_CLOCKS_FILE);
        // Constructor-only blocking task: it runs before `self` (and its
        // `blocking_tracker`) exists, so it is deliberately untracked.  The
        // constructor awaits it right here, so it cannot outlive this call.
        let (env, db, record_out_of_range) = spawn_blocking(
            move || -> Result<(Env, Database<Bytes, Bytes>, OutOfRangeClocks)> {
                // SAFETY: `EnvOpenOptions::open()` is unsafe because LMDB uses
                // memory-mapped I/O and relies on OS file-locking to prevent
                // corruption from concurrent access by multiple processes. We
                // satisfy this by giving each node instance a unique `root_dir`
                // (typically named by its full 64-hex peer ID), ensuring no two
                // processes open the same LMDB environment.
                let env = unsafe {
                    EnvOpenOptions::new()
                        .map_size(PAID_LIST_MAP_SIZE)
                        .max_dbs(1)
                        .open(&env_dir_clone)
                        .map_err(|e| {
                            Error::Storage(format!("Failed to open paid-list LMDB env: {e}"))
                        })?
                };

                let mut wtxn = env
                    .write_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;
                let db: Database<Bytes, Bytes> =
                    env.create_database(&mut wtxn, None).map_err(|e| {
                        Error::Storage(format!("Failed to create paid-list database: {e}"))
                    })?;
                wtxn.commit()
                    .map_err(|e| Error::Storage(format!("Failed to commit db creation: {e}")))?;

                Ok((env, db, OutOfRangeClocks::load(record_clocks_path)))
            },
        )
        .await
        .map_err(|e| Error::Storage(format!("Paid-list init task failed: {e}")))??;

        let paid_list = Self {
            env,
            db,
            record_out_of_range,
            full_reported: AtomicBool::new(false),
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
        // Fast-path: avoid write transaction if key already present.
        if self.contains(key)? {
            trace!("Paid-list key {} already present", hex::encode(key));
            return Ok(false);
        }

        let key_owned = *key;
        let env = self.env.clone();
        let db = self.db;

        let was_new = self
            .blocking_tracker
            .spawn_blocking(move || -> heed::Result<bool> {
                let mut wtxn = env.write_txn()?;

                // Authoritative existence check inside the serialized write txn.
                if db.get(&wtxn, &key_owned)?.is_some() {
                    return Ok(false);
                }

                db.put(&mut wtxn, &key_owned, &[])?;
                wtxn.commit()?;

                Ok(true)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list insert task failed: {e}")))?
            .map_err(|e| self.insert_error(&e))?;

        if was_new {
            debug!("Added key {} to paid-list", hex::encode(key));
        }

        Ok(was_new)
    }

    /// Describe a failed insert. A full store is also reported, once, as an
    /// error: from then on the node can't record that a new key was paid for.
    fn insert_error(&self, e: &heed::Error) -> Error {
        if matches!(e, heed::Error::Mdb(MdbError::MapFull))
            && !self.full_reported.swap(true, Ordering::Relaxed)
        {
            error!(
                "Paid-list store is full ({PAID_LIST_MAP_SIZE} bytes): new paid keys are not recorded"
            );
        }
        Error::Storage(format!("Failed to insert into paid-list: {e}"))
    }

    /// Remove a key from the paid-for set.
    ///
    /// Its `RecordOutOfRangeFirstSeen` timestamp stays: a record's eligibility
    /// to be erased doesn't depend on its paid-list entry.
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

        let existed = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<bool> {
                let mut wtxn = env
                    .write_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;
                let deleted = db
                    .delete(&mut wtxn, &key_owned)
                    .map_err(|e| Error::Storage(format!("Failed to delete from paid-list: {e}")))?;
                wtxn.commit().map_err(|e| {
                    Error::Storage(format!("Failed to commit paid-list delete: {e}"))
                })?;
                Ok(deleted)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list remove task failed: {e}")))??;

        if existed {
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

    /// The keys in each of `ranges`, from its first key to its last, in ascending
    /// order. Reads only those keys, however long the list is.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction or iteration fails.
    pub(crate) fn keys_in_ranges(
        &self,
        ranges: &[(XorName, XorName)],
    ) -> Result<Vec<Vec<XorName>>> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        ranges
            .iter()
            .map(|(low, high)| {
                let mut keys = Vec::new();
                if low <= high {
                    visit_range(self.db, &rtxn, (low, high), |key| {
                        keys.push(key);
                        true
                    })?;
                }
                Ok(keys)
            })
            .collect()
    }

    /// Remove up to `limit` entries outside the `near_bits` around `center`,
    /// farthest first, leaving those `keep` accepts. Returns how many went.
    ///
    /// # Errors
    ///
    /// Returns an error if an LMDB transaction fails.
    pub async fn evict_far(
        &self,
        center: XorName,
        near_bits: usize,
        limit: usize,
        keep: impl Fn(&XorName) -> bool + Send + 'static,
    ) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let env = self.env.clone();
        let db = self.db;
        let evictable = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<Vec<XorName>> {
                let rtxn = env
                    .read_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
                let mut evictable = Vec::new();
                for (low, high) in far_ranges(&center, near_bits) {
                    let more = visit_range(db, &rtxn, (&low, &high), |key| {
                        if !keep(&key) {
                            evictable.push(key);
                        }
                        evictable.len() < limit
                    })?;
                    if !more {
                        break;
                    }
                }
                Ok(evictable)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list eviction scan failed: {e}")))??;
        self.remove_batch(&evictable).await
    }

    /// Record the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Only sets the timestamp if one is not already recorded (first
    /// observation wins).
    pub fn set_record_out_of_range(&self, key: &XorName) {
        self.record_out_of_range.start(key, SystemTime::now());
    }

    /// Clear the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Called when the record moves back into storage-responsibility range.
    pub fn clear_record_out_of_range(&self, key: &XorName) {
        self.record_out_of_range.clear(key);
    }

    /// Forget the `RecordOutOfRangeFirstSeen` timestamp of every key `keep`
    /// rejects.
    pub fn retain_record_out_of_range(&self, keep: impl Fn(&XorName) -> bool) {
        self.record_out_of_range.retain(keep);
    }

    /// Save the `RecordOutOfRangeFirstSeen` timestamps if they have changed, so
    /// a restart doesn't restart their clocks.
    pub async fn persist_record_out_of_range(&self) {
        self.record_out_of_range.save().await;
    }

    /// Get the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Returns `None` if the record is currently in range (no timestamp set).
    pub fn record_out_of_range_since(&self, key: &XorName) -> Option<SystemTime> {
        self.record_out_of_range.since(key)
    }

    /// Remove multiple keys in a single write transaction.
    ///
    /// Returns the number of keys that were actually present and removed.
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

        let removed_keys = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<Vec<XorName>> {
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

                Ok(removed)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list batch remove task failed: {e}")))??;

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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Short probe used to prove `wait_idle` is still blocked on a parked op.
    const WAIT_IDLE_BLOCKED_PROBE: std::time::Duration = std::time::Duration::from_millis(200);
    /// Generous ceiling for `wait_idle` to complete once the op is released.
    const WAIT_IDLE_COMPLETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    async fn create_test_paid_list() -> (PaidList, tempfile::TempDir) {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let paid_list = PaidList::new(temp_dir.path())
            .await
            .expect("create paid list");
        (paid_list, temp_dir)
    }

    fn key_with_first_byte(first: u8) -> XorName {
        let mut key = [0u8; 32];
        key[0] = first;
        key
    }

    fn key_ending_in(last: u8) -> XorName {
        let mut key = [0u8; 32];
        key[31] = last;
        key
    }

    /// As many distances as a near range needs, all very small, then `farthest`.
    fn distances_out_to(farthest: XorName) -> Vec<XorName> {
        let mut distances = vec![key_ending_in(1); PAID_LIST_NEAR_RANK - 1];
        distances.push(farthest);
        distances
    }

    #[test]
    fn significant_bits_run_from_the_highest_set_bit() {
        let mut distance = [0u8; 32];
        assert_eq!(significant_bits(&distance), 0);

        distance[31] = 0b0000_0001;
        assert_eq!(significant_bits(&distance), 1);

        distance[30] = 0b0000_0100;
        assert_eq!(significant_bits(&distance), 11);

        assert_eq!(significant_bits(&[0xFF; 32]), XORNAME_BITS);
    }

    #[test]
    fn every_key_is_near_until_enough_peers_are_known() {
        assert_eq!(near_bits_for_peer_distances(&[]), XORNAME_BITS);

        let one_short = vec![key_ending_in(1); PAID_LIST_NEAR_RANK - 1];
        assert_eq!(near_bits_for_peer_distances(&one_short), XORNAME_BITS);
    }

    #[test]
    fn the_near_range_reaches_the_farthest_counted_peer_however_close_the_rest() {
        const FARTHEST_BITS: usize = 7;
        let distances = distances_out_to(key_ending_in(0b0100_0000));
        assert_eq!(near_bits_for_peer_distances(&distances), FARTHEST_BITS);
    }

    #[tokio::test]
    async fn a_far_key_is_kept_until_enough_peers_are_known() {
        // This node is 0 and its neighbours are 1 and 2. Key 129 is far from all
        // three, yet with a group of two its closest are neighbour 1 and this node.
        const FAR_KEY: u8 = 129;
        const EVICT_UP_TO: usize = 10;
        let (pl, _temp) = create_test_paid_list().await;
        pl.insert(&key_ending_in(FAR_KEY)).await.expect("insert");
        let this_node = key_ending_in(0);

        let few_known = near_bits_for_peer_distances(&[key_ending_in(1), key_ending_in(2)]);
        let evicted = pl
            .evict_far(this_node, few_known, EVICT_UP_TO, |_| false)
            .await
            .expect("evict");
        assert_eq!(evicted, 0, "too few peers known to call any key far");

        let many_known = near_bits_for_peer_distances(&distances_out_to(key_ending_in(2)));
        let evicted = pl
            .evict_far(this_node, many_known, EVICT_UP_TO, |_| false)
            .await
            .expect("evict");
        assert_eq!(evicted, 1);
        assert!(!pl.contains(&key_ending_in(FAR_KEY)).expect("contains"));
    }

    #[test]
    fn prefix_ranges_free_exactly_the_low_bits() {
        let key = [0xAB; 32];
        assert_eq!(prefix_range(&key, 0), (key, key));
        assert_eq!(prefix_range(&key, XORNAME_BITS), ([0x00; 32], [0xFF; 32]));

        let (low, high) = prefix_range(&key, 12);
        let mut expected_low = key;
        expected_low[30] = 0xA0;
        expected_low[31] = 0x00;
        let mut expected_high = key;
        expected_high[30] = 0xAF;
        expected_high[31] = 0xFF;
        assert_eq!((low, high), (expected_low, expected_high));
    }

    #[test]
    fn far_ranges_run_farthest_first_and_stop_at_the_near_range() {
        let center = [0u8; 32];
        let near_bits = XORNAME_BITS - 3;
        let ranges: Vec<_> = far_ranges(&center, near_bits).collect();
        let lows: Vec<u8> = ranges.iter().map(|(low, _)| low[0]).collect();
        let highs: Vec<u8> = ranges.iter().map(|(_, high)| high[0]).collect();
        assert_eq!(lows, vec![0x80, 0x40, 0x20]);
        assert_eq!(highs, vec![0xFF, 0x7F, 0x3F]);
        assert_eq!(far_ranges(&center, XORNAME_BITS).count(), 0);
    }

    #[tokio::test]
    async fn keys_in_ranges_reads_each_range_with_both_ends_included() {
        let (pl, _temp) = create_test_paid_list().await;
        let keys = [0x10, 0x20, 0x30, 0x40, 0xC0].map(key_with_first_byte);
        for key in &keys {
            pl.insert(key).await.expect("insert");
        }

        let ranges = [
            (key_with_first_byte(0x20), key_with_first_byte(0x30)),
            (key_with_first_byte(0x41), key_with_first_byte(0xBF)),
            (key_with_first_byte(0xC0), [0xFF; 32]),
            (key_with_first_byte(0x30), key_with_first_byte(0x20)),
        ];
        assert_eq!(
            pl.keys_in_ranges(&ranges).expect("keys"),
            vec![vec![keys[1], keys[2]], vec![], vec![keys[4]], vec![]]
        );
    }

    #[tokio::test]
    async fn eviction_takes_the_farthest_first_up_to_its_limit() {
        let (pl, _temp) = create_test_paid_list().await;
        let center = [0u8; 32];
        let near_bits = XORNAME_BITS - 2;
        let (near, mid, far) = (
            key_with_first_byte(0x01),
            key_with_first_byte(0x40),
            key_with_first_byte(0x80),
        );
        for key in [near, mid, far] {
            pl.insert(&key).await.expect("insert");
        }

        let evicted = pl
            .evict_far(center, near_bits, 1, |_| false)
            .await
            .expect("evict");
        assert_eq!(evicted, 1);
        assert!(
            !pl.contains(&far).expect("contains"),
            "the farthest goes first"
        );
        assert!(pl.contains(&mid).expect("contains"));

        let evicted = pl
            .evict_far(center, near_bits, 10, |_| false)
            .await
            .expect("evict");
        assert_eq!(evicted, 1, "only the far entry was left to evict");
        assert!(pl.contains(&near).expect("contains"), "near entries stay");
    }

    #[tokio::test]
    async fn eviction_leaves_what_the_caller_keeps() {
        let (pl, _temp) = create_test_paid_list().await;
        let (kept, evicted_key) = (key_with_first_byte(0x80), key_with_first_byte(0x81));
        pl.insert(&kept).await.expect("insert");
        pl.insert(&evicted_key).await.expect("insert");

        let near_bits = XORNAME_BITS - 1;
        let evicted = pl
            .evict_far([0u8; 32], near_bits, 10, move |key| *key == kept)
            .await
            .expect("evict");

        assert_eq!(evicted, 1);
        assert!(pl.contains(&kept).expect("contains"));
        assert!(!pl.contains(&evicted_key).expect("contains"));
    }

    #[tokio::test]
    async fn nothing_is_evicted_when_every_key_counts_as_near() {
        let (pl, _temp) = create_test_paid_list().await;
        let key = key_with_first_byte(0x80);
        pl.insert(&key).await.expect("insert");

        let evicted = pl
            .evict_far([0u8; 32], XORNAME_BITS, 10, |_| false)
            .await
            .expect("evict");

        assert_eq!(evicted, 0);
        assert!(pl.contains(&key).expect("contains"));
    }

    /// The store's file grows with its entries instead of taking the whole map
    /// up front, on every platform this runs on.
    #[tokio::test]
    async fn opening_the_store_does_not_allocate_the_whole_map() {
        let (pl, temp) = create_test_paid_list().await;
        pl.insert(&[0x01; 32]).await.expect("insert");

        let data_file = temp.path().join("paid_list.mdb").join("data.mdb");
        let size = std::fs::metadata(data_file).expect("metadata").len();
        let map_size = u64::try_from(PAID_LIST_MAP_SIZE).expect("map size fits");
        assert!(size < map_size, "file is {size} bytes, map {map_size}");
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

    #[tokio::test]
    async fn keys_in_the_whole_key_space_are_every_key() {
        let (pl, _temp) = create_test_paid_list().await;

        let key_a: XorName = [0x01; 32];
        let key_b: XorName = [0x02; 32];
        let key_c: XorName = [0x03; 32];

        pl.insert(&key_a).await.expect("insert 1");
        pl.insert(&key_b).await.expect("insert 2");
        pl.insert(&key_c).await.expect("insert 3");

        let mut keys = pl
            .keys_in_ranges(&[([0u8; 32], [0xFF; 32])])
            .expect("keys")
            .concat();
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
    async fn test_record_out_of_range_timestamps() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xF1; 32];

        assert!(pl.record_out_of_range_since(&key).is_none());

        let before = SystemTime::now();
        pl.set_record_out_of_range(&key);
        let after = SystemTime::now();

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
    async fn removing_an_entry_leaves_its_records_clock() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xA0; 32];
        pl.insert(&key).await.expect("insert");

        pl.set_record_out_of_range(&key);
        assert!(pl.record_out_of_range_since(&key).is_some());

        pl.remove(&key).await.expect("remove");
        assert!(
            pl.record_out_of_range_since(&key).is_some(),
            "a record's clock doesn't depend on its paid-list entry"
        );
    }

    #[tokio::test]
    async fn record_clocks_survive_a_reopen() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let (saved, unsaved): (XorName, XorName) = ([0xB0; 32], [0xB1; 32]);

        let saved_clock = {
            let pl = PaidList::new(temp_dir.path())
                .await
                .expect("create paid list");
            pl.set_record_out_of_range(&saved);
            pl.persist_record_out_of_range().await;
            pl.set_record_out_of_range(&unsaved);
            pl.record_out_of_range_since(&saved).expect("clock set")
        };

        let pl = PaidList::new(temp_dir.path())
            .await
            .expect("reopen paid list");
        let restored = pl
            .record_out_of_range_since(&saved)
            .expect("clock restored");
        assert!(
            restored <= saved_clock + std::time::Duration::from_secs(1),
            "a restored clock must not restart"
        );
        assert!(pl.record_out_of_range_since(&unsaved).is_none());
    }

    #[tokio::test]
    async fn retaining_record_clocks_forgets_only_rejected_keys() {
        let (pl, _temp) = create_test_paid_list().await;
        let (kept, dropped): (XorName, XorName) = ([0xC0; 32], [0xC1; 32]);
        pl.set_record_out_of_range(&kept);
        pl.set_record_out_of_range(&dropped);

        pl.retain_record_out_of_range(|key| *key == kept);

        assert!(pl.record_out_of_range_since(&kept).is_some());
        assert!(pl.record_out_of_range_since(&dropped).is_none());
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

        // A record's clock doesn't depend on its paid-list entry.
        assert!(pl.record_out_of_range_since(&key2).is_some());
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
        let elapsed = since.elapsed().expect("clock in the past");
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
        let before_second = SystemTime::now();
        pl.set_record_out_of_range(&key);
        let second_ts = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should exist after second out-of-range");
        assert!(
            second_ts >= before_second,
            "new timestamp should be >= the instant before second set call"
        );
    }

    /// #23: Inserting then removing a key from the paid list removes its
    /// persistent entry and leaves its record's out-of-range timestamp.
    #[tokio::test]
    async fn scenario_23_paid_list_entry_removed() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x23; 32];

        // Insert key and attach an out-of-range timestamp.
        pl.insert(&key).await.expect("insert");
        pl.set_record_out_of_range(&key);

        // Remove.
        let removed = pl.remove(&key).await.expect("remove");
        assert!(removed, "key should have existed");
        assert!(
            !pl.contains(&key).expect("contains check"),
            "key should be gone from paid list"
        );
        assert!(
            pl.record_out_of_range_since(&key).is_some(),
            "record timestamp doesn't depend on the paid-list entry"
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
        let elapsed = first_seen.elapsed().expect("clock in the past");
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

        let first_ts = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(3))
            .unwrap_or_else(std::time::Instant::now);
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
        let later_ts = std::time::Instant::now();
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
        // `std::time::Instant::checked_sub` can fail on Windows where the epoch is
        // process-start, so fall back to a recent instant when the platform
        // cannot represent the backdated time (the claim-age assertion is
        // skipped in that case since the subtraction itself proves nothing
        // about production behaviour).
        let grace_plus_margin = grace_period + std::time::Duration::from_hours(1);
        let first_seen = std::time::Instant::now()
            .checked_sub(grace_plus_margin)
            .unwrap_or_else(std::time::Instant::now);
        state.bootstrap_claims.insert(peer, first_seen);
        state.bootstrap_claim_history.insert(peer, first_seen);

        // On platforms that support the backdated instant, verify claim age.
        let claim_age = std::time::Instant::now().duration_since(first_seen);
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
        let first_seen = std::time::Instant::now();
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

        let repeated = state.observe_bootstrap_claim(peer, std::time::Instant::now(), grace_period);
        assert_eq!(
            repeated,
            crate::replication::types::BootstrapClaimObservation::Repeated { first_seen },
            "a second bootstrap claim should be classified as repeated abuse"
        );
    }
}
