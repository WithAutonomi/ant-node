//! Durable storage for pointer records, with merge-on-put.
//!
//! The chunk store answers "already have it" and stops, which is right for an
//! immutable record and wrong for a mutable one — it would silently drop every
//! update. It also requires `BLAKE3(content) == address`, which no pointer can
//! satisfy. So pointers get their own store rather than an exemption carved
//! into that one.
//!
//! # The shape of a write
//!
//! A put is two steps, because the payment check sits between them:
//!
//! 1. [`PointerStore::prepare`] parses, compares against what is held and, only
//!    if the arrival could win, verifies its signature. It returns either a
//!    no-op outcome or a [`PreparedPut`].
//! 2. The caller verifies payment against the candidate's address and state
//!    identifier, then calls [`PointerStore::commit`].
//!
//! Signature verification happens in step 1 **outside** any store lock, so a
//! flood of unpaid candidates cannot block every other address behind one
//! ML-DSA check. Step 2 re-checks under the lock, because the world may have
//! moved while payment was being verified.
//!
//! # Atomicity
//!
//! The commit — compare, write, re-index — runs inside a single blocking task
//! holding a synchronous lock. Splitting it across an `await` would let a
//! cancelled caller release the lock while its write was still in flight,
//! leaving the index describing a record the disk no longer holds. Because the
//! whole transaction lives in one task, dropping the caller's future cannot
//! tear it.
//!
//! On disk each record is one file named by its hex address under
//! `{root}/pointers/`. Writes go to a uniquely named temporary file and are
//! renamed into place, so a crash leaves either the old record or the new one,
//! never a torn one. A lock file under the same directory keeps two processes
//! from keeping two indexes over one set of files.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use fs2::FileExt;
use parking_lot::Mutex;
use tokio::task::spawn_blocking;

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::logging::{debug, warn};
use ant_protocol::pointer::{MergeRank, ParsedPointer, Pointer, PointerState, POINTER_WIRE_LEN};

/// Directory under the store root that holds pointer records.
const POINTERS_DIR_NAME: &str = "pointers";

/// Prefix for the temporary file a write lands in before being renamed.
const TEMP_PREFIX: &str = ".tmp-";

/// Name of the file whose lock grants exclusive use of the directory.
const LOCK_FILE_NAME: &str = ".pointer-store-lock";

/// What a put did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// No record was held for this address; the incoming one was stored.
    Stored,
    /// The incoming record won under the merge rule and replaced the held one.
    Replaced,
    /// The held record is the same authenticated state. Nothing was written.
    ///
    /// This is the case that keeps one payment from funding many writes: an
    /// owner can produce unboundedly many valid signatures over one state, and
    /// every one of them lands here.
    Unchanged,
    /// The incoming record lost under the merge rule. Nothing was written.
    Stale,
}

impl PutOutcome {
    /// Whether this outcome changed what the node holds.
    ///
    /// Only a change is worth announcing to replication or counting towards a
    /// commitment rebuild.
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Stored | Self::Replaced)
    }
}

/// The result of [`PointerStore::inspect`]: what an arrival claims, before any
/// signature has been checked.
pub enum Inspected {
    /// The arrival cannot change what is held. No signature check is owed, and
    /// none was done.
    Noop(PutOutcome),
    /// The arrival would win as it stands. Its signature has **not** been
    /// checked yet — pass it to [`PointerStore::verify`] once admission gates
    /// have had their say.
    Candidate(ParsedPointer),
}

impl Inspected {
    /// What this arrival claims, whether or not it is a candidate.
    #[must_use]
    pub fn state(&self) -> Option<&ant_protocol::pointer::PointerState> {
        match self {
            Self::Noop(_) => None,
            Self::Candidate(parsed) => Some(parsed.state()),
        }
    }
}

/// The result of [`PointerStore::prepare`].
#[derive(Debug)]
pub enum Prepared {
    /// The arrival cannot change what is held, and was rejected without a
    /// signature check. There is nothing to pay for and nothing to commit.
    Noop(PutOutcome),
    /// A validated record that would win as of the moment it was prepared.
    Candidate(PreparedPut),
}

/// A record that parsed, out-ranked what was held, and verified.
///
/// Carries what a payment check needs — [`Self::address`] to route and
/// [`Self::state_id`] to authorize — and holds the validated record so nothing
/// can change between validation and commit.
#[derive(Debug)]
pub struct PreparedPut {
    /// The validated record.
    record: Pointer,
}

impl PreparedPut {
    /// The address this record belongs at, which is what routing uses.
    #[must_use]
    pub fn address(&self) -> XorName {
        self.record.address()
    }

    /// The authenticated-state identifier, which is what a quote is paid against.
    #[must_use]
    pub fn state_id(&self) -> XorName {
        self.record.state_id()
    }

    /// The validated record.
    #[must_use]
    pub const fn record(&self) -> &Pointer {
        &self.record
    }
}

/// What the store knows about a held record without reading it back.
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    /// The held record's authenticated-state identifier.
    state_id: XorName,
    /// The held record's place in the merge order.
    ///
    /// Carried as the record's own [`MergeRank`] rather than as the fields it
    /// is built from, so the store cannot drift from the rule in
    /// `PointerState::replaces`.
    rank: MergeRank,
    /// The held record's counter, for the paid-increment check.
    counter: u64,
    /// `BLAKE3` over the exact stored bytes, which a storage commitment binds.
    bytes_hash: XorName,
    /// Which insertion this entry is.
    ///
    /// Monotonic for the life of this store, so an entry can be told apart
    /// from a later one carrying the same `state_id`. Without it a repair that
    /// restores exactly the state a reader found corrupt would be
    /// indistinguishable from the corrupt entry that reader set out to disown,
    /// and a second reader would erase the repair. Reuse would take 2^64
    /// commits without a restart, and an observation never outlives the store
    /// that produced it, so a restart resetting the counter is harmless.
    generation: u64,
}

impl IndexEntry {
    /// Describe a validated record.
    fn of(record: &Pointer, generation: u64) -> Self {
        Self {
            state_id: record.state_id(),
            rank: record.state().rank(),
            counter: record.counter(),
            bytes_hash: record.bytes_hash(),
            generation,
        }
    }
}

/// A store of pointer records.
#[derive(Debug, Clone)]
pub struct PointerStore {
    inner: Arc<Inner>,
}

/// Shared state behind [`PointerStore`].
#[derive(Debug)]
struct Inner {
    /// Directory holding one file per record.
    dir: PathBuf,
    /// What is held, by address.
    ///
    /// Guarded by a synchronous lock held across the disk write, so the index
    /// and the directory can never disagree about which version is current.
    /// The critical section is one ~5 KB write, and it is only ever taken
    /// inside a blocking task.
    index: Mutex<HashMap<XorName, IndexEntry>>,
    /// Distinguishes concurrent temporary files so two writers to one address
    /// cannot land in the same partial file.
    write_seq: AtomicU64,
    /// Source of index generations, monotonic for this store's lifetime.
    generation: AtomicU64,
    /// Set if a directory sync ever failed after a commit.
    ///
    /// Those writes are stored and visible; what is uncertain is whether they
    /// survive a power loss. Reporting them as failures would be wrong, and
    /// saying nothing would overstate the guarantee, so the store records it.
    durability_degraded: AtomicBool,
    /// Held for the store's lifetime; releasing it releases the directory.
    _lock_file: File,
}

impl PointerStore {
    /// Open a store under `root_dir`, rebuilding its index from disk.
    ///
    /// Takes an exclusive lock on the directory. Two stores over one directory
    /// would each keep their own index, and the one with the staler view would
    /// happily overwrite the other's newer record.
    ///
    /// A file that does not parse as a valid pointer, or that is not at the
    /// address its owner derives, is skipped and logged rather than deleted: a
    /// store that prunes what it cannot read destroys the evidence of its own
    /// bug.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the directory cannot be created, locked or
    /// read.
    pub async fn new(root_dir: &Path) -> Result<Self> {
        let dir = root_dir.join(POINTERS_DIR_NAME);
        let scan_dir = dir.clone();
        let (lock_file, index) = spawn_blocking(move || {
            std::fs::create_dir_all(&scan_dir).map_err(|e| {
                Error::Storage(format!("cannot create {}: {e}", scan_dir.display()))
            })?;
            let lock_file = acquire_lock(&scan_dir)?;
            let index = scan(&scan_dir)?;
            Ok::<_, Error>((lock_file, index))
        })
        .await
        .map_err(|e| Error::Storage(format!("pointer store scan panicked: {e}")))??;

        let next_generation = index
            .values()
            .map(|entry| entry.generation)
            .max()
            .map_or(0, |highest| highest.saturating_add(1));
        debug!(
            "Pointer store opened at {} with {} records",
            dir.display(),
            index.len()
        );
        Ok(Self {
            inner: Arc::new(Inner {
                dir,
                index: Mutex::new(index),
                write_seq: AtomicU64::new(0),
                generation: AtomicU64::new(next_generation),
                durability_degraded: AtomicBool::new(false),
                _lock_file: lock_file,
            }),
        })
    }

    /// Validate an arriving record against what is held.
    ///
    /// Cheap checks first: an arrival that cannot change anything is refused
    /// before its signature is looked at, because it is a no-op whether or not
    /// it is correctly signed. That ordering is what stops repeated submission
    /// of one paid state from buying ML-DSA verifications. A record that would
    /// win is always verified — outside the store lock, so one slow
    /// verification cannot stall every other address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the bytes are not a well-formed record
    /// and [`Error::Crypto`] if a would-be winner's signature does not verify.
    pub async fn prepare(&self, bytes: &[u8]) -> Result<Prepared> {
        match self.inspect(bytes)? {
            Inspected::Noop(outcome) => Ok(Prepared::Noop(outcome)),
            Inspected::Candidate(parsed) => Ok(Prepared::Candidate(self.verify(parsed).await?)),
        }
    }

    /// Parse an arrival and decide whether it could change anything, without
    /// verifying its signature.
    ///
    /// The cheap half of [`Self::prepare`]. Callers that gate on admission —
    /// capacity, responsibility for the address — run this first, apply their
    /// gates, and only then pay for [`Self::verify`]. Otherwise a forged record
    /// for an address the node is not responsible for still buys an ML-DSA
    /// verification before anything rejects it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the bytes are not a well-formed record.
    pub fn inspect(&self, bytes: &[u8]) -> Result<Inspected> {
        // Parsing decodes the owner key once; `verify` reuses that parse rather
        // than decoding again. The bytes travel with it, so the two cannot be
        // mismatched.
        let parsed = ParsedPointer::parse(bytes.to_vec())?;
        let state = *parsed.state();

        if let Some(entry) = self.snapshot(&state.address) {
            if entry.state_id == state.state_id {
                return Ok(Inspected::Noop(PutOutcome::Unchanged));
            }
            if state.rank() <= entry.rank {
                return Ok(Inspected::Noop(PutOutcome::Stale));
            }
        }
        Ok(Inspected::Candidate(parsed))
    }

    /// Verify a candidate's signature.
    ///
    /// Runs with no lock held and off the async executor: an ML-DSA
    /// verification is milliseconds of CPU, and an attacker can ask for one per
    /// forged record, so it must not run on a thread other work needs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the signature does not verify.
    pub async fn verify(&self, parsed: ParsedPointer) -> Result<PreparedPut> {
        let record = spawn_blocking(move || Pointer::verify_parsed(parsed))
            .await
            .map_err(|e| Error::Storage(format!("pointer verification panicked: {e}")))??;
        Ok(PreparedPut { record })
    }

    /// Commit a prepared record.
    ///
    /// Re-checks against what is held before writing: `prepare` may have run
    /// before a payment check that took long enough for a newer state to
    /// arrive, and the re-check is what keeps that newer state from being
    /// overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the write fails.
    pub async fn commit(&self, prepared: PreparedPut) -> Result<PutOutcome> {
        let inner = Arc::clone(&self.inner);
        // The whole transaction runs in one task, so dropping this future
        // cannot leave the write done and the index un-updated.
        spawn_blocking(move || inner.commit_blocking(&prepared.record))
            .await
            .map_err(|e| Error::Storage(format!("pointer commit panicked: {e}")))?
    }

    /// Validate and store in one step, with no payment gate.
    ///
    /// For callers that have already settled payment, and for tests. The
    /// request path should use [`Self::prepare`] and [`Self::commit`] so the
    /// payment check can sit between them.
    ///
    /// # Errors
    ///
    /// As [`Self::prepare`] and [`Self::commit`].
    pub async fn put_bytes(&self, bytes: &[u8]) -> Result<PutOutcome> {
        match self.prepare(bytes).await? {
            Prepared::Noop(outcome) => Ok(outcome),
            Prepared::Candidate(prepared) => self.commit(prepared).await,
        }
    }

    /// Read the record held at `address`, if any.
    ///
    /// Re-validates on the way out, so a file corrupted under the node is
    /// reported as missing rather than served as authentic — and the index
    /// entry for it is dropped, so the node will accept a fresh copy of that
    /// state instead of answering "unchanged" to its own repair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the file cannot be read for a reason other
    /// than its absence.
    pub async fn get(&self, address: &XorName) -> Result<Option<Pointer>> {
        // What the index claimed before the read. A commit can land while the
        // read is in flight, and its entry must not then be mistaken for the
        // stale one this read is about to disown.
        let claimed = self.snapshot(address).map(|entry| entry.generation);

        let path = self.path_for(address);
        // Reading and verifying happen in one blocking task: an ML-DSA check is
        // milliseconds of CPU and must not run on an async worker thread.
        let read = spawn_blocking(move || {
            read_record_file(&path).map(|bytes| bytes.map(|bytes| Pointer::from_bytes(&bytes)))
        })
        .await
        .map_err(|e| Error::Storage(format!("pointer read panicked: {e}")))?;

        let validated = match read {
            Ok(Some(validated)) => validated,
            Ok(None) => {
                self.forget_if_unchanged(address, claimed);
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        match validated {
            Ok(record) if record.address() == *address => Ok(Some(record)),
            Ok(_) => {
                warn!(
                    "Pointer file at {} holds a record for another address; dropping it \
                     from the index",
                    hex::encode(address)
                );
                self.forget_if_unchanged(address, claimed);
                Ok(None)
            }
            Err(e) => {
                warn!(
                    "Pointer file at {} does not validate ({e}); dropping it from the index",
                    hex::encode(address)
                );
                self.forget_if_unchanged(address, claimed);
                Ok(None)
            }
        }
    }

    /// The authenticated-state identifier held at `address`, if any.
    ///
    /// This is what a sync hint carries and what a fetch decision compares. It
    /// names the state, not the encoding, so two replicas holding one state
    /// under different signatures agree and do not refetch each other forever.
    #[must_use]
    pub fn state_id(&self, address: &XorName) -> Option<XorName> {
        self.snapshot(address).map(|e| e.state_id)
    }

    /// `BLAKE3` over the exact bytes held at `address`, if any.
    ///
    /// What a storage commitment binds for this record. Per-storer by design:
    /// each node commits and is audited against the encoding it actually holds.
    #[must_use]
    pub fn bytes_hash(&self, address: &XorName) -> Option<XorName> {
        self.snapshot(address).map(|e| e.bytes_hash)
    }

    /// Whether `state` is the paid successor of what is held.
    ///
    /// One payment buys one increment: a new pointer starts at counter 0, and
    /// an update must be exactly one past what this node holds. Without it an
    /// owner pays once, jumps the counter, skips every intermediate payment and
    /// strands the pointer at a counter nothing can advance.
    ///
    /// Only the client path asks this. Replication uses the merge rule instead,
    /// so a replica that missed an update can still catch up rather than being
    /// stuck behind a gap it can never fill.
    #[must_use]
    pub fn accepts_as_paid_update(&self, state: &PointerState) -> bool {
        self.snapshot(&state.address).map_or_else(
            || state.is_genesis(),
            |entry| state.counter == entry.counter.wrapping_add(1) && entry.counter != u64::MAX,
        )
    }

    /// Whether a record is held at `address`.
    #[must_use]
    pub fn contains(&self, address: &XorName) -> bool {
        self.snapshot(address).is_some()
    }

    /// Whether the record held at `address` is already this exact state.
    ///
    /// The question a fetch decision asks: holding *the key* is not enough for
    /// a mutable record, holding *the state* is.
    #[must_use]
    pub fn holds_state(&self, address: &XorName, state_id: &XorName) -> bool {
        self.snapshot(address)
            .is_some_and(|e| e.state_id == *state_id)
    }

    /// Every address the store holds.
    #[must_use]
    pub fn all_keys(&self) -> Vec<XorName> {
        self.inner.index.lock().keys().copied().collect()
    }

    /// Every address with the state identifier and committed bytes hash held
    /// for it.
    ///
    /// The input a commitment build or a sync round needs in one pass, which is
    /// why the index exists rather than each of those re-reading every file.
    #[must_use]
    pub fn all_states(&self) -> Vec<(XorName, XorName, XorName)> {
        self.inner
            .index
            .lock()
            .iter()
            .map(|(address, entry)| (*address, entry.state_id, entry.bytes_hash))
            .collect()
    }

    /// Which of `wanted` this node does not already hold at the given state.
    ///
    /// The fetch decision a mutable record needs. The chunk path asks "do I
    /// hold this key?" and stops, which for a pointer means a replica on
    /// version N never fetches N+1 and the two diverge permanently. This asks
    /// "do I hold this *state*?" instead.
    #[must_use]
    pub fn missing_states(&self, wanted: &[(XorName, XorName)]) -> Vec<(XorName, XorName)> {
        let index = self.inner.index.lock();
        wanted
            .iter()
            .filter(|(address, state_id)| {
                // `map_or` rather than `is_none_or`: the latter is stable only
                // from 1.82 and this crate's MSRV is 1.75.
                index
                    .get(address)
                    .map_or(true, |entry| entry.state_id != *state_id)
            })
            .copied()
            .collect()
    }

    /// How many records the store holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.index.lock().len()
    }

    /// Whether the store holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether any committed write could not have its directory entry flushed.
    ///
    /// Those records are stored and readable now; what is uncertain is whether
    /// they survive a power loss. A put still reports success, because the
    /// write did happen — this is how an operator learns the filesystem is not
    /// giving the store what it asks for.
    #[must_use]
    pub fn durability_degraded(&self) -> bool {
        self.inner.durability_degraded.load(Ordering::Relaxed)
    }

    /// Directory holding the records.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }

    /// Copy out what is held for `address`, releasing the index lock at once.
    fn snapshot(&self, address: &XorName) -> Option<IndexEntry> {
        self.inner.index.lock().get(address).copied()
    }

    /// Drop the index entry for `address`, but only if it is still the exact
    /// entry the caller found unreadable.
    ///
    /// A read is not atomic with a write. Removing unconditionally would let a
    /// slow read of a corrupt file erase the entry for a record committed while
    /// it was reading, leaving the node holding a record it no longer
    /// announces, commits to, or can be audited for. Matching on the generation
    /// rather than the state identifier also covers the case where the record
    /// written meanwhile is a *repair of the same state*, which a state
    /// comparison could not tell apart from the entry being disowned.
    fn forget_if_unchanged(&self, address: &XorName, claimed: Option<u64>) {
        let Some(claimed) = claimed else {
            // Nothing was claimed when the read began, so there is nothing this
            // read is entitled to remove.
            return;
        };
        let mut index = self.inner.index.lock();
        if index.get(address).map(|entry| entry.generation) == Some(claimed) {
            index.remove(address);
        }
    }

    /// Path of the file backing `address`.
    fn path_for(&self, address: &XorName) -> PathBuf {
        self.inner.dir.join(hex::encode(address))
    }
}

impl Inner {
    /// Compare, write and re-index under one lock.
    ///
    /// Runs entirely inside a blocking task: the lock is synchronous and is
    /// never released between the decision and the index update, so neither
    /// caller cancellation nor a concurrent writer can separate them.
    // Holding the guard across the write is the point of this function, so the
    // lint's advice to drop it earlier would reintroduce exactly the window
    // this closes: a second writer deciding against an index that no longer
    // describes the disk.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the write must happen under the same guard as the decision"
    )]
    fn commit_blocking(&self, record: &Pointer) -> Result<PutOutcome> {
        let address = record.address();
        let path = self.dir.join(hex::encode(address));

        // A cheap look before doing any work. The authoritative check is the
        // one under the lock below; this only avoids staging a file for an
        // arrival that is already obviously a no-op.
        if let Some(entry) = self.index.lock().get(&address) {
            if entry.state_id == record.state_id() {
                return Ok(PutOutcome::Unchanged);
            }
            if record.state().rank() <= entry.rank {
                return Ok(PutOutcome::Stale);
            }
        }

        // Stage and fsync the new bytes *before* taking the lock. This is the
        // slow part — a 5 KB write plus an fsync — and holding the index lock
        // across it would block every other address, including the cheap
        // lookups async callers make.
        let seq = self.write_seq.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .dir
            .join(format!("{TEMP_PREFIX}{}-{seq}", hex::encode(address)));
        stage(&temp, &record.to_bytes())?;

        let outcome = {
            let mut index = self.index.lock();

            // Re-check: staging is not instantaneous and a newer state may
            // have committed while it ran.
            let outcome = match index.get(&address) {
                None => PutOutcome::Stored,
                Some(entry) if entry.state_id == record.state_id() => PutOutcome::Unchanged,
                Some(entry) if record.state().rank() > entry.rank => PutOutcome::Replaced,
                Some(_) => PutOutcome::Stale,
            };
            if !outcome.changed() {
                let _ = std::fs::remove_file(&temp);
                return Ok(outcome);
            }

            // The rename is the commit point: nothing fallible happens between
            // it and the index update, and both are under this one lock.
            if let Err(e) = std::fs::rename(&temp, &path) {
                let _ = std::fs::remove_file(&temp);
                return Err(Error::Storage(format!(
                    "cannot rename {} onto {}: {e}",
                    temp.display(),
                    path.display()
                )));
            }
            let generation = self.generation.fetch_add(1, Ordering::Relaxed);
            index.insert(address, IndexEntry::of(record, generation));
            outcome
        };

        // Durability of the directory entry, after the commit and outside the
        // lock. The record is already stored and indexed, so a failure here
        // cannot be reported as "nothing happened"; it is recorded instead, and
        // `durability_degraded` reports it.
        if let Err(e) = sync_directory(&self.dir) {
            self.durability_degraded.store(true, Ordering::Relaxed);
            warn!(
                "{} is stored and indexed, but {} could not be synced: {e}. It is \
                 visible now; its survival across a power loss depends on the \
                 filesystem",
                path.display(),
                self.dir.display()
            );
        }
        Ok(outcome)
    }
}

/// Take the exclusive lock that grants use of `dir`.
fn acquire_lock(dir: &Path) -> Result<File> {
    let path = dir.join(LOCK_FILE_NAME);
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| {
            Error::Storage(format!(
                "cannot create the pointer store lock {}: {e}",
                path.display()
            ))
        })?;
    file.try_lock_exclusive().map_err(|e| {
        Error::Storage(format!(
            "another pointer store already has {} open ({e}). Two stores over one \
             directory each keep their own index, and the staler one would overwrite \
             the other's newer record",
            dir.display()
        ))
    })?;
    Ok(file)
}

/// Read one record file, refusing anything that is not exactly a record long.
///
/// The length is taken from the directory entry before any bytes are read, so a
/// corrupt oversized file cannot be pulled into memory.
fn read_record_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Storage(format!("pointer read failed: {e}"))),
    };
    let len = file
        .metadata()
        .map_err(|e| Error::Storage(format!("pointer stat failed: {e}")))?
        .len();
    if len != POINTER_WIRE_LEN as u64 {
        warn!(
            "Pointer file {} is {len} bytes, not {POINTER_WIRE_LEN}",
            path.display()
        );
        return Ok(None);
    }

    let mut bytes = Vec::with_capacity(POINTER_WIRE_LEN);
    // One byte past the record: a file that grew between the stat and the read
    // is refused rather than silently truncated into something that parses.
    file.take(POINTER_WIRE_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Storage(format!("pointer read failed: {e}")))?;
    if bytes.len() != POINTER_WIRE_LEN {
        warn!(
            "Pointer file {} changed size while being read",
            path.display()
        );
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// Rebuild the index by reading every record in `dir`.
fn scan(dir: &Path) -> Result<HashMap<XorName, IndexEntry>> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::Storage(format!("cannot read {}: {e}", dir.display())))?;

    let mut index = HashMap::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                warn!("Skipping unreadable pointer directory entry: {e}");
                continue;
            }
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == LOCK_FILE_NAME {
            continue;
        }
        if name.starts_with(TEMP_PREFIX) {
            // A temporary file means a crash mid-write: the rename never
            // happened, so the old record (if any) is intact and the partial
            // file has no claim. Sweep it, or the next write to that address
            // collides with it — `create_new` would refuse, and the write
            // sequence restarts at zero on every opening.
            if let Err(e) = std::fs::remove_file(&path) {
                warn!(
                    "Could not sweep the partial pointer write {}: {e}",
                    path.display()
                );
            }
            continue;
        }
        let bytes = match read_record_file(&path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(e) => {
                warn!("Skipping unreadable pointer file {}: {e}", path.display());
                continue;
            }
        };
        let record = match Pointer::from_bytes(&bytes) {
            Ok(record) => record,
            Err(e) => {
                warn!("Skipping invalid pointer file {}: {e}", path.display());
                continue;
            }
        };
        let address = record.address();
        if hex::encode(address) != name {
            warn!(
                "Skipping pointer file {} that is not at its own address",
                path.display()
            );
            continue;
        }
        let generation = u64::try_from(index.len()).unwrap_or(u64::MAX);
        index.insert(address, IndexEntry::of(&record, generation));
    }
    Ok(index)
}

/// Write `bytes` to `temp` and fsync it, ready to be renamed into place.
///
/// Leaves nothing half written: the bytes are durable in the temporary file
/// before any rename can make them visible, and a failure at any step removes
/// it. The caller performs the rename, which is the commit point.
fn stage(temp: &Path, bytes: &[u8]) -> Result<()> {
    // `create_new` so a leftover temporary file from a crashed write is never
    // silently appended to or shared with a concurrent writer.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)
        .map_err(|e| Error::Storage(format!("cannot create {}: {e}", temp.display())))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::Storage(format!("cannot write {}: {e}", temp.display())));
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(temp);
        return Err(e);
    }
    Ok(())
}

/// Flush the directory entry a rename created.
///
/// Without it a crash can leave the entry unflushed and the record invisible on
/// restart. Opening a directory is not portable, so a directory that cannot be
/// opened is reported as success with a note: there is nothing to sync and
/// nothing went wrong with the write.
fn sync_directory(dir: &Path) -> Result<()> {
    match File::open(dir) {
        Ok(handle) => handle
            .sync_all()
            .map_err(|e| Error::Storage(format!("cannot sync {}: {e}", dir.display()))),
        Err(e) => Err(Error::Storage(format!(
            "cannot open {} to flush it: {e}",
            dir.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_protocol::pointer::{PointerTarget, PointerTargetKind, POINTER_BODY_LEN};
    use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};

    fn keypair(seed: u8) -> (MlDsaPublicKey, MlDsaSecretKey) {
        ml_dsa_65().generate_keypair_from_seed(&[seed; 32])
    }

    fn signed(seed: u8, counter: u64, target_byte: u8) -> Pointer {
        let (pk, sk) = keypair(seed);
        let target = PointerTarget::new(PointerTargetKind::Chunk, [target_byte; 32]);
        Pointer::sign(&sk, &pk, counter, target).expect("sign")
    }

    /// A record with its signature destroyed: the body still parses, the
    /// record does not verify.
    fn forged(record: &Pointer) -> Vec<u8> {
        let mut bytes = record.to_bytes().to_vec();
        if let Some(byte) = bytes.get_mut(POINTER_BODY_LEN + 3) {
            *byte ^= 0xff;
        }
        assert!(
            Pointer::from_bytes(&bytes).is_err(),
            "the forged record must not verify"
        );
        bytes
    }

    async fn store() -> (PointerStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PointerStore::new(dir.path()).await.expect("open store");
        (store, dir)
    }

    #[tokio::test]
    async fn stores_then_reads_back_the_same_bytes() {
        let (store, _dir) = store().await;
        let record = signed(1, 1, 1);
        assert_eq!(
            store.put_bytes(&record.to_bytes()).await.expect("put"),
            PutOutcome::Stored
        );

        let read = store
            .get(&record.address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(read.to_bytes(), record.to_bytes());
        assert_eq!(store.state_id(&record.address()), Some(record.state_id()));
        assert_eq!(
            store.bytes_hash(&record.address()),
            Some(record.bytes_hash())
        );
        assert!(store.contains(&record.address()));
        assert!(store.holds_state(&record.address(), &record.state_id()));
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn a_higher_counter_replaces_and_a_lower_one_does_not() {
        let (store, _dir) = store().await;
        let first = signed(1, 1, 1);
        let second = signed(1, 2, 1);
        assert_eq!(
            store.put_bytes(&first.to_bytes()).await.expect("put"),
            PutOutcome::Stored
        );
        assert_eq!(
            store.put_bytes(&second.to_bytes()).await.expect("put"),
            PutOutcome::Replaced
        );
        assert_eq!(
            store.put_bytes(&first.to_bytes()).await.expect("put"),
            PutOutcome::Stale
        );

        let held = store
            .get(&first.address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(held.counter(), 2);
        assert_eq!(store.len(), 1, "an update replaces in place");
    }

    #[tokio::test]
    async fn re_signing_one_state_never_reaches_the_disk() {
        // One payment must not fund many writes. Every re-signature of a stored
        // state is a no-op, so storage, replication and commitment work is paid
        // for once.
        let (store, _dir) = store().await;
        let first = signed(1, 5, 5);
        store.put_bytes(&first.to_bytes()).await.expect("put");

        let path = store.dir().join(hex::encode(first.address()));
        let held_bytes = std::fs::read(&path).expect("read");

        for _ in 0..16 {
            let variant = signed(1, 5, 5);
            assert_ne!(
                variant.to_bytes(),
                first.to_bytes(),
                "signing is randomized"
            );
            assert_eq!(variant.state_id(), first.state_id());
            assert_eq!(
                store.put_bytes(&variant.to_bytes()).await.expect("put"),
                PutOutcome::Unchanged
            );
        }

        assert_eq!(
            std::fs::read(&path).expect("read"),
            held_bytes,
            "not one of the 16 re-signatures reached the disk"
        );
        assert_eq!(store.bytes_hash(&first.address()), Some(first.bytes_hash()));
    }

    #[tokio::test]
    async fn a_resubmission_is_refused_before_its_signature_is_checked() {
        // An arrival that cannot change anything is a no-op whether or not it
        // is correctly signed, so it must not buy an ML-DSA verification. A
        // record whose signature is destroyed proves the check was skipped:
        // had it run, this would have been an error rather than Unchanged.
        let (store, _dir) = store().await;
        let held = signed(1, 4, 4);
        store.put_bytes(&held.to_bytes()).await.expect("put");

        assert_eq!(
            store.put_bytes(&forged(&held)).await.expect("put"),
            PutOutcome::Unchanged
        );

        let after = store
            .get(&held.address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(after.to_bytes(), held.to_bytes(), "nothing was written");
    }

    #[tokio::test]
    async fn a_stale_arrival_is_refused_before_its_signature_is_checked() {
        let (store, _dir) = store().await;
        store
            .put_bytes(&signed(1, 9, 1).to_bytes())
            .await
            .expect("put");

        // Unsigned *and* stale: refused as Stale, which can only happen if the
        // signature was never checked.
        let older = signed(1, 2, 1);
        assert_eq!(
            store.put_bytes(&forged(&older)).await.expect("put"),
            PutOutcome::Stale
        );
    }

    #[tokio::test]
    async fn a_would_be_winner_is_always_verified() {
        // Losing records skip verification; a record that would win never does.
        let (store, _dir) = store().await;
        store
            .put_bytes(&signed(1, 1, 1).to_bytes())
            .await
            .expect("put");

        let winner = signed(1, 5, 1);
        assert!(store.put_bytes(&forged(&winner)).await.is_err());

        let held = store
            .get(&winner.address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(held.counter(), 1, "the forged winner did not land");
    }

    #[tokio::test]
    async fn prepare_reports_a_no_op_without_a_candidate() {
        let (store, _dir) = store().await;
        let held = signed(1, 6, 6);
        store.put_bytes(&held.to_bytes()).await.expect("put");

        match store.prepare(&held.to_bytes()).await.expect("prepare") {
            Prepared::Noop(outcome) => assert_eq!(outcome, PutOutcome::Unchanged),
            Prepared::Candidate(_) => panic!("an identical state is not a candidate"),
        }
        match store
            .prepare(&signed(1, 1, 6).to_bytes())
            .await
            .expect("prepare")
        {
            Prepared::Noop(outcome) => assert_eq!(outcome, PutOutcome::Stale),
            Prepared::Candidate(_) => panic!("a stale record is not a candidate"),
        }
    }

    #[tokio::test]
    async fn a_candidate_exposes_what_a_payment_check_needs() {
        let (store, _dir) = store().await;
        let record = signed(1, 2, 2);
        match store.prepare(&record.to_bytes()).await.expect("prepare") {
            Prepared::Candidate(prepared) => {
                assert_eq!(prepared.address(), record.address());
                assert_eq!(prepared.state_id(), record.state_id());
                assert_eq!(prepared.record().to_bytes(), record.to_bytes());
                assert_eq!(
                    store.commit(prepared).await.expect("commit"),
                    PutOutcome::Stored
                );
            }
            Prepared::Noop(_) => panic!("a new record is a candidate"),
        }
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn a_commit_rechecks_what_prepare_saw() {
        // `prepare` runs before the payment check; a newer state can land while
        // that check is in flight, and must not then be overwritten.
        let (store, _dir) = store().await;
        let slow = match store
            .prepare(&signed(1, 2, 1).to_bytes())
            .await
            .expect("prepare")
        {
            Prepared::Candidate(prepared) => prepared,
            Prepared::Noop(_) => panic!("expected a candidate"),
        };

        // Someone else's newer state arrives while the payment is being checked.
        store
            .put_bytes(&signed(1, 7, 1).to_bytes())
            .await
            .expect("put");

        assert_eq!(
            store.commit(slow).await.expect("commit"),
            PutOutcome::Stale,
            "the newer state must survive a late commit"
        );
        let held = store
            .get(&signed(1, 2, 1).address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(held.counter(), 7);
    }

    #[tokio::test]
    async fn put_bytes_rejects_junk() {
        let (store, _dir) = store().await;
        assert!(store.put_bytes(b"not a pointer").await.is_err());
        assert!(store.put_bytes(&[]).await.is_err());
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn every_rotation_of_a_delivery_reaches_one_answer() {
        let records = vec![
            signed(1, 1, 9),
            signed(1, 3, 4),
            signed(1, 3, 1),
            signed(1, 2, 8),
            signed(1, 3, 7),
        ];
        let address = records.first().expect("non-empty").address();

        let mut winners = Vec::new();
        for rotation in 0..records.len() {
            let (store, _dir) = store().await;
            for offset in 0..records.len() {
                let index = (rotation + offset) % records.len();
                let record = records.get(index).expect("in range");
                store.put_bytes(&record.to_bytes()).await.expect("put");
            }
            let held = store.get(&address).await.expect("get").expect("present");
            winners.push(held.state_id());
        }

        let distinct: std::collections::BTreeSet<&XorName> = winners.iter().collect();
        assert_eq!(
            distinct.len(),
            1,
            "every rotation converges: {winners:?}. Exhaustive permutations are \
             covered by the convergence property test"
        );
    }

    #[tokio::test]
    async fn a_node_started_empty_reaches_the_same_answer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let address;
        let before;
        {
            let store = PointerStore::new(dir.path()).await.expect("open");
            for record in [signed(1, 1, 1), signed(1, 4, 2), signed(1, 2, 3)] {
                store.put_bytes(&record.to_bytes()).await.expect("put");
            }
            address = signed(1, 1, 1).address();
            before = store.get(&address).await.expect("get").expect("present");
        }

        // A fresh store over the same directory, as after a restart. The first
        // must be dropped: the directory lock allows only one at a time.
        let reopened = PointerStore::new(dir.path()).await.expect("reopen");
        assert_eq!(reopened.len(), 1);
        let after = reopened.get(&address).await.expect("get").expect("present");
        assert_eq!(after.to_bytes(), before.to_bytes());
        assert_eq!(reopened.state_id(&address), Some(before.state_id()));
        assert_eq!(reopened.bytes_hash(&address), Some(before.bytes_hash()));
    }

    #[tokio::test]
    async fn a_second_store_over_one_directory_is_refused() {
        // Two indexes over one set of files means the staler one overwrites the
        // fresher one's record.
        let dir = tempfile::tempdir().expect("tempdir");
        let _first = PointerStore::new(dir.path()).await.expect("open");
        let err = PointerStore::new(dir.path())
            .await
            .err()
            .expect("a second store must not open the same directory");
        let message = format!("{err}");
        assert!(
            message.contains("another pointer store already has"),
            "it must be refused by the directory lock, not by something else: {message}"
        );
    }

    #[tokio::test]
    async fn two_owners_occupy_two_addresses() {
        let (store, _dir) = store().await;
        let first = signed(1, 1, 1);
        let second = signed(2, 1, 1);
        assert_ne!(first.address(), second.address());
        store.put_bytes(&first.to_bytes()).await.expect("put");
        store.put_bytes(&second.to_bytes()).await.expect("put");
        assert_eq!(store.len(), 2);
        assert_eq!(store.all_keys().len(), 2);
        assert_eq!(store.all_states().len(), 2);
    }

    #[tokio::test]
    async fn a_corrupt_file_is_forgotten_so_the_record_can_be_repaired() {
        let (store, _dir) = store().await;
        let record = signed(1, 1, 1);
        store.put_bytes(&record.to_bytes()).await.expect("put");

        let path = store.dir().join(hex::encode(record.address()));
        let mut bytes = std::fs::read(&path).expect("read back");
        if let Some(byte) = bytes.get_mut(10) {
            *byte ^= 0xff;
        }
        std::fs::write(&path, &bytes).expect("corrupt it");

        assert!(store.get(&record.address()).await.expect("get").is_none());
        assert!(
            !store.contains(&record.address()),
            "the index must not keep claiming a record the disk lost"
        );
        assert_eq!(store.state_id(&record.address()), None);

        // The repair a peer would send is accepted rather than dismissed as
        // "unchanged", which is the whole point of forgetting it.
        assert_eq!(
            store.put_bytes(&record.to_bytes()).await.expect("put"),
            PutOutcome::Stored
        );
        assert!(store.get(&record.address()).await.expect("get").is_some());
    }

    #[tokio::test]
    async fn a_deleted_file_is_forgotten_too() {
        let (store, _dir) = store().await;
        let record = signed(1, 1, 1);
        store.put_bytes(&record.to_bytes()).await.expect("put");

        std::fs::remove_file(store.dir().join(hex::encode(record.address()))).expect("remove");
        assert!(store.get(&record.address()).await.expect("get").is_none());
        assert!(!store.contains(&record.address()));
    }

    #[tokio::test]
    async fn a_scan_skips_what_it_cannot_validate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = signed(1, 1, 1);
        {
            let store = PointerStore::new(dir.path()).await.expect("open");
            store.put_bytes(&record.to_bytes()).await.expect("put");

            // Junk under a plausible name, an oversized file, and a partial write.
            std::fs::write(store.dir().join(hex::encode([9u8; 32])), b"not a pointer")
                .expect("write junk");
            std::fs::write(
                store.dir().join(hex::encode([8u8; 32])),
                vec![0u8; POINTER_WIRE_LEN * 4],
            )
            .expect("write oversized");
            std::fs::write(store.dir().join(".tmp-abc-0"), vec![0u8; POINTER_WIRE_LEN])
                .expect("write temp");
        }

        let reopened = PointerStore::new(dir.path()).await.expect("reopen");
        assert_eq!(reopened.len(), 1, "only the valid record is indexed");
        assert!(reopened.contains(&record.address()));
    }

    #[tokio::test]
    async fn concurrent_writers_leave_the_index_agreeing_with_the_disk() {
        let (store, _dir) = store().await;
        let address = signed(1, 0, 0).address();

        let mut tasks = Vec::new();
        for counter in 1..=12u64 {
            let store = store.clone();
            let bytes = signed(1, counter, 1).to_bytes().to_vec();
            tasks.push(tokio::spawn(async move { store.put_bytes(&bytes).await }));
        }
        for task in tasks {
            task.await.expect("join").expect("put");
        }

        let held = store.get(&address).await.expect("get").expect("present");
        assert_eq!(held.counter(), 12, "the highest counter must win");
        assert_eq!(store.state_id(&address), Some(held.state_id()));
        assert_eq!(store.bytes_hash(&address), Some(held.bytes_hash()));
        assert_eq!(store.len(), 1);

        // No temporary file survived the race.
        let leftovers: Vec<_> = std::fs::read_dir(store.dir())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(TEMP_PREFIX))
            .collect();
        assert!(leftovers.is_empty(), "temporary files were left behind");
    }

    #[tokio::test]
    async fn a_cancelled_commit_leaves_the_index_agreeing_with_the_disk() {
        // Dropping the caller's future must not split the transaction: either
        // the write and the index update both happened, or neither did.
        let (store, _dir) = store().await;
        let record = signed(1, 3, 3);
        let prepared = match store.prepare(&record.to_bytes()).await.expect("prepare") {
            Prepared::Candidate(prepared) => prepared,
            Prepared::Noop(_) => panic!("expected a candidate"),
        };

        let abandoned = {
            let committing = store.commit(prepared);
            tokio::pin!(committing);
            // Poll once, then abandon it. If it happened to finish inside the
            // timeout there was no cancellation to test, and the assertion
            // below still has to hold.
            tokio::time::timeout(std::time::Duration::from_nanos(1), &mut committing)
                .await
                .is_err()
        };

        // Wait for the detached task to settle rather than guessing at a
        // duration: poll until the disk and the index agree and stop changing.
        let mut settled = false;
        for _ in 0..200 {
            let on_disk = store.get(&record.address()).await.expect("get").is_some();
            if on_disk == store.contains(&record.address()) && on_disk {
                settled = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let on_disk = store.get(&record.address()).await.expect("get").is_some();
        let indexed = store.contains(&record.address());
        assert_eq!(
            on_disk, indexed,
            "the index and the disk must agree however the commit was interrupted \
             (caller was cancelled: {abandoned})"
        );
        assert!(
            abandoned,
            "the caller must actually have been cancelled, or this proves nothing"
        );
        assert!(
            settled,
            "the detached commit must run to completion rather than stopping half done"
        );
    }

    #[tokio::test]
    async fn an_empty_store_holds_nothing() {
        let (store, _dir) = store().await;
        assert!(store.is_empty());
        assert_eq!(store.state_id(&[0u8; 32]), None);
        assert_eq!(store.bytes_hash(&[0u8; 32]), None);
        assert!(!store.holds_state(&[0u8; 32], &[0u8; 32]));
        assert!(store.get(&[0u8; 32]).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn a_failed_read_does_not_erase_a_record_written_since() {
        // A read that finds the file unreadable may only disown the entry it
        // set out to read. A commit that lands meanwhile must survive, or the
        // node ends up holding a record it never announces or commits to.
        let (store, _dir) = store().await;
        let old = signed(1, 1, 1);
        store.put_bytes(&old.to_bytes()).await.expect("put");

        // Simulate the interleaving: the read observed the old entry, then a
        // newer state was committed, and only then does the read disown what
        // it saw.
        let observed = store.snapshot(&old.address()).map(|entry| entry.generation);
        let new = signed(1, 2, 1);
        store.put_bytes(&new.to_bytes()).await.expect("put");

        store.forget_if_unchanged(&old.address(), observed);
        assert_eq!(
            store.state_id(&new.address()),
            Some(new.state_id()),
            "the record committed during the read must still be indexed"
        );

        // And the ordinary case still works: disowning what is actually there.
        let current = store.snapshot(&new.address()).map(|entry| entry.generation);
        store.forget_if_unchanged(&new.address(), current);
        assert!(!store.contains(&new.address()));
    }

    #[tokio::test]
    async fn a_repair_of_the_same_state_is_not_erased_by_a_second_reader() {
        // Two readers observe one corrupt entry. The first disowns it, a repair
        // restores exactly the same logical state, and the second reader must
        // not then erase the repair — the state identifier alone cannot tell
        // the repaired entry from the corrupt one it replaced.
        let (store, _dir) = store().await;
        let record = signed(1, 1, 1);
        store.put_bytes(&record.to_bytes()).await.expect("put");

        let first_reader = store
            .snapshot(&record.address())
            .map(|entry| entry.generation);
        let second_reader = first_reader;

        // Reader one finds the file unreadable and disowns what it saw.
        store.forget_if_unchanged(&record.address(), first_reader);
        assert!(!store.contains(&record.address()));

        // A peer repairs it with the very same state.
        assert_eq!(
            store.put_bytes(&record.to_bytes()).await.expect("put"),
            PutOutcome::Stored
        );

        // Reader two, still holding its stale observation, must not erase it.
        store.forget_if_unchanged(&record.address(), second_reader);
        assert!(
            store.contains(&record.address()),
            "the repair must survive a second reader disowning the old entry"
        );
        assert_eq!(store.state_id(&record.address()), Some(record.state_id()));
    }

    #[tokio::test]
    async fn a_leftover_partial_write_is_swept_and_does_not_block_the_next_write() {
        // The write sequence restarts at zero on every opening, so a temporary
        // file left by a crash would collide with the next write to that
        // address and `create_new` would refuse it.
        let dir = tempfile::tempdir().expect("tempdir");
        let record = signed(1, 1, 1);
        {
            let store = PointerStore::new(dir.path()).await.expect("open");
            let leftover = store
                .dir()
                .join(format!("{TEMP_PREFIX}{}-0", hex::encode(record.address())));
            std::fs::write(&leftover, vec![0u8; POINTER_WIRE_LEN]).expect("write leftover");
        }

        let reopened = PointerStore::new(dir.path()).await.expect("reopen");
        assert_eq!(
            reopened.put_bytes(&record.to_bytes()).await.expect("put"),
            PutOutcome::Stored,
            "a swept leftover must not block the first write to its address"
        );
    }

    #[tokio::test]
    async fn a_healthy_store_does_not_report_degraded_durability() {
        let (store, _dir) = store().await;
        store
            .put_bytes(&signed(1, 1, 1).to_bytes())
            .await
            .expect("put");
        assert!(
            !store.durability_degraded(),
            "an ordinary write on a working filesystem is fully durable"
        );
    }

    #[tokio::test]
    async fn holding_the_key_is_not_holding_the_state() {
        // The fetch decision a mutable record needs: a replica on version N
        // must not count as satisfied for version N+1.
        let (store, _dir) = store().await;
        let old = signed(1, 1, 1);
        let new = signed(1, 2, 1);
        store.put_bytes(&old.to_bytes()).await.expect("put");

        assert!(store.contains(&new.address()));
        assert!(store.holds_state(&old.address(), &old.state_id()));
        assert!(
            !store.holds_state(&new.address(), &new.state_id()),
            "the newer state is absent even though the key is held"
        );
    }
}
