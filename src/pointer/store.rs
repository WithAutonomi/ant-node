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
//! A put is three steps, because the caller's gates sit between them:
//!
//! 1. `inspect` parses and compares against what is held: the arrival is
//!    either unchanged, stale, or a candidate that would win.
//! 2. `verify` checks the candidate's signature — after the caller's
//!    admission gates, and before it verifies payment.
//! 3. `commit` writes it, and settles the disk charge taken for it.
//!
//! Those three are internal to the crate; [`PointerStore::put_bytes`] is the
//! same sequence in one call, for callers with nothing to do in between.
//!
//! Nothing cheap happens after something expensive: a resubmission of what is
//! held is refused before any signature check, so repeatedly submitting one
//! paid state buys no ML-DSA verifications. Step 2 runs **outside** any store
//! lock, so a flood of unpaid candidates cannot block every other address
//! behind one verification, and step 3 re-checks under the lock, because the
//! world may have moved while payment was being verified.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use fs2::FileExt;
use parking_lot::Mutex;
use tokio::task::spawn_blocking;

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::logging::{debug, warn};
use ant_protocol::pointer::{ParsedPointer, Pointer, PointerState, POINTER_WIRE_LEN};

use crate::storage::Reservation;

/// Directory under the store root that holds pointer records.
const POINTERS_DIR_NAME: &str = "pointers";

/// Prefix for the temporary file a write lands in before being renamed.
const TEMP_PREFIX: &str = ".tmp-";

/// Name of the file whose lock grants exclusive use of the directory.
const LOCK_FILE_NAME: &str = ".pointer-store-lock";

/// What a put did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// The record was written: either nothing was held, or it won the merge.
    ///
    /// One outcome rather than two, because nothing downstream treats "stored"
    /// differently from "replaced": both mean the node now holds this state.
    Changed,
    /// The held record is the same authenticated state. Nothing was written.
    ///
    /// This is the case that keeps one payment from funding many writes: an
    /// owner can produce unboundedly many valid signatures over one state, and
    /// every one of them lands here.
    Unchanged,
    /// The incoming record lost under the merge rule. Nothing was written.
    Stale,
}

/// The result of [`PointerStore::inspect`]: what an arrival claims, before any
/// signature has been checked.
#[derive(Debug)]
pub(crate) enum Inspected {
    /// The node already holds exactly this state. No signature check is owed:
    /// a resubmission of what was paid for and a forgery of it are the same
    /// no-op.
    Unchanged(PointerState),
    /// The arrival loses to what is held, so it changes nothing either.
    Stale(PointerState),
    /// The arrival would win as it stands. Its signature has **not** been
    /// checked yet — pass it to [`PointerStore::verify`] once admission gates
    /// have had their say.
    Candidate(ParsedPointer),
}

/// What the store knows about a held record without reading it back.
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    /// The held record's authenticated state.
    ///
    /// The state itself rather than fields copied out of it, so every rule the
    /// store applies — merge order, the paid increment — is the protocol's own
    /// rule applied to the held state, and cannot drift from it.
    state: PointerState,
    /// Whether the file behind `state` is still there and still that record.
    ///
    /// A read that finds it gone or different clears this rather than dropping
    /// the entry. The node stops serving the record, because it does not have
    /// it — but it still knows what it had, and that is what lets the state be
    /// restored. Dropping the entry would leave the address looking untouched,
    /// where only a counter 0 record is admissible, so a pointer that had ever
    /// been updated could never be repaired.
    on_disk: bool,
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
            state: record.state(),
            on_disk: true,
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
                _lock_file: lock_file,
            }),
        })
    }

    /// Parse an arrival and decide whether it could change anything, without
    /// verifying its signature.
    ///
    /// Cheap checks first: an arrival that cannot change anything is refused
    /// before its signature is looked at, because it is a no-op whether or not
    /// it is correctly signed. That ordering is what stops repeated submission
    /// of one paid state from buying ML-DSA verifications. Callers that gate on
    /// admission — capacity, responsibility for the address — run this first,
    /// apply their
    /// gates, and only then pay for [`Self::verify`]. Otherwise a forged record
    /// for an address the node is not responsible for still buys an ML-DSA
    /// verification before anything rejects it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the bytes are not a well-formed record.
    pub(crate) async fn inspect(&self, bytes: &[u8]) -> Result<Inspected> {
        // Off the executor: deciding this reads the held record back off the
        // disk, and a flood of arrivals must not put a blocking read on a
        // runtime worker for each one.
        let store = self.clone();
        let bytes = bytes.to_vec();
        spawn_blocking(move || store.inspect_blocking(&bytes))
            .await
            .map_err(|e| Error::Storage(format!("pointer inspection panicked: {e}")))?
    }

    /// The body of [`Self::inspect`], on a blocking thread.
    fn inspect_blocking(&self, bytes: &[u8]) -> Result<Inspected> {
        // Parsing decodes the owner key once; `verify` reuses that parse rather
        // than decoding again. The bytes travel with it, so the two cannot be
        // mismatched.
        let parsed = ParsedPointer::parse(bytes.to_vec())?;
        let state = *parsed.state();

        // Both early answers below assert that this node holds something at
        // least as good as what arrived, so neither may be given on the index's
        // word alone.
        if let Some(held) = self.held_state(&state.address) {
            if held.state_id == state.state_id {
                return Ok(Inspected::Unchanged(state));
            }
            if !state.replaces(&held) {
                return Ok(Inspected::Stale(state));
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
    pub(crate) async fn verify(&self, parsed: ParsedPointer) -> Result<Pointer> {
        spawn_blocking(move || Pointer::verify_parsed(parsed))
            .await
            .map_err(|e| Error::Storage(format!("pointer verification panicked: {e}")))?
            .map_err(Into::into)
    }

    /// Commit a prepared record.
    ///
    /// Re-checks against what is held before writing: `prepare` may have run
    /// before a payment check that took long enough for a newer state to
    /// arrive, and the re-check is what keeps that newer state from being
    /// overwritten.
    ///
    /// `reservation` is the disk charge for this write, taken before the call.
    /// It moves into the blocking transaction rather than staying with the
    /// caller, because the caller's future can be dropped while that
    /// transaction runs on: a charge released here would leave the file that
    /// landed a moment later uncounted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the write fails.
    pub(crate) async fn commit(
        &self,
        record: Pointer,
        reservation: Option<Reservation>,
    ) -> Result<PutOutcome> {
        let inner = Arc::clone(&self.inner);
        // The whole transaction runs in one task, so dropping this future
        // cannot leave the write done and the index un-updated.
        spawn_blocking(move || inner.commit_blocking(&record, reservation))
            .await
            .map_err(|e| Error::Storage(format!("pointer commit panicked: {e}")))?
    }

    /// Validate and store in one step, with no payment gate.
    ///
    /// For callers that have already settled payment, and for tests. The
    /// request path runs the same three steps with its admission and payment
    /// gates between them.
    ///
    /// # Errors
    ///
    /// As the three steps it runs: a malformed record, a signature that does
    /// not verify, or a write that fails.
    pub async fn put_bytes(&self, bytes: &[u8]) -> Result<PutOutcome> {
        match self.inspect(bytes).await? {
            Inspected::Unchanged(_) => Ok(PutOutcome::Unchanged),
            Inspected::Stale(_) => Ok(PutOutcome::Stale),
            Inspected::Candidate(parsed) => {
                let record = self.verify(parsed).await?;
                self.commit(record, None).await
            }
        }
    }

    /// Read the record held at `address`, if any.
    ///
    /// Re-validates on the way out: the signature is checked and the record
    /// must belong at the address asked for, so a file corrupted under the node
    /// is reported as missing rather than served as authentic, and the entry is
    /// disowned so the node will take a fresh copy instead of answering
    /// "unchanged" to its own repair.
    ///
    /// The file is what is served, not the index. A file replaced under the
    /// node by a *different* record that is genuinely signed for this address
    /// is served as held — it is a real record, the reader verifies it, and the
    /// read quorum is what decides between replicas that disagree. What the
    /// index is not allowed to do is claim a state the file does not have —
    /// that check guards `inspect`'s two early answers, the ones that
    /// assert this node already holds something.
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
                self.disown_if_unchanged(address, claimed);
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
                self.disown_if_unchanged(address, claimed);
                Ok(None)
            }
            Err(e) => {
                warn!(
                    "Pointer file at {} does not validate ({e}); dropping it from the index",
                    hex::encode(address)
                );
                self.disown_if_unchanged(address, claimed);
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
        self.snapshot(address)
            .filter(|entry| entry.on_disk)
            .map(|entry| entry.state.state_id)
    }

    /// Whether `state` is a paid update of what is held.
    ///
    /// One payment buys one increment: a new pointer starts at counter 0, and
    /// an update either advances the counter by one or wins the target
    /// tie-break at the counter already held. Without the bound an owner pays
    /// once, jumps the counter, skips every intermediate payment and strands
    /// the pointer where nothing can advance it; without the tie-break, two
    /// separately paid states at one counter would leave every node holding
    /// whichever reached it first.
    ///
    /// Only the client path asks this. Replication uses the merge rule instead,
    /// so a replica that missed an update can still catch up rather than being
    /// stuck behind a gap it can never fill.
    ///
    /// A record this node knew and lost takes that same merge rule: anything at
    /// least as good as the lost state restores it. The increment rule exists to
    /// stop an owner buying one state and skipping to it, and a repair skips
    /// nothing — the state it carries was paid for and the rest of the group
    /// already serves it. Holding a lost address to the increment rule would
    /// make every loss above counter 0 permanent, because only a counter 0
    /// record is admissible at an address nothing is known about.
    #[must_use]
    pub fn accepts_as_paid_update(&self, state: &PointerState) -> bool {
        self.snapshot(&state.address).map_or_else(
            || state.is_genesis(),
            |entry| {
                if entry.on_disk {
                    state.is_paid_update_of(&entry.state)
                } else {
                    state.state_id == entry.state.state_id || state.replaces(&entry.state)
                }
            },
        )
    }

    /// Whether a record is held at `address`.
    #[must_use]
    pub fn contains(&self, address: &XorName) -> bool {
        self.snapshot(address).is_some_and(|entry| entry.on_disk)
    }

    /// How many records the store holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .index
            .lock()
            .values()
            .filter(|entry| entry.on_disk)
            .count()
    }

    /// Whether the store holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Directory holding the records.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }

    /// The state this node can actually serve at `address`, having read it
    /// back.
    ///
    /// The index is a claim about a file; this is that claim checked. The file
    /// must still be there and must still be the record the index names —
    /// comparing the state, not merely the address, because the disk and the
    /// index are updated under one lock and an answer taken between the two
    /// would otherwise describe a record that is no longer the one held.
    ///
    /// Only the structure is parsed: these bytes verified when they were
    /// committed, and the question here is what is held, not whether it is
    /// authentic. Corruption inside the signature therefore passes here — the
    /// state is read from the body — and is caught by [`Self::get`], which
    /// verifies and disowns. Checking it here instead would put an ML-DSA
    /// verification in front of the payment gate, which is the one place it
    /// must not be. A failed check disowns the entry, so the arrival that found
    /// it becomes a repair.
    fn held_state(&self, address: &XorName) -> Option<PointerState> {
        let entry = self.snapshot(address).filter(|entry| entry.on_disk)?;
        let serves = matches!(
            read_record_file(&self.path_for(address)),
            Ok(Some(ref bytes)) if matches!(
                PointerState::parse(bytes),
                Ok(ref state) if *state == entry.state
            )
        );
        if !serves {
            self.disown_if_unchanged(address, Some(entry.generation));
            return None;
        }
        Some(entry.state)
    }

    /// Copy out what is held for `address`, releasing the index lock at once.
    fn snapshot(&self, address: &XorName) -> Option<IndexEntry> {
        self.inner.index.lock().get(address).copied()
    }

    /// Stop serving `address`, but only if the entry is still the exact one
    /// the caller found unreadable.
    ///
    /// The entry stays, marked as no longer on disk: what was lost is what says
    /// which states can restore it.
    ///
    /// A read is not atomic with a write. Removing unconditionally would let a
    /// slow read of a corrupt file erase the entry for a record committed while
    /// it was reading, leaving the node holding a record it no longer
    /// announces, commits to, or can be audited for. Matching on the generation
    /// rather than the state identifier also covers the case where the record
    /// written meanwhile is a *repair of the same state*, which a state
    /// comparison could not tell apart from the entry being disowned.
    fn disown_if_unchanged(&self, address: &XorName, claimed: Option<u64>) {
        let Some(claimed) = claimed else {
            // Nothing was claimed when the read began, so there is nothing this
            // read is entitled to disown.
            return;
        };
        let mut index = self.inner.index.lock();
        if let Some(entry) = index.get_mut(address) {
            if entry.generation == claimed {
                entry.on_disk = false;
            }
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
    fn commit_blocking(
        &self,
        record: &Pointer,
        reservation: Option<Reservation>,
    ) -> Result<PutOutcome> {
        let address = record.address();
        let path = self.dir.join(hex::encode(address));

        // A cheap look before doing any work. The authoritative check is the
        // one under the lock below; this only avoids staging a file for an
        // arrival that is already obviously a no-op.
        if let Some(entry) = self.index.lock().get(&address).filter(|e| e.on_disk) {
            if entry.state.state_id == record.state_id() {
                return Ok(PutOutcome::Unchanged);
            }
            if !record.state().replaces(&entry.state) {
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
        if let Err(failed) = stage(&temp, &record.to_bytes()) {
            // Bytes that could not be cleaned up are still on the disk, so the
            // charge for them stands rather than going back.
            if failed.bytes_remain {
                settle(reservation);
            }
            return Err(failed.error);
        }

        let outcome = {
            let mut index = self.index.lock();

            // Re-check: staging is not instantaneous and a newer state may
            // have committed while it ran.
            let outcome = match index.get(&address) {
                // Nothing held, or a record this node lost: either way the
                // write must happen, whatever state it carries.
                None | Some(IndexEntry { on_disk: false, .. }) => PutOutcome::Changed,
                Some(entry) if entry.state.state_id == record.state_id() => PutOutcome::Unchanged,
                Some(entry) if record.state().replaces(&entry.state) => PutOutcome::Changed,
                Some(_) => PutOutcome::Stale,
            };
            if outcome != PutOutcome::Changed {
                // Nothing lands, so the charge goes back — unless the staged
                // bytes could not be removed, in which case they are still on
                // the disk and the charge has to stand for them.
                if std::fs::remove_file(&temp).is_err() {
                    settle(reservation);
                }
                return Ok(outcome);
            }

            // The rename is the commit point: nothing fallible happens between
            // it and the index update, and both are under this one lock.
            if let Err(e) = std::fs::rename(&temp, &path) {
                if std::fs::remove_file(&temp).is_err() {
                    settle(reservation);
                }
                return Err(Error::Storage(format!(
                    "cannot rename {} onto {}: {e}",
                    temp.display(),
                    path.display()
                )));
            }
            let generation = self.generation.fetch_add(1, Ordering::Relaxed);
            index.insert(address, IndexEntry::of(record, generation));
            // A file is on the disk now. Charge it whether or not this replaced
            // one: telling those apart would mean trusting an observation taken
            // before the rename, and that observation can be wrong in the one
            // direction that matters — a file the index claims can be gone, so
            // what looks like a replacement grows the disk after all.
            // Over-counting corrects itself at the next measurement.
            settle(reservation);
            outcome
        };

        // Durability of the directory entry, after the commit and outside the
        // lock. The record is already stored and indexed, so a failure here
        // cannot be reported as "nothing happened"; it is logged instead, which
        // is how an operator learns the filesystem is not giving the store what
        // it asks for.
        if let Err(e) = sync_directory(&self.dir) {
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
/// Returns `Err(StagingFailed { bytes_remain })` where `bytes_remain` says whether
/// the partial file is still on the disk, so the caller knows whether the charge
/// for it can be given back.
fn stage(temp: &Path, bytes: &[u8]) -> std::result::Result<(), StagingFailed> {
    // `create_new` so a leftover temporary file from a crashed write is never
    // silently appended to or shared with a concurrent writer.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)
        .map_err(|e| StagingFailed {
            // Nothing was created, so nothing is left behind.
            error: Error::Storage(format!("cannot create {}: {e}", temp.display())),
            bytes_remain: false,
        })?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::Storage(format!("cannot write {}: {e}", temp.display())));
    drop(file);
    if let Err(error) = written {
        // A partial file exists. If it cannot be removed it is still occupying
        // the disk, and its charge has to stand for it.
        return Err(StagingFailed {
            error,
            bytes_remain: std::fs::remove_file(temp).is_err(),
        });
    }
    Ok(())
}

/// A staged write that did not complete, and whether it left bytes behind.
struct StagingFailed {
    /// What went wrong, for the caller to return.
    error: Error,
    /// Whether a partial file is still on the disk.
    bytes_remain: bool,
}

/// Turn a charge into bytes that are now on the disk.
///
/// A charge that is simply dropped is released instead, which is what every
/// path that writes nothing wants.
fn settle(reservation: Option<Reservation>) {
    if let Some(reservation) = reservation {
        reservation.commit();
    }
}

/// Flush the directory entry a rename created.
///
/// Without it a crash can leave the entry unflushed and the record invisible on
/// restart.
#[cfg(unix)]
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

/// As above, where there is no such thing to ask for.
///
/// A directory cannot be opened as a file on Windows without backup semantics,
/// so the Unix form fails on every write there — which is not a durability
/// warning, it is the wrong question. NTFS orders the rename's own metadata.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps, reason = "one signature for both platforms")]
fn sync_directory(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]
mod tests {
    use super::*;
    use ant_protocol::pointer::{PointerTarget, PointerTargetKind, POINTER_BODY_LEN};
    use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};
    use std::future::Future;

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
        let mut bytes = record.to_bytes();
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
            PutOutcome::Changed
        );

        let read = store
            .get(&record.address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(read.to_bytes(), record.to_bytes());
        assert_eq!(store.state_id(&record.address()), Some(record.state_id()));
        assert!(store.contains(&record.address()));
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn a_higher_counter_replaces_and_a_lower_one_does_not() {
        let (store, _dir) = store().await;
        let first = signed(1, 1, 1);
        let second = signed(1, 2, 1);
        assert_eq!(
            store.put_bytes(&first.to_bytes()).await.expect("put"),
            PutOutcome::Changed
        );
        assert_eq!(
            store.put_bytes(&second.to_bytes()).await.expect("put"),
            PutOutcome::Changed
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
    async fn an_arrival_that_changes_nothing_is_not_a_candidate() {
        let (store, _dir) = store().await;
        let held = signed(1, 6, 6);
        store.put_bytes(&held.to_bytes()).await.expect("put");

        match store.inspect(&held.to_bytes()).await.expect("inspect") {
            Inspected::Unchanged(_) => (),
            other => panic!("an identical state is not a candidate, got {other:?}"),
        }
        match store
            .inspect(&signed(1, 1, 6).to_bytes())
            .await
            .expect("inspect")
        {
            Inspected::Stale(_) => (),
            other => panic!("a stale record is not a candidate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_verified_record_exposes_what_a_payment_check_needs() {
        let (store, _dir) = store().await;
        let record = signed(1, 2, 2);
        let verified = verified(&store, &record).await;
        // A verified record is a `Pointer`, so the payment check reads the
        // address and state straight off it — there is no wrapper type in
        // between restating what it already knows.
        assert_eq!(verified.address(), record.address());
        assert_eq!(verified.state_id(), record.state_id());
        assert_eq!(verified.to_bytes(), record.to_bytes());
        assert_eq!(
            store.commit(verified, None).await.expect("commit"),
            PutOutcome::Changed
        );
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn a_commit_that_writes_nothing_gives_its_charge_back() {
        // The reservation settles inside the commit transaction, so this is
        // where a no-op has to release it. Losing a race is the reachable way
        // to get there: the arrival is a candidate when it is inspected, and by
        // the time it commits a better state is held.
        //
        // Asserted on the guard's own counters, because "the next reservation
        // still succeeds" would pass just as well with the charge stranded.
        let (store, dir) = store().await;
        let chunks = crate::storage::ChunkStore::new(crate::storage::ChunkStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: false,
            max_map_size: 0,
            disk_reserve: 0,
            migration: crate::storage::MigrationConfig::default(),
        })
        .await
        .expect("chunk store");

        // Verified while nothing is held, so it is a candidate...
        let slow = verified(&store, &signed(1, 2, 1)).await;
        // ...and a better state lands before it commits.
        store
            .put_bytes(&signed(1, 7, 1).to_bytes())
            .await
            .expect("put");

        let before = chunks.capacity_counters();
        let charge = chunks.reserve(POINTER_WIRE_LEN as u64).expect("reserve");
        assert!(
            chunks.capacity_counters().1 > before.1,
            "taking a charge must raise in-flight"
        );

        assert_eq!(
            store.commit(slow, Some(charge)).await.expect("commit"),
            PutOutcome::Stale,
            "the newer state must stand"
        );
        assert_eq!(
            chunks.capacity_counters(),
            before,
            "a write that did not happen must leave both counters where it found them"
        );
    }

    #[tokio::test]
    async fn a_commit_that_writes_charges_the_disk_for_it() {
        // The other half: bytes that land move from in-flight to written, so
        // the guard counts them against the reserve from then on.
        let (store, dir) = store().await;
        let chunks = crate::storage::ChunkStore::new(crate::storage::ChunkStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: false,
            max_map_size: 0,
            disk_reserve: 0,
            migration: crate::storage::MigrationConfig::default(),
        })
        .await
        .expect("chunk store");

        let record = verified(&store, &signed(1, 0, 1)).await;
        let (written_before, in_flight_before) = chunks.capacity_counters();
        let charge = chunks.reserve(POINTER_WIRE_LEN as u64).expect("reserve");

        assert_eq!(
            store.commit(record, Some(charge)).await.expect("commit"),
            PutOutcome::Changed
        );
        let (written_after, in_flight_after) = chunks.capacity_counters();
        assert!(
            written_after > written_before,
            "the bytes that landed must be counted as written"
        );
        assert_eq!(
            in_flight_after, in_flight_before,
            "and must no longer be counted as in flight"
        );

        // A replacement charges too: telling it apart would mean trusting an
        // observation taken before the rename.
        let update = verified(&store, &signed(1, 1, 1)).await;
        let charge = chunks.reserve(POINTER_WIRE_LEN as u64).expect("reserve");
        assert_eq!(
            store.commit(update, Some(charge)).await.expect("commit"),
            PutOutcome::Changed
        );
        assert!(chunks.capacity_counters().0 > written_after);
    }

    #[tokio::test]
    async fn a_commit_rechecks_what_verification_saw() {
        // Verification runs before the payment check; a newer state can land
        // while that check is in flight, and must not then be overwritten.
        let (store, _dir) = store().await;
        let slow = verified(&store, &signed(1, 2, 1)).await;

        // Someone else's newer state arrives while the payment is being checked.
        store
            .put_bytes(&signed(1, 7, 1).to_bytes())
            .await
            .expect("put");

        assert_eq!(
            store.commit(slow, None).await.expect("commit"),
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
        let records = [
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
    }

    #[tokio::test]
    async fn a_second_store_over_one_directory_is_refused() {
        // Two indexes over one set of files means the staler one overwrites the
        // fresher one's record.
        let dir = tempfile::tempdir().expect("tempdir");
        let _first = PointerStore::new(dir.path()).await.expect("open");
        let err = PointerStore::new(dir.path())
            .await
            .expect_err("a second store must not open the same directory");
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
            PutOutcome::Changed
        );
        assert!(store.get(&record.address()).await.expect("get").is_some());
    }

    /// Run the production sequence as far as the payment gate: inspect, then
    /// verify the candidate it yields.
    async fn verified(store: &PointerStore, record: &Pointer) -> Pointer {
        match store.inspect(&record.to_bytes()).await.expect("inspect") {
            Inspected::Candidate(parsed) => store.verify(parsed).await.expect("verify"),
            other => panic!("expected a candidate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_resubmission_repairs_a_record_the_disk_lost() {
        // "Unchanged" is an acknowledgement: the sender stops on it. If the
        // index still claims a record whose file has gone, answering Unchanged
        // would end the write while this node holds nothing.
        let (store, _dir) = store().await;
        let record = signed(1, 0, 1);
        store.put_bytes(&record.to_bytes()).await.expect("put");

        // The file disappears under the node; the index has not noticed.
        std::fs::remove_file(store.dir().join(hex::encode(record.address()))).expect("remove");
        assert!(
            store.contains(&record.address()),
            "the index still claims it"
        );

        // The same state arriving again is a repair, not a no-op.
        assert_eq!(
            store.put_bytes(&record.to_bytes()).await.expect("put"),
            PutOutcome::Changed,
            "a resubmission must repair a record the disk lost"
        );
        assert!(store.get(&record.address()).await.expect("get").is_some());
    }

    #[tokio::test]
    async fn a_lost_record_above_counter_zero_is_still_repairable() {
        // The admission rule alone would make this impossible: an address the
        // node knows nothing about admits only a counter 0 record, so an entry
        // that was *forgotten* on a failed read could never be restored above
        // genesis, and every loss would be permanent.
        let (store, _dir) = store().await;
        for counter in 0..=3u64 {
            store
                .put_bytes(&signed(1, counter, 1).to_bytes())
                .await
                .expect("put");
        }
        let held = signed(1, 3, 1);

        std::fs::remove_file(store.dir().join(hex::encode(held.address()))).expect("remove");
        // A read notices the loss and stops the node answering for it.
        assert!(store.get(&held.address()).await.expect("get").is_none());
        assert!(!store.contains(&held.address()), "it is not served");
        assert_eq!(store.state_id(&held.address()), None);

        // What it lost is what it will take back, and so is anything newer.
        assert!(
            store.accepts_as_paid_update(&held.state()),
            "the state this node lost must be admissible again"
        );
        assert!(
            store.accepts_as_paid_update(&signed(1, 9, 1).state()),
            "so must a newer state the rest of the group has moved on to"
        );
        assert!(
            !store.accepts_as_paid_update(&signed(1, 2, 1).state()),
            "but not one that loses to what was lost"
        );

        assert_eq!(
            store.put_bytes(&held.to_bytes()).await.expect("put"),
            PutOutcome::Changed,
            "the repair must write, not be answered as unchanged"
        );
        let back = store
            .get(&held.address())
            .await
            .expect("get")
            .expect("present");
        assert_eq!(back.counter(), 3);
        assert_eq!(back.state_id(), held.state_id());

        // And the increment rule is back in force now that it holds one.
        assert!(store.accepts_as_paid_update(&signed(1, 4, 1).state()));
        assert!(!store.accepts_as_paid_update(&signed(1, 6, 1).state()));
    }

    #[tokio::test]
    async fn a_file_swapped_for_another_valid_record_is_not_answered_for() {
        // The index names one state; the disk holds a different, perfectly
        // valid one. Answering from the index would acknowledge a state this
        // node cannot serve.
        let (store, _dir) = store().await;
        let indexed = signed(1, 4, 1);
        store.put_bytes(&indexed.to_bytes()).await.expect("put");

        let other = signed(1, 9, 1);
        std::fs::write(
            store.dir().join(hex::encode(indexed.address())),
            other.to_bytes(),
        )
        .expect("swap the file");

        match store.inspect(&indexed.to_bytes()).await.expect("inspect") {
            Inspected::Candidate(_) => (),
            other => panic!("a state the node cannot serve must not be answered for: {other:?}"),
        }
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
            let bytes = signed(1, counter, 1).to_bytes();
            tasks.push(tokio::spawn(async move { store.put_bytes(&bytes).await }));
        }
        for task in tasks {
            task.await.expect("join").expect("put");
        }

        let held = store.get(&address).await.expect("get").expect("present");
        assert_eq!(held.counter(), 12, "the highest counter must win");
        assert_eq!(store.state_id(&address), Some(held.state_id()));
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
        let prepared = verified(&store, &record).await;

        {
            let committing = store.commit(prepared, None);
            tokio::pin!(committing);
            // Poll exactly once, then drop. That first poll hands the write to
            // a blocking thread and returns `Pending`, so the caller is always
            // abandoned mid-commit. A timeout would not be: on a fast machine
            // the commit finishes inside any timeout and the test then proves
            // nothing, which is how this failed on CI and passed locally.
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(
                committing.as_mut().poll(&mut cx).is_pending(),
                "the first poll must hand the write to a blocking task, not finish it"
            );
        }

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
            "the index and the disk must agree however the commit was interrupted"
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

        store.disown_if_unchanged(&old.address(), observed);
        assert_eq!(
            store.state_id(&new.address()),
            Some(new.state_id()),
            "the record committed during the read must still be indexed"
        );

        // And the ordinary case still works: disowning what is actually there.
        let current = store.snapshot(&new.address()).map(|entry| entry.generation);
        store.disown_if_unchanged(&new.address(), current);
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
        store.disown_if_unchanged(&record.address(), first_reader);
        assert!(!store.contains(&record.address()));

        // A peer repairs it with the very same state.
        assert_eq!(
            store.put_bytes(&record.to_bytes()).await.expect("put"),
            PutOutcome::Changed
        );

        // Reader two, still holding its stale observation, must not erase it.
        store.disown_if_unchanged(&record.address(), second_reader);
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
            PutOutcome::Changed,
            "a swept leftover must not block the first write to its address"
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
    }
}
