//! Moving a node off LMDB and onto the file store without losing a chunk.
//!
//! LMDB never returns a deleted page to the filesystem. Disk comes back exactly once,
//! when `chunks.mdb` is removed whole, so a node cannot free space by deleting chunks
//! and cannot compact its way out either (compaction needs free space equal to the live
//! data, which is the same condition). That single fact shapes everything here.
//!
//! # The two ways this could lose data, and why neither can happen
//!
//! 1. **A node deletes its LMDB before the chunks are safely in files.** Retirement is
//!    gated on the file store already holding every key the node still claims, and on
//!    the existing retention contract: a key the node is still answerable for under a
//!    gossiped commitment vetoes the delete.
//! 2. **Every node sheds the same chunk at once.** A node only sheds when it cannot fit
//!    its own payload, and it sheds by close-group rank, furthest first. A chunk has
//!    exactly one 7th-closest and one 6th-closest holder, so it is only ever a shed
//!    candidate for two of its seven holders, and the staged rollout brings that to one.
//!
//! # Three releases
//!
//! Slashing is the *auditor's* decision, so a node cannot protect itself from being
//! penalised for a shed. Everyone else has to stop first, which is why this lands over
//! three releases rather than one:
//!
//! | Release | Penalise not holding a close-group chunk? | [`MigrationConfig::retire_legacy`] |
//! |---|---|---|
//! | First: stop that one penalty | no | `false` |
//! | Second: migrate | no | `true` |
//! | Third: restore it | yes | `true` |
//!
//! The penalty column is not a field here. It lives once, in
//! [`crate::replication::config::RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY`], and both
//! the auditors that apply it and the shedder that depends on it being withheld read that
//! same switch. Two copies would let a node shed while its peers still penalised.
//!
//! Audits keep running and keep recording throughout. What the first release withholds is narrow and
//! deliberate: only the penalty for *not holding a close-group chunk*. The
//! commitment-bound subtree audit still penalises in every release, because the whole
//! migration turns on a node's reduced commitment still being binding. The record those
//! audits keep is also how we will know when the third release is safe to ship.

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::replication::config::{storage_admission_width, ReplicationConfig};
use crate::replication::pruning::{
    prove_peers_hold_records, prune_proofs_needed, target_peers_reported_present,
};
use crate::storage::chunk_store::{ChunkStore, VerifyReport};
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

/// Filename of the persisted migration marker, under the node root.
pub const MIGRATION_STATE_FILE: &str = "migration-state.json";

/// Marker schema this build writes and understands.
const STATE_SCHEMA: u32 = 1;

/// Floor on [`MigrationConfig::retire_delay_hours`].
///
/// `GOSSIP_ANSWERABILITY_TTL` is three hours at a one-hour rotation cadence, so a
/// commitment that named a shed key stops being answerable three hours after it was last
/// gossiped. Four hours clears that with an hour to spare.
pub const MIN_RETIRE_DELAY_HOURS: u64 = 4;

/// How long between attempts to reopen an environment this node has lost its handle to.
///
/// Each attempt scans every key in it, so retrying on every tick would spend a large store
/// entirely on failing to open it.
const HANDLE_RECOVERY_INTERVAL: Duration = Duration::from_secs(300);

/// The longest one node may hold the volume migration lock before giving others a turn.
///
/// Every branch that waits rather than works is meant to give the lock back on its own.
/// This is the backstop for the one that does not: without it, a node stuck on a condition
/// that never resolves stops every other node sharing the disk from ever starting, for the
/// whole release. Longer than a copy pass and a verification take, so it never interrupts
/// a node that is genuinely working.
const MAX_VOLUME_LOCK_HOLD: Duration = Duration::from_secs(6 * 3600);

/// How long a node stands back after the cap takes the volume lock off it.
///
/// Long enough that another node waiting on the lock actually gets it, rather than losing
/// the race to the node that has just been holding it for six hours.
const VOLUME_LOCK_COOLDOWN: Duration = Duration::from_secs(120);

/// How many commitment rebuilds must be observed after the node commits to its
/// file-backed set before the legacy environment may be retired.
///
/// One proves the builder read the new set. Two proves it published and survived a
/// rotation, which is what makes the retention window meaningful.
pub const REQUIRED_REBUILDS_BEFORE_RETIRE: u32 = 2;

/// Operator-facing controls for the migration.
// Four independent switches, three of which are operator controls and one of which is a
// release constant. Collapsing them into an enum would tie choices together that are
// deliberately separate.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Run the background copier at all.
    ///
    /// Turning this off leaves a node reading the union of both stores forever. It never
    /// frees the LMDB's disk, so it is an escape hatch rather than a supported mode.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Write every new chunk to the legacy environment as well as the file store.
    ///
    /// Costs roughly a gigabyte per node per month at the observed fill rate, and buys
    /// the ability to roll the fleet back: a chunk uploaded during the bridge to holders
    /// that all revert to a pre-migration build would otherwise be gone from every one
    /// of them. Automatically irrelevant once the legacy environment is retired.
    #[serde(default = "default_true")]
    pub dual_write_legacy: bool,

    /// Allow a node that cannot fit its payload to drop its furthest keys.
    ///
    /// An operator who would rather add disk than shed can set this to `false`. The node
    /// then keeps both stores and never frees the LMDB's space.
    #[serde(default = "default_true")]
    pub allow_shed: bool,

    /// Delete `chunks.mdb` once the retirement gate is satisfied.
    ///
    /// **On in this release**, because it is the only step that returns disk. It is also
    /// the only destructive step in the whole migration and the only one that cannot be
    /// undone, which is why everything in front of it is a gate: the wave the node is
    /// assigned to, the shed hold, the reduced commitment reaching the close group,
    /// possession of every chunk being given up proven elsewhere, a re-read of every
    /// remaining chunk, and a retention delay on top.
    ///
    /// Deliberately never serialised. A node writes its effective configuration back to
    /// disk, so shipping this as an ordinary field would bake R1's `false` into every
    /// operator's config file and R2 would then never retire anything. The release phase
    /// belongs to the build, not to the operator's file. `ANT_MIGRATION_RETIRE_LEGACY`
    /// overrides it for a canary.
    #[serde(skip, default = "release_retire_legacy")]
    pub retire_legacy: bool,

    /// Hours after this build first starts before a node may shed anything.
    ///
    /// Long enough for peers still on a pre-R1 build to upgrade, because one of those
    /// still penalises a shedder at the full audit weight.
    #[serde(default = "default_shed_hold_hours")]
    pub shed_hold_hours: u64,

    /// Hours between committing to the file-backed key set and deleting `chunks.mdb`.
    ///
    /// Clamped up to [`MIN_RETIRE_DELAY_HOURS`]. Longer buys a rollback window on nodes
    /// that can afford to hold both copies.
    #[serde(default = "default_retire_delay_hours")]
    pub retire_delay_hours: u64,

    /// Free megabytes the copier leaves untouched, on top of the disk reserve.
    ///
    /// The copier stops here rather than filling to the brink, so a node that is
    /// mid-migration still has room to accept a chunk it is paid for.
    #[serde(default = "default_copier_slack_mb")]
    pub copier_slack_mb: u64,

    /// Copy rate ceiling, in mebibytes per second.
    ///
    /// The quiet responsible audit lane is where audit timeouts actually cost trust, and
    /// an unthrottled copier competing with it for I/O is the fastest way to turn a
    /// storage migration into an audit incident.
    #[serde(default = "default_copier_throttle_mib_per_sec")]
    pub copier_throttle_mib_per_sec: u64,

    /// Hours between one migration wave opening and the next.
    ///
    /// A close group is split into waves so that only
    /// [`CONCURRENT_MIGRATIONS_PER_GROUP`] of it give chunks up at a time. This is how
    /// long a wave gets to finish copying, retiring and refetching before the next one may
    /// start. Only nodes that have to give something up wait for their wave; a node with
    /// room migrates immediately.
    #[serde(default = "default_wave_hours")]
    pub wave_hours: u64,

    /// Seconds between copier ticks.
    #[serde(default = "default_tick_secs")]
    pub tick_secs: u64,

    /// Chunks copied per tick before yielding.
    #[serde(default = "default_batch_chunks")]
    pub batch_chunks: usize,

    /// Where the volume lock lives, overriding the filesystem this node's root sits on.
    ///
    /// `None` in production, which keys the lock by device id so every node on one disk
    /// serialises against the others. Tests set it so a test's migration contends only
    /// with its own, rather than with every other test sharing the machine's filesystem.
    ///
    /// Never serialised: it exists to scope a test, not to configure a node.
    #[serde(skip)]
    pub lock_dir: Option<PathBuf>,
}

const fn default_true() -> bool {
    true
}

/// Whether this build deletes the legacy environment once the gate is satisfied.
///
/// **`true` in this release.** Deleting `chunks.mdb` is the only step that returns disk,
/// and a build that ships with it off is a migration that never finishes: the fleet
/// already deleted 2.29M chunks out of LMDB and got back nothing, because LMDB does not
/// return freed pages to the filesystem. Every gate in front of this is still enforced,
/// and `ANT_MIGRATION_RETIRE_LEGACY=0` turns it off on a single node if one is ever
/// needed to hold both stores.
pub const RELEASE_RETIRE_LEGACY: bool = true;

/// Environment override for [`RELEASE_RETIRE_LEGACY`], for a canary node.
pub const RETIRE_LEGACY_ENV: &str = "ANT_MIGRATION_RETIRE_LEGACY";

/// Read a boolean override from the environment, falling back to the build constant.
fn env_override(name: &str, build_default: bool) -> bool {
    let Ok(raw) = std::env::var(name) else {
        return build_default;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        other => {
            warn!("{name}={other} is not a boolean; using the build default {build_default}");
            build_default
        }
    }
}

/// The retirement switch for this build, after any environment override.
fn release_retire_legacy() -> bool {
    env_override(RETIRE_LEGACY_ENV, RELEASE_RETIRE_LEGACY)
}

const fn default_shed_hold_hours() -> u64 {
    72
}

const fn default_retire_delay_hours() -> u64 {
    MIN_RETIRE_DELAY_HOURS
}

const fn default_wave_hours() -> u64 {
    24
}

const fn default_copier_slack_mb() -> u64 {
    2048
}

const fn default_copier_throttle_mib_per_sec() -> u64 {
    32
}

const fn default_tick_secs() -> u64 {
    30
}

const fn default_batch_chunks() -> usize {
    64
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dual_write_legacy: true,
            allow_shed: true,
            retire_legacy: release_retire_legacy(),
            shed_hold_hours: default_shed_hold_hours(),
            retire_delay_hours: default_retire_delay_hours(),
            wave_hours: default_wave_hours(),
            copier_slack_mb: default_copier_slack_mb(),
            copier_throttle_mib_per_sec: default_copier_throttle_mib_per_sec(),
            tick_secs: default_tick_secs(),
            batch_chunks: default_batch_chunks(),
            lock_dir: None,
        }
    }
}

impl MigrationConfig {
    /// The retire delay, never shorter than the retention contract allows.
    #[must_use]
    pub fn effective_retire_delay_hours(&self) -> u64 {
        self.retire_delay_hours.max(MIN_RETIRE_DELAY_HOURS)
    }

    /// Copier slack in bytes.
    #[must_use]
    pub fn copier_slack_bytes(&self) -> u64 {
        self.copier_slack_mb.saturating_mul(1024 * 1024)
    }
}

/// Where a node is in the migration.
///
/// The phase is persisted, but only as a *decision* record. Everything derivable from
/// the filesystem is re-derived at every start: which keys are still legacy-only is
/// simply "in the LMDB and not in the file store", so an interrupted copy resumes for
/// free with no progress bookkeeping to corrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    /// Copying the legacy environment into files. Reads are the union of both stores,
    /// writes go to files, and the commitment still covers everything.
    Bridging,
    /// The node has settled on what it will keep and commits only to its file-backed
    /// keys. It keeps serving the rest from LMDB until they stop being answerable.
    Committed,
    /// No legacy environment. Steady state, and where every fresh node starts.
    FilesOnly,
}

/// The persisted migration marker.
///
/// Two facts genuinely need to survive a restart: when this build first ran (so the shed
/// hold is not restarted by a reboot loop) and when the node committed to its file-backed
/// set (so the retirement clock is not either). Everything else is re-derived.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationState {
    /// Marker schema version.
    pub schema: u32,
    /// Where the node is.
    pub phase: MigrationPhase,
    /// Unix seconds when this build first started on this node.
    pub first_start_unix: u64,
    /// Unix seconds when the node committed to its file-backed key set.
    pub committed_at_unix: Option<u64>,
    /// Commitment rebuilds observed since committing.
    pub rebuilds_since_commit: u32,
    /// How many keys the node decided not to keep, for the operator's benefit.
    pub shed_key_count: u64,
    /// How many chunks the file store held when the node committed.
    ///
    /// Cross-checked at open. A marker claiming the node is past the copying stage while
    /// the file store is far emptier than it said means the two disagree about reality,
    /// and the filesystem wins.
    #[serde(default)]
    pub kept_key_count: u64,
}

impl MigrationState {
    /// A fresh marker for a node that has just started.
    #[must_use]
    pub fn new(phase: MigrationPhase) -> Self {
        Self {
            schema: STATE_SCHEMA,
            phase,
            first_start_unix: now_unix(),
            committed_at_unix: None,
            rebuilds_since_commit: 0,
            shed_key_count: 0,
            kept_key_count: 0,
        }
    }

    /// Load the marker, writing a fresh one if there is none.
    ///
    /// Persisting immediately matters: `first_start_unix` is what the shed hold counts
    /// from, and a marker that is only written at the first phase change would reset that
    /// clock on every restart before then, so a node that restarts more often than the
    /// hold would never become eligible to shed and never finish migrating.
    pub fn load_or_create(root_dir: &Path, phase: MigrationPhase) -> Self {
        let state = Self::load_or_new(root_dir, phase);
        if !state_path(root_dir).exists() {
            if let Err(e) = state.save(root_dir) {
                warn!("Could not write the migration marker: {e}");
            }
        }
        state
    }

    /// Load the marker, or start a fresh one.
    ///
    /// An unreadable marker is replaced rather than fatal: it is a hint, and every fact
    /// it holds is either recoverable or conservative to reset. Losing it restarts the
    /// shed hold and the retirement clock, which delays a migration and never rushes one.
    pub fn load_or_new(root_dir: &Path, phase: MigrationPhase) -> Self {
        let path = state_path(root_dir);
        let Ok(bytes) = std::fs::read(&path) else {
            return Self::new(phase);
        };
        match serde_json::from_slice::<Self>(&bytes) {
            Ok(state) if state.schema <= STATE_SCHEMA => state.with_sane_clocks(),
            Ok(state) => {
                warn!(
                    "Migration marker {} was written by a newer build (schema {}); \
                     starting a fresh one",
                    path.display(),
                    state.schema
                );
                Self::new(phase)
            }
            Err(e) => {
                warn!(
                    "Migration marker {} is unreadable ({e}); starting a fresh one. \
                     The shed hold and retirement clock restart from now.",
                    path.display()
                );
                Self::new(phase)
            }
        }
    }

    /// Persist the marker so a reader sees either the old content or the new.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the marker cannot be written.
    pub fn save(&self, root_dir: &Path) -> Result<()> {
        let path = state_path(root_dir);
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Storage(format!("Failed to encode migration marker: {e}")))?;
        crate::storage::file_store::write_file_durably(&path, &bytes)?;
        debug!("Migration marker updated: phase {:?}", self.phase);
        Ok(())
    }

    /// Replace timestamps that cannot be true with "now".
    ///
    /// Zero and future values both make a hold vacuous, and a node whose clock was not
    /// yet synchronised at first boot writes zero without anyone tampering. Resetting to
    /// now delays a migration, which is the safe direction.
    #[must_use]
    fn with_sane_clocks(mut self) -> Self {
        let now = now_unix();
        if self.first_start_unix == 0 || self.first_start_unix > now {
            warn!("Migration marker has an implausible first-start time; restarting the hold");
            self.first_start_unix = now;
        }
        self.committed_at_unix = self.committed_at_unix.map(|at| {
            if at == 0 || at > now {
                warn!("Migration marker has an implausible commit time; restarting the clock");
                now
            } else {
                at
            }
        });
        self
    }

    /// Whether the shed hold has elapsed.
    #[must_use]
    pub fn shed_hold_elapsed(&self, config: &MigrationConfig) -> bool {
        let hold = config.shed_hold_hours.saturating_mul(3600);
        now_unix().saturating_sub(self.first_start_unix) >= hold
    }

    /// Whether the retirement delay has elapsed since committing.
    #[must_use]
    pub fn retire_delay_elapsed(&self, config: &MigrationConfig) -> bool {
        let Some(at) = self.committed_at_unix else {
            return false;
        };
        let delay = config.effective_retire_delay_hours().saturating_mul(3600);
        now_unix().saturating_sub(at) >= delay
    }
}

/// Path of the persisted marker.
#[must_use]
pub fn state_path(root_dir: &Path) -> PathBuf {
    root_dir.join(MIGRATION_STATE_FILE)
}

/// Seconds since the Unix epoch, saturating at zero if the clock is before it.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A host-wide advisory lock that serialises migrations sharing one volume.
///
/// Twelve nodes on one 492 GiB volume each need roughly their live payload free to copy
/// and each return rather more when they retire, so one at a time the host gains space
/// and the queue accelerates. All twelve at once need twelve times the space and all
/// twelve stall. The lock is taken non-blocking: a node that cannot get it simply waits
/// for the next tick.
///
/// The lock file sits in the parent of the node root, which for a default deployment is
/// the shared `nodes/` directory. That is a heuristic for "same volume", not a guarantee;
/// an operator who spreads node roots across volumes gets more serialisation than they
/// need, which is slow rather than unsafe.
#[derive(Debug)]
pub struct VolumeLock {
    /// The held file. Dropping it releases the lock.
    file: std::fs::File,
    /// Where it lives, for logging.
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    path: PathBuf,
}

/// The result of asking for the volume lock.
pub enum LockAttempt {
    /// This node has it.
    Acquired(VolumeLock),
    /// Another node on the volume is migrating. Wait.
    Busy,
    /// No lock is possible here at all, so proceed unserialised.
    ///
    /// Kept distinct from `Busy` because conflating the two silently strands any node
    /// whose parent directory is not writable: it would wait forever for a lock nobody
    /// holds.
    Unavailable,
}

impl VolumeLock {
    /// Try to take the lock for the volume hosting `root_dir`.
    #[must_use]
    pub fn try_acquire(root_dir: &Path, scope: Option<&Path>) -> LockAttempt {
        use fs2::FileExt;
        let path = scope.map_or_else(
            || lock_path_for(root_dir),
            |dir| dir.join("ant-migration.lock"),
        );
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    "Could not create the migration lock at {}: {e}. This node will \
                     migrate without serialising against others on the same volume, so \
                     watch its free space.",
                    path.display()
                );
                return LockAttempt::Unavailable;
            }
        };
        match file.try_lock_exclusive() {
            Ok(()) => {
                debug!("Took the volume migration lock at {}", path.display());
                LockAttempt::Acquired(Self { file, path })
            }
            // Only contention means another node is migrating. Everything else, a
            // filesystem that does not implement locking at all being the one that
            // matters, is a lock this node will never get, and reporting it as contention
            // would leave it waiting forever for a holder that does not exist.
            Err(e) if is_lock_contention(&e) => LockAttempt::Busy,
            Err(e) => {
                warn!(
                    "Could not lock {}: {e}. This node will migrate without serialising \
                     against others on the same volume, so watch its free space.",
                    path.display()
                );
                LockAttempt::Unavailable
            }
        }
    }
}

/// Is this the error a lock held by someone else produces?
fn is_lock_contention(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::WouldBlock
        || (e.raw_os_error().is_some()
            && e.raw_os_error() == fs2::lock_contended_error().raw_os_error())
}

/// Where the lock for the volume hosting `root_dir` lives.
///
/// Keyed by the filesystem, not by the path. Two nodes on one host are configured with
/// different roots by definition, so a lock beside the root serialises a node against
/// nobody: `/srv/node-a/data` and `/srv/node-b/data` would take two different locks on one
/// disk and copy at the same time, which is the case the lock exists to prevent.
///
/// The device id names the filesystem, and the host's temporary directory is somewhere
/// every node on that host can reach. If the device cannot be read, this falls back to a
/// lock beside the root: weaker, but never worse than having none.
fn lock_path_for(root_dir: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(root_dir) {
            return std::env::temp_dir().join(format!("ant-migration-{}.lock", meta.dev()));
        }
    }
    // Resolved first, because a relative root has no volume in it to read. Two nodes
    // started from different working directories on one drive would otherwise each fall
    // through to a lock beside their own root, which serialises neither against the other.
    #[cfg(not(unix))]
    let resolved = std::fs::canonicalize(root_dir).unwrap_or_else(|_| root_dir.to_path_buf());
    #[cfg(not(unix))]
    let root_dir = resolved.as_path();
    // Off Unix, the volume root: the drive or share the path starts from. Not as precise
    // as a device id, since a mount point below it belongs to another volume, but it
    // groups the ordinary case of several nodes under one drive letter, which is what a
    // lock beside each node's own root does not.
    #[cfg(not(unix))]
    {
        use std::path::Component;
        if let Some(Component::Prefix(prefix)) = root_dir.components().next() {
            let key: String = prefix
                .as_os_str()
                .to_string_lossy()
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .collect();
            if !key.is_empty() {
                return std::env::temp_dir().join(format!("ant-migration-{key}.lock"));
            }
        }
    }
    root_dir
        .parent()
        .unwrap_or(root_dir)
        .join("ant-migration.lock")
}

impl Drop for VolumeLock {
    fn drop(&mut self) {
        use fs2::FileExt;
        if let Err(e) = FileExt::unlock(&self.file) {
            debug!(
                "Releasing the migration lock {} failed: {e}",
                self.path.display()
            );
        }
    }
}

/// Summary of what the copier moved during one pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// Chunks copied into the file store.
    pub copied: u64,
    /// Bytes copied.
    pub bytes: u64,
    /// Keys skipped because the legacy bytes did not hash to their address, or were
    /// larger than a chunk may be.
    pub unusable: u64,
    /// Keys that could not be copied for a reason that may clear on a later pass.
    pub failed: u64,
    /// Keys that had vanished from the legacy store between the scan and the copy.
    pub vanished: u64,
    /// Whether the pass stopped because free space reached the slack floor.
    pub stopped_for_space: bool,
}

impl CopyReport {
    /// Fold another pass into this one.
    pub fn merge(&mut self, other: Self) {
        self.copied += other.copied;
        self.bytes += other.bytes;
        self.unusable += other.unusable;
        self.failed += other.failed;
        self.vanished += other.vanished;
        self.stopped_for_space |= other.stopped_for_space;
    }
}

/// How many waves a close group is divided into, so that at most
/// [`CONCURRENT_MIGRATIONS_PER_GROUP`] of it are giving chunks up at once.
#[must_use]
pub fn migration_wave_count(close_group_size: usize) -> u64 {
    let group = close_group_size.max(1) as u64;
    let per_wave = CONCURRENT_MIGRATIONS_PER_GROUP.max(1) as u64;
    group.div_ceil(per_wave).max(1)
}

/// Which wave this node belongs to, derived from its own ID.
///
/// Deterministic and needs no coordination, which is the point: a node cannot ask its
/// close group "are you migrating?" without a protocol change, and the answer would be
/// stale by the time it arrived. Hashing the peer ID spreads the members of any group
/// across the waves without anybody agreeing on anything.
///
/// It is a stagger, not a guarantee. Seven IDs hashed into four waves will not always land
/// two, two, two, one. What makes it safe rather than merely tidy is that it composes with
/// the possession gate: a node whose turn has come still cannot give a chunk up until its
/// neighbours have proven they hold it, so an unlucky wave waits instead of over-shedding.
#[must_use]
pub fn migration_wave_for(self_id: Option<&PeerId>, close_group_size: usize) -> u64 {
    let waves = migration_wave_count(close_group_size);
    let Some(peer) = self_id else {
        return 0;
    };
    let digest = blake3::hash(&[MIGRATION_WAVE_DOMAIN, peer.as_bytes().as_slice()].concat());
    let mut head = [0u8; 8];
    head.copy_from_slice(digest.as_bytes().get(..8).unwrap_or(&[0u8; 8]));
    u64::from_le_bytes(head) % waves
}

/// Domain separator so the wave assignment cannot be confused with any other use of a
/// hashed peer ID.
const MIGRATION_WAVE_DOMAIN: &[u8] = b"ant-node/storage-migration-wave/v1";

/// Whether this node's wave has opened yet.
///
/// Wave `w` opens `w * wave_hours` after this build first started on this node. A node
/// that has room for everything never consults this: it copies and retires without ever
/// being unable to serve, so it is not part of the problem the waves exist to solve.
#[must_use]
pub fn wave_has_opened(state: &MigrationState, config: &MigrationConfig, wave: u64) -> bool {
    now_unix() >= wave_opens_at(state, config, wave)
}

/// When a given wave opens, in Unix seconds.
///
/// Measured from the END of the shed hold, not from first start. Measured from the start
/// the two settings cancel each other out: with a 72 hour hold and 24 hour waves, waves
/// would open at 0, 24, 48 and 72 hours while nothing at all may shed until hour 72, so
/// every wave would be open the moment the first one could act and the whole close group
/// would migrate together. That is the pile-up the waves exist to prevent.
#[must_use]
pub fn wave_opens_at(state: &MigrationState, config: &MigrationConfig, wave: u64) -> u64 {
    state
        .first_start_unix
        .saturating_add(config.shed_hold_hours.saturating_mul(3600))
        .saturating_add(wave.saturating_mul(config.wave_hours.saturating_mul(3600)))
}

/// Order keys closest-first by XOR distance from this node.
///
/// Shedding walks this list from the far end, so the keys a node gives up are the ones it
/// is furthest from, and therefore the ones its close group covers best.
#[must_use]
pub fn rank_closest_first(mut keys: Vec<XorName>, self_xor: Option<XorName>) -> Vec<XorName> {
    let Some(me) = self_xor else {
        // No identity available (devnet, unit tests). Ascending key order is stable and
        // deterministic, which is all the copier needs.
        keys.sort_unstable();
        return keys;
    };
    keys.sort_unstable_by_key(|k| crate::client::xor_distance(k, &me));
    keys
}

/// Structured field marking every line the fleet gate for R3 is read from.
///
/// R3 ships when the fleet shows migrations have finished, so these lines have to be
/// queryable rather than merely readable. One field name, three values.
pub const MIGRATION_EVENT: &str = "migration_event";

/// Log the operator-facing summary of a completed migration.
///
/// `freed_bytes` is what the retired environment held, which is what the deletion running
/// in the background will return. The line that says the space is actually back is
/// `migration_event = "space_returned"`, emitted by that deletion when it finishes. Two
/// lines rather than one because the deletion of a large environment takes minutes, and a
/// node that reports the disk back before it is back is a node whose operator cannot tell
/// a slow deletion from a failed one.
pub fn log_migration_complete(kept: u64, shed: u64, freed_bytes: u64) {
    #[allow(clippy::cast_precision_loss)] // display only
    let freed_gib = freed_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    if shed == 0 {
        info!(
            migration_event = "complete",
            kept,
            shed,
            freed_bytes,
            "Storage migration complete: {kept} chunks now in the file store, nothing shed, \
             {freed_gib:.2} GiB being returned to the filesystem"
        );
    } else {
        info!(
            migration_event = "complete",
            kept,
            shed,
            freed_bytes,
            "Storage migration complete: kept {kept} chunks, shed {shed} that would not fit, \
             {freed_gib:.2} GiB being returned to the filesystem. The shed keys are the ones this \
             node was furthest from; replication will refetch what still belongs here now \
             that there is room."
        );
    }
}

// ────────────────────────────────────────────────────────────────────────────
// The driver
// ────────────────────────────────────────────────────────────────────────────

/// How many positions from the end of the admission group a node may give up.
///
/// A chunk has exactly one holder at each rank, so restricting shedding to the last two
/// positions means only two of its holders ever consider dropping it, and the staged
/// rollout brings that to one. Without this rule the property is only statistical:
/// every holder could be short of space at once, each shed the same chunk, and the
/// per-volume lock would not know, because it serialises one volume and this is a
/// network-wide question.
///
/// Measured against [`storage_admission_width`], not the close group, so the migration is
/// never more willing to drop a chunk than the pruner is. The pruner treats the wider
/// group as strictly in-range and refuses to delete inside it; shedding ranks that the
/// pruner protects would make a one-off migration weaker than the thing that runs every
/// day.
pub const SHEDDABLE_TAIL_RANKS: usize = 2;

/// How many nodes of one close group may be giving chunks up at the same time.
///
/// The close group is the unit that matters, not the volume and not the fleet. If every
/// holder of a chunk migrates at once, none of them can prove to the others that a copy
/// survives, and the whole group deadlocks waiting on each other. Holding it to two means
/// the other five are steady, can answer possession challenges, and are still serving the
/// chunk while the two rebuild.
pub const CONCURRENT_MIGRATIONS_PER_GROUP: usize = 2;

/// How many keys a refusal names, so the log stays readable.
const REFUSAL_SAMPLE: usize = 4;

/// How recently a peer must have published a commitment to be trusted as a holder.
///
/// Commitments rotate hourly and are gossiped on the neighbour-sync cadence, so a peer
/// that has not published one for this long is not simply quiet: it has either stopped
/// speaking the protocol or retired its commitment and not yet rotated a new one. The
/// second is exactly what a node in the middle of its own migration looks like, and
/// counting it as a holder is how two migrating nodes could each conclude the other was
/// covering the chunk.
const COMMITMENT_FRESHNESS: Duration = Duration::from_secs(2 * 3600);

/// How many keys one possession round asks about.
///
/// The round batches by peer, so this bounds the size of a single request rather than the
/// number of requests.
const POSSESSION_BATCH_KEYS: usize = 256;

/// How long to wait before re-evaluating a shed decision that was refused.
const SHED_REEVALUATION_INTERVAL: Duration = Duration::from_secs(600);

/// How many copied chunks between operator-facing progress lines.
const PROGRESS_LOG_EVERY: usize = 500;

/// How long a clean pre-retirement verification stays usable.
///
/// Chunks written since the pass were content-checked on the way in and flushed, so the
/// only thing the window exposes is bit rot in the last half hour, which is the ordinary
/// risk of any file and is caught on read.
const VERIFICATION_REUSE_WINDOW: Duration = Duration::from_secs(1800);

/// The network facts the driver needs, kept behind one type so the store itself stays
/// free of any knowledge of routing or commitments.
pub struct MigrationContext {
    /// Routing, for close-group rank and possession checks. `None` in devnet and tests.
    pub p2p: Option<Arc<P2PNode>>,
    /// This node's peer ID.
    pub self_id: Option<PeerId>,
    /// This node's address in the key space, for ordering the copy closest-first.
    pub self_xor: Option<XorName>,
    /// The responder commitment state, which owns the retention contract.
    pub commitment: Option<Arc<crate::replication::commitment_state::ResponderCommitmentState>>,
    /// Replication settings, for the possession round that gates shedding.
    pub replication: Option<Arc<ReplicationConfig>>,
    /// Neighbour-sync state, which the possession challenge needs.
    pub sync_state: Option<Arc<tokio::sync::RwLock<crate::replication::types::NeighborSyncState>>>,
    /// Coordinator for the possession challenges.
    pub audit_challenge_coordinator:
        Option<Arc<crate::replication::audit_coordinator::AuditChallengeCoordinator>>,
    /// What this node last heard each peer commit to.
    ///
    /// Used to require that a peer trusted to hold a chunk is currently publishing a
    /// claim, rather than sitting between a retired commitment and its next rotation,
    /// which is precisely the state a node in the middle of its own migration is in.
    pub peer_commitments: Option<
        Arc<
            tokio::sync::RwLock<
                HashMap<PeerId, crate::replication::commitment_state::PeerCommitmentRecord>,
            >,
        >,
    >,
    /// Close-group width.
    pub close_group_size: usize,
}

/// How many of the peers auditing this node now have seen its reduced commitment.
///
/// `received` is who was sent the current root, `current` is the close group as routing
/// sees it at this moment. Only the overlap counts. A peer that received the root and has
/// since left is not going to audit this node, and a peer that has since joined has never
/// seen the root, so neither is evidence that shedding is safe.
fn enough_of_the_group_knows(
    received: &HashSet<PeerId>,
    current: &[PeerId],
    needed: usize,
) -> bool {
    if needed == 0 {
        return false;
    }
    current.iter().filter(|p| received.contains(*p)).count() >= needed
}

impl MigrationContext {
    /// How many peers of the close group must have seen the reduced commitment.
    ///
    /// The same tolerance the pruner applies to possession proofs: all of them for a group
    /// of one or two, one short of the group otherwise, so a single unreachable peer
    /// cannot veto the migration forever without accepting an uninformed close group.
    #[must_use]
    pub fn commitment_recipients_needed(&self) -> usize {
        prune_proofs_needed(self.close_group_size.saturating_sub(1))
    }

    /// Have enough of this node's close group actually received its reduced commitment?
    ///
    /// A rotation is not the same as neighbours knowing. Until they have seen the smaller
    /// key set they keep auditing against the one this node used to hold, so giving a
    /// chunk up before then turns a legitimate migration into a wave of audit failures.
    pub async fn neighbours_know_the_commitment(&self) -> bool {
        let needed = self.commitment_recipients_needed();
        if needed == 0 {
            return false;
        }
        let Some(state) = self.commitment.as_ref() else {
            return false;
        };
        let received = state.current_delivered_peers();
        if received.is_empty() {
            return false;
        }
        // Counted against the group as it stands now, not as it stood when the root went
        // out. A peer that has since left knowing this node's reduced commitment says
        // nothing about the peers that will actually audit it, and letting a departed
        // peer satisfy the gate is how a node gives chunks up while its real neighbours
        // still hold it to the larger key set.
        let Some(current) = self.current_close_group().await else {
            return false;
        };
        enough_of_the_group_knows(&received, &current, needed)
    }

    /// This node's close group as routing sees it now, or `None` if the view is too thin
    /// to be evidence about a group at all.
    async fn current_close_group(&self) -> Option<Vec<PeerId>> {
        let (Some(p2p), Some(me), Some(self_xor)) = (
            self.p2p.as_ref(),
            self.self_id.as_ref(),
            self.self_xor.as_ref(),
        ) else {
            return None;
        };
        // Self-inclusive, then self filtered out. The self-excluding call would return
        // `close_group_size` *remote* peers, one more than the group actually has, and the
        // threshold is computed from a group that includes this node. Four real
        // neighbours plus one peer outside the group would then clear a bar meant to
        // require five real ones.
        let closest = p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(self_xor, self.close_group_size)
            .await;
        let peers: Vec<PeerId> = closest
            .iter()
            .map(|n| n.peer_id)
            .filter(|p| p != me)
            .collect();
        if peers.len() + 1 < self.close_group_size {
            return None;
        }
        Some(peers)
    }

    /// Is this key still answerable under a retained commitment slot?
    ///
    /// This is the pruner's existing veto, reused verbatim: a key the node could still
    /// be challenged on must not lose its last local copy.
    #[must_use]
    pub fn still_answerable(&self, key: &XorName) -> bool {
        self.commitment
            .as_ref()
            .is_some_and(|state| state.is_held(key))
    }

    /// The width this node measures ranks against: the admission group, not the close
    /// group.
    #[must_use]
    pub fn shed_width(&self) -> usize {
        storage_admission_width(self.close_group_size)
    }

    /// This node's position in `key`'s admission group.
    pub async fn close_group_rank(&self, key: &XorName) -> GroupRank {
        let (Some(p2p), Some(me)) = (self.p2p.as_ref(), self.self_id.as_ref()) else {
            return GroupRank::Unknown;
        };
        let closest = p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(key, self.shed_width())
            .await;
        closest
            .iter()
            .position(|n| n.peer_id == *me)
            .map_or(GroupRank::Outside, GroupRank::Inside)
    }

    /// May this node give up `key` without risking its last replica?
    ///
    /// Only if it is outside the admission group entirely, or sits in that group's last
    /// [`SHEDDABLE_TAIL_RANKS`] positions. Never when the answer is unknown.
    pub async fn may_shed(&self, key: &XorName) -> bool {
        rank_is_sheddable(self.close_group_rank(key).await, self.shed_width())
    }
}

/// Where this node sits in a key's admission group.
///
/// `Unknown` is deliberately distinct from `Outside`. Collapsing the two would turn "this
/// node has no routing table to consult" into "no other node is closer", which is a
/// licence to give up every chunk on no evidence whatsoever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRank {
    /// This node is at this position, counting from the closest.
    Inside(usize),
    /// This node is not among the closest for this key.
    Outside,
    /// Routing state is unavailable, so the question cannot be answered.
    Unknown,
}

/// Which of `keys` this node has no proof anyone else is holding.
///
/// This is the gate on giving a chunk up at all, and it is deliberately the **same**
/// evidence the pruner demands before it deletes: cryptographic possession proofs from
/// all but one of the key's current close group, which is six of seven at
/// production width.
///
/// Rank alone was not enough. Being far from a chunk says something about who *should*
/// hold it, not about who *does*, and during a fleet-wide migration the nodes that should
/// hold it are exactly the ones that may also be short of space. Nor is the cheap
/// `VerificationRequest` enough: it carries a self-reported `present: bool`, and a node
/// that has silently lost a chunk still answers yes. The challenge here makes a peer
/// return a digest over a nonce it has never seen, which it cannot do without the bytes.
///
/// Returns the keys that failed, so the caller can name them. An empty result means every
/// key asked about is proven to live somewhere else.
///
/// Without routing state, every key is unconfirmed: no view of the network is no evidence.
pub async fn unconfirmed_by_neighbours(
    store: &Arc<ChunkStore>,
    context: &MigrationContext,
    keys: &[XorName],
) -> Vec<XorName> {
    let (Some(p2p), Some(self_id), Some(config), Some(sync_state), Some(coordinator)) = (
        context.p2p.as_ref(),
        context.self_id.as_ref(),
        context.replication.as_ref(),
        context.sync_state.as_ref(),
        context.audit_challenge_coordinator.as_ref(),
    ) else {
        return keys.to_vec();
    };

    let local_key_count =
        usize::try_from(store.current_chunks().unwrap_or(0)).unwrap_or(usize::MAX);
    let dht = p2p.dht_manager();
    let mut unconfirmed = Vec::new();

    for batch in keys.chunks(POSSESSION_BATCH_KEYS) {
        // Ask only the peers that are currently closest to each key. A proof from a peer
        // that has since moved out of the group is not evidence the chunk will stay there.
        let mut targets_by_key: HashMap<XorName, Vec<PeerId>> = HashMap::new();
        let mut keys_by_peer: HashMap<PeerId, Vec<XorName>> = HashMap::new();
        for key in batch {
            // Self-inclusive, matching the pruner, whose evidence this is. The
            // self-excluding call returns one peer more than the key's group holds, and a
            // proof from a peer outside it is not evidence the chunk stays in it.
            let closest = dht
                .find_closest_nodes_local_with_self(key, config.close_group_size)
                .await;
            let peers: Vec<PeerId> = closest
                .iter()
                .map(|n| n.peer_id)
                .filter(|p| p != self_id)
                .collect();
            for peer in &peers {
                keys_by_peer.entry(*peer).or_default().push(*key);
            }
            targets_by_key.insert(*key, peers);
        }

        let proofs = prove_peers_hold_records(
            &keys_by_peer,
            local_key_count,
            store,
            p2p,
            config,
            sync_state,
            coordinator,
        )
        .await;

        // A proof is necessary but not sufficient. The peer must also be currently
        // publishing a commitment, so a node that has retired its own and not yet rotated
        // a replacement, which is what a node mid-migration looks like, is not counted as
        // the reason this node may give a chunk up.
        let publishing = peers_publishing_a_recent_commitment(context).await;

        for key in batch {
            let group = targets_by_key.get(key).map_or(&[][..], Vec::as_slice);

            // The lookup is self-inclusive, and this node is giving the chunk up, so a
            // full group is `close_group_size` peers none of which is this node. Fewer
            // than that is a routing view too thin to be evidence about the group at all,
            // which is what a table looks like shortly after a restart. This node still
            // appearing in the group means it is not outside it after all, and the
            // decision to give the chunk up was taken against a view that has since
            // changed.
            if group.len() < config.close_group_size {
                unconfirmed.push(*key);
                continue;
            }

            // The threshold comes from the configured group size, never from whichever
            // subset happens to qualify, nor from however many peers routing returned.
            // Deriving it from the filtered list is how two last holders destroy a chunk
            // between them: each sees only the other publishing, so each needs exactly one
            // proof, each gets it from the other, and both delete. Deriving it from the
            // observed length is the same mistake more quietly: a view that has lost a
            // peer lowers the bar exactly when it should not be trusted.
            let needed = prune_proofs_needed(config.close_group_size);
            let qualifying: Vec<PeerId> = group
                .iter()
                .filter(|p| publishing.contains(*p))
                .copied()
                .collect();
            if !target_peers_reported_present(key, &qualifying, &proofs, needed) {
                unconfirmed.push(*key);
            }
        }
    }
    unconfirmed
}

/// The peers this node has heard a commitment from recently enough to trust as holders.
async fn peers_publishing_a_recent_commitment(context: &MigrationContext) -> HashSet<PeerId> {
    let Some(records) = context.peer_commitments.as_ref() else {
        return HashSet::new();
    };
    records
        .read()
        .await
        .iter()
        .filter(|(_, record)| {
            record.last_commitment().is_some()
                && record.received_at.elapsed() < COMMITMENT_FRESHNESS
        })
        .map(|(peer, _)| *peer)
        .collect()
}

/// Whether a position in the admission group may be given up.
///
/// Split out from the routing lookup so the rule itself is testable without a network.
/// `width` is [`storage_admission_width`], not the close-group size: a key this node is
/// outside the admission group for is one the pruner would delete anyway, and inside it
/// only the last [`SHEDDABLE_TAIL_RANKS`] positions may go.
#[must_use]
pub fn rank_is_sheddable(rank: GroupRank, width: usize) -> bool {
    // A group no wider than the tail has no tail to give up. Saturating alone would set
    // the threshold to zero and make every member sheddable, which is the opposite of
    // what a narrow group needs.
    let protected_below = if width <= SHEDDABLE_TAIL_RANKS {
        width
    } else {
        width - SHEDDABLE_TAIL_RANKS
    };
    match rank {
        // No routing to ask. Never a licence: a node with no view of the network has no
        // grounds at all for believing anyone else holds the chunk.
        GroupRank::Unknown => false,
        GroupRank::Outside => true,
        GroupRank::Inside(rank) => rank >= protected_below,
    }
}

/// Whether this store needs a migration driver at all.
///
/// The single predicate both the spawn site and its test use, so "should this node be
/// migrating" cannot be answered one way by the wiring and another way by what checks it.
#[must_use]
pub fn should_migrate(store: &Arc<ChunkStore>) -> bool {
    // Or has a removal to finish, or has something at the environment's path it could not
    // open. A node whose retirement was interrupted has no handle and nothing left to
    // copy, but its disk has not come back. A node whose environment is a link to storage
    // that was not mounted at startup has neither, and its chunks come back when the
    // storage does; without a driver it would stay blind to them until a restart.
    store.has_legacy() || store.has_cleanup_pending() || store.legacy_dir_is_on_disk()
}

/// Runs the migration to completion, then returns.
///
/// Everything it does is idempotent and derived from the filesystem, so a crash at any
/// point costs at most the work of one tick.
pub async fn run(store: Arc<ChunkStore>, context: MigrationContext, shutdown: CancellationToken) {
    let config = store.migration_config().clone();
    if !worth_starting(&store, &config) {
        return;
    }

    let tick = Duration::from_secs(config.tick_secs.max(1));
    let mut volume_lock: Option<VolumeLock> = None;
    let mut held = LockHold::default();
    let mut next_shed_evaluation = Instant::now();
    let mut next_handle_recovery = Instant::now();
    // A clean verification is a full re-read of everything both stores hold. If
    // retirement is then deferred (a read still holds the legacy handle), re-hashing on
    // every tick would be minutes of disk for nothing, so a recent pass is reused.
    let mut verified: Option<(VerifyReport, Instant)> = None;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                debug!("Storage migration stopping for shutdown");
                return;
            }
            () = tokio::time::sleep(tick) => {}
        }

        // Never hold the volume against the rest of the machine for longer than this,
        // whatever the node is waiting on. Dropping it costs a tick: if nobody else wants
        // it, the branches below take it straight back.
        if held.has_overstayed() {
            debug!(
                "Held the volume migration lock for {} hour(s); giving it back so any \
                 other node on this volume gets a turn",
                MAX_VOLUME_LOCK_HOLD.as_secs() / 3600
            );
            volume_lock = None;
            held.give_up();
        }

        // Cleanup first. It can put an unmarked directory back under the live name, and
        // recovery is what gives the node a handle to it; the other order leaves that
        // until the next tick, and the completion check in between would see no handle
        // and no pending cleanup and call the migration finished.
        let cleanup = cleanup_state(&store);
        // Before anything reads the key set: a write that nobody waited for leaves a
        // note behind, and only the disk can say what became of it.
        store.reconcile_pending_writes().await;
        maybe_recover_lost_handle(&store, &mut next_handle_recovery).await;
        if cleanup == CleanupState::Finished && !store.has_legacy() {
            info!("Storage migration finished; nothing left on disk to clean up");
            return;
        }

        match store.migration_phase() {
            // Nothing left to migrate. Whether there is anything left to clean up is
            // decided at the top of the loop, which is also where this returns from.
            MigrationPhase::FilesOnly => {
                volume_lock = None;
                held.released();
            }
            MigrationPhase::Bridging => {
                // Held from the first copy through retirement, not released in between:
                // a node that let go after copying would let its eleven neighbours start
                // theirs before it had returned a byte, which is the exact pile-up the
                // lock exists to prevent. The one exception is a node that has become
                // permanently stuck (see below), which must not go on excluding the
                // others for a release.
                if matches!(
                    take_volume_lock(
                        &mut volume_lock,
                        &mut held,
                        store.root_dir(),
                        config.lock_dir.as_deref(),
                    ),
                    LockStep::WaitATick
                ) {
                    continue;
                }
                if bridge_tick(
                    &store,
                    &context,
                    &config,
                    &mut next_shed_evaluation,
                    &shutdown,
                )
                .await
                {
                    // The copier ran. That is the volume lock being used rather than held.
                    held.note_disk_work();
                } else {
                    // Copying is blocked on something only an operator can change, so
                    // stop holding the volume lock against the other nodes here.
                    volume_lock = None;
                    held.released();
                }
            }
            MigrationPhase::Committed => {
                // A node that restarted in this phase has no lock, and the work below
                // (copying anything that must be kept, then re-reading the whole store to
                // verify it) is exactly the disk-heavy work the lock exists to serialise.
                if matches!(
                    take_volume_lock(
                        &mut volume_lock,
                        &mut held,
                        store.root_dir(),
                        config.lock_dir.as_deref(),
                    ),
                    LockStep::WaitATick
                ) {
                    continue;
                }
                match retire_tick(&store, &context, &config, &mut verified, &shutdown).await {
                    // Not a return. The environment is gone from the node's point of
                    // view, but its directory is still being deleted in the background,
                    // and if that fails there has to be something left to try again. The
                    // loop exits at the top once nothing is pending.
                    RetireOutcome::Done => {
                        volume_lock = None;
                        held.released();
                    }
                    // Time spent reading or copying is the volume lock doing its job, not
                    // a node sitting on it. The cap is there for a node that waits, and
                    // restarting a full verification because a large store took longer
                    // than the cap would be the cap causing the problem it prevents.
                    RetireOutcome::Working => held.note_disk_work(),
                    RetireOutcome::Waiting => {}
                    RetireOutcome::NoWorkToSerialise => {
                        // Nothing this node can do will return space, so holding the
                        // volume lock only stops its neighbours from trying. In R1, where
                        // retirement is switched off entirely, holding it would mean one
                        // node per volume copies and the other eleven do nothing for the
                        // whole release.
                        volume_lock = None;
                        held.released();
                    }
                }
            }
        }
    }
}

/// Should the driver run at all, and say why in the log if not?
fn worth_starting(store: &Arc<ChunkStore>, config: &MigrationConfig) -> bool {
    if !config.enabled {
        warn!(
            "Storage migration is disabled. This node will keep reading both stores and \
             will never return the legacy environment's disk space."
        );
        return false;
    }
    // The same question the spawn site asks. A different one here means a driver that is
    // started and then returns immediately, which is how a node whose environment is a
    // link to storage that was not mounted yet ends up never picking it up.
    if !should_migrate(store) {
        debug!("No legacy chunk environment; nothing to migrate");
        return false;
    }

    let to_copy = store.legacy_only_keys().len();
    info!(
        migration_event = "start",
        to_copy,
        legacy_bytes = store.legacy_bytes(),
        "Storage migration starting: {to_copy} chunk(s) still only in the legacy \
         environment, {:.2} GiB to reclaim",
        bytes_to_gib(store.legacy_bytes())
    );
    true
}

/// Retry any removal that did not finish, and say whether the driver is done.
///
/// Runs independently of the phase. A removal that could not finish leaves nothing to
/// migrate but a disk that has not come back, and the reasons it failed (a name already
/// taken, a directory that could not be flushed, a scanner holding a handle) are the kind
/// that clear on their own.
fn cleanup_state(store: &Arc<ChunkStore>) -> CleanupState {
    if store.has_cleanup_pending() {
        store.retry_cleanup();
    }
    if store.has_cleanup_pending() || store.legacy_dir_is_on_disk() {
        return CleanupState::Pending;
    }
    CleanupState::Finished
}

/// Whether anything is left on disk for the driver to see through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupState {
    /// Something is still there.
    Pending,
    /// Nothing is.
    Finished,
}

/// Put a lost legacy handle back, if there is one to put back.
///
/// A node that lost its handle to an environment still on disk cannot read the chunks that
/// live only there. The cause is usually transient, so this runs every tick rather than
/// leaving the node half-blind until somebody restarts it.
async fn maybe_recover_lost_handle(store: &Arc<ChunkStore>, next_attempt: &mut Instant) {
    if Instant::now() < *next_attempt {
        return;
    }
    if store.recover_lost_legacy_handle().await {
        info!("Reopened the legacy chunk environment; the migration continues");
        *next_attempt = Instant::now();
        return;
    }
    // Backed off, because each attempt scans the whole environment and a cause that has
    // not cleared in half a minute is unlikely to clear in the next.
    *next_attempt = Instant::now() + HANDLE_RECOVERY_INTERVAL;
}

/// How long this node has had the volume migration lock, and when it may ask again.
///
/// Split out because the rule is easy to get wrong in one branch and not another: a
/// branch that takes the lock without recording when, or that gives it up without a
/// cooldown, silently opts out of the cap that stops one node holding a whole machine.
#[derive(Default)]
struct LockHold {
    /// When the lock was taken, or when it was last used for real disk work.
    since: Option<Instant>,
    /// Before this, do not ask for it again.
    cooldown_until: Option<Instant>,
}

impl LockHold {
    /// Record that the lock has just been taken.
    fn taken(&mut self) {
        self.since = Some(Instant::now());
    }

    /// Record that it is no longer held.
    fn released(&mut self) {
        self.since = None;
    }

    /// Record that this tick used the lock for what it is for.
    ///
    /// Copying and verifying are the exclusive disk work the lock exists to serialise, so
    /// time spent on them is not time spent sitting on it. Without this a node with a
    /// large store would have the cap fire in the middle of a verification pass and
    /// restart it, which is the cap causing the problem it prevents.
    fn note_disk_work(&mut self) {
        self.since = Some(Instant::now());
    }

    /// Has this node held the lock past the cap without using it?
    fn has_overstayed(&self) -> bool {
        self.since
            .is_some_and(|at| at.elapsed() >= MAX_VOLUME_LOCK_HOLD)
    }

    /// Give the lock up and stand back so somebody else can take it.
    fn give_up(&mut self) {
        self.since = None;
        self.cooldown_until = Some(Instant::now() + VOLUME_LOCK_COOLDOWN);
    }

    /// May this node ask for the lock yet?
    fn may_ask(&self) -> bool {
        !self
            .cooldown_until
            .is_some_and(|until| Instant::now() < until)
    }
}

/// What taking the volume lock produced for the driver loop.
enum LockStep {
    /// Held, or not needed because none is possible here.
    Proceed,
    /// Someone else has it. Try again next tick.
    WaitATick,
}

/// Take the volume lock if it is not already held, stamping when it was taken.
///
/// One place, because the stamp is what stops a node holding the volume against every
/// other node on the machine, and a branch that acquires without stamping silently opts
/// out of that.
fn take_volume_lock(
    lock: &mut Option<VolumeLock>,
    held: &mut LockHold,
    root_dir: &Path,
    scope: Option<&Path>,
) -> LockStep {
    if lock.is_some() {
        return LockStep::Proceed;
    }
    // After giving the volume up at the cap, stand back for a moment. Reacquiring in the
    // same breath would hand nobody anything.
    if !held.may_ask() {
        return LockStep::WaitATick;
    }
    match VolumeLock::try_acquire(root_dir, scope) {
        LockAttempt::Acquired(taken) => {
            *lock = Some(taken);
            held.taken();
            LockStep::Proceed
        }
        LockAttempt::Busy => {
            debug!("Another node on this volume is migrating; waiting");
            LockStep::WaitATick
        }
        // No lock is possible here, so waiting for one would strand this node
        // permanently. Proceed; the slack floor is the backstop.
        LockAttempt::Unavailable => LockStep::Proceed,
    }
}

/// One pass of the copier. Returns `false` when this node cannot make progress that
/// needs the volume to itself.
async fn bridge_tick(
    store: &Arc<ChunkStore>,
    context: &MigrationContext,
    config: &MigrationConfig,
    next_shed_evaluation: &mut Instant,
    shutdown: &CancellationToken,
) -> bool {
    let remaining = store.legacy_only_keys();
    if remaining.is_empty() {
        if let Err(e) = store.commit_to_files() {
            // Not progress, and not something exclusive disk access fixes. Saying it was
            // would reset the hold cap every tick and let this node keep the volume from
            // every other node on the machine for as long as the failure lasts.
            warn!(
                "Everything is copied but the migration commitment could not be recorded: \
                 {e}. Retrying on the next tick."
            );
            return false;
        }
        return true;
    }

    let ordered = rank_closest_first(remaining, context.self_xor);
    let batch: Vec<XorName> = ordered
        .into_iter()
        .take(config.batch_chunks.max(1))
        .collect();
    let report = match store
        .copy_batch(
            &batch,
            config.copier_slack_bytes(),
            config.copier_throttle_mib_per_sec,
            shutdown,
        )
        .await
    {
        Ok(report) => report,
        Err(e) => {
            // Still retried every tick, but the volume lock goes back: if this is
            // permanent, holding it would block every other node on the volume on a node
            // that is getting nowhere.
            warn!("Storage migration copy failed: {e}. Retrying on the next tick.");
            return false;
        }
    };

    if report.copied > 0 {
        debug!(
            "Storage migration copied {} chunk(s) ({:.2} GiB) this pass",
            report.copied,
            bytes_to_gib(report.bytes)
        );
        // A migration runs for hours. One periodic line at info level is what an operator
        // watching a node actually sees, and what says the copier has not silently stalled.
        let left = store.legacy_only_keys().len();
        if left % PROGRESS_LOG_EVERY < usize::try_from(report.copied).unwrap_or(usize::MAX) {
            info!(
                migration_event = "progress",
                remaining = left,
                "Storage migration: {left} chunk(s) left to copy out of the legacy environment"
            );
        }
    }
    if report.unusable > 0 {
        warn!(
            "{} chunk(s) in the legacy environment did not match their own address and \
             were dropped from the key set",
            report.unusable
        );
    }

    if report.stopped_for_space {
        // Out of space. Whatever happens next, this node is not going to write more until
        // something changes, so it stops excluding its neighbours from the volume. That
        // covers the 72-hour shed hold as well as an outright refusal: holding the lock
        // for three days would leave every other node on the volume unmigrated.
        if Instant::now() < *next_shed_evaluation {
            return false;
        }
        *next_shed_evaluation = Instant::now() + SHED_REEVALUATION_INTERVAL;
        return evaluate_shed(store, context, config).await;
    }
    true
}

/// Decide whether the node may give up what it could not copy.
async fn evaluate_shed(
    store: &Arc<ChunkStore>,
    context: &MigrationContext,
    config: &MigrationConfig,
) -> bool {
    let remaining = store.legacy_only_keys();
    let short_by = remaining.len();

    // Read from the one switch the auditors read, not from a second copy of it. There
    // used to be two constants of the same name with two environment overrides, one on
    // each side of this decision, and nothing coupling them: a node could have been
    // willing to shed while every peer was still applying the full penalty, which is the
    // exact outcome the release ordering exists to prevent.
    if !crate::replication::config::close_group_storage_penalty_suspended() {
        warn!(
            "This node cannot fit {short_by} chunk(s) in the file store, but this release \
             has audit penalties switched back on, so giving anything up now would be \
             penalised by every peer. Keeping both stores. Add disk, or migrate this node \
             on a build that still suspends penalties."
        );
        return false;
    }

    if !config.allow_shed {
        warn!(
            "This node cannot fit {short_by} chunk(s) in the file store and shedding is \
             turned off. Add disk, or set storage.migration.allow_shed. Until then it \
             keeps serving from both stores and the legacy environment stays."
        );
        return false;
    }

    let state = store.migration_state();

    // Wait for this node's turn. A close group is split into waves so at most
    // CONCURRENT_MIGRATIONS_PER_GROUP of it are giving chunks up at once; if all seven
    // holders went together, none could prove to the others that a copy survived and the
    // whole group would sit deadlocked waiting on each other. Only nodes that have to give
    // something up wait: a node with room has already copied everything and retired.
    let wave = migration_wave_for(context.self_id.as_ref(), context.close_group_size);
    if !wave_has_opened(&state, config, wave) {
        info!(
            "This node is {short_by} chunk(s) short of disk and is in migration wave {wave} \
             of {}. Its turn opens {} hour(s) after this build first started, so the rest of \
             its close group stays steady and can keep serving what it is about to give up.",
            migration_wave_count(context.close_group_size),
            config
                .shed_hold_hours
                .saturating_add(wave.saturating_mul(config.wave_hours))
        );
        return false;
    }

    // Kept as its own check even though the wave now starts after it: the hold is about
    // peers on an older build still applying the penalty, the wave is about the close
    // group being able to cover for whoever moves. Different reasons, both required.
    if !state.shed_hold_elapsed(config) {
        info!(
            "This node is {short_by} chunk(s) short of disk. Holding for {} hour(s) after \
             first start before giving any up, so peers still on an older build have \
             upgraded and stopped penalising a shed.",
            config.shed_hold_hours
        );
        return false;
    }

    // First filter, and the cheap one: a node never gives up a chunk it is near the front
    // of the group for. In practice it rarely fires, by construction, because the copier
    // walks closest-first, so whatever is left when the disk fills is the far end of the
    // list. Finding a protected key still uncopied means the node could not fit even the
    // chunks it is closest to, which is exactly when it must not shed anything.
    let mut protected = Vec::new();
    for key in &remaining {
        if !context.may_shed(key).await {
            protected.push(*key);
            if protected.len() >= REFUSAL_SAMPLE {
                break;
            }
        }
    }
    if !protected.is_empty() {
        let sample: Vec<String> = protected.iter().map(hex::encode).collect();
        warn!(
            "This node is {short_by} chunk(s) short of disk, and at least {} of them are \
             chunks it is near the front of the group for (for example {}). It will not \
             give those up. The legacy environment stays and its disk is not returned \
             until storage is added.",
            protected.len(),
            sample.join(", ")
        );
        return false;
    }

    // Second filter, and the one that decides it: proof that somebody else holds every
    // chunk this node is about to give up. Being far from a chunk is not evidence
    // that a copy exists. During a fleet-wide migration the nodes that ought to hold it
    // are exactly the ones that may also be out of disk, so the question has to be asked
    // rather than inferred.
    info!(
        "Checking that other nodes hold the {short_by} chunk(s) this node cannot fit, \
         before giving any of them up"
    );
    let unconfirmed = unconfirmed_by_neighbours(store, context, &remaining).await;
    if !unconfirmed.is_empty() {
        let sample: Vec<String> = unconfirmed
            .iter()
            .take(REFUSAL_SAMPLE)
            .map(hex::encode)
            .collect();
        warn!(
            "{} of the {short_by} chunk(s) this node cannot fit could not be proven to \
             exist anywhere else (for example {}). Nothing is given up and the legacy \
             environment stays. Add disk, or wait for replication to place them.",
            unconfirmed.len(),
            sample.join(", ")
        );
        return false;
    }

    info!(
        migration_event = "shed",
        shed = short_by,
        "Every one of the {short_by} chunk(s) this node cannot fit is proven to be held \
         elsewhere. Committing to what it can hold. They stay readable from the legacy \
         environment until it is removed, and replication refetches whatever still belongs \
         here once there is room."
    );
    if let Err(e) = store.commit_to_files() {
        warn!("Could not record the migration commitment: {e}");
        return false;
    }
    true
}

/// The keys still only in the legacy store that this node is too close to give up.
async fn keys_this_node_must_not_give_up(
    store: &Arc<ChunkStore>,
    context: &MigrationContext,
) -> Vec<XorName> {
    let mut must_keep = Vec::new();
    for key in store.legacy_only_keys() {
        if !context.may_shed(&key).await {
            must_keep.push(key);
        }
    }
    must_keep
}

/// Re-ask every network gate, after verification and immediately before the deletion.
///
/// Verification re-reads the whole store and can run for hours. A gate satisfied before it
/// started says nothing about the moment of deletion: peers leave, replicas are pruned
/// elsewhere, and a write whose file half failed adds a fresh legacy-only key that has
/// faced none of these checks. This is the last point at which the answer can still be
/// acted on, so it is the point at which it has to be true.
async fn every_gate_still_holds(
    store: &Arc<ChunkStore>,
    context: &MigrationContext,
    candidates: &std::collections::BTreeSet<XorName>,
) -> Option<RetireOutcome> {
    // A key that joined the legacy-only set since the snapshot was taken has been through
    // none of this. Stop now rather than asking the gates about a set that has already
    // moved; the next tick copies it and takes a fresh snapshot.
    let live: std::collections::BTreeSet<XorName> = store.legacy_only_keys().into_iter().collect();
    if live != *candidates {
        debug!(
            "Legacy environment not retired: the set changed while the gates were being \
             checked ({} keys then, {} now)",
            candidates.len(),
            live.len()
        );
        return Some(RetireOutcome::Waiting);
    }
    if !keys_this_node_must_not_give_up(store, context)
        .await
        .is_empty()
    {
        debug!("Legacy environment not retired: the shed rule changed during verification");
        return Some(RetireOutcome::Waiting);
    }
    if let Some(outcome) = shedding_is_still_safe(store, context, candidates).await {
        return Some(outcome);
    }
    // And the retention contract once more, for the same reason.
    if let Some(reason) = store.retirement_blocker(|k| context.still_answerable(k)) {
        debug!("Legacy environment not retired: {reason}");
        return Some(RetireOutcome::Waiting);
    }
    None
}

/// The last two questions before anything is deleted, asked in this order because the
/// order is the safety argument: reduce the claim, let the group learn it, then give the
/// chunks up.
///
/// Returns `Some` with the reason to stop, or `None` when it is safe to proceed.
async fn shedding_is_still_safe(
    store: &Arc<ChunkStore>,
    context: &MigrationContext,
    shedding: &std::collections::BTreeSet<XorName>,
) -> Option<RetireOutcome> {
    // Nothing below is reached until the node has reduced its commitment (the phase
    // is `Committed`) and that reduction has been rebuilt and published. What remains
    // is to confirm the close group has actually *received* it, and that the chunks
    // being given up still exist elsewhere. Only then is anything deleted.
    if !shedding.is_empty() {
        // A rotation is not the same as neighbours knowing. Until they have the
        // smaller key set they keep auditing this node against the one it used to
        // hold, and a wave of audit failures is as damaging as losing the chunks.
        // Asked only when there is a commitment to deliver. A node whose file-backed set
        // is empty commits to nothing, so there is no hash for a neighbour to acknowledge
        // and this gate would never open, stranding its disk for good. Nothing is lost by
        // skipping it: the gate exists to stop neighbours auditing this node against a key
        // set it no longer holds, and a node claiming nothing cannot fail such an audit.
        // The possession check below, which proves every chunk being given up still exists
        // elsewhere, is the gate that protects the data, and it still runs.
        let commits_to_nothing = store
            .committable_keys()
            .await
            .is_ok_and(|keys| keys.is_empty());
        if commits_to_nothing {
            info!(
                "This node's file-backed set is empty, so it commits to nothing and has \
                 no reduced commitment for its close group to receive. Proceeding to the \
                 possession check on the {} chunk(s) it is giving up.",
                shedding.len()
            );
        } else if !context.neighbours_know_the_commitment().await {
            info!(
                "Holding: {} of this node's close group must receive its reduced \
                 commitment before it gives up {} chunk(s). {} have it so far.",
                context.commitment_recipients_needed(),
                shedding.len(),
                context
                    .commitment
                    .as_ref()
                    .map_or(0, |s| s.current_delivered_peer_count())
            );
            // Give the volume back while waiting on this. It is a network condition, not
            // a disk one, and it may never resolve: holding the lock through it would let
            // one node stop every other node on the machine from ever starting.
            return Some(RetireOutcome::NoWorkToSerialise);
        }
        // Asked again here, not only when the node committed. Hours pass in between,
        // the group moves, and a peer that held a copy then may not now. This is the
        // last moment at which the answer still matters.
        let ordered: Vec<XorName> = shedding.iter().copied().collect();
        let unconfirmed = unconfirmed_by_neighbours(store, context, &ordered).await;
        if !unconfirmed.is_empty() {
            let sample: Vec<String> = unconfirmed
                .iter()
                .take(REFUSAL_SAMPLE)
                .map(hex::encode)
                .collect();
            warn!(
                "{} of the {} chunk(s) this node is giving up can no longer be proven \
                 to exist elsewhere (for example {}). The legacy environment stays.",
                unconfirmed.len(),
                shedding.len(),
                sample.join(", ")
            );
            return Some(RetireOutcome::NoWorkToSerialise);
        }
    }
    None
}

/// What one pass of the retirement gate concluded.
enum RetireOutcome {
    /// The legacy environment is gone. The driver is finished.
    Done,
    /// Exclusive disk work happened this tick: copying, or re-reading the store to verify
    /// it. Keep the volume, and count the time as time spent using it rather than time
    /// spent holding it.
    Working,
    /// Still working towards it, but waiting on a clock rather than on the disk. Keep the
    /// volume, because the node is about to need it, but let the hold cap run.
    Waiting,
    /// Blocked on something no amount of exclusive disk access will fix.
    NoWorkToSerialise,
}

/// When this node last said out loud that its migration needs a person.
static LAST_OPERATOR_WARNING: parking_lot::Mutex<Option<Instant>> = parking_lot::Mutex::new(None);

/// How often to repeat it. Often enough to be noticed, rarely enough not to drown the log.
const OPERATOR_WARNING_INTERVAL: Duration = Duration::from_secs(3600);

/// Should the "this needs a person" warning be repeated now?
///
/// The condition it reports is checked on every tick and does not clear on its own, so
/// without this it would be a line every thirty seconds for as long as the node runs.
fn operator_should_hear_again() -> bool {
    let mut last = LAST_OPERATOR_WARNING.lock();
    let now = Instant::now();
    if last.is_some_and(|at| now.duration_since(at) < OPERATOR_WARNING_INTERVAL) {
        return false;
    }
    *last = Some(now);
    true
}

/// The retention contract, asked before anything else in the tick.
///
/// `Some` with what the driver should do, or `None` when nothing is in the way.
fn blocked_before_the_gates(
    store: &Arc<ChunkStore>,
    context: &MigrationContext,
    config: &MigrationConfig,
) -> Option<RetireOutcome> {
    let reason = store.retirement_blocker(|k| context.still_answerable(k))?;
    // Two blockers no amount of exclusive disk access will clear: an environment this
    // node cannot read, and one it must not delete because it is a link to somewhere
    // else. Both need a person, so give the volume back to the nodes that can use it and
    // say so where an operator will see it rather than at debug.
    if store.has_lost_its_legacy_handle() || store.legacy_is_a_link() {
        if operator_should_hear_again() {
            warn!(
                migration_event = "needs_an_operator",
                "The legacy chunk environment will not be retired automatically: {reason}"
            );
        }
        return Some(RetireOutcome::NoWorkToSerialise);
    }
    debug!("Legacy environment not retired yet: {reason}");
    Some(if config.retire_legacy {
        RetireOutcome::Waiting
    } else {
        // Retirement is switched off on this node, so it will never free its disk here
        // however long it waits.
        RetireOutcome::NoWorkToSerialise
    })
}

/// One pass of the retirement gate.
async fn retire_tick(
    store: &Arc<ChunkStore>,
    context: &MigrationContext,
    config: &MigrationConfig,
    verified: &mut Option<(VerifyReport, Instant)>,
    shutdown: &CancellationToken,
) -> RetireOutcome {
    if let Some(outcome) = blocked_before_the_gates(store, context, config) {
        return outcome;
    }

    // Re-check the shed rule against live routing immediately before the destructive
    // step, not once when the node committed hours ago. Two things put a key back into
    // the legacy-only set after that decision: a file that failed verification and is now
    // served from the legacy copy, and a write whose file half failed. Neither went
    // through the rank check, and both would be thrown away by the removal below.
    let must_keep = keys_this_node_must_not_give_up(store, context).await;
    if !must_keep.is_empty() {
        warn!(
            "{} chunk(s) are still only in the legacy environment and this node is too \
             close to them to give them up. Copying them before anything is removed.",
            must_keep.len()
        );
        match store
            .copy_batch(
                &must_keep,
                config.copier_slack_bytes(),
                config.copier_throttle_mib_per_sec,
                shutdown,
            )
            .await
        {
            Ok(report) if report.stopped_for_space => {
                warn!(
                    "Out of disk while copying {} chunk(s) this node must not give up. \
                     The legacy environment stays until there is room for them.",
                    must_keep.len()
                );
                *verified = None;
                return RetireOutcome::NoWorkToSerialise;
            }
            Ok(_) => {}
            Err(e) => {
                warn!("Could not copy the chunks this node must keep: {e}");
                *verified = None;
                return RetireOutcome::NoWorkToSerialise;
            }
        }
        // Anything copied changed the file store, so a previous verification no longer
        // covers it.
        *verified = None;
        return RetireOutcome::Working;
    }

    // The real report from a recent pass, never a fabricated one. Reuse deliberately does
    // NOT refresh the window: re-arming it from a reused proof would let a node that
    // keeps deferring retirement run the verification exactly once and coast on it.
    let reusable = verified
        .filter(|(_, at)| at.elapsed() < VERIFICATION_REUSE_WINDOW)
        .map(|(proof, _)| proof);
    let proof = match reusable {
        Some(proof) => proof,
        None => match store
            .verify_before_retire(config.copier_throttle_mib_per_sec, shutdown)
            .await
        {
            Ok(proof) => {
                if proof.is_clean() {
                    *verified = Some((proof, Instant::now()));
                }
                proof
            }
            Err(e) => {
                // A pass that failed is not progress, however quickly it failed, and
                // treating it as work would let a node whose store cannot be read hold
                // the volume against every other node on the machine for good.
                warn!("Pre-retirement verification failed: {e}. Retrying on the next tick.");
                return RetireOutcome::NoWorkToSerialise;
            }
        },
    };
    if !proof.is_clean() {
        *verified = None;
        warn!(
            "Pre-retirement verification found {} chunk(s) that are damaged in the file \
             store and cannot be repaired from the legacy environment. The legacy \
             environment stays.",
            proof.unrepairable()
        );
        return RetireOutcome::NoWorkToSerialise;
    }

    // Snapshotted BEFORE the gates, not after. Every gate below is asked about exactly
    // this set, and exactly this set is what the removal is permitted to destroy. Taken
    // afterwards, a key that joined between the last gate and the snapshot would be
    // counted as approved having passed nothing, which is the case the gates exist for.
    let approved: std::collections::BTreeSet<XorName> =
        store.legacy_only_keys().into_iter().collect();

    if let Some(outcome) = every_gate_still_holds(store, context, &approved).await {
        return outcome;
    }

    let kept = store.current_chunks().unwrap_or(0);
    let shed = store.migration_state().shed_key_count;
    match store
        .retire_legacy(
            &proof,
            &|k: &XorName| context.still_answerable(k),
            &approved,
        )
        .await
    {
        Ok(freed) => {
            log_migration_complete(kept, shed, freed);
            RetireOutcome::Done
        }
        Err(e) => {
            debug!("Legacy environment not retired yet: {e}");
            RetireOutcome::Waiting
        }
    }
}

/// Convert a byte count to GiB for human-readable log messages.
#[allow(clippy::cast_precision_loss)] // display only
#[cfg_attr(not(feature = "logging"), allow(dead_code))]
fn bytes_to_gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    fn peer_id(byte: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        if let Some(slot) = bytes.first_mut() {
            *slot = byte;
        }
        PeerId::from_bytes(bytes)
    }

    /// The width shedding is measured against: the admission group, not the close group.
    const WIDTH: usize = storage_admission_width(7);

    #[test]
    fn shedding_is_measured_against_the_width_the_pruner_protects() {
        // The pruner treats the admission group (close group plus its margin) as strictly
        // in-range and refuses to delete inside it. A one-off migration must not be more
        // willing to drop a chunk than the thing that runs every day.
        assert_eq!(WIDTH, storage_admission_width(7));
        assert!(
            storage_admission_width(7) > 7,
            "the admission group is wider than the close group"
        );
        // A rank the close group would have called sheddable is protected here.
        assert!(!rank_is_sheddable(GroupRank::Inside(5), WIDTH));
        assert!(!rank_is_sheddable(GroupRank::Inside(6), WIDTH));
    }

    #[test]
    fn a_node_never_gives_up_a_chunk_it_is_among_the_closest_to() {
        // This node is one of the closest for these ranks. Giving one of them up is the
        // case where every short-of-space holder could drop the same chunk and take its
        // last replica, so it is refused outright.
        for rank in 0..WIDTH - SHEDDABLE_TAIL_RANKS {
            assert!(
                !rank_is_sheddable(GroupRank::Inside(rank), WIDTH),
                "rank {rank} must be protected"
            );
        }
        // The last two positions may be given up: a chunk has exactly one holder at each,
        // so it is only ever a candidate for two of its holders.
        for rank in WIDTH - SHEDDABLE_TAIL_RANKS..WIDTH {
            assert!(
                rank_is_sheddable(GroupRank::Inside(rank), WIDTH),
                "rank {rank} is in the tail and may be shed"
            );
        }
        // Out of range entirely: nothing to protect.
        assert!(rank_is_sheddable(GroupRank::Outside, WIDTH));
        // No routing to consult is never a licence.
        assert!(!rank_is_sheddable(GroupRank::Unknown, WIDTH));
    }

    #[test]
    fn a_group_narrower_than_the_tail_protects_everything_in_it() {
        // A group with no tail has nothing to give up. Subtracting saturatingly would put
        // the threshold at zero and make every member sheddable, which is exactly
        // backwards for the narrowest groups.
        assert!(!rank_is_sheddable(GroupRank::Inside(0), 2));
        assert!(!rank_is_sheddable(GroupRank::Inside(0), 1));
        assert!(!rank_is_sheddable(GroupRank::Inside(1), 2));
        // Out of the group entirely is still out.
        assert!(rank_is_sheddable(GroupRank::Outside, 2));
        // And a group with a tail still has one.
        assert!(!rank_is_sheddable(GroupRank::Inside(0), 3));
        assert!(rank_is_sheddable(GroupRank::Inside(1), 3));
    }

    #[test]
    fn the_marker_round_trips_and_a_corrupt_one_starts_over_conservatively() {
        let dir = TempDir::new().expect("temp dir");
        let mut state = MigrationState::new(MigrationPhase::Bridging);
        state.phase = MigrationPhase::Committed;
        state.shed_key_count = 12;
        state.committed_at_unix = Some(1_700_000_000);
        state.save(dir.path()).expect("save");

        let loaded = MigrationState::load_or_new(dir.path(), MigrationPhase::Bridging);
        assert_eq!(loaded.phase, MigrationPhase::Committed);
        assert_eq!(loaded.shed_key_count, 12);
        assert_eq!(loaded.committed_at_unix, Some(1_700_000_000));

        // An unreadable marker restarts the clocks rather than being fatal. Losing it
        // delays a migration and can never rush one.
        std::fs::write(state_path(dir.path()), b"not json").expect("corrupt");
        let recovered = MigrationState::load_or_new(dir.path(), MigrationPhase::Bridging);
        assert_eq!(recovered.phase, MigrationPhase::Bridging);
        assert_eq!(recovered.committed_at_unix, None);
    }

    #[test]
    fn the_shed_hold_and_retirement_clocks_run_from_recorded_times() {
        let config = MigrationConfig {
            shed_hold_hours: 72,
            retire_delay_hours: MIN_RETIRE_DELAY_HOURS,
            ..MigrationConfig::default()
        };

        let mut state = MigrationState::new(MigrationPhase::Bridging);
        assert!(!state.shed_hold_elapsed(&config), "just started");
        state.first_start_unix = now_unix().saturating_sub(73 * 3600);
        assert!(state.shed_hold_elapsed(&config));

        assert!(
            !state.retire_delay_elapsed(&config),
            "never committed, so the clock has not started"
        );
        state.committed_at_unix = Some(now_unix().saturating_sub(3600));
        assert!(!state.retire_delay_elapsed(&config), "an hour is not four");
        state.committed_at_unix =
            Some(now_unix().saturating_sub(MIN_RETIRE_DELAY_HOURS * 3600 + 60));
        assert!(state.retire_delay_elapsed(&config));
    }

    #[test]
    fn only_one_node_on_a_volume_migrates_at_a_time() {
        let volume = TempDir::new().expect("temp dir");
        let node_a = volume.path().join("node-a");
        let node_b = volume.path().join("node-b");
        std::fs::create_dir_all(&node_a).expect("mkdir");
        std::fs::create_dir_all(&node_b).expect("mkdir");

        let LockAttempt::Acquired(held) = VolumeLock::try_acquire(&node_a, None) else {
            panic!("the first node must take the lock");
        };
        assert!(
            matches!(VolumeLock::try_acquire(&node_b, None), LockAttempt::Busy),
            "a second node on the same volume must be told to wait, not that no lock exists"
        );

        drop(held);
        assert!(
            matches!(
                VolumeLock::try_acquire(&node_b, None),
                LockAttempt::Acquired(_)
            ),
            "and take it once the first is done"
        );
    }

    /// Seed a real LMDB chunk store, the way a node upgrading into this build has one.
    async fn seed_legacy(root: &std::path::Path, count: u32) -> Vec<XorName> {
        let lmdb = crate::storage::LmdbStorage::new(crate::storage::LmdbStorageConfig {
            root_dir: root.to_path_buf(),
            verify_on_read: true,
            max_map_size: 0,
            disk_reserve: 0,
        })
        .await
        .expect("open legacy");
        let mut keys = Vec::new();
        for i in 0..count {
            let content = format!("legacy-chunk-{i}").into_bytes();
            let addr = crate::client::compute_address(&content);
            lmdb.put(&addr, &content).await.expect("legacy put");
            keys.push(addr);
        }
        lmdb.wait_idle().await;
        drop(lmdb);
        keys
    }

    /// The whole point, end to end: a node that starts with an LMDB chunk store and a
    /// disk to hold it finishes with the chunks in files and the LMDB gone.
    ///
    /// Driven by `run`, the same entry point node startup calls, rather than by poking the
    /// pieces. That matters: the wiring that calls it went missing once and every test
    /// passed, because they all built the store directly and a node with no legacy store
    /// starts no migration.
    #[tokio::test]
    async fn a_node_with_room_copies_everything_and_removes_the_legacy_store() {
        const CHUNKS: u32 = 24;

        let tmp = TempDir::new().expect("temp dir");
        // Nested, so the volume lock this node takes lives in its own directory rather
        // than one shared with every other test running in parallel.
        let root = tmp.path().join("node");
        std::fs::create_dir_all(&root).expect("mkdir");
        let keys = seed_legacy(&root, CHUNKS).await;

        let mut config = crate::storage::ChunkStoreConfig {
            root_dir: root.clone(),
            ..crate::storage::ChunkStoreConfig::test_default()
        };
        // Deliberately NOT setting `retire_legacy`. The shipped default has to be what
        // carries this all the way to a removed environment, or the release migrates every
        // node and reclaims nothing.
        config.migration.tick_secs = 1;
        // Scoped to this test's own directory. In production the lock is keyed by the
        // filesystem, so without this every test on this machine would serialise against
        // every other one that runs a migration.
        config.migration.lock_dir = Some(root.clone());
        config.migration.copier_throttle_mib_per_sec = 0;
        let store = Arc::new(
            crate::storage::ChunkStore::new(config)
                .await
                .expect("open store"),
        );

        // Precondition: everything is in the legacy store and nothing is in files.
        assert!(store.has_legacy(), "the node must start with an LMDB store");
        assert_eq!(store.migration_phase(), MigrationPhase::Bridging);
        assert_eq!(store.legacy_only_keys().len(), CHUNKS as usize);
        assert!(root.join("chunks.mdb").exists());

        let shutdown = CancellationToken::new();
        let driver = tokio::spawn(run(
            Arc::clone(&store),
            MigrationContext {
                p2p: None,
                self_id: None,
                self_xor: None,
                commitment: None,
                replication: None,
                sync_state: None,
                audit_challenge_coordinator: None,
                peer_commitments: None,
                close_group_size: 7,
            },
            shutdown.clone(),
        ));

        // The copier runs on its own and settles once nothing is left only in the legacy
        // store. This node has room, so it sheds nothing and needs no network at all.
        wait_for(
            &store,
            MigrationPhase::Committed,
            "the copier should finish",
        )
        .await;
        assert!(
            store.legacy_only_keys().is_empty(),
            "every chunk should have been copied"
        );

        // Stand in for the commitment builder, which lives in the replication engine: the
        // retirement gate wants the reduced commitment published and its window elapsed.
        store.note_commitment_rebuilt();
        store.note_commitment_rebuilt();
        store.force_migration_state(|s| {
            s.committed_at_unix =
                Some(now_unix().saturating_sub(MIN_RETIRE_DELAY_HOURS * 3600 + 60));
        });

        wait_for(
            &store,
            MigrationPhase::FilesOnly,
            "retirement should complete",
        )
        .await;
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), driver).await;

        // The point of the whole exercise: the LMDB is gone from the filesystem.
        assert!(
            !root.join("chunks.mdb").exists(),
            "the legacy store must be removed, which is the only moment disk comes back"
        );
        assert!(!store.has_legacy());

        // And nothing was lost: every chunk still reads, now out of a file.
        assert_eq!(store.current_chunks().expect("count"), u64::from(CHUNKS));
        for (i, key) in keys.iter().enumerate() {
            let expected = format!("legacy-chunk-{i}").into_bytes();
            assert_eq!(
                store.get(key).await.expect("get").expect("present"),
                expected,
                "chunk {i} did not survive the migration"
            );
        }

        // In files, under the suffix shard its address names.
        let sample = keys.first().copied().expect("a key");
        let path = root
            .join(crate::storage::file_store::CHUNKS_DIR_NAME)
            .join(format!("{:02x}", sample.last().copied().unwrap_or(0)))
            .join(hex::encode(sample));
        assert!(path.exists(), "expected a chunk file at {}", path.display());
    }

    /// The other half: a node that cannot fit its chunks and cannot prove anyone else
    /// holds them keeps both stores and deletes nothing.
    ///
    /// This is the case that must fail safe. The node is out of disk, so it would like to
    /// give chunks up, but with no view of the network it cannot show a single one exists
    /// elsewhere. Refusing costs it disk. Proceeding would cost the network data.
    #[tokio::test]
    async fn a_node_that_cannot_prove_its_chunks_are_safe_deletes_nothing() {
        const CHUNKS: u32 = 8;

        let tmp = TempDir::new().expect("temp dir");
        let root = tmp.path().join("node");
        std::fs::create_dir_all(&root).expect("mkdir");
        let keys = seed_legacy(&root, CHUNKS).await;

        let mut config = crate::storage::ChunkStoreConfig {
            root_dir: root.clone(),
            // Nothing will fit: the copier stops for space on its first chunk.
            disk_reserve: u64::MAX / 2,
            ..crate::storage::ChunkStoreConfig::test_default()
        };
        config.migration.retire_legacy = true;
        config.migration.tick_secs = 1;
        // Scoped to this test's own directory. In production the lock is keyed by the
        // filesystem, so without this every test on this machine would serialise against
        // every other one that runs a migration.
        config.migration.lock_dir = Some(root.clone());
        // Elapsed, so the hold is not what is doing the refusing here.
        config.migration.shed_hold_hours = 0;
        config.migration.wave_hours = 0;
        let store = Arc::new(
            crate::storage::ChunkStore::new(config)
                .await
                .expect("open store"),
        );
        assert_eq!(store.legacy_only_keys().len(), CHUNKS as usize);

        let shutdown = CancellationToken::new();
        let driver = tokio::spawn(run(
            Arc::clone(&store),
            MigrationContext {
                p2p: None,
                self_id: None,
                self_xor: None,
                commitment: None,
                replication: None,
                sync_state: None,
                audit_challenge_coordinator: None,
                peer_commitments: None,
                close_group_size: 7,
            },
            shutdown.clone(),
        ));

        // Give it long enough to have tried, re-tried, and evaluated shedding.
        tokio::time::sleep(Duration::from_secs(5)).await;
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), driver).await;

        assert_eq!(
            store.migration_phase(),
            MigrationPhase::Bridging,
            "a node that cannot prove its chunks are held elsewhere must not commit"
        );
        assert!(
            root.join("chunks.mdb").exists(),
            "and must not remove the only copy of them"
        );
        assert_eq!(store.legacy_only_keys().len(), CHUNKS as usize);
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                store.get(key).await.expect("get").expect("present"),
                format!("legacy-chunk-{i}").into_bytes(),
                "chunk {i} must still be served throughout"
            );
        }
    }

    /// Poll until the store reaches `phase`, or fail with what it reached instead.
    ///
    /// The deadline is generous because it is measured on the wall clock while the driver
    /// it is waiting on runs on the runtime. On a saturated machine both stretch, and a
    /// deadline sized for the work rather than for the contention turns a slow build into
    /// a failing test. The work itself is two ticks.
    async fn wait_for(store: &Arc<crate::storage::ChunkStore>, phase: MigrationPhase, what: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        while std::time::Instant::now() < deadline {
            if store.migration_phase() == phase {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "{what}: still in {:?} after the deadline, expected {phase:?}",
            store.migration_phase()
        );
    }

    #[tokio::test]
    async fn the_driver_exits_immediately_when_there_is_nothing_to_migrate() {
        // The whole feature hangs off `run` being reachable from node startup. A port that
        // dropped that call once already, and nothing caught it, because a fresh node has
        // no legacy environment and every test built one directly. This asserts the entry
        // point is callable and terminates on its own for a node with nothing to do.
        let dir = TempDir::new().expect("temp dir");
        let store = Arc::new(
            crate::storage::ChunkStore::new(crate::storage::ChunkStoreConfig {
                root_dir: dir.path().to_path_buf(),
                ..crate::storage::ChunkStoreConfig::test_default()
            })
            .await
            .expect("open store"),
        );
        assert!(!store.has_legacy());

        let context = MigrationContext {
            p2p: None,
            self_id: None,
            self_xor: None,
            commitment: None,
            replication: None,
            sync_state: None,
            audit_challenge_coordinator: None,
            peer_commitments: None,
            close_group_size: 7,
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            run(store, context, CancellationToken::new()),
        )
        .await
        .expect("the driver must return rather than idle when there is nothing to migrate");
    }

    #[tokio::test]
    async fn a_node_with_no_view_of_the_network_gives_up_nothing() {
        // Every field is `None`, which is what a devnet or a node whose routing is not up
        // yet looks like. No view of the network is no evidence, and the answer has to be
        // "keep everything" rather than "nobody is closer, so give it all away".
        let dir = TempDir::new().expect("temp dir");
        let store = Arc::new(
            crate::storage::ChunkStore::new(crate::storage::ChunkStoreConfig {
                root_dir: dir.path().to_path_buf(),
                ..crate::storage::ChunkStoreConfig::test_default()
            })
            .await
            .expect("open store"),
        );
        let context = MigrationContext {
            p2p: None,
            self_id: None,
            self_xor: None,
            commitment: None,
            replication: None,
            sync_state: None,
            audit_challenge_coordinator: None,
            peer_commitments: None,
            close_group_size: 7,
        };

        let keys = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let unconfirmed = unconfirmed_by_neighbours(&store, &context, &keys).await;
        assert_eq!(
            unconfirmed, keys,
            "with no routing state every key must count as unproven"
        );
        for key in &keys {
            assert!(
                !context.may_shed(key).await,
                "and none of them may be given up"
            );
        }
    }

    #[test]
    fn the_possession_threshold_comes_from_the_whole_group_not_the_qualifying_subset() {
        use crate::replication::pruning::{prune_proofs_needed, target_peers_reported_present};
        use std::collections::{HashMap, HashSet};

        // Seven holders. Deriving the bar from whichever peers happen to qualify is how
        // two last holders destroy a chunk between them: each sees only the other
        // publishing, so each needs exactly one proof, each gets it from the other, and
        // both delete. The bar must come from the group.
        let key = [7u8; 32];
        let group: Vec<PeerId> = (0..6u8).map(peer_id).collect();
        let only_one_qualifies: Vec<PeerId> = group.iter().take(1).copied().collect();

        // That one peer does answer the challenge.
        let mut proofs: HashMap<XorName, HashSet<PeerId>> = HashMap::new();
        proofs.insert(key, only_one_qualifies.iter().copied().collect());

        // The dangerous reading: bar taken from the qualifying subset, so one is enough.
        assert!(
            target_peers_reported_present(
                &key,
                &only_one_qualifies,
                &proofs,
                prune_proofs_needed(only_one_qualifies.len()),
            ),
            "this is the mistake being guarded against, shown here to be a real risk"
        );

        // The correct reading: bar taken from the whole group, so one is nowhere near.
        assert!(
            !target_peers_reported_present(
                &key,
                &only_one_qualifies,
                &proofs,
                prune_proofs_needed(group.len()),
            ),
            "one proof must never satisfy a group of six"
        );

        // And with the whole group answering, it passes.
        proofs.insert(key, group.iter().copied().collect());
        assert!(target_peers_reported_present(
            &key,
            &group,
            &proofs,
            prune_proofs_needed(group.len()),
        ));
    }

    #[test]
    #[serial]
    fn shedding_reads_the_same_switch_the_auditors_read() {
        use crate::replication::config::{
            close_group_storage_penalty_suspended, set_close_group_storage_penalty_suspended,
        };
        // One switch, not two. There used to be a second constant of the same name with
        // its own environment override on this side of the decision, and nothing coupling
        // them: a node could have been willing to shed while every peer still applied the
        // full penalty, which is precisely what the release ordering exists to prevent.
        set_close_group_storage_penalty_suspended(true);
        assert!(close_group_storage_penalty_suspended());
        set_close_group_storage_penalty_suspended(false);
        assert!(!close_group_storage_penalty_suspended());
        set_close_group_storage_penalty_suspended(
            crate::replication::config::RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY,
        );
    }

    #[test]
    fn a_close_group_is_split_into_enough_waves_to_bound_concurrent_migrations() {
        // Seven holders, two at a time, is four waves.
        assert_eq!(migration_wave_count(7), 4);
        assert_eq!(migration_wave_count(2), 1);
        assert_eq!(migration_wave_count(1), 1);
        // A degenerate width must still yield a usable wave count rather than dividing by
        // zero or collapsing to "everyone at once".
        assert_eq!(migration_wave_count(0), 1);
    }

    #[test]
    fn wave_assignment_is_stable_per_node_and_spread_across_the_group() {
        use std::collections::HashMap;
        let waves = migration_wave_count(7);

        // The same node always gets the same wave: a restart must not move a node into a
        // turn that has already passed.
        let peer = peer_id(7);
        assert_eq!(
            migration_wave_for(Some(&peer), 7),
            migration_wave_for(Some(&peer), 7)
        );

        // And across many nodes every wave is used, so the group is genuinely staggered
        // rather than all landing together.
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for b in 0..=255u8 {
            let w = migration_wave_for(Some(&peer_id(b)), 7);
            assert!(w < waves, "wave {w} outside 0..{waves}");
            *counts.entry(w).or_default() += 1;
        }
        assert_eq!(
            counts.len() as u64,
            waves,
            "every wave should be occupied, got {counts:?}"
        );
    }

    #[test]
    fn waves_are_actually_staggered_under_the_shipped_defaults() {
        // The combination is what matters, not either setting alone. Measured from first
        // start, a 72 hour hold and 24 hour waves cancel out: waves would open at 0, 24,
        // 48 and 72 hours while nothing may shed until 72, so every wave is open the
        // moment the first one can act and the whole close group moves together. Measured
        // from the end of the hold, they stagger as intended.
        let config = MigrationConfig::default();
        assert_eq!(config.shed_hold_hours, 72);
        assert_eq!(config.wave_hours, 24);

        let mut state = MigrationState::new(MigrationPhase::Bridging);
        let waves = migration_wave_count(7);
        assert_eq!(waves, 4);

        // Nothing is open before the hold ends.
        state.first_start_unix = now_unix();
        for w in 0..waves {
            assert!(
                !wave_has_opened(&state, &config, w),
                "wave {w} opened too early"
            );
        }

        // At the end of the hold, exactly the first wave is open.
        state.first_start_unix = now_unix().saturating_sub(72 * 3600 + 60);
        assert!(wave_has_opened(&state, &config, 0));
        for w in 1..waves {
            assert!(
                !wave_has_opened(&state, &config, w),
                "wave {w} must wait its turn, or the group migrates together"
            );
        }

        // Each later wave opens one wave_hours after the one before it.
        for open in 1..waves {
            state.first_start_unix = now_unix().saturating_sub((72 + open * 24) * 3600 + 60);
            for w in 0..=open {
                assert!(wave_has_opened(&state, &config, w));
            }
            for w in open + 1..waves {
                assert!(!wave_has_opened(&state, &config, w));
            }
        }
    }

    #[test]
    fn an_implausible_clock_restarts_the_holds_rather_than_voiding_them() {
        let dir = TempDir::new().expect("temp dir");
        let config = MigrationConfig::default();

        // Zero is what a node with an unsynchronised clock writes at first boot, and it
        // would make every hold vacuous. So would a time in the future.
        let mut state = MigrationState::new(MigrationPhase::Committed);
        state.first_start_unix = 0;
        state.committed_at_unix = Some(0);
        state.save(dir.path()).expect("save");

        let loaded = MigrationState::load_or_new(dir.path(), MigrationPhase::Bridging);
        assert!(
            !loaded.shed_hold_elapsed(&config),
            "the hold must not be void"
        );
        assert!(!loaded.retire_delay_elapsed(&config));

        let mut future = MigrationState::new(MigrationPhase::Committed);
        future.first_start_unix = now_unix().saturating_add(10 * 365 * 24 * 3600);
        future.committed_at_unix = Some(future.first_start_unix);
        future.save(dir.path()).expect("save");
        let loaded = MigrationState::load_or_new(dir.path(), MigrationPhase::Bridging);
        assert!(!loaded.shed_hold_elapsed(&config));
        assert!(!loaded.retire_delay_elapsed(&config));
    }

    #[test]
    fn copy_reports_accumulate_across_passes() {
        let mut total = CopyReport::default();
        total.merge(CopyReport {
            copied: 3,
            bytes: 300,
            ..CopyReport::default()
        });
        total.merge(CopyReport {
            copied: 2,
            bytes: 200,
            unusable: 1,
            stopped_for_space: true,
            ..CopyReport::default()
        });
        assert_eq!(total.copied, 5);
        assert_eq!(total.bytes, 500);
        assert_eq!(total.unusable, 1);
        assert!(total.stopped_for_space);
    }
    /// A peer that received the commitment and then left the group is not evidence.
    ///
    /// It is not going to audit this node, so counting it lets a node give chunks up
    /// while the neighbours who will audit it still hold it to the old, larger key set.
    #[test]
    fn a_departed_peer_that_knows_the_commitment_does_not_open_the_gate() {
        let received: HashSet<PeerId> = (0..6).map(peer_id).collect();
        let still_here: Vec<PeerId> = (0..3).map(peer_id).collect();
        let joined_since: Vec<PeerId> = (100..103).map(peer_id).collect();
        let current: Vec<PeerId> = still_here
            .iter()
            .chain(joined_since.iter())
            .copied()
            .collect();

        // Six peers know it and the group is six wide, so a count that ignores who is
        // actually here would sail past the threshold.
        assert_eq!(received.len(), 6);
        assert_eq!(current.len(), 6);
        assert!(!enough_of_the_group_knows(&received, &current, 5));

        // Only the three that are both here and informed count.
        assert!(enough_of_the_group_knows(&received, &current, 3));
        assert!(!enough_of_the_group_knows(&received, &current, 4));
    }

    #[test]
    fn a_group_that_has_all_seen_the_commitment_opens_the_gate() {
        let group: Vec<PeerId> = (0..6).map(peer_id).collect();
        let received: HashSet<PeerId> = group.iter().copied().collect();
        assert!(enough_of_the_group_knows(&received, &group, 5));
    }

    #[test]
    fn no_peer_ever_satisfies_a_zero_threshold() {
        let group: Vec<PeerId> = (0..6).map(peer_id).collect();
        let received: HashSet<PeerId> = group.iter().copied().collect();
        // A group this node cannot reason about must not be read as unanimous consent.
        assert!(!enough_of_the_group_knows(&received, &group, 0));
    }

    /// The gate stays shut when routing cannot show a full close group at all.
    ///
    /// Without a routing view there is no way to tell an informed neighbour from a
    /// departed one, and an unanswerable question must not read as a yes.
    #[tokio::test]
    async fn without_a_routing_view_the_commitment_gate_stays_shut() {
        let context = MigrationContext {
            p2p: None,
            self_id: None,
            self_xor: None,
            commitment: None,
            replication: None,
            sync_state: None,
            audit_challenge_coordinator: None,
            peer_commitments: None,
            close_group_size: 7,
        };
        assert!(!context.neighbours_know_the_commitment().await);
    }
}
