//! A devnet run's own data directory, and the one rule for deleting one: a
//! devnet deletes only a directory it can show it created (ant-node#261).
//!
//! Each run creates a fresh `{pid}-{random}` directory inside the configured
//! parent, exclusively, so it never adopts something that was already there.
//! Before anything else goes in, it takes an exclusive lock on [`LOCK_FILE`],
//! held for as long as the run lasts, and then writes [`MARKER_FILE`] naming
//! the run. The parent itself is never deleted.
//!
//! - On shutdown a run deletes its directory, and only if the marker there
//!   still names that run.
//! - Anything else, a later run included, may delete a run directory only if
//!   it has a marker, the marker does not ask to keep it (`--no-cleanup`), and
//!   its lock is free. The OS releases the lock however the process ends,
//!   SIGKILL included, and only a run's own process ever takes it, so a free
//!   lock means the run is over. A directory without a marker is never
//!   touched.
//!
//! On Unix every step after the parent is opened goes through a handle on the
//! parent, and deletion walks the tree through handles opened without
//! following links. Retargeting a symlink above the run directory mid-run
//! cannot redirect any of it. Windows has no such calls: there, deletion goes
//! through [`std::fs::remove_dir_all`], which does not follow links inside
//! the tree, after the same marker check.

use crate::logging::{debug, info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs::{File, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// File in a run directory naming the run it belongs to (JSON).
pub const MARKER_FILE: &str = ".ant-devnet-run.json";

/// File in a run directory whose exclusive lock the run holds while it lasts.
pub const LOCK_FILE: &str = ".ant-devnet-run.lock";

/// The marker is written here first and renamed into place, so a reader sees
/// either no marker or a whole one.
const MARKER_TEMP_FILE: &str = ".ant-devnet-run.json.tmp";

/// A marker is a few hundred bytes. Anything larger is not one.
const MAX_MARKER_LEN: usize = 4096;

/// Names tried before giving up when a random name is already taken.
const CREATE_ATTEMPTS: usize = 8;

/// What [`MARKER_FILE`] holds.
#[derive(Debug, Serialize, Deserialize)]
struct Marker {
    /// Random and unique to the run.
    run_id: String,
    /// The process that ran the devnet.
    pid: u32,
    /// When the run started, in seconds since the Unix epoch.
    started_at: u64,
    /// The ant-node version that wrote the marker.
    version: String,
    /// Set by `--no-cleanup`: nothing but the user deletes this directory.
    keep: bool,
}

/// This run's directory: created, locked and marked by [`RunDir::create`].
///
/// Dropping it releases the lock and leaves the directory, which a later run
/// then removes unless it is kept.
pub struct RunDir {
    path: PathBuf,
    name: String,
    run_id: String,
    parent: Parent,
    lock: File,
}

impl RunDir {
    /// Create a fresh run directory inside `parent`, creating `parent` first
    /// if it does not exist. Run directories that earlier runs left in
    /// `parent`, and that are over and not kept, are removed first.
    ///
    /// `keep` marks the directory as one that nothing but the user deletes.
    ///
    /// # Errors
    ///
    /// Fails if `parent` cannot be created or opened, or the run directory
    /// cannot be created, locked or marked.
    pub fn create(parent: &Path, keep: bool) -> io::Result<Self> {
        let parent = Parent::open(parent)?;
        sweep(&parent);

        let pid = std::process::id();
        let mut rng = rand::thread_rng();
        let mut attempt = 0;
        let name = loop {
            let name = format!("{pid}-{:08x}", rng.gen::<u32>());
            match parent.create_run(&name) {
                Ok(()) => break name,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    attempt += 1;
                    if attempt == CREATE_ATTEMPTS {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        };

        let run = parent.open_run(&name)?;
        let marker = Marker {
            run_id: hex::encode(rng.gen::<[u8; 16]>()),
            pid,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            keep,
        };
        let lock = match claim(&run, &marker) {
            Ok(lock) => lock,
            Err(e) => {
                // Unmarked, it would be left alone for good. It is ours: we
                // have just created it.
                if let Err(cleanup) = parent.remove_run(&name, run) {
                    warn!("Could not remove half-created devnet run directory {name}: {cleanup}");
                }
                return Err(e);
            }
        };

        Ok(Self {
            path: parent.path.join(&name),
            name,
            run_id: marker.run_id,
            parent,
            lock,
        })
    }

    /// The run directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the run directory, if its marker still names this run.
    ///
    /// # Errors
    ///
    /// Fails, deleting nothing, if the directory is no longer this run's, and
    /// otherwise if the deletion fails.
    pub fn remove(self) -> io::Result<()> {
        let run = self.parent.open_run(&self.name)?;
        let marker = read_marker(&run)?;
        if marker.run_id != self.run_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is no longer this run's directory: its marker names another run",
                    self.path.display()
                ),
            ));
        }
        // Windows refuses to delete a directory with a file open in it.
        drop(self.lock);
        self.parent.remove_run(&self.name, run)
    }
}

/// Lock `run`, then mark it. Marking second is what lets a free lock mean the
/// run is over: a marked run has always taken its lock already.
fn claim(run: &Run, marker: &Marker) -> io::Result<File> {
    let lock = run.create_file(LOCK_FILE)?;
    lock.try_lock().map_err(io::Error::from)?;
    let json = serde_json::to_vec_pretty(marker).map_err(io::Error::other)?;
    let mut temp = run.create_file(MARKER_TEMP_FILE)?;
    temp.write_all(&json)?;
    temp.sync_all()?;
    drop(temp);
    run.rename(MARKER_TEMP_FILE, MARKER_FILE)?;
    Ok(lock)
}

fn read_marker(run: &Run) -> io::Result<Marker> {
    let mut json = Vec::new();
    run.open_file(MARKER_FILE)?
        .take(MAX_MARKER_LEN as u64 + 1)
        .read_to_end(&mut json)?;
    if json.len() > MAX_MARKER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the marker is too large to be one",
        ));
    }
    serde_json::from_slice(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Whether `name` has the shape of a run directory's: `{pid}-{8 hex digits}`.
fn is_run_name(name: &str) -> bool {
    name.split_once('-').is_some_and(|(pid, random)| {
        !pid.is_empty()
            && pid.bytes().all(|b| b.is_ascii_digit())
            && random.len() == 8
            && random
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Remove the run directories in `parent` that are over and not kept. Never
/// fails: whatever it cannot read or remove, it leaves.
fn sweep(parent: &Parent) {
    let names = match parent.names() {
        Ok(names) => names,
        Err(e) => {
            warn!(
                "Could not list {} for finished devnet runs: {e}",
                parent.path.display()
            );
            return;
        }
    };
    let mut removed = 0_usize;
    for name in names.iter().filter(|name| is_run_name(name)) {
        match finished_run(parent, name) {
            Ok(Some(run)) => match parent.remove_run(name, run) {
                Ok(()) => removed += 1,
                Err(e) => warn!(
                    "Could not remove the finished devnet run directory {}: {e}",
                    parent.path.join(name).display()
                ),
            },
            Ok(None) => {}
            Err(e) => debug!("Leaving {}: {e}", parent.path.join(name).display()),
        }
    }
    if removed > 0 {
        info!(
            "Removed {removed} directories left by earlier devnet runs from {}",
            parent.path.display()
        );
    }
}

/// `Some` if `name` is a run that is over and not kept, so may be deleted.
fn finished_run(parent: &Parent, name: &str) -> io::Result<Option<Run>> {
    let run = parent.open_run(name)?;
    let marker = read_marker(&run)?;
    let pid_in_name = name.split_once('-').map(|(pid, _)| pid);
    if marker.keep || pid_in_name != Some(marker.pid.to_string().as_str()) {
        return Ok(None);
    }
    let lock = run.open_file(LOCK_FILE)?;
    match lock.try_lock() {
        // Released again when `lock` drops, before the caller deletes. No run
        // takes this lock again: a run only ever locks a directory it has
        // just created.
        Ok(()) => Ok(Some(run)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(unix)]
use unix::{Parent, Run};

#[cfg(not(unix))]
use path_based::{Parent, Run};

/// Every operation relative to a directory handle, never following a link.
#[cfg(unix)]
mod unix {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};

    const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    /// The directory run directories are created in, opened once.
    pub struct Parent {
        pub path: PathBuf,
        fd: OwnedFd,
    }

    /// A run directory, opened without following a link.
    pub struct Run {
        fd: OwnedFd,
    }

    impl Parent {
        pub fn open(path: &Path) -> io::Result<Self> {
            std::fs::create_dir_all(path)?;
            let fd = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(Self {
                path: path.to_path_buf(),
                fd,
            })
        }

        pub fn create_run(&self, name: &str) -> io::Result<()> {
            Ok(rustix::fs::mkdirat(
                &self.fd,
                name,
                Mode::from_raw_mode(0o755),
            )?)
        }

        pub fn open_run(&self, name: &str) -> io::Result<Run> {
            let fd = rustix::fs::openat(&self.fd, name, DIR_FLAGS, Mode::empty())?;
            Ok(Run { fd })
        }

        pub fn names(&self) -> io::Result<Vec<String>> {
            Ok(read_names(&self.fd)?
                .into_iter()
                .filter_map(|name| name.into_string().ok())
                .collect())
        }

        /// Empty `run` through its handle, then remove the now-empty entry
        /// `name`. Should `name` have been swapped for another directory in
        /// between, `rmdir` removes that only if it is empty.
        pub fn remove_run(&self, name: &str, run: Run) -> io::Result<()> {
            remove_contents(&run.fd)?;
            drop(run);
            gone_is_fine(rustix::fs::unlinkat(&self.fd, name, AtFlags::REMOVEDIR))
        }
    }

    impl Run {
        pub fn create_file(&self, name: &str) -> io::Result<File> {
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            )?;
            Ok(File::from(fd))
        }

        /// Open an existing regular file for reading and locking. `NONBLOCK`
        /// so that a FIFO wearing the name cannot stall the open.
        pub fn open_file(&self, name: &str) -> io::Result<File> {
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            if FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{name} is not a regular file"),
                ));
            }
            Ok(File::from(fd))
        }

        pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            Ok(rustix::fs::renameat(&self.fd, from, &self.fd, to)?)
        }
    }

    /// Delete everything in `dir`, descending only through handles opened
    /// without following a link: a link is removed, never entered.
    fn remove_contents(dir: &OwnedFd) -> io::Result<()> {
        for name in read_names(dir)? {
            let stat = match rustix::fs::statat(dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(Errno::NOENT) => continue,
                Err(e) => return Err(e.into()),
            };
            if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
                let child = match rustix::fs::openat(dir, name.as_c_str(), DIR_FLAGS, Mode::empty())
                {
                    Ok(child) => child,
                    Err(Errno::NOENT) => continue,
                    Err(e) => return Err(e.into()),
                };
                remove_contents(&child)?;
                gone_is_fine(rustix::fs::unlinkat(
                    dir,
                    name.as_c_str(),
                    AtFlags::REMOVEDIR,
                ))?;
            } else {
                gone_is_fine(rustix::fs::unlinkat(dir, name.as_c_str(), AtFlags::empty()))?;
            }
        }
        Ok(())
    }

    /// Every name in `dir` but `.` and `..`. Collected before anything is
    /// deleted: unlinking while a directory stream is open is not something
    /// every filesystem keeps coherent.
    fn read_names(dir: &OwnedFd) -> io::Result<Vec<CString>> {
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(dir)? {
            let name = entry?.file_name().to_owned();
            if name.as_bytes() != b"." && name.as_bytes() != b".." {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Something else, another run's sweep for one, may delete first.
    fn gone_is_fine(result: rustix::io::Result<()>) -> io::Result<()> {
        match result {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Without `openat`: the same checks, by path.
#[cfg(not(unix))]
mod path_based {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};

    /// The directory run directories are created in.
    pub struct Parent {
        pub path: PathBuf,
    }

    /// A run directory, checked to be a directory and not a link.
    pub struct Run {
        path: PathBuf,
    }

    impl Parent {
        pub fn open(path: &Path) -> io::Result<Self> {
            std::fs::create_dir_all(path)?;
            Ok(Self {
                path: path.to_path_buf(),
            })
        }

        pub fn create_run(&self, name: &str) -> io::Result<()> {
            std::fs::create_dir(self.path.join(name))
        }

        pub fn open_run(&self, name: &str) -> io::Result<Run> {
            let path = self.path.join(name);
            // `symlink_metadata` reports a symlink or junction as a link, not
            // as the directory it points at.
            if !std::fs::symlink_metadata(&path)?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is not a directory", path.display()),
                ));
            }
            Ok(Run { path })
        }

        pub fn names(&self) -> io::Result<Vec<String>> {
            let mut names = Vec::new();
            for entry in std::fs::read_dir(&self.path)? {
                if let Ok(name) = entry?.file_name().into_string() {
                    names.push(name);
                }
            }
            Ok(names)
        }

        /// `run` is the check that `name` is a directory and not a link.
        pub fn remove_run(&self, name: &str, run: Run) -> io::Result<()> {
            drop(run);
            match std::fs::remove_dir_all(self.path.join(name)) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                result => result,
            }
        }
    }

    impl Run {
        pub fn create_file(&self, name: &str) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(self.path.join(name))
        }

        pub fn open_file(&self, name: &str) -> io::Result<File> {
            let path = self.path.join(name);
            if !std::fs::symlink_metadata(&path)?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is not a regular file", path.display()),
                ));
            }
            OpenOptions::new().read(true).write(true).open(path)
        }

        pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            std::fs::rename(self.path.join(from), self.path.join(to))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn marker_in(dir: &Path) -> std::result::Result<Marker, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(&std::fs::read(
            dir.join(MARKER_FILE),
        )?)?)
    }

    /// Whether another handle can take `dir`'s lock: false while its run lasts.
    fn lock_is_free(dir: &Path) -> std::result::Result<bool, Box<dyn std::error::Error>> {
        let lock = File::options()
            .read(true)
            .write(true)
            .open(dir.join(LOCK_FILE))?;
        match lock.try_lock() {
            Ok(()) => Ok(true),
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(e)) => Err(e.into()),
        }
    }

    /// A finished run's directory, as a run killed by `SIGKILL` leaves it.
    fn finished(
        parent: &Path,
        keep: bool,
    ) -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
        let run = RunDir::create(parent, keep)?;
        let path = run.path().to_path_buf();
        std::fs::create_dir_all(path.join("nodes").join("peer"))?;
        std::fs::write(path.join("nodes").join("peer").join("chunk"), b"data")?;
        drop(run);
        Ok(path)
    }

    #[test]
    fn create_makes_a_locked_marked_directory_inside_the_parent() -> TestResult {
        let temp = tempfile::tempdir()?;
        let parent = temp.path().join("not").join("there").join("yet");

        let run = RunDir::create(&parent, false)?;

        assert_eq!(run.path().parent(), Some(parent.as_path()));
        let name = run
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("no name")?;
        assert!(is_run_name(name), "{name}");
        let marker = marker_in(run.path())?;
        assert_eq!(marker.pid, std::process::id());
        assert_eq!(marker.run_id, run.run_id);
        assert!(!marker.keep);
        assert!(!run.path().join(MARKER_TEMP_FILE).exists());
        assert!(
            !lock_is_free(run.path())?,
            "the lock is free while the run lasts"
        );
        Ok(())
    }

    #[test]
    fn remove_deletes_the_run_directory_and_nothing_beside_it() -> TestResult {
        let temp = tempfile::tempdir()?;
        let parent = temp.path().join("devnets");
        std::fs::create_dir_all(parent.join("mine"))?;
        std::fs::write(parent.join("mine").join("sentinel"), b"keep")?;
        std::fs::write(temp.path().join("sentinel"), b"keep")?;

        let run = RunDir::create(&parent, false)?;
        let path = run.path().to_path_buf();
        std::fs::create_dir_all(path.join("nodes").join("peer").join("deeper"))?;
        std::fs::write(
            path.join("nodes").join("peer").join("deeper").join("f"),
            b"x",
        )?;
        run.remove()?;

        assert!(!path.exists());
        assert!(parent.is_dir(), "the parent is not the run's to delete");
        assert!(parent.join("mine").join("sentinel").is_file());
        assert!(temp.path().join("sentinel").is_file());
        Ok(())
    }

    #[test]
    fn remove_refuses_a_directory_another_run_has_marked() -> TestResult {
        let temp = tempfile::tempdir()?;
        let run = RunDir::create(temp.path(), false)?;
        let path = run.path().to_path_buf();
        let mut marker = marker_in(&path)?;
        marker.run_id = "someone-else".to_string();
        std::fs::write(path.join(MARKER_FILE), serde_json::to_vec(&marker)?)?;

        assert!(run.remove().is_err());
        assert!(path.join(MARKER_FILE).is_file());
        Ok(())
    }

    #[test]
    fn the_next_run_sweeps_a_finished_run() -> TestResult {
        let temp = tempfile::tempdir()?;
        let old = finished(temp.path(), false)?;
        assert!(old.is_dir());

        let run = RunDir::create(temp.path(), false)?;

        assert!(!old.exists(), "{} was not swept", old.display());
        assert!(run.path().is_dir());
        Ok(())
    }

    #[test]
    fn a_live_run_is_never_swept() -> TestResult {
        let temp = tempfile::tempdir()?;
        let first = RunDir::create(temp.path(), false)?;
        let second = RunDir::create(temp.path(), false)?;

        assert!(first.path().join(MARKER_FILE).is_file());
        assert!(second.path().join(MARKER_FILE).is_file());
        assert_ne!(first.path(), second.path());
        Ok(())
    }

    #[test]
    fn a_kept_run_is_never_swept() -> TestResult {
        let temp = tempfile::tempdir()?;
        let kept = finished(temp.path(), true)?;
        assert!(marker_in(&kept)?.keep);

        let _run = RunDir::create(temp.path(), false)?;

        assert!(kept.join("nodes").join("peer").join("chunk").is_file());
        Ok(())
    }

    #[test]
    fn directories_without_a_matching_marker_are_never_swept() -> TestResult {
        let temp = tempfile::tempdir()?;
        let parent = temp.path();
        // A finished run's marker and lock, copied into places a sweep must leave.
        let donor = finished(&temp.path().join("donor"), false)?;
        let copy_run = |name: &str| -> std::io::Result<PathBuf> {
            let dir = parent.join(name);
            std::fs::create_dir_all(&dir)?;
            std::fs::copy(donor.join(MARKER_FILE), dir.join(MARKER_FILE))?;
            std::fs::copy(donor.join(LOCK_FILE), dir.join(LOCK_FILE))?;
            std::fs::write(dir.join("sentinel"), b"keep")?;
            Ok(dir)
        };
        let pid = std::process::id();
        let survivors = [
            // The right shape but no marker.
            {
                let dir = parent.join("1-deadbeef");
                std::fs::create_dir_all(&dir)?;
                std::fs::write(dir.join("sentinel"), b"keep")?;
                dir
            },
            // A marker, but not a run directory's name.
            copy_run("other")?,
            copy_run(&format!("{pid}-DEADBEEF"))?,
            copy_run(&format!("{pid}-deadbeef0"))?,
            // A marker naming another process.
            copy_run(&format!("{}-deadbeef", pid.wrapping_add(1)))?,
            // A marker that is not one.
            {
                let dir = copy_run(&format!("{pid}-0badf00d"))?;
                std::fs::write(dir.join(MARKER_FILE), b"{ not json")?;
                dir
            },
            {
                let dir = copy_run(&format!("{pid}-0ddba11a"))?;
                let mut big = std::fs::read(dir.join(MARKER_FILE))?;
                big.resize(MAX_MARKER_LEN + 1, b' ');
                std::fs::write(dir.join(MARKER_FILE), big)?;
                dir
            },
            // A marker but no lock: a run that never got as far as locking.
            {
                let dir = copy_run(&format!("{pid}-ca11ab1e"))?;
                std::fs::remove_file(dir.join(LOCK_FILE))?;
                dir
            },
        ];

        let _run = RunDir::create(parent, false)?;

        for dir in &survivors {
            assert!(
                dir.join("sentinel").is_file(),
                "{} was swept",
                dir.display()
            );
        }
        Ok(())
    }

    #[test]
    fn run_names() {
        assert!(is_run_name("1-deadbeef"));
        assert!(is_run_name("123456-0000000a"));
        for name in [
            "",
            "-deadbeef",
            "1-",
            "1-deadbee",
            "1-deadbeef0",
            "1-DEADBEEF",
            "a-deadbeef",
            "1_deadbeef",
            "1-deadbeeg",
            "1-dead-bee",
        ] {
            assert!(!is_run_name(name), "{name}");
        }
    }

    /// Hermes round 2 on #263: a parent reached through a dangling symlink
    /// fails to start and deletes nothing.
    #[cfg(unix)]
    #[test]
    fn a_parent_behind_a_dangling_symlink_fails_closed() -> TestResult {
        let temp = tempfile::tempdir()?;
        let victim = temp.path().join("victim");
        std::fs::create_dir_all(&victim)?;
        std::fs::write(victim.join("sentinel"), b"keep")?;
        std::os::unix::fs::symlink(victim.join("not-yet"), temp.path().join("alias"))?;

        assert!(RunDir::create(&temp.path().join("alias").join("devnets"), false).is_err());

        assert!(victim.join("sentinel").is_file());
        assert!(!victim.join("not-yet").exists());
        Ok(())
    }

    /// A link wearing a finished run's name is removed, never followed.
    #[cfg(unix)]
    #[test]
    fn a_link_named_like_a_run_is_never_followed() -> TestResult {
        let temp = tempfile::tempdir()?;
        let parent = temp.path().join("devnets");
        let outside = finished(&temp.path().join("outside"), false)?;
        std::fs::write(outside.join("sentinel"), b"keep")?;
        std::fs::create_dir_all(&parent)?;
        let link = parent.join(outside.file_name().ok_or("no name")?);
        std::os::unix::fs::symlink(&outside, &link)?;

        let _run = RunDir::create(&parent, false)?;

        assert!(outside.join("sentinel").is_file());
        assert!(std::fs::symlink_metadata(&link)?.file_type().is_symlink());
        Ok(())
    }

    /// Hermes round 2 on #263: retargeting a symlink above the run directory
    /// while the run lasts does not redirect its removal, even onto a copy of
    /// the run directory carrying the run's own marker.
    #[cfg(unix)]
    #[test]
    fn retargeting_a_symlink_above_the_run_does_not_redirect_removal() -> TestResult {
        let temp = tempfile::tempdir()?;
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        std::fs::create_dir_all(&first)?;
        std::fs::create_dir_all(&second)?;
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&first, &link)?;

        let run = RunDir::create(&link.join("devnets"), false)?;
        let name = run.path().file_name().ok_or("no name")?.to_owned();
        let decoy = second.join("devnets").join(&name);
        std::fs::create_dir_all(&decoy)?;
        std::fs::copy(run.path().join(MARKER_FILE), decoy.join(MARKER_FILE))?;
        std::fs::write(decoy.join("sentinel"), b"keep")?;
        std::fs::remove_file(&link)?;
        std::os::unix::fs::symlink(&second, &link)?;

        run.remove()?;

        assert!(!first.join("devnets").join(&name).exists());
        assert!(
            decoy.join("sentinel").is_file(),
            "the removal followed the retargeted link"
        );
        Ok(())
    }
}
