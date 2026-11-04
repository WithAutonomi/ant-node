//! A devnet run's own data directory, and the one rule for deleting one: a
//! devnet deletes only a directory it can show it created (ant-node#261).
//!
//! Each run creates a fresh `{pid}-{random}` directory inside the configured
//! parent, exclusively, and claims it only if, once opened, it is still empty
//! and, on Unix, owned by the run's user, so it never adopts something that
//! was already there or that another user put in its place. (A process of
//! the run's own user could put an empty directory there, but it could as
//! well delete whatever the run keeps: no check could hold that line. On
//! Windows, which has no owner check without unsafe code, the parent's
//! permissions decide who could.) Before anything else goes in, it takes an exclusive lock on
//! [`LOCK_FILE`], held for as long as the run lasts, and then writes
//! [`MARKER_FILE`] naming the run, the directory itself and the lock file,
//! by their file numbers (inode, or file index on Windows): a copy of the
//! marker in any other directory does not match, nor does a lock file put
//! in place of the one the run holds. The parent itself is never deleted.
//!
//! - On shutdown a run deletes its directory through the handle it opened
//!   when it created it, and only if the name still refers to that directory
//!   and the marker there still names the run.
//! - Anything else, a later run included, may delete a run directory only if
//!   it belongs to the user (on Unix), is on the parent's filesystem and
//!   mount, its marker names that very directory and does not ask to keep it
//!   (`--no-cleanup`), and the lock file the
//!   marker names is there and free. The OS releases the lock however the
//!   process ends, SIGKILL included, and only a run's own process ever takes
//!   it, so a free lock means the run is over. A directory without such a
//!   marker is never touched. (The marker keeps no device number: on some
//!   filesystems, btrfs and NFS among them, that changes when they are
//!   mounted again.)
//! - Deletion first checks that the name still refers to the directory it
//!   has open, then removes the data, and the marker and lock last, so one
//!   that stops part-way leaves a directory the next run still recognises as
//!   a finished run, and finishes. It does not cross into another mount: on
//!   Linux mounts are told apart by their mount ids, which tell a bind mount
//!   from the filesystem it shows, and where the kernel cannot give one (it
//!   is older than 5.8, or a sandbox refuses `statx`) nothing is deleted.
//!   macOS has no bind mounts, so there the device tells them apart.
//!
//! On Unix every step after the parent is opened goes through a handle on the
//! parent or the run directory, and deletion walks the tree through handles
//! opened without following links. The handles do not keep the paths still,
//! though. Whoever can write to a directory can rename what is in it: swap a
//! directory above the run directory for a link to another tree, which
//! writes through [`RunDir::path`] would then follow, or move the run
//! directory away while it is being deleted. So the parent must be one no
//! other user can change: it, and every directory above it, must belong to
//! the user or root, and be one no one else can write to, or sticky, as
//! `/tmp` is, which lets no one rename what they do not own. (On Linux, one
//! its group can write to passes if the group is the user's own, as with
//! Ubuntu's user private groups, and no ACL lets anyone else in. On macOS,
//! where every user shares a group, it does not.) A run refuses to start in
//! any other parent. Windows has no such calls in the standard library.
//! There, links in the parent's path are resolved once, and the
//! parent and the run directory are held open without delete sharing: while
//! they are, neither they nor any directory above them can be renamed or
//! removed, so the paths built on them keep naming the same directories, and
//! [`std::fs::remove_dir_all`] does not follow links inside the tree. Either
//! way, retargeting a link above the run directory mid-run redirects nothing:
//! not the deletion, and not what is written through [`RunDir::path`], which
//! has the links in the parent's path resolved.

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
    /// The run directory's file number on its filesystem ([`FileId::file`]).
    file_id: u64,
    /// The lock file's, so that one put in its place does not pass for it.
    lock_id: u64,
    /// The process that ran the devnet.
    pid: u32,
    /// When the run started, in seconds since the Unix epoch.
    started_at: u64,
    /// The ant-node version that wrote the marker.
    version: String,
    /// Set by `--no-cleanup`: nothing but the user deletes this directory.
    keep: bool,
}

/// Which directory or file a handle or a name refers to.
#[derive(Debug, PartialEq, Eq)]
struct FileId {
    /// Its device (Unix) or volume serial number (Windows). Compared only
    /// between handles open at the same time, never kept.
    device: String,
    /// Its inode (Unix) or file index (Windows).
    file: u64,
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
    /// The directory as created, held open until it is deleted.
    run: Run,
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
    /// Fails if `parent` cannot be created or opened, or, on Unix, another
    /// user could change it or a directory above it (see the module docs); or
    /// if the run directory cannot be created, locked or marked.
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

        #[cfg(test)]
        after_create(&parent.path.join(&name))?;
        let run = parent.open_run(&name)?;
        // Between its creation and its opening, something else could have put
        // a directory of its own in place of this one. If what was opened has
        // anything in it, or another user owns it, it is not this run's:
        // leave it as it is.
        #[cfg(unix)]
        let replaced = !run.is_empty()? || !run.is_owned_by_this_user()?;
        #[cfg(windows)]
        let replaced = !run.is_empty()?;
        if replaced {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} was replaced before this run could open it",
                    parent.path.join(&name).display()
                ),
            ));
        }
        let claimed = run.id().and_then(|id| {
            let mut marker = Marker {
                run_id: hex::encode(rng.gen::<[u8; 16]>()),
                file_id: id.file,
                // Set by `claim`, once the lock file exists.
                lock_id: 0,
                pid,
                started_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |since| since.as_secs()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                keep,
            };
            let lock = claim(&run, &mut marker)?;
            Ok((marker.run_id, lock))
        });
        let (run_id, lock) = match claimed {
            Ok(claimed) => claimed,
            Err(e) => {
                // Unmarked, it would be left alone for good, so remove it, but
                // only if it is empty: claiming has removed what it created,
                // and anything else in it is not known to be this run's.
                if let Err(cleanup) =
                    same_dir(&parent, &name, &run).and_then(|()| parent.remove_empty(&name, run))
                {
                    warn!("Could not remove half-created devnet run directory {name}: {cleanup}");
                }
                return Err(e);
            }
        };

        Ok(Self {
            path: parent.path.join(&name),
            name,
            run_id,
            parent,
            run,
            lock,
        })
    }

    /// The run directory, with any link in the parent's path resolved, so
    /// that retargeting one does not redirect what is written through it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the run directory, if its name still refers to the directory
    /// this run created and the marker there still names this run.
    ///
    /// # Errors
    ///
    /// Fails, deleting nothing, if the directory is no longer this run's:
    /// moved, replaced, or marked by another run. Otherwise fails if the
    /// deletion does, leaving the marker and lock for the next run's sweep.
    pub fn remove(self) -> io::Result<()> {
        let Self {
            path,
            name,
            run_id,
            parent,
            run,
            lock,
        } = self;
        let marker = read_marker(&run)?;
        if marker.run_id != run_id || marker.file_id != run.id()?.file {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is no longer this run's directory: its marker names another run",
                    path.display()
                ),
            ));
        }
        delete(&parent, &name, run, lock)
    }

    /// Leave the directory, and keep it locked until the process exits, when
    /// the OS releases the lock. For a run that may still have nodes writing
    /// into it: no sweep deletes it while it is locked.
    pub fn keep_locked_until_exit(self) {
        let Self { lock, .. } = self;
        std::mem::forget(lock);
    }
}

/// Lock `run`, then mark it, recording the lock file in `marker`. Marking
/// second is what lets a free lock mean the run is over: a marked run has
/// always taken its lock already. Should it fail, it removes what it created,
/// and nothing else.
fn claim(run: &Run, marker: &mut Marker) -> io::Result<File> {
    let lock = run.create_file(LOCK_FILE)?;
    let outcome = lock.try_lock().map_err(io::Error::from).and_then(|()| {
        marker.lock_id = file_id(&lock)?.file;
        write_marker(run, marker)
    });
    match outcome {
        Ok(()) => Ok(lock),
        Err(e) => {
            drop(lock);
            if let Err(cleanup) = run.remove_file(LOCK_FILE) {
                warn!("Could not remove the lock file of a devnet run that failed to start: {cleanup}");
            }
            Err(e)
        }
    }
}

/// Write `marker` under a temporary name, then rename it into place.
fn write_marker(run: &Run, marker: &Marker) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(marker).map_err(io::Error::other)?;
    let mut temp = run.create_file(MARKER_TEMP_FILE)?;
    let written = temp.write_all(&json).and_then(|()| temp.sync_all());
    drop(temp);
    let renamed = written.and_then(|()| run.rename(MARKER_TEMP_FILE, MARKER_FILE));
    if renamed.is_err() {
        if let Err(cleanup) = run.remove_file(MARKER_TEMP_FILE) {
            warn!("Could not remove the marker of a devnet run that failed to start: {cleanup}");
        }
    }
    renamed
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

/// Fail unless `name` in `parent` is still the directory `run` has open.
fn same_dir(parent: &Parent, name: &str, run: &Run) -> io::Result<()> {
    if parent.id_of(name)? == run.id()? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "it has been moved or replaced since it was opened",
        ))
    }
}

/// Delete the run directory `name`, which `run` has open and whose `lock` is
/// held, if `name` still refers to it: the data first, then the marker, then
/// the lock, then the directory, empty by then. Should it stop before the
/// marker goes, the marker and the free lock make the rest a finished run
/// that the next sweep removes. After that, only an empty directory and an
/// empty lock file can be left.
fn delete(parent: &Parent, name: &str, run: Run, lock: File) -> io::Result<()> {
    // Moved since it was opened, it would be emptied through `run` wherever
    // it went. Once this has passed, only the user or root can still move it:
    // no one else can change the parent (see the module docs), and on Windows
    // the handle keeps it where it is.
    same_dir(parent, name, &run)?;
    run.remove_all_but(&[MARKER_FILE, LOCK_FILE])?;
    run.remove_file(MARKER_FILE)?;
    // Windows removes no directory with a file open in it.
    drop(lock);
    run.remove_file(LOCK_FILE)?;
    // Only an empty directory is removed, so should `name` be swapped between
    // this check and the removal, nothing with data in it goes.
    same_dir(parent, name, &run)?;
    parent.remove_empty(name, run)
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
            Ok(Some((run, lock))) => {
                #[cfg(test)]
                after_found(&parent.path.join(name));
                match delete(parent, name, run, lock) {
                    Ok(()) => removed += 1,
                    Err(e) => warn!(
                        "Could not remove the finished devnet run directory {}: {e}",
                        parent.path.join(name).display()
                    ),
                }
            }
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

/// `Some`, with its lock taken, if `name` is a run that is over and not kept,
/// so may be deleted.
fn finished_run(parent: &Parent, name: &str) -> io::Result<Option<(Run, File)>> {
    let run = parent.open_run(name)?;
    // Another user's is theirs, whatever is in it, and in a parent anyone can
    // make directories in, a sticky one, they could still move it.
    #[cfg(unix)]
    if !run.is_owned_by_this_user()? {
        return Ok(None);
    }
    let marker = read_marker(&run)?;
    let pid_in_name = name.split_once('-').map(|(pid, _)| pid);
    let id = run.id()?;
    if marker.keep
        || pid_in_name != Some(marker.pid.to_string().as_str())
        || marker.file_id != id.file
        || id.device != parent.id()?.device
    {
        return Ok(None);
    }
    // Not a mount wearing a run's name, a bind mount of a finished run's
    // directory kept elsewhere for one: deleting through it would empty what
    // it shows. (On Windows a mounted folder is a link, which `open_run`
    // refuses.)
    #[cfg(unix)]
    if run.mount()? != parent.mount()? {
        return Ok(None);
    }
    let lock = run.open_file(LOCK_FILE)?;
    // The run's lock stays held under whatever name its file is moved to, so
    // a free lock means something only if it is that file.
    let lock_id = file_id(&lock)?;
    let the_runs_lock = lock_id.file == marker.lock_id;
    if !the_runs_lock || lock_id.device != id.device {
        return Ok(None);
    }
    match lock.try_lock() {
        // Held while the directory is deleted. No run takes this lock again:
        // a run only ever locks a directory it has just created.
        Ok(()) => Ok(Some((run, lock))),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(test)]
thread_local! {
    /// Tests set this to make a deletion fail after removing this many
    /// entries, as one interrupted part-way would.
    static FAIL_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// Tests set this to act on a new run directory, by its path, between
    /// its creation and its opening, as something else could.
    static AFTER_CREATE: std::cell::RefCell<Option<AfterCreate>> =
        const { std::cell::RefCell::new(None) };
    /// Tests set this to act on a finished run's directory, by its path,
    /// once the sweep has found it finished and before it deletes it.
    static AFTER_FOUND: std::cell::RefCell<Option<AfterFound>> =
        const { std::cell::RefCell::new(None) };
    /// Tests set this to have a directory of this name inside a run
    /// directory count as a mount point.
    #[cfg(unix)]
    static MOUNT_POINT: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type AfterCreate = Box<dyn FnOnce(&Path) -> io::Result<()>>;

#[cfg(test)]
type AfterFound = Box<dyn FnOnce(&Path)>;

#[cfg(test)]
fn after_create(path: &Path) -> io::Result<()> {
    AFTER_CREATE
        .with(|act| act.borrow_mut().take())
        .map_or(Ok(()), |act| act(path))
}

#[cfg(test)]
fn after_found(path: &Path) {
    if let Some(act) = AFTER_FOUND.with(|act| act.borrow_mut().take()) {
        act(path);
    }
}

#[cfg(all(test, unix))]
fn is_test_mount_point(name: &std::ffi::CStr) -> bool {
    MOUNT_POINT.with(|mount| mount.borrow().as_deref().map(str::as_bytes) == Some(name.to_bytes()))
}

/// Called before each entry a deletion removes, to fail where a test asks.
#[cfg(test)]
fn injected_failure() -> io::Result<()> {
    FAIL_AFTER.with(|left| match left.get() {
        Some(0) => Err(io::Error::other("injected failure")),
        Some(n) => {
            left.set(Some(n - 1));
            Ok(())
        }
        None => Ok(()),
    })
}

#[cfg(unix)]
use unix::{file_id, Parent, Run};

#[cfg(windows)]
use windows::{file_id, Parent, Run};

/// Every operation relative to a directory handle, never following a link.
#[cfg(unix)]
mod unix {
    use super::FileId;
    use rustix::fs::{AtFlags, Dev, FileType, Mode, OFlags, Stat};
    use rustix::io::Errno;
    use std::ffi::{CStr, CString};
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
        /// The path it was opened by, with every link in it resolved.
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
            let real = std::fs::canonicalize(path)?;
            no_one_else_can_change(&real)?;
            let fd = rustix::fs::open(
                &real,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            // The run directory's path is built on `real`, so it must still
            // be free of links, and name the directory just opened.
            if std::fs::canonicalize(&real)? != real
                || id(&rustix::fs::stat(&real)?) != id(&rustix::fs::fstat(&fd)?)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} changed while it was being opened", path.display()),
                ));
            }
            Ok(Self { path: real, fd })
        }

        pub fn mount(&self) -> io::Result<Mount> {
            mount_of(&self.fd)
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

        pub fn id(&self) -> io::Result<FileId> {
            Ok(id(&rustix::fs::fstat(&self.fd)?))
        }

        /// The directory `name`, not following a link.
        pub fn id_of(&self, name: &str) -> io::Result<FileId> {
            let stat = rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{name} is not a directory"),
                ));
            }
            Ok(id(&stat))
        }

        /// Close `run`, then remove the entry `name` if it is an empty
        /// directory.
        pub fn remove_empty(&self, name: &str, run: Run) -> io::Result<()> {
            drop(run);
            gone_is_fine(rustix::fs::unlinkat(&self.fd, name, AtFlags::REMOVEDIR))
        }
    }

    impl Run {
        pub fn id(&self) -> io::Result<FileId> {
            Ok(id(&rustix::fs::fstat(&self.fd)?))
        }

        pub fn is_empty(&self) -> io::Result<bool> {
            Ok(read_names(&self.fd)?.is_empty())
        }

        pub fn is_owned_by_this_user(&self) -> io::Result<bool> {
            Ok(rustix::fs::fstat(&self.fd)?.st_uid == rustix::process::geteuid().as_raw())
        }

        pub fn mount(&self) -> io::Result<Mount> {
            mount_of(&self.fd)
        }

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

        pub fn remove_file(&self, name: &str) -> io::Result<()> {
            gone_is_fine(rustix::fs::unlinkat(&self.fd, name, AtFlags::empty()))
        }

        /// Delete everything in the directory but the entries named in `keep`.
        pub fn remove_all_but(&self, keep: &[&str]) -> io::Result<()> {
            let mount = mount_of(&self.fd)?;
            for name in read_names(&self.fd)? {
                if keep.iter().any(|keep| keep.as_bytes() == name.as_bytes()) {
                    continue;
                }
                #[cfg(test)]
                super::injected_failure()?;
                remove_entry(&self.fd, &name, &mount)?;
            }
            Ok(())
        }
    }

    pub fn file_id(file: &File) -> io::Result<FileId> {
        Ok(id(&rustix::fs::fstat(file)?))
    }

    fn id(stat: &Stat) -> FileId {
        FileId {
            device: stat.st_dev.to_string(),
            file: stat.st_ino,
        }
    }

    /// Fail unless only the user and root can change `real`: neither it nor
    /// any directory above it may belong to another user, or be one another
    /// user can write to, unless it is sticky, which lets no one rename what
    /// they do not own. Whoever could write to one could move what is in it,
    /// a run directory or a directory above one.
    fn no_one_else_can_change(real: &Path) -> io::Result<()> {
        let uid = rustix::process::geteuid().as_raw();
        for dir in real.ancestors() {
            let stat = rustix::fs::lstat(dir)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} changed while it was being opened", real.display()),
                ));
            }
            let mode = Mode::from_raw_mode(stat.st_mode);
            let who = if stat.st_uid != 0 && stat.st_uid != uid {
                Some(format!("belongs to user {}", stat.st_uid))
            } else if mode.contains(Mode::SVTX) {
                None
            } else if mode.contains(Mode::WOTH) {
                Some("can be written to by every user".to_string())
            } else if mode.contains(Mode::WGRP) {
                group_writers(dir, &stat)?
            } else {
                None
            };
            if let Some(who) = who {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} {who}, so another user could move or redirect a devnet's \
                         data under it: use a data directory that only you and root \
                         can change, with only such directories above it",
                        dir.display()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Who but the user can write to `dir`, which its group can write to.
    fn group_writers(dir: &Path, stat: &Stat) -> io::Result<Option<String>> {
        // On Linux, the user's own group, which with user private groups,
        // Ubuntu's default, is the user alone. macOS has none: every user's
        // group there is `staff`.
        #[cfg(target_os = "linux")]
        if stat.st_gid == rustix::process::getegid().as_raw() {
            // An ACL shows in the group bits only as its mask, the most it
            // grants anyone it names.
            return match rustix::fs::lgetxattr(dir, "system.posix_acl_access", &mut [0_u8; 0]) {
                Ok(_) => Ok(Some(
                    "has an ACL, which can let other users write to it".to_string(),
                )),
                Err(Errno::NODATA | Errno::OPNOTSUPP) => Ok(None),
                Err(e) => Err(e.into()),
            };
        }
        #[cfg(not(target_os = "linux"))]
        let _ = dir;
        Ok(Some(format!("can be written to by group {}", stat.st_gid)))
    }

    /// Where a directory is mounted: its device and, on Linux, the mount
    /// itself, which also tells a bind mount from the filesystem it shows.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Mount {
        device: Dev,
        #[cfg(target_os = "linux")]
        id: u64,
    }

    /// Fails where mounts cannot be told apart, so that nothing is deleted
    /// there.
    pub(super) fn mount_of(dir: &OwnedFd) -> io::Result<Mount> {
        let device = rustix::fs::fstat(dir)?.st_dev;
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::StatxFlags;
            let unsupported = || {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "cannot tell a bind mount from the directory it is in: that needs \
                     mount ids, from Linux 5.8, and `statx` allowed",
                )
            };
            let statx = match rustix::fs::statx(dir, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID) {
                Ok(statx) => statx,
                Err(Errno::NOSYS | Errno::PERM) => return Err(unsupported()),
                Err(e) => return Err(e.into()),
            };
            if statx.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
                return Err(unsupported());
            }
            Ok(Mount {
                device,
                id: statx.stx_mnt_id,
            })
        }
        // No bind mounts on macOS: another mount is another device.
        #[cfg(target_os = "macos")]
        {
            Ok(Mount { device })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = device;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cannot tell mounts apart on this system",
            ))
        }
    }

    /// Delete the entry `name` in `dir`, descending only through handles
    /// opened without following a link, and only on `mount`: a link is
    /// removed, never entered, and a mount point is left, with all in it.
    fn remove_entry(dir: &OwnedFd, name: &CStr, mount: &Mount) -> io::Result<()> {
        let stat = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return gone_is_fine(rustix::fs::unlinkat(dir, name, AtFlags::empty()));
        }
        let child = match rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty()) {
            Ok(child) => child,
            Err(Errno::NOENT) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        #[cfg(not(test))]
        let mount_point = mount_of(&child)? != *mount;
        #[cfg(test)]
        let mount_point = mount_of(&child)? != *mount || super::is_test_mount_point(name);
        if mount_point {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is a mount point, so it and what is in it are left",
                    name.to_string_lossy()
                ),
            ));
        }
        for entry in read_names(&child)? {
            remove_entry(&child, &entry, mount)?;
        }
        gone_is_fine(rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR))
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

/// Paths built on directories held open without delete sharing, which keeps
/// them, and every directory above them, from being renamed or removed.
#[cfg(windows)]
mod windows {
    use super::FileId;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    /// Lets `CreateFileW` open a directory.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    /// Opens a link itself rather than what it points at.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    /// `FILE_SHARE_READ | FILE_SHARE_WRITE`, without `FILE_SHARE_DELETE`.
    const SHARE_ALL_BUT_DELETE: u32 = 0x1 | 0x2;

    /// The directory run directories are created in, held open.
    pub struct Parent {
        /// `real`, without the `\\?\` prefix where it means the same.
        pub path: PathBuf,
        /// The path it was opened by, with every link in it resolved.
        real: PathBuf,
        held: File,
    }

    /// A run directory, held open.
    pub struct Run {
        path: PathBuf,
        held: File,
    }

    impl Parent {
        pub fn open(path: &Path) -> io::Result<Self> {
            std::fs::create_dir_all(path)?;
            let real = std::fs::canonicalize(path)?;
            let held = hold_dir(&real)?;
            // Held, none of its directories can be renamed or removed any
            // more, so if `real` has no link in it now, it never will.
            if std::fs::canonicalize(&real)? != real {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} changed while it was being opened", path.display()),
                ));
            }
            Ok(Self {
                path: plain(&real),
                real,
                held,
            })
        }

        pub fn create_run(&self, name: &str) -> io::Result<()> {
            std::fs::create_dir(self.real.join(name))
        }

        pub fn open_run(&self, name: &str) -> io::Result<Run> {
            let path = self.real.join(name);
            let held = hold_dir(&path)?;
            Ok(Run { path, held })
        }

        pub fn names(&self) -> io::Result<Vec<String>> {
            let mut names = Vec::new();
            for entry in std::fs::read_dir(&self.real)? {
                if let Ok(name) = entry?.file_name().into_string() {
                    names.push(name);
                }
            }
            Ok(names)
        }

        pub fn id(&self) -> io::Result<FileId> {
            file_id(&self.held)
        }

        /// The directory `name`, not following a link.
        pub fn id_of(&self, name: &str) -> io::Result<FileId> {
            file_id(&hold_dir(&self.real.join(name))?)
        }

        /// Close `run`, then remove the entry `name` if it is an empty
        /// directory or a link.
        pub fn remove_empty(&self, name: &str, run: Run) -> io::Result<()> {
            drop(run);
            gone_is_fine(std::fs::remove_dir(self.real.join(name)))
        }
    }

    impl Run {
        pub fn id(&self) -> io::Result<FileId> {
            file_id(&self.held)
        }

        pub fn is_empty(&self) -> io::Result<bool> {
            Ok(std::fs::read_dir(&self.path)?.next().is_none())
        }

        pub fn create_file(&self, name: &str) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(self.path.join(name))
        }

        /// Open an existing regular file for reading and locking, not
        /// following a link.
        pub fn open_file(&self, name: &str) -> io::Result<File> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.path.join(name))?;
            let meta = file.metadata()?;
            if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{name} is not a regular file"),
                ));
            }
            Ok(file)
        }

        pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            std::fs::rename(self.path.join(from), self.path.join(to))
        }

        pub fn remove_file(&self, name: &str) -> io::Result<()> {
            gone_is_fine(std::fs::remove_file(self.path.join(name)))
        }

        /// Delete everything in the directory but the entries named in `keep`.
        pub fn remove_all_but(&self, keep: &[&str]) -> io::Result<()> {
            for entry in std::fs::read_dir(&self.path)? {
                let entry = entry?;
                if keep.iter().any(|keep| entry.file_name() == *keep) {
                    continue;
                }
                #[cfg(test)]
                super::injected_failure()?;
                // An entry's metadata describes a link, not what it points
                // at. A link to a directory counts as a directory, and
                // `remove_dir_all` removes the link itself.
                let path = entry.path();
                gone_is_fine(
                    if entry.metadata()?.file_attributes() & FILE_ATTRIBUTE_DIRECTORY == 0 {
                        std::fs::remove_file(path)
                    } else {
                        std::fs::remove_dir_all(path)
                    },
                )?;
            }
            Ok(())
        }
    }

    /// `real` without its `\\?\` prefix, if it names the same without it,
    /// as a path on a drive does: [`super::RunDir::path`] is shown in logs and
    /// the manifest, and read by other programs.
    fn plain(real: &Path) -> PathBuf {
        real.to_str()
            .and_then(|text| text.strip_prefix(r"\\?\"))
            .map(PathBuf::from)
            .filter(|plain| std::fs::canonicalize(plain).is_ok_and(|again| again == real))
            .unwrap_or_else(|| real.to_path_buf())
    }

    /// Open the directory `path` to hold it, refusing a link.
    fn hold_dir(path: &Path) -> io::Result<File> {
        let dir = OpenOptions::new()
            .read(true)
            .share_mode(SHARE_ALL_BUT_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let meta = dir.metadata()?;
        if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not a directory", path.display()),
            ));
        }
        Ok(dir)
    }

    pub fn file_id(file: &File) -> io::Result<FileId> {
        let info = winapi_util::file::information(file)?;
        Ok(FileId {
            device: info.volume_serial_number().to_string(),
            file: info.file_index(),
        })
    }

    /// Something else, another run's sweep for one, may delete first.
    fn gone_is_fine(result: io::Result<()>) -> io::Result<()> {
        match result {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
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

    fn file_id_of(path: &Path) -> std::result::Result<u64, Box<dyn std::error::Error>> {
        Ok(file_id(&File::open(path)?)?.file)
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

    /// A directory `name` in `parent` carrying a free lock and a marker that
    /// names it, for this process, as a finished run would, then `edit`ed;
    /// and a sentinel file.
    fn forged(
        parent: &Path,
        name: &str,
        edit: impl FnOnce(&mut Marker),
    ) -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = parent.join(name);
        std::fs::create_dir_all(&dir)?;
        let file_id = Parent::open(parent)?.open_run(name)?.id()?.file;
        std::fs::write(dir.join(LOCK_FILE), b"")?;
        let lock_id = file_id_of(&dir.join(LOCK_FILE))?;
        let mut marker = Marker {
            run_id: "forged".to_string(),
            file_id,
            lock_id,
            pid: std::process::id(),
            started_at: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
            keep: false,
        };
        edit(&mut marker);
        std::fs::write(dir.join(MARKER_FILE), serde_json::to_vec(&marker)?)?;
        std::fs::write(dir.join("sentinel"), b"keep")?;
        Ok(dir)
    }

    #[test]
    fn create_makes_a_locked_marked_directory_inside_the_parent() -> TestResult {
        let temp = tempfile::tempdir()?;
        let parent = temp.path().join("not").join("there").join("yet");

        let run = RunDir::create(&parent, false)?;

        assert_eq!(
            run.path().parent().map(std::fs::canonicalize).transpose()?,
            Some(std::fs::canonicalize(&parent)?)
        );
        #[cfg(windows)]
        assert!(
            !run.path().to_string_lossy().starts_with(r"\\?\"),
            "{}",
            run.path().display()
        );
        let name = run
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("no name")?;
        assert!(is_run_name(name), "{name}");
        let marker = marker_in(run.path())?;
        assert_eq!(marker.pid, std::process::id());
        assert_eq!(marker.run_id, run.run_id);
        assert_eq!(marker.file_id, run.run.id()?.file);
        assert_eq!(marker.lock_id, file_id(&run.lock)?.file);
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

    /// Hermes round 3 on #263: once the run directory has been moved away, a
    /// directory put in its place, with copies of its marker and lock, is not
    /// the run's, and nothing is deleted.
    #[cfg(unix)]
    #[test]
    fn remove_refuses_a_replacement_carrying_a_copy_of_the_marker() -> TestResult {
        let temp = tempfile::tempdir()?;
        let run = RunDir::create(temp.path(), false)?;
        let path = run.path().to_path_buf();
        std::fs::write(path.join("data"), b"the run's")?;
        let moved = temp.path().join("moved");
        std::fs::rename(&path, &moved)?;
        std::fs::create_dir(&path)?;
        std::fs::copy(moved.join(MARKER_FILE), path.join(MARKER_FILE))?;
        std::fs::copy(moved.join(LOCK_FILE), path.join(LOCK_FILE))?;
        std::fs::write(path.join("sentinel"), b"not the run's")?;

        assert!(run.remove().is_err());
        assert!(path.join("sentinel").is_file());
        assert!(path.join(MARKER_FILE).is_file());
        assert!(moved.join("data").is_file());
        Ok(())
    }

    /// On Windows the same replacement cannot even be set up: while a run
    /// lasts, neither its directory nor the parent can be moved.
    /// Hermes round 6 on #263: nor can any directory above the parent, so
    /// `RunDir::path` keeps naming the run directory.
    #[cfg(windows)]
    #[test]
    fn a_run_directory_and_every_directory_above_it_cannot_be_moved_while_the_run_lasts(
    ) -> TestResult {
        let temp = tempfile::tempdir()?;
        let above = temp.path().join("above");
        let parent = above.join("devnets");
        let run = RunDir::create(&parent, false)?;
        let path = run.path().to_path_buf();

        assert!(std::fs::rename(&path, parent.join("moved")).is_err());
        assert!(std::fs::rename(&parent, above.join("moved")).is_err());
        assert!(std::fs::rename(&above, temp.path().join("moved")).is_err());
        let temp_moved = temp.path().with_extension("moved");
        assert!(std::fs::rename(temp.path(), &temp_moved).is_err());

        run.remove()?;
        assert!(!path.exists());
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

    /// Hermes round 3 on #263: a deletion that stops part-way leaves the
    /// marker and the lock, so the next run still knows the rest is a
    /// finished run's, and removes it.
    #[test]
    fn a_removal_that_stops_part_way_is_finished_by_the_next_run() -> TestResult {
        let temp = tempfile::tempdir()?;
        let run = RunDir::create(temp.path(), false)?;
        let path = run.path().to_path_buf();
        for i in 0..4 {
            std::fs::create_dir_all(path.join(format!("node-{i}")))?;
            std::fs::write(path.join(format!("node-{i}")).join("chunk"), b"data")?;
        }

        FAIL_AFTER.with(|left| left.set(Some(2)));
        let stopped = run.remove();
        FAIL_AFTER.with(|left| left.set(None));

        assert!(stopped.is_err());
        assert!(path.join(MARKER_FILE).is_file());
        assert!(path.join(LOCK_FILE).is_file());
        let _next = RunDir::create(temp.path(), false)?;
        assert!(!path.exists(), "{} was not swept", path.display());
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
    fn a_run_kept_locked_until_exit_is_never_swept() -> TestResult {
        let temp = tempfile::tempdir()?;
        let run = RunDir::create(temp.path(), false)?;
        let path = run.path().to_path_buf();
        run.keep_locked_until_exit();

        let _next = RunDir::create(temp.path(), false)?;

        assert!(path.join(MARKER_FILE).is_file());
        assert!(!lock_is_free(&path)?);
        Ok(())
    }

    /// Hermes round 4 on #263: a live run's lock file moved aside and
    /// another put in its place. That one is free, but it is not the lock the
    /// run holds.
    #[test]
    fn a_live_run_whose_lock_file_is_replaced_is_never_swept() -> TestResult {
        let temp = tempfile::tempdir()?;
        let run = RunDir::create(temp.path(), false)?;
        let path = run.path().to_path_buf();
        std::fs::write(path.join("data"), b"the run's")?;
        std::fs::rename(path.join(LOCK_FILE), path.join("moved.lock"))?;
        std::fs::write(path.join(LOCK_FILE), b"")?;
        assert!(lock_is_free(&path)?);

        let _next = RunDir::create(temp.path(), false)?;

        assert!(path.join("data").is_file(), "{} was swept", path.display());
        drop(run);
        Ok(())
    }

    /// Hermes round 4 on #263: a directory put in place of a new run
    /// directory before the run opens it is not the run's, so the run neither
    /// claims it nor deletes anything in it, whether or not claiming it would
    /// have failed.
    #[test]
    fn a_directory_put_in_place_of_a_new_run_directory_is_left_alone() -> TestResult {
        for with_lock in [false, true] {
            let temp = tempfile::tempdir()?;
            let parent = temp.path().join("devnets");
            let moved = temp.path().join("moved");
            let replaced = std::rc::Rc::new(std::cell::RefCell::new(None));
            let record = std::rc::Rc::clone(&replaced);
            AFTER_CREATE.with(|act| {
                *act.borrow_mut() = Some(Box::new(move |path: &Path| {
                    std::fs::rename(path, &moved)?;
                    std::fs::create_dir(path)?;
                    std::fs::write(path.join("sentinel"), b"not the run's")?;
                    if with_lock {
                        std::fs::write(path.join(LOCK_FILE), b"not the run's")?;
                    }
                    *record.borrow_mut() = Some(path.to_path_buf());
                    Ok(())
                }));
            });

            let created = RunDir::create(&parent, false);
            AFTER_CREATE.with(|act| act.borrow_mut().take());

            assert!(created.is_err(), "with_lock: {with_lock}");
            let path = replaced.borrow_mut().take().ok_or("never replaced")?;
            assert!(path.join("sentinel").is_file(), "with_lock: {with_lock}");
            assert!(!path.join(MARKER_FILE).exists(), "with_lock: {with_lock}");
            assert_eq!(path.join(LOCK_FILE).is_file(), with_lock);
        }
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

    /// Hermes round 3 on #263: a finished run's directory moved away, and
    /// another put in its place with a copy of its marker and its very lock
    /// file. The copy names the moved directory, not this one.
    #[test]
    fn a_copy_of_a_finished_runs_marker_is_never_swept() -> TestResult {
        let temp = tempfile::tempdir()?;
        let old = finished(temp.path(), false)?;
        let moved = temp.path().join("moved");
        std::fs::rename(&old, &moved)?;
        std::fs::create_dir(&old)?;
        std::fs::copy(moved.join(MARKER_FILE), old.join(MARKER_FILE))?;
        std::fs::rename(moved.join(LOCK_FILE), old.join(LOCK_FILE))?;
        std::fs::write(old.join("sentinel"), b"keep")?;

        let _run = RunDir::create(temp.path(), false)?;

        assert!(old.join("sentinel").is_file());
        assert!(moved.join("nodes").join("peer").join("chunk").is_file());
        Ok(())
    }

    /// Hermes round 6 on #263: a finished run's directory moved out of its
    /// name once the sweep has found it finished is not emptied where it went.
    /// On Windows the sweep holds it, and it cannot be moved.
    #[test]
    fn a_finished_run_moved_once_it_is_found_is_left() -> TestResult {
        let temp = tempfile::tempdir()?;
        let old = finished(temp.path(), false)?;
        let moved = temp.path().join("moved");
        let to = moved.clone();
        let outcome = std::rc::Rc::new(std::cell::RefCell::new(None));
        let record = std::rc::Rc::clone(&outcome);
        AFTER_FOUND.with(|act| {
            *act.borrow_mut() = Some(Box::new(move |path: &Path| {
                *record.borrow_mut() = Some(std::fs::rename(path, &to).is_ok());
            }));
        });

        let created = RunDir::create(temp.path(), false);
        AFTER_FOUND.with(|act| act.borrow_mut().take());
        let _run = created?;

        let was_moved = outcome.borrow_mut().take().ok_or("never found")?;
        if cfg!(windows) {
            assert!(!was_moved, "moved while the sweep held it");
            assert!(!old.exists(), "{} was not swept", old.display());
        } else {
            assert!(was_moved);
            assert!(
                moved.join("nodes").join("peer").join("chunk").is_file(),
                "emptied where it was moved to"
            );
            assert!(moved.join(MARKER_FILE).is_file());
        }
        Ok(())
    }

    #[test]
    fn directories_without_a_matching_marker_are_never_swept() -> TestResult {
        let temp = tempfile::tempdir()?;
        let parent = temp.path();
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
            forged(parent, "other", |_| {})?,
            forged(parent, &format!("{pid}-DEADBEEF"), |_| {})?,
            forged(parent, &format!("{pid}-deadbeef0"), |_| {})?,
            // A marker naming another process than the name does.
            forged(parent, &format!("{}-deadbeef", pid.wrapping_add(1)), |_| {})?,
            // A marker naming another directory.
            forged(parent, &format!("{pid}-d1ffe4e7"), |marker| {
                marker.file_id = marker.file_id.wrapping_add(1);
            })?,
            // A marker naming another lock file than the one there.
            forged(parent, &format!("{pid}-10c4ed00"), |marker| {
                marker.lock_id = marker.lock_id.wrapping_add(1);
            })?,
            // A marker asking to keep it.
            forged(parent, &format!("{pid}-cee9cee9"), |marker| {
                marker.keep = true;
            })?,
            // A marker that is not one.
            {
                let dir = forged(parent, &format!("{pid}-0badf00d"), |_| {})?;
                std::fs::write(dir.join(MARKER_FILE), b"{ not json")?;
                dir
            },
            {
                let dir = forged(parent, &format!("{pid}-0ddba11a"), |_| {})?;
                let mut big = std::fs::read(dir.join(MARKER_FILE))?;
                big.resize(MAX_MARKER_LEN + 1, b' ');
                std::fs::write(dir.join(MARKER_FILE), big)?;
                dir
            },
            // A marker but no lock: a run never marks before it has locked.
            {
                let dir = forged(parent, &format!("{pid}-ca11ab1e"), |_| {})?;
                std::fs::remove_file(dir.join(LOCK_FILE))?;
                dir
            },
        ];
        // Unedited, the same forgery is swept: each survivor survives for
        // its one difference alone.
        let control = forged(parent, &format!("{pid}-c0ffee00"), |_| {})?;

        let _run = RunDir::create(parent, false)?;

        for dir in &survivors {
            assert!(
                dir.join("sentinel").is_file(),
                "{} was swept",
                dir.display()
            );
        }
        assert!(!control.exists(), "{} was not swept", control.display());
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

    /// Hermes round 4 on #263: a deletion does not cross into another mount
    /// inside the run directory. It stops, leaving the mount point, what is
    /// in it, and the marker.
    #[cfg(unix)]
    #[test]
    fn removal_does_not_cross_into_another_mount() -> TestResult {
        let temp = tempfile::tempdir()?;
        let run = RunDir::create(temp.path(), false)?;
        let path = run.path().to_path_buf();
        let mounted = path.join("nodes").join("mounted");
        std::fs::create_dir_all(&mounted)?;
        std::fs::write(mounted.join("data"), b"not the run's")?;

        MOUNT_POINT.with(|mount| *mount.borrow_mut() = Some("mounted".to_string()));
        let removed = run.remove();
        MOUNT_POINT.with(|mount| mount.borrow_mut().take());

        assert!(removed.is_err());
        assert!(mounted.join("data").is_file());
        assert!(path.join(MARKER_FILE).is_file());
        Ok(())
    }

    /// Run `sudo -n`, with `args` and then `path`.
    #[cfg(target_os = "linux")]
    fn sudo(args: &[&std::ffi::OsStr], path: &Path) -> io::Result<()> {
        let status = std::process::Command::new("sudo")
            .arg("-n")
            .args(args)
            .arg(path)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "sudo {args:?} {} failed",
                path.display()
            )))
        }
    }

    /// A mount made through `sudo`, undone when dropped.
    #[cfg(target_os = "linux")]
    struct Mounted(PathBuf);

    #[cfg(target_os = "linux")]
    impl Mounted {
        fn new(at: &Path, how: &[&std::ffi::OsStr]) -> io::Result<Self> {
            sudo(&[&[std::ffi::OsStr::new("mount")], how].concat(), at)?;
            Ok(Self(at.to_path_buf()))
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for Mounted {
        fn drop(&mut self) {
            if let Err(e) = sudo(&[std::ffi::OsStr::new("umount")], &self.0) {
                eprintln!("{e}");
            }
        }
    }

    /// Whether `mv from to`, run as `nobody` through `sudo -n`, succeeds.
    #[cfg(target_os = "linux")]
    fn nobody_moves(from: &Path, to: &Path) -> io::Result<bool> {
        Ok(std::process::Command::new("sudo")
            .args(["-n", "-u", "nobody", "mv"])
            .arg(from)
            .arg(to)
            .stderr(std::process::Stdio::null())
            .status()?
            .success())
    }

    /// Hermes round 5 on #263, with real mounts: neither a tmpfs nor a bind
    /// mount of a directory on the same filesystem, which only the mount id
    /// tells apart, is crossed. The `with_sudo_` tests need root, through
    /// `sudo -n`; CI runs them in a step of their own.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "mounts through sudo; CI runs it"]
    fn with_sudo_mounts_inside_a_run_directory_are_not_crossed() -> TestResult {
        use std::ffi::OsStr;
        for bind in [false, true] {
            let temp = tempfile::tempdir()?;
            let source = temp.path().join("source");
            std::fs::create_dir(&source)?;
            std::fs::write(source.join("data"), b"not the run's")?;
            let run = RunDir::create(&temp.path().join("devnets"), false)?;
            let path = run.path().to_path_buf();
            let at = path.join("nodes").join("mounted");
            std::fs::create_dir_all(&at)?;
            let _mounted = if bind {
                Mounted::new(&at, &[OsStr::new("--bind"), source.as_os_str()])?
            } else {
                let tmpfs = ["-t", "tmpfs", "-o", "mode=1777", "none"].map(OsStr::new);
                let mounted = Mounted::new(&at, &tmpfs)?;
                std::fs::write(at.join("data"), b"not the run's")?;
                mounted
            };

            assert!(run.remove().is_err(), "bind: {bind}");
            assert!(at.join("data").is_file(), "bind: {bind}");
            assert!(source.join("data").is_file(), "bind: {bind}");
            assert!(path.join(MARKER_FILE).is_file(), "bind: {bind}");
        }
        Ok(())
    }

    /// Hermes round 5 on #263: a bind mount of a finished run's directory,
    /// kept elsewhere on the same filesystem, put in the parent under the
    /// run's name. Everything about it matches but its mount, and the sweep
    /// would delete through it what it shows.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "mounts through sudo; CI runs it"]
    fn with_sudo_a_mount_wearing_a_finished_runs_name_is_not_swept() -> TestResult {
        let temp = tempfile::tempdir()?;
        let outside = finished(&temp.path().join("outside"), false)?;
        let parent = temp.path().join("devnets");
        let at = parent.join(outside.file_name().ok_or("no name")?);
        std::fs::create_dir_all(&at)?;
        let _mounted = Mounted::new(&at, &[std::ffi::OsStr::new("--bind"), outside.as_os_str()])?;
        assert!(at.join(MARKER_FILE).is_file());

        let _run = RunDir::create(&parent, false)?;

        assert!(
            outside.join("nodes").join("peer").join("chunk").is_file(),
            "swept through the mount"
        );
        Ok(())
    }

    /// Hermes round 5 on #263: an empty directory another user owns, put in
    /// place of a new run directory before the run opens it, is not claimed,
    /// though the run could write in it.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "makes a directory another user owns through sudo; CI runs it"]
    fn with_sudo_an_empty_directory_of_another_user_is_not_claimed() -> TestResult {
        let temp = tempfile::tempdir()?;
        let parent = temp.path().join("devnets");
        let moved = temp.path().join("moved");
        let replaced = std::rc::Rc::new(std::cell::RefCell::new(None));
        let record = std::rc::Rc::clone(&replaced);
        AFTER_CREATE.with(|act| {
            *act.borrow_mut() = Some(Box::new(move |path: &Path| {
                std::fs::rename(path, &moved)?;
                // root's, and open to anyone.
                sudo(&["mkdir", "-m", "0777"].map(std::ffi::OsStr::new), path)?;
                *record.borrow_mut() = Some(path.to_path_buf());
                Ok(())
            }));
        });

        let created = RunDir::create(&parent, false);
        AFTER_CREATE.with(|act| act.borrow_mut().take());

        assert!(created.is_err());
        let path = replaced.borrow_mut().take().ok_or("never replaced")?;
        assert!(!path.join(MARKER_FILE).exists());
        assert!(!path.join(LOCK_FILE).exists());
        Ok(())
    }

    /// Hermes round 6 on #263, as another user: `nobody` can move what the
    /// user makes in a directory anyone can write to, and so could swap a
    /// directory above a run directory for a link; a run refuses to start
    /// below one. Below a sticky one, which a run does start in, `nobody`
    /// cannot, and writes through `RunDir::path` land in the run directory.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "acts as another user through sudo; CI runs it"]
    fn with_sudo_another_user_cannot_redirect_what_a_run_writes() -> TestResult {
        use std::ffi::OsStr;
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir()?;
        // Within `nobody`'s reach.
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))?;

        // root's, open to anyone, not sticky.
        let open = temp.path().join("open");
        sudo(&["mkdir", "-m", "0777"].map(OsStr::new), &open)?;
        std::fs::create_dir(open.join("mine"))?;
        assert!(nobody_moves(&open.join("mine"), &open.join("moved"))?);
        let refused = RunDir::create(&open.join("moved").join("devnets"), false);
        assert_eq!(
            refused.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );

        // root's, open to anyone, sticky.
        let sticky = temp.path().join("sticky");
        sudo(&["mkdir", "-m", "1777"].map(OsStr::new), &sticky)?;
        let mine = sticky.join("mine");
        let run = RunDir::create(&mine.join("devnets"), false)?;
        assert!(!nobody_moves(&mine, &sticky.join("moved"))?);
        std::fs::write(run.path().join("written"), b"the run's")?;
        let name = run.path().file_name().ok_or("no name")?;
        assert!(mine.join("devnets").join(name).join("written").is_file());
        run.remove()?;
        Ok(())
    }

    /// Hermes round 6 on #263: nor below a directory another user owns, or
    /// one a group other than the user's own can write to.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "makes directories another user owns through sudo; CI runs it"]
    fn with_sudo_a_parent_below_another_users_or_groups_directory_is_refused() -> TestResult {
        use std::ffi::OsStr;
        let temp = tempfile::tempdir()?;
        let me = rustix::process::geteuid().as_raw().to_string();
        for (name, how) in [
            ("theirs", ["-o", "65534", "-m", "0755"]),
            ("their-group", ["-g", "65534", "-m", "0775"]),
        ] {
            let above = temp.path().join(name);
            let parent = above.join("devnets");
            let make: Vec<&OsStr> = ["install", "-d"]
                .into_iter()
                .chain(how)
                .map(OsStr::new)
                .collect();
            sudo(&make, &above)?;
            sudo(
                &["install", "-d", "-o", me.as_str()].map(OsStr::new),
                &parent,
            )?;

            let refused = RunDir::create(&parent, false);

            assert_eq!(
                refused.err().map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied),
                "{name}"
            );
            assert!(std::fs::read_dir(&parent)?.next().is_none(), "{name}");
        }
        Ok(())
    }

    /// Hermes round 6 on #263: a finished run's directory another user owns
    /// is theirs, whatever is in it, and in a sticky parent they could still
    /// move it once the sweep has found it. It is not swept, though the user
    /// could delete what is in it.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "hands a directory to another user through sudo; CI runs it"]
    fn with_sudo_another_users_finished_run_is_not_swept() -> TestResult {
        use std::ffi::OsStr;
        let temp = tempfile::tempdir()?;
        let old = finished(temp.path(), false)?;
        sudo(&["chown", "-R", "65534"].map(OsStr::new), &old)?;
        sudo(&["chmod", "-R", "a+rwX"].map(OsStr::new), &old)?;

        let _run = RunDir::create(temp.path(), false)?;

        assert!(old.join("nodes").join("peer").join("chunk").is_file());
        Ok(())
    }

    /// What that rests on: a directory on another mount is told apart from
    /// one on the run's.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_directory_on_another_mount_is_told_apart() -> TestResult {
        use rustix::fs::{Mode, OFlags};
        let open = |path: &Path| {
            rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
        };
        let temp = tempfile::tempdir()?;
        std::fs::create_dir(temp.path().join("sub"))?;
        // procfs on Linux, devfs on macOS: always mounts of their own.
        let other = if cfg!(target_os = "linux") {
            "/proc"
        } else {
            "/dev"
        };

        let here = unix::mount_of(&open(temp.path())?)?;
        assert_eq!(unix::mount_of(&open(&temp.path().join("sub"))?)?, here);
        assert_ne!(unix::mount_of(&open(Path::new(other))?)?, here);
        Ok(())
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

    /// `parent` inside `above`, inside a fresh temporary directory, with
    /// `mode` set on whichever of the two `which` names.
    #[cfg(unix)]
    fn parent_with(
        which: &str,
        mode: u32,
    ) -> std::result::Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir()?;
        let above = temp.path().join("above");
        let parent = above.join("devnets");
        std::fs::create_dir_all(&parent)?;
        let dir = if which == "above" { &above } else { &parent };
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
        Ok((temp, parent))
    }

    /// Hermes round 6 on #263: another user who can write to the parent, or
    /// to a directory above it, can move what is in it. A run refuses to
    /// start there, and makes nothing there.
    #[cfg(unix)]
    #[test]
    fn a_parent_another_user_could_change_is_refused() -> TestResult {
        let mut cases = vec![("above", 0o777), ("parent", 0o777)];
        // No user private groups on macOS: a group there is shared.
        if cfg!(not(target_os = "linux")) {
            cases.push(("above", 0o775));
        }
        for (which, mode) in cases {
            let (_temp, parent) = parent_with(which, mode)?;

            let refused = RunDir::create(&parent, false);

            assert_eq!(
                refused.err().map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied),
                "{which} {mode:o}"
            );
            assert!(
                std::fs::read_dir(&parent)?.next().is_none(),
                "{which} {mode:o}"
            );
        }
        Ok(())
    }

    /// What a run does start in: a parent in, or below, a sticky directory
    /// anyone can write to, as `/tmp` is, which lets no one rename what they
    /// do not own; and on Linux, below one the user's own group can write to.
    #[cfg(unix)]
    #[test]
    fn a_parent_only_this_user_can_change_is_accepted() -> TestResult {
        let mut cases = vec![("above", 0o1777), ("parent", 0o1777)];
        if cfg!(target_os = "linux") {
            cases.push(("above", 0o775));
        }
        for (which, mode) in cases {
            let (_temp, parent) = parent_with(which, mode)?;

            let run =
                RunDir::create(&parent, false).map_err(|e| format!("{which} {mode:o}: {e}"))?;

            assert!(run.path().join(MARKER_FILE).is_file(), "{which} {mode:o}");
        }
        Ok(())
    }

    /// With an ACL, a directory's group bits are only its mask, the most it
    /// grants anyone it names, so one the user's own group can write to does
    /// not pass if it has one.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_parent_below_a_directory_with_an_acl_is_refused() -> TestResult {
        let (_temp, parent) = parent_with("above", 0o755)?;
        let above = parent.parent().ok_or("no parent")?;
        // user::rwx, user:65534:rwx, group::r-x, mask::rwx, other::r-x, in the
        // kernel's `system.posix_acl_access` format.
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (0x01_u16, 7_u16, u32::MAX),
            (0x02, 7, 65534),
            (0x04, 5, u32::MAX),
            (0x10, 7, u32::MAX),
            (0x20, 5, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&perm.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        rustix::fs::lsetxattr(
            above,
            "system.posix_acl_access",
            &acl,
            rustix::fs::XattrFlags::empty(),
        )?;
        let mode = rustix::fs::Mode::from_raw_mode(rustix::fs::lstat(above)?.st_mode);
        assert!(mode.contains(rustix::fs::Mode::WGRP), "{mode:?}");

        let refused = RunDir::create(&parent, false);

        assert_eq!(
            refused.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
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

        // Hermes round 5: nor are writes through the path it hands out.
        std::fs::write(run.path().join("written"), b"the run's")?;
        assert!(first.join("devnets").join(&name).join("written").is_file());
        assert!(!decoy.join("written").exists(), "path() followed the link");
        run.remove()?;

        assert!(!first.join("devnets").join(&name).exists());
        assert!(
            decoy.join("sentinel").is_file(),
            "the removal followed the retargeted link"
        );
        Ok(())
    }

    /// `mklink /J`: a directory junction, which needs no privilege to make.
    /// The paths reach `cmd` through the environment and are expanded inside
    /// quotes, once, where none of its metacharacters act, and a Windows path
    /// cannot hold a quote: whatever they contain, they stay two paths.
    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) -> TestResult {
        use std::os::windows::process::CommandExt;
        let status = std::process::Command::new("cmd")
            .raw_arg(r#"/D /V:OFF /S /C "mklink /J "%ANT_TEST_LINK%" "%ANT_TEST_TARGET%"""#)
            .env("ANT_TEST_LINK", link)
            .env("ANT_TEST_TARGET", target)
            .stdout(std::process::Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("mklink /J {} {} failed", link.display(), target.display()).into())
        }
    }

    /// The same on Windows, with a junction.
    #[cfg(windows)]
    #[test]
    fn retargeting_a_junction_above_the_run_does_not_redirect_removal() -> TestResult {
        let temp = tempfile::tempdir()?;
        // Names that mean something to `cmd`, which `junction` goes through.
        let first = temp.path().join("first & %USERNAME% ^(1)!");
        let second = temp.path().join("second ; %PATH% = ^&");
        std::fs::create_dir_all(&first)?;
        std::fs::create_dir_all(&second)?;
        let link = temp.path().join("link & %TEMP%");
        junction(&link, &first)?;

        let run = RunDir::create(&link.join("devnets"), false)?;
        let name = run.path().file_name().ok_or("no name")?.to_owned();
        let decoy = second.join("devnets").join(&name);
        std::fs::create_dir_all(&decoy)?;
        std::fs::copy(run.path().join(MARKER_FILE), decoy.join(MARKER_FILE))?;
        std::fs::write(decoy.join("sentinel"), b"keep")?;
        std::fs::remove_dir(&link)?;
        junction(&link, &second)?;

        std::fs::write(run.path().join("written"), b"the run's")?;
        assert!(first.join("devnets").join(&name).join("written").is_file());
        assert!(
            !decoy.join("written").exists(),
            "path() followed the junction"
        );
        run.remove()?;

        assert!(!first.join("devnets").join(&name).exists());
        assert!(
            decoy.join("sentinel").is_file(),
            "the removal followed the retargeted junction"
        );
        Ok(())
    }
}
