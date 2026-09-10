//! What a node does when it finds the old chunk store still on disk.
//!
//! Chunks used to live in an LMDB environment at `{root}/chunks.mdb`. The previous release
//! copied them into a file per chunk and deleted that environment; this build has no code
//! that can read one. So a node starting with something still there needs an answer, and
//! there are three plausible ones. Two of them are wrong.
//!
//! **Refusing to start is wrong.** It was the first answer, and the reasoning was not silly:
//! those chunks are unreachable, so the node serves less than its published commitment
//! claims, and it spends the answerability window failing commitment-bound audits for keys
//! it cannot read. But a node that refuses serves *nothing* — not the chunks it cannot read,
//! and not the far larger number it migrated perfectly well. Nor can it be recovered:
//! `build_upgrade_monitor` is called unconditionally and `UpgradeConfig` has no field that
//! switches it off, so a node put back on the previous release is dragged forward again
//! within the hour, and on the deployed unit it is a ten-second restart loop until a person
//! intervenes. A few hours of trust penalty avoided, paid for with the whole node,
//! indefinitely.
//!
//! **Deleting whatever is there is also wrong**, and more obviously so once written down.
//! The upgrade monitor picks the newest eligible release rather than the next one, so a node
//! that was offline through the previous release arrives here with every chunk it owns in
//! that environment and nothing in the file store. Deleting it destroys data that may have
//! no other copy, to reclaim disk.
//!
//! So: **start, and remove only what is provably finished with.** The previous release wrote
//! a `RETIRED` mark inside the directory before it deleted anything, so a directory carrying
//! that mark is one whose retirement gates were all met and is pure cost. So is an empty one,
//! which is what a cleanup interrupted between emptying a tombstone and removing it leaves.
//! Those go, and their disk comes back. Anything else stays exactly where it is, and is
//! named once so an operator can decide.
//!
//! "Gates were met" is not "its contents are in the file store", and the difference is load
//! bearing. Retirement cleared a directory on two grounds: every chunk the node KEPT was copied
//! into the file store and re-hashed there, and every chunk it SHED was proven held by its close
//! group — all but one answering a possession challenge — and then deliberately not copied. So a
//! marked directory can legitimately hold bytes that are in no file store on this node. Removing
//! them is finishing what the previous release had already started; the safety argument for them
//! is the close group's proofs, not a local copy.
//!
//! **What may be deleted is decided by [`migration_signal::classify`], not by a second
//! reading of the same directory.** The previous release put each node's answer on the wire
//! so a fleet could be seen to have finished, and this release is published on the strength
//! of that count. If the cleanup had its own notion of which directories are finished with,
//! the two could drift, and a node could delete a directory it was still reporting as
//! unfinished, or report `files` while keeping one. They are one function, and the names
//! they match are one set of constants.
//!
//! Two things are never done, both because a name is not evidence of what is behind it. A
//! link is neither followed nor unlinked: what is behind it is on storage this node does not
//! own. And only the exact names the previous release created are considered at all.

use std::path::{Path, PathBuf};

use crate::logging::{info, warn};
use crate::storage::migration_signal::{classify, legacy_directories, Leftover, RETIRED_MARKER};

/// Remove what the storage migration finished with, and start either way.
///
/// Returns nothing and fails at nothing. **This is what never vetoes a start** — it is not a
/// claim that every node starts, which is not this module's to make: the file store is built
/// before this runs and a store that cannot open still stops the node. What is ruled out is
/// a node kept from running by what it found left over, which is what the first draft of this
/// release did.
///
/// Called once the file store has opened, and not before. "Finished with" means the chunks
/// are in the file store, which is only true if the file store is there to hold them: running
/// this earlier put the deletion in front of a constructor that can still fail, and a node
/// that lost both stores that way had nothing to go back to. A node that never opens a store
/// at all does not call this.
///
/// This runs after the user agent that carries this node's migration state to every peer has
/// already been fixed, and that turns out not to matter: everything removed here is a
/// leftover the signal already calls finished with, because carrying the mark or being empty
/// is exactly what makes it removable and exactly what makes it harmless. The node announces
/// `files` either way, whether the deletion has finished or not yet started.
pub fn clean_up(root_dir: &Path) {
    // A root that cannot be listed hides every tombstone under it. The previous release's
    // own reporting calls that `unknown` rather than `files`, and the matching answer here is
    // to remove nothing and say so: an unlistable root is not evidence that there is nothing
    // to keep. Said out loud because an earlier version returned silently, which left the
    // decision record promising a warning that no code emitted.
    let Ok(leftovers) = legacy_directories(root_dir) else {
        warn!(
            migration_event = "legacy_store_left",
            "{} could not be listed, so nothing left over from the storage migration was \
             removed from it. Any leftover is still costing disk.",
            root_dir.display()
        );
        return;
    };

    let mut finished_with = Vec::new();
    for dir in leftovers {
        match classify(&dir) {
            // Its chunks are in the file store and the previous release simply did not
            // finish deleting it, or there is nothing in it at all. Either way it holds
            // nothing, so removing it cannot lose anything.
            Leftover::Harmless => finished_with.push(dir),
            Leftover::Holding | Leftover::Unreadable => warn!(
                migration_event = "legacy_store_left",
                "{} is left over from the storage migration and this build will not remove \
                 it: {}. It is costing disk until it is dealt with by hand.",
                dir.display(),
                why_it_is_kept(&dir)
            ),
        }
    }

    if !finished_with.is_empty() {
        remove_all(finished_with);
    }
}

/// Why one directory is being kept, for the operator who has to decide what to do with it.
///
/// Prose only. The decision was already made by `classify`; this re-reads the directory
/// solely to say which of its reasons applied. If the disk changes underneath the two, the
/// cost is a warning that names the wrong reason, never a directory deleted that should not
/// have been.
///
/// Its only caller is inside a `warn!`, which compiles to nothing without the `logging`
/// feature, so off that feature this has no caller at all. Same treatment as the signal's own
/// token helpers rather than a `#[cfg]`, which would take the function out of the build the
/// tests run in.
#[cfg_attr(not(feature = "logging"), allow(dead_code))]
fn why_it_is_kept(dir: &Path) -> &'static str {
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return "it cannot be examined";
    };
    if meta.file_type().is_symlink() {
        return "it is a link to storage this node does not own";
    }
    if !meta.is_dir() {
        return "it is not a directory";
    }
    match std::fs::symlink_metadata(dir.join(RETIRED_MARKER)) {
        Ok(meta) if meta.is_file() => "it carries the mark that says it was finished with",
        Ok(_) => {
            "something that is not the storage migration's mark is using the name the mark \
             would have, so this node cannot tell whether it was finished with"
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            "it has chunks in it that were never copied into the file store, and this build \
             cannot read them. Nothing here will delete them, so they are not lost. Whether \
             this node's close group still needs them is the question to answer before \
             removing it by hand"
        }
        Err(_) => "whether it was finished with cannot be established",
    }
}

/// Delete every directory retirement had already cleared, one after another.
///
/// Not "every directory that holds no chunks": a marked one can hold the chunks the node shed,
/// which retirement proved the close group holds and deliberately did not copy here.
///
/// **One thread, in sequence.** The names this release recognises are the live directory, the
/// unnumbered tombstone and sixty-four numbered ones, so a root that has been through enough
/// restore cycles can present sixty-six at once. A thread each would put sixty-six concurrent
/// recursive deletions on the disk that is also serving chunks, at the moment a node is
/// starting up. They are pure disk work with nothing waiting on them, so doing them in turn
/// costs nothing that matters and bounds what this can do to a node's I/O.
///
/// In the background and in place. Nothing has to be got out of the way first: these
/// directories hold nothing, and this build has no code that would read them if they did. Not
/// renaming also means no name to allocate, which is what an earlier version of this could
/// run out of and wedge itself on.
fn remove_all(dirs: Vec<PathBuf>) {
    let spawned = std::thread::Builder::new()
        .name("legacy-store-cleanup".into())
        .spawn(move || {
            for dir in dirs {
                match delete_mark_last(&dir) {
                    // Said only once the deletion has finished. Announcing the space before
                    // it is back is how an operator comes to trust a number that is wrong for
                    // the next several minutes.
                    Ok(()) => info!(
                        migration_event = "space_returned",
                        "Removed {}, which the storage migration had finished with, and \
                         returned its space.",
                        dir.display()
                    ),
                    Err(e) => warn!(
                        migration_event = "legacy_store_left",
                        "{} was finished with by the storage migration but could not be \
                         removed ({e}). It is costing disk. The next start tries again.",
                        dir.display()
                    ),
                }
            }
        });
    if let Err(e) = spawned {
        // Naming what did not happen, not just that something did not. An earlier version
        // said only that a thread could not start, which tells an operator nothing about
        // which disk stayed full.
        warn!(
            migration_event = "legacy_store_left",
            "Could not start the storage migration's cleanup thread ({e}), so nothing it had \
             finished with was removed. Those directories are still costing disk and the next \
             start tries again."
        );
    }
}

/// The most entries this will look at in one leftover.
///
/// A retired chunk environment holds `data.mdb`, `lock.mdb` and the mark. Something with
/// thousands of entries in it is not one, and reading a corrupt or hostile directory's whole
/// listing into memory is how a cleanup takes the node down with it instead of returning some
/// disk. Over this, the directory is kept and named, which is what happens to everything else
/// this cannot make sense of.
const MAX_ENTRIES: usize = 1024;

/// Empty a directory, then remove its mark, then remove the directory.
///
/// The order is the whole of it. `remove_dir_all` gives no promise about which entry it
/// unlinks first, and the mark is the only thing that says this directory was finished with:
/// if it goes before the contents do and the process stops there, the next start finds an
/// unmarked directory with data in it, decides it might be an unmigrated store, and keeps it
/// forever. It is not one, but nothing on disk says so any more, and the node then reports
/// itself as unfinished to the whole network for as long as it lives.
///
/// **On Unix the directory is opened once and never named again.** An earlier version checked
/// `symlink_metadata(dir)` and then re-opened the same path with `read_dir`, which follows a
/// link. Anything that could replace the directory between the two — a local actor with write
/// access to the node's data directory — could point it at a target elsewhere on the disk and
/// have this process delete that target's contents instead. The node can reach more of the
/// filesystem than such an actor can, so that is not one more way to lose data inside the data
/// directory: it is a way to reach outside it. One handle, opened `O_NOFOLLOW | O_DIRECTORY`,
/// carries every gate and every unlink including the mark's, so the answer that authorises the
/// deletion and the deletion itself are about the same inode by construction. A second open
/// for the mark was a second window and is gone.
///
/// **Subdirectories are refused, not entered.** `O_NOFOLLOW` declines a trailing symlink; it
/// says nothing about a mount point, and `openat` walks into one happily. A retired chunk
/// environment is flat — two files and a mark — so a directory inside one is already something
/// this build does not understand, and descending into it risks emptying a filesystem that has
/// nothing to do with this node. Refusing also means there is no recursion to bound, no
/// descriptor chain to exhaust, and no cycle a bind mount could build.
///
/// The directory itself still goes by path, and that is safe on its own terms: `rmdir` refuses
/// a symlink, so a swapped name fails the call rather than following it. It does not preserve
/// identity — a directory swapped for another real directory would be the one removed — but by
/// then the only thing that can be removed is an empty directory, and removing an empty
/// directory somebody else just put there costs nothing.
///
/// Off Unix there is no `unlinkat`. That build keeps the path-based version, with the same
/// refusals and the same re-check, and the window the previous release's deleter also had.
fn delete_mark_last(dir: &Path) -> std::io::Result<()> {
    empty_and_unmark(dir)?;
    // `rmdir`, not `unlink`: it refuses a symlink outright, so this one path cannot be followed
    // anywhere even if the name were swapped after the emptying.
    std::fs::remove_dir(dir)
}

/// The gates, the contents and the mark, all against one directory handle.
#[cfg(unix)]
fn empty_and_unmark(dir: &Path) -> std::io::Result<()> {
    use rustix::fs::{AtFlags, FileType};

    let dirfd = open_dir_nofollow(dir)?;

    // Asked again, here, on the thread that does the deleting, and asked of the handle. The
    // classification that got this path happened on another thread and is already in the past.
    //
    // A REGULAR file, and the comparison masks with `S_IFMT` to say so. Testing
    // `st_mode & S_IFREG == S_IFREG` is not that test: `S_IFLNK` and `S_IFSOCK` both contain
    // every bit of `S_IFREG`, so a symlink or a socket wearing the mark's name would pass it
    // and authorise deleting a store nothing had migrated.
    let marked = matches!(
        rustix::fs::statat(&dirfd, RETIRED_MARKER, AtFlags::SYMLINK_NOFOLLOW),
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
    );

    let names = read_names(&dirfd)?;
    if !marked
        && names
            .iter()
            .any(|name| name.as_bytes() != RETIRED_MARKER.as_bytes())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "it no longer carries the mark that said it was finished with, and it is not \
             empty either",
        ));
    }

    for name in &names {
        if name.as_bytes() == RETIRED_MARKER.as_bytes() {
            continue;
        }
        match rustix::fs::unlinkat(&dirfd, name.as_c_str(), AtFlags::empty()) {
            // Gone already is the outcome this wanted.
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            // A directory: EISDIR on Linux, EPERM on the BSDs and macOS. Both answers are
            // about the inode the handle names, so neither can have been redirected — and
            // neither is entered.
            Err(rustix::io::Errno::ISDIR | rustix::io::Errno::PERM) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "it has a directory inside it, which a retired chunk environment never \
                     has. Whatever it is, this build will not walk into it",
                ))
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Asked once more, on the same handle, before the one irreversible step. `read_names` is a
    // listing, not a snapshot: anything created while the loop above ran is not in it and is
    // still here. Removing the mark over it is exactly the state the ordering exists to
    // prevent — an unmarked directory with something in it, which every later start keeps.
    if !is_empty_but_for_the_mark(&dirfd)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "something was created in it while it was being emptied, so the mark stays and \
             the next start looks again",
        ));
    }

    // Now, and only now, the thing that said it was safe to do any of the above.
    match rustix::fs::unlinkat(&dirfd, RETIRED_MARKER, AtFlags::empty()) {
        // Already gone is success: the directory qualified by being empty, or something else
        // finished this.
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Open a directory, refusing a link or anything that is not one, on the handle.
#[cfg(unix)]
fn open_dir_nofollow(dir: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        // A link, or something that is not a directory at all, arrives here as ELOOP or
        // ENOTDIR. Both mean the same thing to this caller and it is worth saying which.
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is no longer the directory that was found to be finished with ({e})",
                dir.display()
            ),
        )
    })
}

/// Is there anything in here besides the mark?
#[cfg(unix)]
fn is_empty_but_for_the_mark(dirfd: &std::os::fd::OwnedFd) -> std::io::Result<bool> {
    Ok(read_names(dirfd)?
        .iter()
        .all(|name| name.as_bytes() == RETIRED_MARKER.as_bytes()))
}

/// Every name in a directory handle, without `.` and `..`, and never more than a leftover has.
///
/// Collected rather than streamed, because unlinking while a directory stream is open is not
/// something any filesystem promises to keep coherent. It is a listing and not a snapshot, so
/// the caller asks again before the step it cannot take back.
#[cfg(unix)]
fn read_names(dirfd: &std::os::fd::OwnedFd) -> std::io::Result<Vec<std::ffi::CString>> {
    let mut names = Vec::new();
    let dir = rustix::fs::Dir::read_from(dirfd)?;
    for entry in dir {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if names.len() >= MAX_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "it holds more than {MAX_ENTRIES} entries, which a retired chunk \
                     environment never does"
                ),
            ));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

/// The path-based version, for the platforms with no `unlinkat`.
///
/// The same refusals and the same re-check, so the two do not drift on anything but the window
/// between naming a path and acting on it, which is what `unlinkat` closes and this cannot.
#[cfg(not(unix))]
fn empty_and_unmark(dir: &Path) -> std::io::Result<()> {
    if !matches!(std::fs::symlink_metadata(dir), Ok(meta) if meta.is_dir()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "it is no longer the directory that was found to be finished with",
        ));
    }
    let marked = matches!(
        std::fs::symlink_metadata(dir.join(RETIRED_MARKER)),
        Ok(meta) if meta.is_file()
    );
    let names = read_names_by_path(dir)?;
    if !marked && names.iter().any(|name| name != RETIRED_MARKER) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "it no longer carries the mark that said it was finished with, and it is not \
             empty either",
        ));
    }
    for name in &names {
        if name == RETIRED_MARKER {
            continue;
        }
        let path = dir.join(name);
        if matches!(std::fs::symlink_metadata(&path), Ok(meta) if meta.is_dir()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "it has a directory inside it, which a retired chunk environment never has. \
                 Whatever it is, this build will not walk into it",
            ));
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if read_names_by_path(dir)?
        .iter()
        .any(|name| name != RETIRED_MARKER)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "something was created in it while it was being emptied, so the mark stays and \
             the next start looks again",
        ));
    }
    match std::fs::remove_file(dir.join(RETIRED_MARKER)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Every name in a directory, and never more than a leftover has.
#[cfg(not(unix))]
fn read_names_by_path(dir: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        if names.len() >= MAX_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "it holds more than {MAX_ENTRIES} entries, which a retired chunk \
                     environment never does"
                ),
            ));
        }
        names.push(entry?.file_name());
    }
    Ok(names)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::storage::migration_signal::{is_tombstone_name, LEGACY_ENV_DIR, MAX_TOMBSTONES};
    use tempfile::TempDir;

    /// The deletion runs on its own thread.
    fn wait_gone(path: &Path) -> bool {
        for _ in 0..200 {
            if !path.exists() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        false
    }

    fn settle() {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    fn env_with_chunks(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.mdb"), b"chunks").unwrap();
        dir
    }

    /// A socket at `path`, for the one type test that needs one.
    #[cfg(unix)]
    fn bind_socket(path: &Path) {
        std::os::unix::net::UnixListener::bind(path).expect("bind");
    }

    fn mark_retired(dir: &Path) {
        std::fs::write(dir.join(RETIRED_MARKER), b"retired").unwrap();
    }

    /// The property this module exists for: whatever is on disk, the node runs.
    #[test]
    fn nothing_here_can_stop_a_node_starting() {
        let root = TempDir::new().unwrap();
        env_with_chunks(root.path(), LEGACY_ENV_DIR);
        env_with_chunks(root.path(), "chunks.mdb.retired.2");
        std::fs::create_dir_all(root.path().join("chunks.mdb.retired")).unwrap();

        // No Result to unwrap: there is no way for this to refuse.
        clean_up(root.path());
        settle();
    }

    #[test]
    fn a_root_that_does_not_exist_yet_is_fine() {
        let root = TempDir::new().unwrap();
        clean_up(&root.path().join("not").join("created"));
    }

    /// The one this release is for: a store the migration finished with but did not delete.
    #[test]
    fn a_store_the_migration_finished_with_is_removed() {
        let root = TempDir::new().unwrap();
        let env = env_with_chunks(root.path(), LEGACY_ENV_DIR);
        mark_retired(&env);
        clean_up(root.path());
        assert!(wait_gone(&env));
    }

    #[test]
    fn a_marked_tombstone_is_removed_too() {
        let root = TempDir::new().unwrap();
        let tomb = env_with_chunks(root.path(), "chunks.mdb.retired.7");
        mark_retired(&tomb);
        clean_up(root.path());
        assert!(wait_gone(&tomb));
    }

    #[test]
    fn an_empty_leftover_is_removed() {
        // What a cleanup interrupted between emptying a tombstone and removing it leaves.
        let root = TempDir::new().unwrap();
        let tomb = root.path().join("chunks.mdb.retired");
        std::fs::create_dir_all(&tomb).unwrap();
        clean_up(root.path());
        assert!(wait_gone(&tomb));
    }

    /// A marked directory goes even though its bytes are in no file store on this node.
    ///
    /// This is the case the record used to describe wrongly, and the tests used to conceal by
    /// never staging a file store at all: they showed that a mark triggers deletion, which
    /// leaves a reader free to assume the deleted bytes had been copied somewhere first.
    ///
    /// They need not have been. Retirement cleared a directory on two grounds, and only one is
    /// a local copy: chunks the node KEPT were copied into the file store and re-hashed there,
    /// and chunks it SHED were proven held by its close group and then deliberately not copied
    /// — the pre-retirement pass skips exactly those keys. So the state staged here, a marked
    /// directory beside an empty file store, is one the previous release produces on purpose on
    /// any node that was short of disk, and it is reachable through its own kill point between
    /// writing the mark and finishing the delete.
    ///
    /// Removing it is right: the previous release was about to. What this pins is that the
    /// deletion does NOT depend on a local copy existing, so nobody later "fixes" it by adding
    /// a file-store check that would strand every shedding node's directory for ever.
    #[test]
    fn a_marked_store_goes_even_when_nothing_was_copied_into_this_node() {
        let root = TempDir::new().unwrap();
        let env = env_with_chunks(root.path(), LEGACY_ENV_DIR);
        mark_retired(&env);

        // No file store, and nothing in one. A node that shed everything it held looks exactly
        // like this.
        assert!(!root.path().join("chunks").exists());

        clean_up(root.path());
        assert!(
            wait_gone(&env),
            "a marked directory must go whether or not this node kept a copy: the close \
             group's possession proofs are what cleared it, not a local file"
        );
    }

    /// The one that would be data loss.
    ///
    /// A node that missed the previous release entirely arrives here with every chunk it
    /// owns in that directory and nothing in the file store, and the upgrade monitor picks
    /// the newest release rather than the next one, so this build is genuinely reachable
    /// from that state. Unmarked is the whole difference from the test above: nothing
    /// cleared this directory, so nothing here may remove it.
    #[test]
    fn a_store_that_was_never_migrated_is_left_exactly_where_it_is() {
        let root = TempDir::new().unwrap();
        let env = env_with_chunks(root.path(), LEGACY_ENV_DIR);
        clean_up(root.path());
        settle();
        assert!(
            env.join("data.mdb").exists(),
            "an unmarked store passed no retirement gate, and was deleted anyway"
        );
    }

    #[test]
    fn an_unmarked_tombstone_with_chunks_in_it_is_left_too() {
        // A crash between the rename and the mark leaves an intact environment wearing a
        // retired-looking name. What it is called is not evidence.
        let root = TempDir::new().unwrap();
        let tomb = env_with_chunks(root.path(), "chunks.mdb.retired.3");
        clean_up(root.path());
        settle();
        assert!(tomb.join("data.mdb").exists());
    }

    /// A name is not evidence, and this decides what gets deleted.
    #[test]
    fn a_directory_that_only_looks_like_a_tombstone_is_left_alone() {
        let root = TempDir::new().unwrap();
        let mine = env_with_chunks(root.path(), "chunks.mdb.retired-keep-this");
        mark_retired(&mine);
        let also = env_with_chunks(root.path(), "chunks.mdb.backup");
        mark_retired(&also);
        let high = env_with_chunks(root.path(), "chunks.mdb.retired.65");
        mark_retired(&high);
        let padded = env_with_chunks(root.path(), "chunks.mdb.retired.007");
        mark_retired(&padded);

        clean_up(root.path());
        settle();
        for kept in [&mine, &also, &high, &padded] {
            assert!(
                kept.exists(),
                "{} was deleted and nothing here created it",
                kept.display()
            );
        }

        assert!(is_tombstone_name("chunks.mdb.retired"));
        assert!(is_tombstone_name("chunks.mdb.retired.1"));
        assert!(is_tombstone_name("chunks.mdb.retired.64"));
        assert!(!is_tombstone_name("chunks.mdb.retired.65"));
        assert!(!is_tombstone_name("chunks.mdb.retired.0"));
        assert!(!is_tombstone_name("chunks.mdb.retired.007"));
        assert!(!is_tombstone_name("chunks.mdb.retired-keep-this"));
        assert!(!is_tombstone_name("chunks.mdb.retired."));
        assert!(!is_tombstone_name("chunks.mdb.retired.x"));
    }

    /// The name is reserved, but only a file R2 could have written is evidence.
    #[test]
    fn something_else_wearing_the_marks_name_is_not_the_mark() {
        let root = TempDir::new().unwrap();
        let env = env_with_chunks(root.path(), LEGACY_ENV_DIR);
        // A directory at the reserved name, which `try_exists` cannot tell from the file
        // retirement writes. Believing it deletes an unmigrated store.
        std::fs::create_dir_all(env.join(RETIRED_MARKER)).unwrap();

        clean_up(root.path());
        settle();
        assert!(
            env.join("data.mdb").exists(),
            "a directory called RETIRED authorised deleting an unmigrated store"
        );
    }

    /// The mark is removed last, so an interrupted deletion is still recognisable.
    ///
    /// `remove_dir_all` promises nothing about order. If the mark went first and the process
    /// stopped there, the next start would find an unmarked directory with data in it, treat
    /// it as a store that was never migrated, and keep it for good — and the node would
    /// report itself unfinished to the whole network for as long as it lived.
    #[test]
    fn the_mark_outlives_everything_it_was_vouching_for() {
        let root = TempDir::new().unwrap();
        let env = env_with_chunks(root.path(), LEGACY_ENV_DIR);
        std::fs::write(env.join("lock.mdb"), b"lock").unwrap();
        mark_retired(&env);

        // The deletion, run inline so its intermediate states can be inspected rather than
        // raced.
        delete_mark_last(&env).unwrap();
        assert!(!env.exists());

        // And the order it does it in: with the directory made unremovable, the mark has to
        // still be there when the attempt fails.
        let other = TempDir::new().unwrap();
        let env = env_with_chunks(other.path(), LEGACY_ENV_DIR);
        mark_retired(&env);
        let nested = env.join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("data.mdb"), b"chunks").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o500)).unwrap();
            let failed = delete_mark_last(&env);
            std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(failed.is_err(), "the deletion was supposed to fail here");
            assert!(
                env.join(RETIRED_MARKER).exists(),
                "the mark went before the chunks did, so the next start cannot tell this \
                 directory was already finished with"
            );
        }
    }

    /// The deleting thread asks again rather than trusting a path it was handed.
    ///
    /// What is at a path is not a property of the path. The classification happened on
    /// another thread and is already in the past, so between the two moments the directory
    /// can be replaced with a link to somewhere else, and following it would delete through
    /// it. Staged directly here because a real race is not reproducible in a test.
    #[cfg(unix)]
    #[test]
    fn the_deleting_thread_refuses_a_path_that_is_no_longer_what_was_classified() {
        let root = TempDir::new().unwrap();
        let elsewhere = env_with_chunks(root.path(), "elsewhere");
        // MARKED, and that is the whole point of this test. An unmarked target would be
        // refused by the gates even by a deleter that happily followed the link, so the test
        // would pass while proving nothing about following it. Marked, the target satisfies
        // every gate: anything that reaches it through the link deletes it.
        mark_retired(&elsewhere);
        let swapped = root.path().join(LEGACY_ENV_DIR);
        std::os::unix::fs::symlink(&elsewhere, &swapped).unwrap();

        assert!(
            delete_mark_last(&swapped).is_err(),
            "the deletion followed a link that appeared after the classification"
        );
        assert!(
            elsewhere.join("data.mdb").exists(),
            "the link was followed and the contents of somewhere else were deleted"
        );
        assert!(elsewhere.join(RETIRED_MARKER).exists());

        // And a directory that lost its mark in between: it might be a store nothing
        // migrated, so it is not deleted on the strength of an answer given earlier.
        let unmarked = env_with_chunks(root.path(), "chunks.mdb.retired.9");
        assert!(delete_mark_last(&unmarked).is_err());
        assert!(unmarked.join("data.mdb").exists());
    }

    /// A link never yields a directory handle, which is what leaves no window to win.
    ///
    /// The test above stages a link that is already there when the deletion starts, and the
    /// path-based version caught that too, by asking `symlink_metadata` first. What it could
    /// not catch is a link that arrives *between* that question and the `read_dir` that acted
    /// on the answer: `read_dir` resolves the path again and follows what it finds. A local
    /// actor with write access to the node's data directory could point that name at a target
    /// elsewhere on the disk, and the node — which reaches more of the filesystem than the
    /// actor does, and on plenty of installations runs as root — would empty the target
    /// instead. Not one more way to lose data inside the data directory: a way out of it.
    ///
    /// That interleaving cannot be staged from a test without instrumenting the deleter, so
    /// what is pinned here is the primitive that removes the window rather than the race
    /// itself. The directory is opened once, and every unlink is made against that handle, so
    /// if a link can never produce a handle then no unlink can ever be redirected through one.
    /// This is the "can never produce a handle" half, and it is the half that a change would
    /// silently undo: drop `O_NOFOLLOW` and the open below starts succeeding.
    #[cfg(unix)]
    #[test]
    fn a_link_never_yields_a_directory_handle() {
        let root = TempDir::new().unwrap();
        let real = env_with_chunks(root.path(), "real");

        assert!(
            open_dir_nofollow(&real).is_ok(),
            "a directory that is what it says it is has to open, or nothing is ever cleaned up"
        );

        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            open_dir_nofollow(&link).is_err(),
            "a link produced a handle, so every unlink made against it lands on the target"
        );

        // The other thing that must never be mistaken for a store. A FIFO would block a
        // plain open forever; refusing on the handle refuses it without opening it.
        let not_a_dir = root.path().join("file");
        std::fs::write(&not_a_dir, b"x").unwrap();
        assert!(open_dir_nofollow(&not_a_dir).is_err());
    }

    /// Only a regular file is the mark. A link wearing its name is not, and neither is a socket.
    ///
    /// This is a type test, and the arithmetic is the whole of it. `S_IFLNK` and `S_IFSOCK` each
    /// contain every bit of `S_IFREG`, so `st_mode & S_IFREG == S_IFREG` is true for all three
    /// and is not a test for a regular file at all. Masking with `S_IFMT` is.
    ///
    /// What it costs to get wrong: the classifier on the main thread can call a leftover
    /// harmless while it is empty, and between that and the worker opening it, a restore or a
    /// local actor can fill it with a store nothing migrated and drop a symlink called `RETIRED`
    /// beside the contents. The worker asks again — that re-ask is the whole reason it exists —
    /// and a mask that accepts a link answers yes, and the store goes.
    ///
    /// Asserted against `delete_mark_last` rather than against the classifier, because the
    /// classifier is not where the re-ask happens and a test on it cannot see this.
    #[cfg(unix)]
    #[test]
    fn only_a_regular_file_is_the_mark_when_the_deleting_thread_asks() {
        let root = TempDir::new().unwrap();

        // A link at the mark's name, pointing at a real regular file so that following it
        // would find one.
        let linked = env_with_chunks(root.path(), "chunks.mdb.retired.11");
        let real_file = root.path().join("somewhere-else");
        std::fs::write(&real_file, b"not the mark").unwrap();
        std::os::unix::fs::symlink(&real_file, linked.join(RETIRED_MARKER)).unwrap();

        assert!(
            delete_mark_last(&linked).is_err(),
            "a symlink was accepted as the mark, which authorises deleting an unmigrated store"
        );
        assert!(
            linked.join("data.mdb").exists(),
            "and the store it was guarding is gone"
        );

        // A socket at the mark's name. Same arithmetic, different type.
        let socketed = env_with_chunks(root.path(), "chunks.mdb.retired.12");
        bind_socket(&socketed.join(RETIRED_MARKER));
        assert!(
            delete_mark_last(&socketed).is_err(),
            "a socket was accepted as the mark"
        );
        assert!(socketed.join("data.mdb").exists());

        // And the real thing still works, or none of the above proves anything.
        let genuine = env_with_chunks(root.path(), "chunks.mdb.retired.13");
        mark_retired(&genuine);
        assert!(delete_mark_last(&genuine).is_ok());
        assert!(!genuine.exists());
    }

    /// A directory inside a leftover is refused, never entered.
    ///
    /// `O_NOFOLLOW` declines a trailing symlink and says nothing about a mount point, and
    /// `openat` walks into one without complaint. A retired chunk environment is flat — two
    /// files and a mark — so a directory inside one is already something this build does not
    /// understand, and descending into it could empty a filesystem that has nothing to do with
    /// this node. Refusing also leaves no recursion to bound and no cycle a bind mount could
    /// build.
    #[test]
    fn a_directory_inside_a_leftover_is_refused_rather_than_entered() {
        let root = TempDir::new().unwrap();
        let env = env_with_chunks(root.path(), LEGACY_ENV_DIR);
        mark_retired(&env);
        let inside = env.join("somewhere");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::write(inside.join("not-ours"), b"another filesystem's problem").unwrap();

        assert!(
            delete_mark_last(&env).is_err(),
            "a directory inside a leftover was walked into"
        );
        assert!(
            inside.join("not-ours").exists(),
            "and its contents were deleted"
        );
        assert!(
            env.join(RETIRED_MARKER).exists(),
            "the mark has to survive a refusal, or the next start cannot tell what this is"
        );
    }

    /// A listing is not a snapshot, so the mark is not removed over something that arrived late.
    ///
    /// The names are read once and then unlinked one by one. Anything created after that read
    /// is not in the list and is still there when the loop finishes. Removing the mark over it
    /// leaves an unmarked directory with something in it, which is the exact state the ordering
    /// exists to prevent and which every later start then keeps for good.
    ///
    /// The real interleaving needs a write between the read and the mark's removal; staged here
    /// by leaving an entry the loop was never told about, which is the same state it produces.
    #[test]
    fn the_mark_is_not_removed_over_an_entry_that_arrived_late() {
        let root = TempDir::new().unwrap();
        let env = env_with_chunks(root.path(), LEGACY_ENV_DIR);
        mark_retired(&env);

        // A name the loop cannot unlink, so the directory is still non-empty when the re-ask
        // happens. What matters is the answer to that re-ask, not how the entry got there.
        let stubborn = env.join("arrived-late");
        std::fs::create_dir_all(&stubborn).unwrap();

        assert!(delete_mark_last(&env).is_err());
        assert!(
            env.join(RETIRED_MARKER).exists(),
            "the mark went while the directory still had something in it, so the next start \
             sees an unmigrated store and keeps it for ever"
        );
    }

    /// A directory far wider than any leftover is refused rather than read into memory.
    #[test]
    fn an_implausibly_wide_leftover_is_refused() {
        let root = TempDir::new().unwrap();
        let env = root.path().join(LEGACY_ENV_DIR);
        std::fs::create_dir_all(&env).unwrap();
        mark_retired(&env);
        for n in 0..(MAX_ENTRIES + 8) {
            std::fs::write(env.join(format!("e{n}")), b"x").unwrap();
        }

        assert!(
            delete_mark_last(&env).is_err(),
            "a directory with more entries than any leftover has was read in full"
        );
        assert!(env.join(RETIRED_MARKER).exists());
    }

    /// The cleanup removes exactly what the fleet signal calls finished with, and nothing else.
    ///
    /// This is the property that lets the previous release's count authorise this one. That
    /// count is each node reporting `files` when nothing under its root is `Leftover::Holding`
    /// or `Leftover::Unreadable`. If this release deleted anything the signal would not have
    /// called harmless, a node could destroy a directory it was still reporting as unfinished;
    /// if it kept something the signal called harmless, a node would report `files` and go on
    /// paying for the disk for ever.
    ///
    /// They cannot disagree today because there is one `classify`. This is what fails if
    /// somebody gives the cleanup its own again: every shape below is checked both ways round,
    /// so a classifier that is wrong in either direction shows up here rather than on a fleet.
    #[test]
    fn the_cleanup_removes_exactly_what_the_signal_calls_finished_with() {
        let root = TempDir::new().unwrap();
        let base = root.path();

        // Every shape a real root can present, harmless and not, with the near misses that
        // are not this release's to touch at all.
        let marked_live = env_with_chunks(base, LEGACY_ENV_DIR);
        mark_retired(&marked_live);
        let marked_tomb = env_with_chunks(base, "chunks.mdb.retired.5");
        mark_retired(&marked_tomb);
        let empty_tomb = base.join("chunks.mdb.retired");
        std::fs::create_dir_all(&empty_tomb).unwrap();
        let unmarked_tomb = env_with_chunks(base, "chunks.mdb.retired.6");
        let fake_mark = env_with_chunks(base, "chunks.mdb.retired.7");
        std::fs::create_dir_all(fake_mark.join(RETIRED_MARKER)).unwrap();
        let near_miss = env_with_chunks(base, "chunks.mdb.retired.65");
        mark_retired(&near_miss);
        let operators = env_with_chunks(base, "chunks.mdb.retired-keep-this");
        mark_retired(&operators);

        // Not a directory at all, wearing a name in the set. The marker probe cannot even be
        // asked of it, so it classifies unreadable and must be kept.
        let not_a_dir = base.join("chunks.mdb.retired.8");
        std::fs::write(&not_a_dir, b"not a store").unwrap();

        // A link wearing a name in the set. What is behind it is somebody else's, and neither
        // following it nor unlinking it is this build's decision.
        #[cfg(unix)]
        let linked = {
            let elsewhere = env_with_chunks(base, "elsewhere-for-the-link");
            mark_retired(&elsewhere);
            let link = base.join("chunks.mdb.retired.9");
            std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
            (link, elsewhere)
        };

        // What the signal says about each, before anything is removed. Every classification
        // the enum can produce is represented: Harmless three ways, Holding two, Unreadable
        // two.
        // The `mut` is used only where the link below exists, which is not everywhere.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut considered = vec![
            &marked_live,
            &marked_tomb,
            &empty_tomb,
            &unmarked_tomb,
            &fake_mark,
            &not_a_dir,
        ];
        #[cfg(unix)]
        considered.push(&linked.0);
        let verdicts: Vec<_> = considered.iter().map(|dir| (*dir, classify(dir))).collect();

        clean_up(base);
        settle();

        for (dir, verdict) in verdicts {
            let gone = !dir.exists();
            assert_eq!(
                gone,
                verdict == Leftover::Harmless,
                "{} was classified {verdict:?} and {} removed",
                dir.display(),
                if gone { "was" } else { "was not" }
            );
        }

        // And the names outside the set are not classified at all, so they are never even
        // considered for deletion.
        for untouched in [&near_miss, &operators] {
            assert!(
                untouched.join("data.mdb").exists(),
                "{} is not a name retirement can have created",
                untouched.display()
            );
        }

        // A link is kept as a link, and what it points at keeps its data: following it would
        // delete storage this node does not own, unlinking it would throw away the only record
        // of where that data went.
        #[cfg(unix)]
        {
            let (link, elsewhere) = &linked;
            assert!(
                std::fs::symlink_metadata(link).is_ok(),
                "the link was removed"
            );
            assert!(
                elsewhere.join("data.mdb").exists(),
                "the link was followed and somebody else's data was deleted"
            );
        }
    }

    /// Sixty-six leftovers are removed one after another, on one thread.
    ///
    /// The accepted names are the live directory, the unnumbered tombstone and sixty-four
    /// numbered ones. A thread each would put sixty-six recursive deletions on the disk that
    /// is also serving chunks, at the moment the node is starting.
    #[test]
    fn every_leftover_a_root_can_hold_is_removed_without_a_thread_each() {
        let root = TempDir::new().unwrap();
        let base = root.path();

        let mut staged = vec![env_with_chunks(base, LEGACY_ENV_DIR)];
        staged.push(env_with_chunks(base, "chunks.mdb.retired"));
        for n in 1..=MAX_TOMBSTONES {
            staged.push(env_with_chunks(base, &format!("chunks.mdb.retired.{n}")));
        }
        assert_eq!(staged.len(), 66, "the accepted namespace is this big");
        for dir in &staged {
            mark_retired(dir);
        }

        let before = std::thread::available_parallelism().is_ok();
        clean_up(base);
        assert!(before, "sanity: the platform reports its parallelism");

        for dir in &staged {
            assert!(
                wait_gone(dir),
                "{} was finished with and is still there",
                dir.display()
            );
        }
    }

    /// A root that cannot be listed removes nothing, and says so.
    ///
    /// An unlistable root hides every tombstone under it, so it is not evidence that there is
    /// nothing to keep. An earlier version returned silently here, which left the decision
    /// record promising a warning that no code emitted.
    #[cfg(unix)]
    #[test]
    fn a_root_that_cannot_be_listed_removes_nothing() {
        use std::os::unix::fs::PermissionsExt;

        let root = TempDir::new().unwrap();
        let base = root.path().join("locked");
        std::fs::create_dir_all(&base).unwrap();
        let env = env_with_chunks(&base, LEGACY_ENV_DIR);
        mark_retired(&env);

        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o000)).unwrap();
        clean_up(&base);
        settle();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            env.join("data.mdb").exists(),
            "a root that could not be listed had something removed from it anyway"
        );
    }

    /// What a link points at belongs to somebody else, and is never followed or removed.
    #[cfg(unix)]
    #[test]
    fn a_linked_environment_is_left_exactly_as_it_is() {
        let root = TempDir::new().unwrap();
        let elsewhere = env_with_chunks(root.path(), "elsewhere");
        mark_retired(&elsewhere);
        let link = root.path().join(LEGACY_ENV_DIR);
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

        clean_up(root.path());
        settle();

        assert!(
            std::fs::symlink_metadata(&link).is_ok(),
            "the link itself was removed, which throws away the only record of where the \
             data went"
        );
        assert!(
            elsewhere.join("data.mdb").exists(),
            "the link was followed and somebody else's data was deleted"
        );
    }
}
