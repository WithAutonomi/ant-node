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
//! that mark has already had its contents copied out and is pure cost. So is an empty one,
//! which is what a cleanup interrupted between emptying a tombstone and removing it leaves.
//! Those go, and their disk comes back. Anything else stays exactly where it is, and is
//! named once so an operator can decide.
//!
//! That is the answer the previous release's fleet signal is designed around: it reports
//! which nodes still have an unfinished store, and this release is published when that count
//! is clean. The nodes this leaves a directory on are the ones that count missed, and leaving
//! it is what keeps their data recoverable.
//!
//! Two things are never done, both because a name is not evidence of what is behind it. A
//! link is neither followed nor unlinked: what is behind it is on storage this node does not
//! own. And only the exact names the previous release created are considered at all.

use crate::logging::{info, warn};
use std::path::{Path, PathBuf};

/// The directory the old chunk store lived in.
pub const LEGACY_ENV_DIR: &str = "chunks.mdb";

/// What retirement renamed it to before deleting it.
pub const RETIRED_SUFFIX: &str = ".retired";

/// The file retirement wrote inside a directory to say it had finished with it.
const RETIRED_MARKER: &str = "RETIRED";

/// The most tombstones the previous release will ever have created.
const MAX_TOMBSTONES: u32 = 64;

/// Remove what the storage migration finished with, and start either way.
///
/// Returns nothing and fails at nothing. Every outcome is a node that runs: the worst case
/// is a directory left where it is, which costs disk, is said out loud, and is a far better
/// place to be than a node that will not start.
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
    for dir in leftovers(root_dir) {
        match classify(&dir) {
            // Its chunks are in the file store and the previous release simply did not
            // finish deleting it, or there is nothing in it at all. Either way it holds
            // nothing, so removing it cannot lose anything.
            Verdict::FinishedWith => remove(dir),
            Verdict::Keep(reason) => warn!(
                migration_event = "legacy_store_left",
                "{} is left over from the storage migration and this build will not remove \
                 it: {reason}. It is costing disk until it is dealt with by hand.",
                dir.display()
            ),
        }
    }
}

/// What one leftover directory means.
enum Verdict {
    /// It provably holds no chunks, so it is pure cost.
    FinishedWith,
    /// It might hold chunks, or nothing here can tell. Left alone, with the reason.
    Keep(&'static str),
}

/// Every leftover of the old chunk store under `root_dir`, live name and tombstones alike.
///
/// Matched by exact name. Retirement only ever created `chunks.mdb`, `chunks.mdb.retired`,
/// or `chunks.mdb.retired.<n>` for `n` in `1..=64`, and what this returns is considered for
/// deletion: a prefix match would also claim a `chunks.mdb.retired-keep-this` that somebody
/// put there on purpose.
fn leftovers(root_dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();

    // `symlink_metadata`, not `try_exists`: the latter follows links, so a dangling or
    // looping one at the live name would read as nothing being there at all.
    let live = root_dir.join(LEGACY_ENV_DIR);
    if !matches!(
        std::fs::symlink_metadata(&live),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound
    ) {
        found.push(live);
    }

    let Ok(entries) = std::fs::read_dir(root_dir) else {
        // A root that is not there yet holds nothing, and one that cannot be listed is a
        // problem the store's own constructor reports far better than this can.
        return found;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_str().is_some_and(is_tombstone_name) {
            found.push(entry.path());
        }
    }
    found
}

/// Is this a name retirement gave a tombstone?
///
/// The bounds are not decoration: retirement only ever counted up to 64, so `.65` and `.007`
/// are names it cannot have produced, and this decides what gets deleted.
fn is_tombstone_name(name: &str) -> bool {
    let base = format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}");
    if name == base {
        return true;
    }
    let Some(suffix) = name.strip_prefix(&format!("{base}.")) else {
        return false;
    };
    // Parsed and written back out, so a leading zero or a plus sign fails to match itself.
    suffix
        .parse::<u32>()
        .is_ok_and(|n| (1..=MAX_TOMBSTONES).contains(&n) && suffix == n.to_string())
}

/// Decide what one leftover is, erring every way towards keeping it.
fn classify(dir: &Path) -> Verdict {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        // Gone between listing and looking. Nothing to do and nothing to say.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Verdict::FinishedWith,
        Err(_) => return Verdict::Keep("it cannot be examined"),
    };

    // Behind a link is a directory on storage this node does not own. Following it would
    // delete somebody else's data; unlinking it would throw away the only record of where
    // that data went. Neither is this build's decision to make.
    if meta.file_type().is_symlink() {
        return Verdict::Keep("it is a link to storage this node does not own");
    }
    if !meta.is_dir() {
        return Verdict::Keep("it is not a directory");
    }

    // The mark the previous release wrote inside the directory before it deleted anything.
    // It is the only durable evidence there is that the chunks were copied out.
    //
    // A regular file, not merely something at that name. Retirement writes it with
    // `create_new`, so it is always an ordinary file; a directory, a link, a FIFO or anything
    // else wearing the name proves nothing, and this answer is what authorises deleting every
    // chunk underneath it.
    match std::fs::symlink_metadata(dir.join(RETIRED_MARKER)) {
        Ok(meta) if meta.is_file() => return Verdict::FinishedWith,
        Ok(_) => {
            return Verdict::Keep(
                "something that is not the storage migration's mark is using the name the \
                 mark would have, so this node cannot tell whether it was finished with",
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Verdict::Keep("whether it was finished with cannot be established"),
    }

    // No mark. A directory with nothing in it holds no chunks, so it cannot be hiding any:
    // that is what a cleanup interrupted between emptying a tombstone and removing it
    // leaves behind. Anything else might be a whole node's chunks, and is kept.
    std::fs::read_dir(dir).map_or(
        Verdict::Keep("what is in it cannot be established"),
        |mut entries| {
            if entries.next().is_none() {
                Verdict::FinishedWith
            } else {
                Verdict::Keep(
                    "it has chunks in it that were never copied into the file store, and \
                     this build cannot read them. Nothing here will delete them, so they \
                     are not lost. Whether this node's close group still needs them is the \
                     question to answer before removing it by hand",
                )
            }
        },
    )
}

/// Delete a directory that provably holds no chunks.
///
/// In the background and in place. Nothing has to be got out of the way first: this
/// directory holds nothing, and this build has no code that would read it if it did. Not
/// renaming also means no name to allocate, which is what an earlier version of this could
/// run out of and wedge itself on.
fn remove(dir: PathBuf) {
    let spawned = std::thread::Builder::new()
        .name("legacy-store-cleanup".into())
        .spawn(move || match delete_mark_last(&dir) {
            // Said only once the deletion has finished. Announcing the space before it is
            // back is how an operator comes to trust a number that is wrong for the next
            // several minutes.
            Ok(()) => info!(
                migration_event = "space_returned",
                "Removed {}, which the storage migration had finished with, and returned \
                 its space.",
                dir.display()
            ),
            Err(e) => warn!(
                migration_event = "legacy_store_left",
                "{} was finished with by the storage migration but could not be removed \
                 ({e}). It is costing disk. The next start tries again.",
                dir.display()
            ),
        });
    if let Err(e) = spawned {
        warn!("Could not start the storage migration's cleanup thread: {e}");
    }
}

/// Empty a directory, then remove its mark, then remove the directory.
///
/// The order is the whole of it. `remove_dir_all` gives no promise about which entry it
/// unlinks first, and the mark is the only thing that says this directory was finished with:
/// if it goes before the chunks do and the process stops there, the next start finds an
/// unmarked directory with data in it, decides it might be an unmigrated store, and keeps it
/// forever. It is not one, but nothing on disk says so any more, and the node then reports
/// itself as unfinished to the whole network for as long as it lives.
///
/// Done this way there is no such moment. At every point either the mark is still there, and
/// the next start resumes, or the directory is empty or gone, which is also finished with.
///
/// What this does NOT close, and does not pretend to: the checks above name a path, and the
/// unlinking below names it again. Anything that can replace the directory between the two
/// wins. Closing that properly needs a directory handle held across the whole operation and
/// `unlinkat` against it, which Rust's standard library does not offer portably. It is
/// accepted rather than half-fixed, on the ground that whoever can win that race already has
/// write access to this node's data directory and does not need the race to delete anything
/// in it.
fn delete_mark_last(dir: &Path) -> std::io::Result<()> {
    // Asked again, here, on the thread that does the deleting. The classification that got
    // this path happened on another thread and is already in the past, and what is at a path
    // is not a property of the path: swap the directory for a link between the two moments
    // and everything below would follow it and delete through it. Cheap to re-ask, and the
    // thing being asked about is the deletion of every chunk under this name.
    if !matches!(std::fs::symlink_metadata(dir), Ok(meta) if meta.is_dir()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "it is no longer the directory that was found to be finished with",
        ));
    }
    // And the same two things `classify` accepted: it carries the mark, or it is empty.
    let marked = matches!(
        std::fs::symlink_metadata(dir.join(RETIRED_MARKER)),
        Ok(meta) if meta.is_file()
    );
    if !marked && std::fs::read_dir(dir)?.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "it no longer carries the mark that said it was finished with, and it is not \
             empty either",
        ));
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name() == RETIRED_MARKER {
            continue;
        }
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    // Now, and only now, the thing that said it was safe to do any of the above.
    match std::fs::remove_file(dir.join(RETIRED_MARKER)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::remove_dir(dir)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
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

    /// The one that would be data loss.
    ///
    /// A node that missed the previous release entirely arrives here with every chunk it
    /// owns in that directory and nothing in the file store, and the upgrade monitor picks
    /// the newest release rather than the next one, so this build is genuinely reachable
    /// from that state.
    #[test]
    fn a_store_that_was_never_migrated_is_left_exactly_where_it_is() {
        let root = TempDir::new().unwrap();
        let env = env_with_chunks(root.path(), LEGACY_ENV_DIR);
        clean_up(root.path());
        settle();
        assert!(
            env.join("data.mdb").exists(),
            "chunks that were never copied out were deleted"
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
        let swapped = root.path().join(LEGACY_ENV_DIR);
        std::os::unix::fs::symlink(&elsewhere, &swapped).unwrap();

        assert!(
            delete_mark_last(&swapped).is_err(),
            "the deletion followed a link that appeared after the classification"
        );
        assert!(elsewhere.join("data.mdb").exists());

        // And a directory that lost its mark in between: it might be a store nothing
        // migrated, so it is not deleted on the strength of an answer given earlier.
        let unmarked = env_with_chunks(root.path(), "chunks.mdb.retired.9");
        assert!(delete_mark_last(&unmarked).is_err());
        assert!(unmarked.join("data.mdb").exists());
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
