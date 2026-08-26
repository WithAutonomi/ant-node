//! What survives a process dying part-way through the migration.
//!
//! The design rests on being able to stop at any moment and start again: every step is
//! idempotent and re-derived from the filesystem. That is easy to assert and hard to
//! believe without trying it, so these tests kill a real child process at a real point in
//! the work and then open the store in this one and check what is there.
//!
//! **What this does and does not prove.** A killed process loses nothing the kernel has
//! already accepted, so this covers ordering and bookkeeping: a chunk is whole or absent
//! and never half-indexed, what an interrupted write leaves behind is swept, and the store
//! always opens. It does not cover losing the page cache, which is what a real power cut
//! adds and what no hosted runner can do. That remains a fleet gate, and this is the part
//! of it that can be automated.
//!
//! The children stop at a named failpoint and say so, and the parent kills them there. An
//! earlier version slept and hoped; on a quick machine the child had finished before the
//! kill arrived, so the test was checking a clean shutdown while claiming to check a
//! crash.
//!
//! Runs on every platform CI covers, which is the filesystem matrix that matters: ext4,
//! APFS and NTFS.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    // Test fixtures: every cast here is of a bounded loop counter into a byte, and the
    // wrap is what makes the fill vary.
    clippy::cast_possible_truncation
)]

use ant_node::storage::{ChunkStore, ChunkStoreConfig, LmdbStorage, LmdbStorageConfig};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

/// Chunks the child writes before it is killed.
const CHUNKS: usize = 120;

/// Deterministic content for chunk `n`. `n` goes in verbatim so no two differ only by a
/// wrap and collapse into one chunk.
fn chunk_bytes(n: usize) -> Vec<u8> {
    let mut content = vec![0u8; 4096];
    content[..8].copy_from_slice(&(n as u64).to_le_bytes());
    for (i, byte) in content.iter_mut().enumerate().skip(8) {
        *byte = ((i.wrapping_mul(17)).wrapping_add(n) % 251) as u8;
    }
    content
}

/// Run this test binary again as a child in the mode named by `role`, wait until it has
/// reached the named point, and kill it there.
///
/// A child process rather than a thread, because the point is to lose everything the
/// process was holding: buffers, in-memory index, locks, half-finished intentions.
///
/// The wait is a handshake, not a sleep. An earlier version of this slept and hoped, and
/// on a quick machine the child had finished everything before the kill arrived, so the
/// test was checking a clean shutdown while claiming to check a crash. The child now stops
/// at a failpoint inside the write and says so by writing a marker; this waits for the
/// marker and then kills it, so the process always dies at the same point in the same
/// operation.
fn kill_child_at_failpoint(role: &str, root: &Path, failpoint: &str, let_through: u64) -> PathBuf {
    let marker = root.join(format!("reached-{role}"));
    let _ = std::fs::remove_file(&marker);

    let exe = std::env::current_exe().expect("this test binary");
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg(role)
        .arg("--nocapture")
        .arg("--ignored")
        .env("ANT_CRASH_TEST_ROOT", root)
        .env(failpoint, &marker)
        .env(
            ant_node::storage::file_store::HALT_AFTER,
            let_through.to_string(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the child");

    // Generous, but not unbounded. Without a deadline a failpoint that stopped working
    // would hang the job rather than fail it, and a hang says nothing about the code.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while !marker.exists() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the child exited before reaching the failpoint: {status}");
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("the child never reached the failpoint");
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    child.kill().expect("kill the child");
    let _ = child.wait();
    marker
}

/// Where the child was told to work.
fn child_root() -> PathBuf {
    PathBuf::from(std::env::var("ANT_CRASH_TEST_ROOT").expect("the child needs a root"))
}

/// Child mode: write chunks into a file store until killed.
#[tokio::test]
#[ignore = "child process of a crash test, not run on its own"]
async fn child_writes_until_killed() {
    let root = child_root();
    let store = ChunkStore::new(ChunkStoreConfig {
        root_dir: root,
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    })
    .await
    .expect("open");

    // Always a chunk it has not written before, so the kill lands in real work rather
    // than in a re-offer of something already on disk. An earlier version cycled the same
    // hundred keys and spent almost all its time confirming duplicates.
    let mut n = 0usize;
    loop {
        let content = chunk_bytes(n);
        let address = ant_node::client::compute_address(&content);
        let _ = store.put(&address, &content).await;
        n += 1;
    }
}

/// Child mode: copy a legacy environment into files until killed.
#[tokio::test]
#[ignore = "child process of a crash test, not run on its own"]
async fn child_migrates_until_killed() {
    let root = child_root();
    let mut config = ChunkStoreConfig {
        root_dir: root.clone(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    config.migration.tick_secs = 1;
    config.migration.copier_throttle_mib_per_sec = 0;
    config.migration.copier_slack_mb = 0;
    config.migration.lock_dir = Some(root);
    let store = ChunkStore::new(config).await.expect("open");

    let shutdown = tokio_util::sync::CancellationToken::new();
    // One chunk at a time, so the kill lands between two of them rather than after the
    // whole thing. Deliberately no sleep at the end: a child that finished and then idled
    // would let this test pass having crashed nothing.
    loop {
        let keys = store.legacy_only_keys();
        let Some(key) = keys.first() else {
            break;
        };
        let _ = store.copy_batch(&[*key], 0, 0, &shutdown).await;
    }
    panic!("the child copied everything before it was killed, so nothing was interrupted");
}

/// Plant a legacy environment holding chunks numbered from `first`, and close it.
async fn seed_legacy_from(root: &Path, first: usize) -> Vec<(usize, [u8; 32])> {
    let lmdb = LmdbStorage::new(LmdbStorageConfig {
        root_dir: root.to_path_buf(),
        verify_on_read: true,
        max_map_size: 0,
        disk_reserve: 0,
    })
    .await
    .expect("open legacy");
    let mut keys = Vec::new();
    for n in first..first + CHUNKS {
        let content = chunk_bytes(n);
        let address = ant_node::client::compute_address(&content);
        lmdb.put(&address, &content).await.expect("seed");
        // Paired with its chunk number, because half of these are about to be deleted and
        // a bare position in the surviving list no longer says which chunk it is.
        keys.push((n, address));
    }

    // Then delete some, which is what makes this look like a real node rather than a
    // fresh file. The environment is pinned to its current size for the whole migration,
    // so a write during the bridge lands only if there are free pages to land in. On a
    // production node there are plenty: this migration exists precisely because deleting
    // millions of chunks filled the free list and returned nothing to the filesystem.
    // Seeded and never deleted from, the environment would have no room and the bridge's
    // second write would never happen, which is not the case worth testing.
    let discarded: Vec<(usize, [u8; 32])> = keys.drain(..CHUNKS / 2).collect();
    for (_, address) in &discarded {
        lmdb.delete(address).await.expect("make room");
    }
    lmdb.wait_idle().await;
    keys
}

/// Child mode: retire the legacy environment, and be killed once it is marked.
///
/// Everything before the mark is done here rather than in the parent, because the whole
/// point is that the process that wrote the mark is the one that dies.
#[tokio::test]
#[ignore = "child process of a crash test, not run on its own"]
async fn child_retires_until_killed() {
    let root = child_root();
    let store = reopen(&root).await;

    let shutdown = tokio_util::sync::CancellationToken::new();
    let keys = store.legacy_only_keys();
    store
        .copy_batch(&keys, 0, 0, &shutdown)
        .await
        .expect("copy every chunk");
    store.wait_idle().await;
    store.commit_to_files().expect("commit to the file set");
    store.note_commitment_rebuilt();
    store.note_commitment_rebuilt();
    store.force_migration_state(|state| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        state.committed_at_unix = Some(
            now.saturating_sub(ant_node::storage::migration::MIN_RETIRE_DELAY_HOURS * 3600 + 60),
        );
    });

    let proof = store
        .verify_before_retire(0, &shutdown)
        .await
        .expect("verify before retiring");
    // Parks inside this call, once the environment is renamed aside and marked.
    let _ = store
        .retire_legacy(
            &proof,
            &|_: &[u8; 32]| false,
            &std::collections::BTreeSet::new(),
        )
        .await;
    panic!("the child finished retiring without being killed, so nothing was interrupted");
}

/// A process killed inside a publish leaves no chunk it cannot serve.
///
/// The child is stopped at the last moment before the chunk's name exists on disk: on Unix
/// the bytes written to a temporary file with the rename not yet made, off Unix the point
/// before the file is created at all, since that platform writes under the final name
/// because a rename there carries no durability guarantee. The failure this guards against
/// is the same on both: a name outliving its bytes. The index is built from filenames at
/// startup, so a partial file wearing a real chunk name would be advertised, committed to,
/// and unservable.
#[tokio::test]
async fn a_process_killed_mid_publish_leaves_no_chunk_it_cannot_serve() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    // Twenty chunks land before the crash, so the store this reopens has real content in
    // it. Stopping the very first write would leave nothing indexed and the loop below
    // would pass by iterating over nothing.
    let marker = kill_child_at_failpoint(
        "child_writes_until_killed",
        &root,
        ant_node::storage::file_store::HALT_BEFORE_PUBLISH,
        20,
    );
    assert!(
        marker.exists(),
        "the child must have reached the failpoint before it was killed"
    );

    // Reopening is itself part of the assertion: a store that cannot start after a crash
    // is a node that cannot start.
    let store = reopen(&root).await;
    for key in store.all_keys().await.expect("all_keys") {
        let served = store.get(&key).await;
        assert!(
            matches!(served, Ok(Some(_))),
            "chunk {} is claimed after a crash but cannot be served: {served:?}",
            hex::encode(key)
        );
    }
}

/// The temporary file a killed publish left behind is swept, not indexed.
///
/// It carries no chunk name, so it can never be served, and leaving it would cost disk
/// for the life of the node.
///
/// Unix only, because the leftover only exists on Unix. Off Unix the store creates the
/// file under its final name and flushes it, deliberately, since a rename there is not
/// documented to be durable. So there is no temporary file to sweep and the equivalent
/// hazard is different: a real chunk name over bytes that are short or wrong. That one is
/// covered by the store's own tests, which run on every platform, and by the
/// re-hash-everything pass the retirement does before it deletes anything.
#[cfg(unix)]
#[tokio::test]
async fn the_leftovers_of_a_killed_publish_are_swept() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    kill_child_at_failpoint(
        "child_writes_until_killed",
        &root,
        ant_node::storage::file_store::HALT_BEFORE_PUBLISH,
        5,
    );

    let before = temp_files(&root.join("chunks"));
    assert!(
        before > 0,
        "the child should have left a temporary file behind when it was killed"
    );

    let store = reopen(&root).await;
    store.wait_idle().await;
    assert_eq!(
        temp_files(&root.join("chunks")),
        0,
        "the store should sweep what an interrupted write left"
    );
    drop(store);
}

/// How many partly-written files are under `chunks_dir`.
#[cfg(unix)]
fn temp_files(chunks_dir: &Path) -> usize {
    let Ok(shards) = std::fs::read_dir(chunks_dir) else {
        return 0;
    };
    shards
        .flatten()
        .filter_map(|shard| std::fs::read_dir(shard.path()).ok())
        .flat_map(std::iter::IntoIterator::into_iter)
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| !name.chars().all(|c| c.is_ascii_hexdigit()))
        })
        .count()
}

/// Open the store the way a restart would.
async fn reopen(root: &Path) -> ChunkStore {
    let mut config = ChunkStoreConfig {
        root_dir: root.to_path_buf(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    config.migration.lock_dir = Some(root.to_path_buf());
    ChunkStore::new(config)
        .await
        .expect("the store must open after a crash")
}

/// A crash part-way through copying loses nothing: the environment still has everything.
///
/// The copier is only allowed to drop a key from its list once the file is durably
/// published, so a crash mid-copy costs the work of one chunk, never the chunk.
#[tokio::test]
async fn a_killed_migration_still_has_every_chunk_somewhere() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");
    let keys = seed_legacy_from(&root, 0).await;

    // Ten chunks copied, the eleventh interrupted. An earlier version killed the child
    // after a fixed delay, which on a fast runner meant it had copied everything and on a
    // slow one meant it had copied nothing; both make this test say something other than
    // what it claims.
    kill_child_at_failpoint(
        "child_migrates_until_killed",
        &root,
        ant_node::storage::file_store::HALT_BEFORE_PUBLISH,
        10,
    );

    // Interrupted, which is two claims and not one: some chunks copied, and some not.
    // Only the upper bound was checked before, so a copier that did nothing at all passed
    // as long as everything was still readable from the environment.
    let store = reopen(&root).await;
    let left = store.legacy_only_keys().len();
    assert!(
        left > 0,
        "the child was supposed to be killed part-way through, not after finishing"
    );
    assert!(
        left < keys.len(),
        "the child copied nothing, so nothing was interrupted: {left} of {} left",
        keys.len()
    );

    for (n, key) in &keys {
        let served = store
            .get(key)
            .await
            .expect("read after a crash")
            .expect("every seeded chunk must still be readable from one store or the other");
        assert_eq!(served, chunk_bytes(*n), "chunk {n} came back wrong");
    }
}

/// A crash between the two halves of a dual write does not leave a chunk unprotected.
///
/// The environment's copy is written first and the file second. A crash in between leaves
/// a chunk only the environment has, and it must be on the copier's list, because a key
/// in neither view is what retirement destroys.
///
/// The chunks the child writes are deliberately ones the environment does not already
/// hold. An earlier version seeded the same addresses the child then wrote, and the write
/// path skips the environment half for a key that is already legacy-only, so no dual
/// write happened at all and the test proved nothing.
#[tokio::test]
async fn a_crash_between_the_two_halves_leaves_the_chunk_on_the_list() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");
    // Seeded with chunks the child will not write: the child starts at 0 and these are
    // far above anything it reaches in the time it has.
    seed_legacy_from(&root, 1_000_000).await;

    // The crash lands inside the write of chunk 20, so chunks 0 to 19 completed and 20
    // is the one caught between the two halves.
    kill_child_at_failpoint(
        "child_writes_until_killed",
        &root,
        ant_node::storage::file_store::HALT_BEFORE_PUBLISH,
        20,
    );

    let store = reopen(&root).await;

    // Whatever the environment holds and the file store does not is on the list. It is
    // derived at open from the two key sets, which is the property that makes a crash
    // survivable: re-read from disk, never carried across.
    // The specific key, not merely a non-empty list. The environment was seeded with
    // unrelated keys, and an earlier version asserted only that something was on the
    // list, which those seeds satisfied whether or not a dual write had happened at all.
    let interrupted = ant_node::client::compute_address(&chunk_bytes(20));
    let legacy_only = store.legacy_only_keys();
    assert!(
        legacy_only.contains(&interrupted),
        "the chunk whose file half never landed must be on the copier's list: it reached \
         the environment and nothing else knows about it"
    );
    for key in &legacy_only {
        let served = store
            .get(key)
            .await
            .expect("read")
            .expect("a key on the copier's list must be readable from the environment");
        assert_eq!(ant_node::client::compute_address(&served), *key);
    }

    // And nothing the store claims is unservable, from either side of the union.
    for key in store.all_keys().await.expect("all_keys") {
        assert!(
            matches!(store.get(&key).await, Ok(Some(_))),
            "chunk {} is claimed after a crash but cannot be served",
            hex::encode(key)
        );
    }
}

/// A retirement killed after the mark is finished on the next start, never reopened.
///
/// The most destructive moment in the whole migration. By the time the mark is written the
/// environment has been renamed aside and the node has already told the network it serves
/// those chunks from the file store. A start that put the directory back would leave the
/// node running two stores again with the disk it came here to free still spent; a start
/// that deleted an *unmarked* directory would destroy a live environment. The mark is what
/// separates the two, and it is written by the process that then dies.
///
/// Its recovery has unit tests that plant the mark by hand. What those cannot show is that
/// the mark is really on disk at that moment, which is what a killed process settles.
#[tokio::test]
async fn a_retirement_killed_after_the_mark_is_finished_not_reopened() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");
    let seeded = seed_legacy_from(&root, 0).await;

    kill_child_at_failpoint(
        "child_retires_until_killed",
        &root,
        ant_node::storage::file_store::HALT_AFTER_RETIRE_MARK,
        0,
    );

    // The child died with the directory renamed aside and marked. Nothing had been
    // deleted, so this is the state a power cut would leave behind.
    let store = reopen(&root).await;
    for _ in 0..600 {
        if !store.legacy_dir_is_on_disk() && tombstones(&root) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !store.legacy_dir_is_on_disk(),
        "the marked environment was put back rather than finished"
    );
    assert_eq!(
        tombstones(&root),
        0,
        "the marked directory is still on disk, so its space was never returned"
    );

    // And every chunk the environment held is still served, from the file store.
    for (n, key) in &seeded {
        let served = store
            .get(key)
            .await
            .expect("read")
            .expect("a chunk must survive an interrupted retirement");
        assert_eq!(served, chunk_bytes(*n), "chunk {n} came back wrong");
    }
}

/// Directories beside the live environment that a retirement left behind.
fn tombstones(root: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(ant_node::storage::LEGACY_ENV_DIR))
        })
        .count()
}
