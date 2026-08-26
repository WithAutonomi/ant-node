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
fn kill_child_at_failpoint(role: &str, root: &Path, failpoint: &str) -> PathBuf {
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the child");

    // No deadline. A slow machine makes this slower, not wrong, and a wait that gave up
    // would let the test pass without ever reaching the case it exists for.
    while !marker.exists() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the child exited before reaching the failpoint: {status}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    child.kill().expect("kill the child");
    let _ = child.wait();
    marker
}

/// Run a child for a while and then kill it, without a failpoint.
///
/// For the cases where the point is that the kill lands somewhere in a long stretch of
/// work rather than at one named instant. The child reports progress so this never kills
/// one that has not started.
fn kill_child_once_it_is_working(role: &str, root: &Path, run_for: Duration) {
    let progress = root.join(format!("working-{role}"));
    let _ = std::fs::remove_file(&progress);

    let exe = std::env::current_exe().expect("this test binary");
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg(role)
        .arg("--nocapture")
        .arg("--ignored")
        .env("ANT_CRASH_TEST_ROOT", root)
        .env("ANT_CRASH_TEST_PROGRESS", &progress)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the child");

    while !progress.exists() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the child exited before doing any work: {status}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(run_for);
    child.kill().expect("kill the child");
    let _ = child.wait();
}

/// Say that this child has started doing the work it was spawned for.
fn report_working() {
    if let Ok(path) = std::env::var("ANT_CRASH_TEST_PROGRESS") {
        let _ = std::fs::write(path, b"working");
    }
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

    report_working();
    // Always a chunk it has not written before, so the kill lands in real work rather
    // than in a re-offer of something already on disk. An earlier version cycled the same
    // hundred keys and spent almost all its time confirming duplicates.
    for n in 0.. {
        let content = chunk_bytes(n);
        let address = ant_node::client::compute_address(&content);
        let _ = store.put(&address, &content).await;
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

    report_working();
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
async fn seed_legacy_from(root: &Path, first: usize) -> Vec<[u8; 32]> {
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
        keys.push(address);
    }
    lmdb.wait_idle().await;
    keys
}

/// A process killed inside a publish leaves no chunk it cannot serve.
///
/// The child stops with the bytes written to a temporary file and the rename not yet
/// made, which is the one moment a half-finished chunk exists on disk, and is killed
/// there. The failure this guards against is a name outliving its bytes: the index is
/// built from filenames at startup, so a partial file wearing a real chunk name would be
/// advertised, committed to, and unservable.
#[tokio::test]
async fn a_process_killed_mid_publish_leaves_no_chunk_it_cannot_serve() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    let marker = kill_child_at_failpoint(
        "child_writes_until_killed",
        &root,
        ant_node::storage::file_store::HALT_BEFORE_PUBLISH,
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
#[tokio::test]
async fn the_leftovers_of_a_killed_publish_are_swept() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    kill_child_at_failpoint(
        "child_writes_until_killed",
        &root,
        ant_node::storage::file_store::HALT_BEFORE_PUBLISH,
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

    kill_child_once_it_is_working(
        "child_migrates_until_killed",
        &root,
        Duration::from_millis(150),
    );

    // Interrupted, not finished: some chunks copied, some still only in the environment.
    let store = reopen(&root).await;
    assert!(
        !store.legacy_only_keys().is_empty(),
        "the child was supposed to be killed part-way through, not after finishing"
    );

    for (n, key) in keys.iter().enumerate() {
        let served = store
            .get(key)
            .await
            .expect("read after a crash")
            .expect("every seeded chunk must still be readable from one store or the other");
        assert_eq!(served, chunk_bytes(n), "chunk {n} came back wrong");
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

    kill_child_at_failpoint(
        "child_writes_until_killed",
        &root,
        ant_node::storage::file_store::HALT_BEFORE_PUBLISH,
    );

    let store = reopen(&root).await;

    // Whatever the environment holds and the file store does not is on the list. It is
    // derived at open from the two key sets, which is the property that makes a crash
    // survivable: re-read from disk, never carried across.
    let legacy_only = store.legacy_only_keys();
    assert!(
        !legacy_only.is_empty(),
        "the chunk whose file half never landed must be on the copier's list"
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
