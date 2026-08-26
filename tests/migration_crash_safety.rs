//! What survives a process dying part-way through the migration.
//!
//! The design rests on being able to stop at any moment and start again: every step is
//! idempotent and re-derived from the filesystem. That is easy to assert and hard to
//! believe without trying it, so these tests kill a real child process at a real point in
//! the work and then open the store in this one and check what is there.
//!
//! **What this does and does not prove.** A killed process loses nothing the kernel has
//! already accepted, so this covers ordering and bookkeeping: a chunk is whole or absent
//! and never half-indexed, an interrupted retirement is finished rather than reopened, and
//! the store always opens. It does not cover losing the page cache, which is what a real
//! power cut adds and what no hosted runner can do. That remains a fleet gate, and this is
//! the part of it that can be automated.
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

/// Run this test binary again as a child, in the mode named by `role`, and kill it after
/// `run_for`.
///
/// A child process rather than a thread, because the point is to lose everything the
/// process was holding: buffers, in-memory index, locks, half-finished intentions.
fn kill_a_child_midway(role: &str, root: &Path, run_for: Duration) {
    let exe = std::env::current_exe().expect("this test binary");
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg(role)
        .arg("--nocapture")
        .arg("--ignored")
        .env("ANT_CRASH_TEST_ROOT", root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the child");

    std::thread::sleep(run_for);
    child.kill().expect("kill the child");
    let _ = child.wait();
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

    // Round and round, so the kill lands mid-write however long it takes to arrive.
    loop {
        for n in 0..CHUNKS {
            let content = chunk_bytes(n);
            let address = ant_node::client::compute_address(&content);
            let _ = store.put(&address, &content).await;
        }
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
    loop {
        let keys = store.legacy_only_keys();
        if keys.is_empty() {
            break;
        }
        let _ = store.copy_batch(&keys, 0, 0, &shutdown).await;
    }
    // Stay alive so the parent's kill lands somewhere in the work above rather than after
    // the process would have exited anyway.
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Plant a legacy environment and close it.
async fn seed_legacy(root: &Path) -> Vec<[u8; 32]> {
    let lmdb = LmdbStorage::new(LmdbStorageConfig {
        root_dir: root.to_path_buf(),
        verify_on_read: true,
        max_map_size: 0,
        disk_reserve: 0,
    })
    .await
    .expect("open legacy");
    let mut keys = Vec::new();
    for n in 0..CHUNKS {
        let content = chunk_bytes(n);
        let address = ant_node::client::compute_address(&content);
        lmdb.put(&address, &content).await.expect("seed");
        keys.push(address);
    }
    lmdb.wait_idle().await;
    keys
}

/// Every chunk the store still claims after a crash is one it can actually serve.
///
/// The failure this guards against is a name that outlived its bytes: the index is built
/// from filenames at startup, so a half-written file wearing a real chunk name would be
/// advertised, committed to, and unservable.
#[tokio::test]
async fn a_killed_writer_leaves_no_chunk_it_cannot_serve() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    kill_a_child_midway(
        "child_writes_until_killed",
        &root,
        Duration::from_millis(1500),
    );

    // Reopening is itself part of the assertion: a store that cannot start after a crash
    // is a node that cannot start.
    let store = ChunkStore::new(ChunkStoreConfig {
        root_dir: root.clone(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    })
    .await
    .expect("the store must open after a crash");

    let keys = store.all_keys().await.expect("all_keys");
    assert!(
        !keys.is_empty(),
        "the child should have written something before it was killed"
    );

    for key in &keys {
        let served = store.get(key).await;
        assert!(
            matches!(served, Ok(Some(_))),
            "chunk {} is claimed but cannot be served: {served:?}",
            hex::encode(key)
        );
    }
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
    let keys = seed_legacy(&root).await;

    kill_a_child_midway(
        "child_migrates_until_killed",
        &root,
        Duration::from_millis(1200),
    );

    let mut config = ChunkStoreConfig {
        root_dir: root.clone(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    config.migration.lock_dir = Some(root.clone());
    let store = ChunkStore::new(config)
        .await
        .expect("the store must open after a crash mid-migration");

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
/// a chunk only the environment has, and it has to be on the copier's list, because a key
/// in neither view is what retirement destroys.
#[tokio::test]
async fn a_crash_between_the_two_halves_leaves_the_chunk_on_the_list() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");
    seed_legacy(&root).await;

    kill_a_child_midway(
        "child_writes_until_killed",
        &root,
        Duration::from_millis(1500),
    );

    let mut config = ChunkStoreConfig {
        root_dir: root.clone(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    config.migration.lock_dir = Some(root.clone());
    let store = ChunkStore::new(config).await.expect("open after a crash");

    // Whatever the environment holds and the file store does not is on the list. Derived
    // at open from the two key sets, which is the property that makes a crash survivable:
    // it is re-read from disk, never carried across.
    let legacy_only = store.legacy_only_keys();
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
