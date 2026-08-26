//! Proof that the migration actually returns disk to the filesystem.
//!
//! This is the claim the whole change exists to make good, and until now it was the one
//! thing the test suite did not check. The unit tests prove the environment is *removed*;
//! that is not the same as the space coming back, which is exactly the mistake that
//! started this work. The fleet deleted 2.29 million chunks, every counter said the
//! chunks were gone, and not one byte returned to the filesystem, because LMDB moves
//! freed pages to its own free list and never shortens the file.
//!
//! So these tests measure the filesystem, not the store's opinion of itself: the size of
//! the data on disk before and after, and the free space the operating system reports.
//!
//! They run on every platform CI covers, which is also the filesystem matrix that matters
//! here: ext4 on Linux, APFS on macOS, NTFS on Windows.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    // Test fixtures: every cast here is of a bounded loop counter into a byte, and the
    // wrap is what makes the fill vary.
    clippy::cast_possible_truncation
)]

use ant_node::storage::migration::{MigrationPhase, MIN_RETIRE_DELAY_HOURS};
use ant_node::storage::{ChunkStore, ChunkStoreConfig, LmdbStorage, LmdbStorageConfig};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// Chunks to plant. Enough that the environment is meaningfully larger than its own
/// overhead, so "the file shrank" cannot be an accounting artefact.
const CHUNKS: usize = 400;

/// Bytes per chunk. Small enough for a hosted runner, large enough that 400 of them are
/// unmistakable on disk.
const CHUNK_BYTES: usize = 16 * 1024;

/// Blocks actually allocated under `path`, in bytes, following no links.
///
/// Allocated blocks rather than file lengths. A length is what the file claims; blocks
/// are what the filesystem has handed out, and the two part company exactly where this
/// test needs to be careful: a sparse file, a file whose last block is mostly padding, or
/// a file that has been unlinked while something still holds it open.
#[cfg(unix)]
fn allocated_bytes(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    walk(path, &|meta| meta.blocks() * 512)
}

/// Off Unix, the length is the best the standard library offers.
#[cfg(not(unix))]
fn allocated_bytes(path: &Path) -> u64 {
    walk(path, &|meta| meta.len())
}

/// Sum `size` over everything under `path`.
fn walk(path: &Path, size: &dyn Fn(&std::fs::Metadata) -> u64) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return std::fs::symlink_metadata(path).map_or(0, |m| size(&m));
    };
    entries
        .flatten()
        .map(|entry| {
            let path = entry.path();
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => walk(&path, size),
                Ok(meta) => size(&meta),
                Err(_) => 0,
            }
        })
        .sum()
}

/// What the filesystem says is free, right now.
///
/// The measurement that cannot be argued with, and the one this test exists for. A path
/// disappearing proves nothing: unlink a file that something still holds open and every
/// name is gone while every block is still spoken for, which is a fair description of the
/// bug that started all this.
fn free_space(path: &Path) -> u64 {
    fs2::available_space(path).expect("the filesystem should report its free space")
}

/// Deterministic content for chunk `n`, filled so it does not compress to nothing.
///
/// `n` goes in verbatim at the front rather than being folded into the fill, because a
/// fill that wraps makes two different `n` produce the same bytes, and content-addressed
/// storage would then hold one chunk where the test believed it held two. The first
/// version of this test did exactly that and undercounted by a third.
fn chunk_bytes(n: usize) -> Vec<u8> {
    let mut content = vec![0u8; CHUNK_BYTES];
    content[..8].copy_from_slice(&(n as u64).to_le_bytes());
    for (i, byte) in content.iter_mut().enumerate().skip(8) {
        *byte = ((i.wrapping_mul(31)).wrapping_add(n) % 251) as u8;
    }
    content
}

/// Plant a legacy environment holding `CHUNKS` chunks and close it.
async fn seed_legacy_environment(root: &Path) -> Vec<[u8; 32]> {
    let lmdb = LmdbStorage::new(LmdbStorageConfig {
        root_dir: root.to_path_buf(),
        verify_on_read: true,
        max_map_size: 0,
        disk_reserve: 0,
    })
    .await
    .expect("open the legacy environment");

    let mut keys = Vec::with_capacity(CHUNKS);
    for n in 0..CHUNKS {
        let content = chunk_bytes(n);
        let address = ant_node::client::compute_address(&content);
        lmdb.put(&address, &content).await.expect("seed a chunk");
        keys.push(address);
    }
    lmdb.wait_idle().await;
    keys
}

/// A store configured to migrate promptly, so a test does not wait out real delays.
fn migrating_config(root: &Path) -> ChunkStoreConfig {
    let mut config = ChunkStoreConfig {
        root_dir: root.to_path_buf(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    config.migration.tick_secs = 1;
    config.migration.copier_throttle_mib_per_sec = 0;
    config.migration.copier_slack_mb = 0;
    config.migration.lock_dir = Some(root.to_path_buf());
    config
}

/// Take a settled store all the way through retirement.
///
/// Drives the steps the driver would, rather than running the driver, so the test does
/// not depend on wall-clock gates it has no business waiting for. The gates themselves
/// are covered by their own tests; what this one is about is the disk.
async fn copy_everything(store: &Arc<ChunkStore>, keys: &[[u8; 32]]) {
    store
        .copy_batch(keys, 0, 0, &CancellationToken::new())
        .await
        .expect("copy every chunk into the file store");
    assert!(
        store.legacy_only_keys().is_empty(),
        "every chunk should have been copied"
    );
    store.wait_idle().await;
}

/// Take an already-copied store through retirement, returning the bytes it freed.
///
/// Separate from the copying so a caller can measure the disk in between, at the peak
/// where both stores hold everything. That is the moment a node is most at risk of
/// filling up, and measuring only the ends would miss it.
async fn retire(store: &Arc<ChunkStore>) -> u64 {
    let shutdown = CancellationToken::new();

    store
        .commit_to_files()
        .expect("commit to the file-backed set");
    store.note_commitment_rebuilt();
    store.note_commitment_rebuilt();
    store.force_migration_state(|state| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        state.committed_at_unix = Some(now.saturating_sub(MIN_RETIRE_DELAY_HOURS * 3600 + 60));
    });

    let proof = store
        .verify_before_retire(0, &shutdown)
        .await
        .expect("verify before retiring");
    assert!(proof.is_clean(), "verification must pass: {proof:?}");

    store
        .retire_legacy(
            &proof,
            &|_: &[u8; 32]| false,
            &std::collections::BTreeSet::new(),
        )
        .await
        .expect("retire the legacy environment")
}

/// The bytes the legacy environment occupied come back to the filesystem.
///
/// Three measurements, because only the third one settles it: what the filesystem says is
/// free before anything is written, at the peak when both stores hold everything, and
/// after the environment is gone. A test that only watched paths disappear would pass
/// while every block stayed allocated, which is a fair description of the bug that
/// started all this.
///
/// The numbers are noisy on a shared machine, so the assertion is about the shape: the
/// peak is materially below the start, and the end recovers most of the way back to it.
#[tokio::test]
async fn retiring_the_legacy_environment_returns_its_bytes_to_the_filesystem() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    let payload = (CHUNKS * CHUNK_BYTES) as u64;
    let free_at_start = free_space(&root);

    let keys = seed_legacy_environment(&root).await;
    let environment = root.join("chunks.mdb");
    let environment_blocks = allocated_bytes(&environment);
    assert!(
        environment_blocks >= payload,
        "the seeded environment should have at least the chunk bytes allocated, has \
         {environment_blocks}"
    );

    let store = Arc::new(
        ChunkStore::new(migrating_config(&root))
            .await
            .expect("open the store"),
    );
    assert!(store.has_legacy());

    // Both stores hold everything: the peak, and the moment a node is most at risk of
    // filling its disk.
    copy_everything(&store, &keys).await;
    let free_at_peak = free_space(&root);
    assert!(
        free_at_peak < free_at_start,
        "holding both copies should have consumed disk"
    );

    let freed = retire(&store).await;
    store.wait_idle().await;
    assert_eq!(store.migration_phase(), MigrationPhase::FilesOnly);
    assert!(freed > 0, "retirement reported no bytes freed");

    // The deletion runs on a detached thread so the node can serve while it happens.
    for _ in 0..400 {
        if !environment.exists() && allocated_bytes(&root) < environment_blocks + payload {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        !environment.exists(),
        "the environment directory is still on disk"
    );

    // Dropping the store closes every handle. A file that is unlinked while something
    // still holds it open keeps its blocks and shows in no directory, so measuring before
    // this point would be measuring the wrong thing.
    drop(store);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let free_at_end = free_space(&root);

    // Only the file store's copy should be left.
    let left_on_disk = allocated_bytes(&root);
    let file_store_blocks = allocated_bytes(&root.join("chunks"));
    assert!(
        left_on_disk <= file_store_blocks + (payload / 10),
        "something other than the file store is still using disk: {left_on_disk} total \
         against {file_store_blocks} in the file store"
    );

    // And the filesystem agrees, measured against the peak rather than against a guess.
    // Retiring should hand back most of what the environment was occupying, which makes
    // this a statement about the environment's own size rather than about the payload.
    let recovered = free_at_end.saturating_sub(free_at_peak);
    assert!(
        recovered > environment_blocks / 2,
        "retiring recovered {recovered} bytes of an environment occupying \
         {environment_blocks}"
    );

    // And what is left costs roughly one copy rather than two.
    let consumed = free_at_start.saturating_sub(free_at_end);
    assert!(
        consumed < environment_blocks,
        "the filesystem is still down {consumed} bytes against an environment of \
         {environment_blocks}, so its space did not come back"
    );

    // Every chunk is still served, read back through a store opened from scratch, which
    // is what a restart does. Space recovered by losing data would be no achievement, and
    // it is the failure this whole change exists to avoid.
    let fresh = store_reopened(&root).await;
    for (n, key) in keys.iter().enumerate() {
        let served = fresh
            .get(key)
            .await
            .expect("read a migrated chunk")
            .expect("a migrated chunk should still be there");
        assert_eq!(served, chunk_bytes(n), "chunk {n} came back wrong");
    }
}

/// Open the store again from scratch, which is what a restart does.
async fn store_reopened(root: &Path) -> ChunkStore {
    ChunkStore::new(ChunkStoreConfig {
        root_dir: root.to_path_buf(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    })
    .await
    .expect("the store must reopen after retirement")
}

/// The file store holds the same payload in less space than the environment did.
///
/// Not a compression claim: it is that one file per chunk carries no free list and no
/// map overhead, which is the whole reason the space can be returned at all.
#[tokio::test]
async fn the_file_store_holds_the_same_chunks_in_less_space() {
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    let keys = seed_legacy_environment(&root).await;
    let environment_bytes = allocated_bytes(&root.join("chunks.mdb"));

    let store = Arc::new(
        ChunkStore::new(migrating_config(&root))
            .await
            .expect("open the store"),
    );
    store
        .copy_batch(&keys, 0, 0, &CancellationToken::new())
        .await
        .expect("copy");
    store.wait_idle().await;

    let payload = (CHUNKS * CHUNK_BYTES) as u64;
    let file_store_bytes = allocated_bytes(&root.join("chunks"));
    assert!(
        file_store_bytes >= payload,
        "the file store should hold at least the payload: {file_store_bytes} < {payload}"
    );
    assert!(
        file_store_bytes <= environment_bytes,
        "one file per chunk should not cost more than the environment did: \
         {file_store_bytes} > {environment_bytes}"
    );
}
