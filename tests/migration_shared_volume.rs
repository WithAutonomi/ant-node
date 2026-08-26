//! Several nodes migrating on one disk.
//!
//! Operators run many nodes per machine, and during the bridge each one briefly holds two
//! copies of everything it stores. If they all did that at once the disk would fill, which
//! is the failure this migration exists to prevent rather than cause. A lock keyed by the
//! filesystem lets one node at a time do the copying.
//!
//! The lock has a cap on how long a single node may hold it, so one node stuck waiting on
//! its neighbours cannot keep the rest of the machine from ever starting. That cap is
//! hours long by design, so what is checked here is the exclusion itself and the
//! accounting around it, not the cap expiring.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    // Test fixtures: every cast here is of a bounded loop counter into a byte, and the
    // wrap is what makes the fill vary.
    clippy::cast_possible_truncation
)]

use ant_node::storage::migration::{LockAttempt, VolumeLock};
use ant_node::storage::{ChunkStore, ChunkStoreConfig, LmdbStorage, LmdbStorageConfig};
use std::path::Path;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// Chunks each node holds.
const CHUNKS: usize = 60;

fn chunk_bytes(node: usize, n: usize) -> Vec<u8> {
    let mut content = vec![0u8; 8192];
    content[..8].copy_from_slice(&(n as u64).to_le_bytes());
    content[8..16].copy_from_slice(&(node as u64).to_le_bytes());
    for (i, byte) in content.iter_mut().enumerate().skip(16) {
        *byte = ((i.wrapping_mul(29)).wrapping_add(n).wrapping_add(node) % 251) as u8;
    }
    content
}

async fn seed_legacy(root: &Path, node: usize) -> Vec<[u8; 32]> {
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
        let content = chunk_bytes(node, n);
        let address = ant_node::client::compute_address(&content);
        lmdb.put(&address, &content).await.expect("seed");
        keys.push(address);
    }
    lmdb.wait_idle().await;
    keys
}

/// One node at a time copies; the others wait rather than piling on.
///
/// The lock is taken per filesystem, not per node directory. That distinction is the
/// whole point: two nodes are configured with different roots by definition, so a lock
/// beside each root would serialise neither against the other.
#[test]
fn only_one_node_on_a_volume_holds_the_lock() {
    let volume = TempDir::new().expect("temp dir");
    let node_a = volume.path().join("node-a");
    let node_b = volume.path().join("node-b");
    let node_c = volume.path().join("node-c");
    for root in [&node_a, &node_b, &node_c] {
        std::fs::create_dir_all(root).expect("mkdir");
    }

    // Scoped to this volume directory so the test does not contend with anything else on
    // the machine's real filesystem.
    let scope = Some(volume.path());

    let LockAttempt::Acquired(held) = VolumeLock::try_acquire(&node_a, scope) else {
        panic!("the first node must take the lock");
    };
    assert!(
        matches!(VolumeLock::try_acquire(&node_b, scope), LockAttempt::Busy),
        "a second node on the same volume must wait"
    );
    assert!(
        matches!(VolumeLock::try_acquire(&node_c, scope), LockAttempt::Busy),
        "and so must a third"
    );

    drop(held);
    assert!(
        matches!(
            VolumeLock::try_acquire(&node_b, scope),
            LockAttempt::Acquired(_)
        ),
        "the lock must pass on once the first node lets go"
    );
}

/// Two nodes sharing a disk both finish, and neither loses a chunk to the other.
///
/// Run one after the other, which is what the lock produces. What is checked is that the
/// second node's migration is unaffected by the first having already run on the same
/// filesystem: no shared state, no name collisions, no lock left behind.
#[tokio::test]
async fn nodes_sharing_a_volume_each_migrate_completely() {
    let volume = TempDir::new().expect("temp dir");
    let shutdown = CancellationToken::new();

    let mut nodes = Vec::new();
    for node in 0..2 {
        let root = volume.path().join(format!("node-{node}"));
        std::fs::create_dir_all(&root).expect("mkdir");
        let keys = seed_legacy(&root, node).await;
        nodes.push((root, keys));
    }

    for (node, (root, keys)) in nodes.iter().enumerate() {
        let mut config = ChunkStoreConfig {
            root_dir: root.clone(),
            disk_reserve: 0,
            ..ChunkStoreConfig::default()
        };
        config.migration.lock_dir = Some(volume.path().to_path_buf());
        let store = ChunkStore::new(config).await.expect("open");

        store.copy_batch(keys, 0, 0, &shutdown).await.expect("copy");
        store.wait_idle().await;

        assert!(
            store.legacy_only_keys().is_empty(),
            "node {node} should have copied everything"
        );
        for (n, key) in keys.iter().enumerate() {
            let served = store
                .get(key)
                .await
                .expect("read")
                .expect("every chunk this node seeded must still be here");
            assert_eq!(
                served,
                chunk_bytes(node, n),
                "node {node} chunk {n} came back wrong"
            );
        }
    }

    // Neither node picked up the other's chunks, which sharing a filesystem must not
    // cause: the stores are separate, only the lock is shared.
    let (root_a, keys_a) = &nodes[0];
    let store_a = ChunkStore::new(ChunkStoreConfig {
        root_dir: root_a.clone(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    })
    .await
    .expect("reopen node 0");
    assert_eq!(
        store_a.current_chunks().expect("count") as usize,
        keys_a.len(),
        "a node must hold its own chunks and only its own"
    );
}

/// A node that cannot take the lock does not migrate, and does not lose anything either.
///
/// Waiting is the correct answer: the chunks stay where they are, served from both stores,
/// until the volume is free.
#[tokio::test]
async fn a_node_that_cannot_take_the_lock_keeps_serving() {
    let volume = TempDir::new().expect("temp dir");
    let root = volume.path().join("waiting-node");
    std::fs::create_dir_all(&root).expect("mkdir");
    let keys = seed_legacy(&root, 0).await;

    let LockAttempt::Acquired(_held) =
        VolumeLock::try_acquire(&volume.path().join("busy-node"), Some(volume.path()))
    else {
        panic!("the other node must take the lock");
    };

    let mut config = ChunkStoreConfig {
        root_dir: root.clone(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    config.migration.lock_dir = Some(volume.path().to_path_buf());
    let store = ChunkStore::new(config).await.expect("open");

    // The store opens and serves regardless of the lock: only the copier waits for it.
    assert!(store.has_legacy());
    for (n, key) in keys.iter().enumerate() {
        let served = store
            .get(key)
            .await
            .expect("read")
            .expect("a node waiting for the volume still serves everything it holds");
        assert_eq!(served, chunk_bytes(0, n));
    }
}
