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

use ant_node::storage::migration::{self, LockAttempt, VolumeLock, MIN_RETIRE_DELAY_HOURS};
use ant_node::storage::{ChunkStore, ChunkStoreConfig, LmdbStorage, LmdbStorageConfig};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
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

/// A migration context with no network, which is all these tests need.
///
/// The gates that consult routing have their own tests; what is under test here is the
/// lock, and a node with no view of the network still copies.
fn offline_context() -> migration::MigrationContext {
    migration::MigrationContext {
        p2p: None,
        self_id: None,
        self_xor: None,
        commitment: None,
        replication: None,
        sync_state: None,
        audit_challenge_coordinator: None,
        peer_commitments: None,
        close_group_size: 7,
    }
}

/// Two migration drivers on one disk: only one copies at a time.
///
/// This drives `migration::run`, not `copy_batch`. The copier does not take the volume
/// lock; the driver does, and an earlier version of this test called the copier directly
/// and would have passed with the lock removed from the driver entirely.
#[tokio::test]
async fn two_drivers_on_one_volume_do_not_copy_at_the_same_time() {
    let volume = TempDir::new().expect("temp dir");
    let mut stores = Vec::new();
    let mut all_keys = Vec::new();

    for node in 0..2 {
        let root = volume.path().join(format!("node-{node}"));
        std::fs::create_dir_all(&root).expect("mkdir");
        let keys = seed_legacy(&root, node).await;

        stores.push(driven_node(volume.path(), &root).await);
        all_keys.push(keys);
    }

    // Hold the volume before either driver starts, so both are shut out and neither can
    // be observed making progress.
    let LockAttempt::Acquired(held) =
        VolumeLock::try_acquire(&volume.path().join("an-outsider"), Some(volume.path()))
    else {
        panic!("the outsider must take the lock");
    };

    let shutdown = CancellationToken::new();
    let drivers: Vec<_> = stores
        .iter()
        .map(|store| {
            tokio::spawn(migration::run(
                Arc::clone(store),
                offline_context(),
                shutdown.clone(),
            ))
        })
        .collect();

    // Long enough for several ticks. Neither driver may copy anything while the lock is
    // held by somebody else.
    tokio::time::sleep(Duration::from_secs(4)).await;
    for (node, store) in stores.iter().enumerate() {
        assert_eq!(
            store.legacy_only_keys().len(),
            CHUNKS,
            "node {node} copied while another holder had the volume"
        );
    }

    // Released: one of them takes it and copies. The other must not, because the holder
    // keeps the volume from its first copy through to retiring, rather than handing it
    // back between chunks. That is the point of the lock: two nodes copying at once each
    // hold two copies of everything, and the disk this migration exists to free is the
    // one that fills.
    drop(held);
    let mut copier = None;
    for _ in 0..300 {
        if let Some(node) = stores
            .iter()
            .position(|s| s.legacy_only_keys().len() < CHUNKS)
        {
            copier = Some(node);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let copier = copier.expect("one driver should have taken the volume and started");

    // Give the other one many ticks to misbehave in.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let waiting = 1 - copier;
    assert_eq!(
        stores[waiting].legacy_only_keys().len(),
        CHUNKS,
        "node {waiting} copied while node {copier} held the volume"
    );

    // And the one that has it finishes copying, checking on every tick that the other has
    // still not started. The window being watched is the whole of the first node's copy
    // rather than its two ends.
    //
    // Copying is as far as this one goes. Retirement is gated behind hours of wall clock
    // that a test has no business waiting out, so whether the lock spans that half too has
    // its own test below.
    for _ in 0..600 {
        assert_eq!(
            stores[waiting].legacy_only_keys().len(),
            CHUNKS,
            "node {waiting} copied while node {copier} still held the volume"
        );
        if stores[copier].legacy_only_keys().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    shutdown.cancel();
    for driver in drivers {
        let _ = driver.await;
    }

    assert!(
        stores[copier].legacy_only_keys().is_empty(),
        "the node holding the volume did not finish copying"
    );
    // Both of them, not just the one that went first. Counting only the copier would pass
    // for a node that had picked up its neighbour's chunks as well as its own.
    for (node, store) in stores.iter().enumerate() {
        holds_exactly_its_own(store, node, &all_keys[node]).await;
    }
}

/// A node set up to be driven by `migration::run` on a shared volume.
async fn driven_node(volume: &Path, root: &Path) -> Arc<ChunkStore> {
    let mut config = ChunkStoreConfig {
        root_dir: root.to_path_buf(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    config.migration.tick_secs = 1;
    config.migration.copier_throttle_mib_per_sec = 0;
    config.migration.copier_slack_mb = 0;
    // Small enough that copying takes several ticks, so there is a window in which the
    // other node could misbehave and be caught, and large enough that the whole thing
    // finishes in seconds rather than one chunk per tick.
    config.migration.batch_chunks = 8;
    config.migration.lock_dir = Some(volume.to_path_buf());
    Arc::new(ChunkStore::new(config).await.expect("open a node"))
}

/// Every chunk this node seeded is still served, and nothing else is.
async fn holds_exactly_its_own(store: &ChunkStore, node: usize, keys: &[[u8; 32]]) {
    assert_eq!(
        store.current_chunks().expect("count") as usize,
        keys.len(),
        "node {node} must hold its own chunks and only its own"
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
            "node {node} chunk {n} is wrong"
        );
    }
}

/// A node waits for the volume before it retires, not only before it copies.
///
/// The driver is documented as holding the volume from the first copy through retirement
/// and not handing it back in between. The test above covers the copying half. This one
/// covers the other, which is the half that matters most: retiring means re-reading every
/// chunk in the store to verify it and then deleting an environment, so it is the heaviest
/// the disk gets. A driver that took the lock only for copying would run that pass while
/// eleven neighbours ran theirs.
///
/// Shaped the same way as the copying test, and for the same reason: an outsider holds the
/// volume first, so the answer does not depend on catching a short window. The node is put
/// in the phase where retirement is the next thing it would do, and then watched for not
/// doing it.
#[tokio::test]
async fn a_node_waits_for_the_volume_before_it_retires() {
    let volume = TempDir::new().expect("temp dir");
    let root = volume.path().join("node-0");
    std::fs::create_dir_all(&root).expect("mkdir");
    let keys = seed_legacy(&root, 0).await;

    let store = ready_to_retire(volume.path(), &root, &keys).await;
    let shutdown = CancellationToken::new();

    let LockAttempt::Acquired(held) =
        VolumeLock::try_acquire(&volume.path().join("an-outsider"), Some(volume.path()))
    else {
        panic!("the outsider must take the lock");
    };

    let driver = tokio::spawn(migration::run(
        Arc::clone(&store),
        offline_context(),
        shutdown.clone(),
    ));

    // Several ticks with everything else in place. The environment must still be there.
    for _ in 0..40 {
        assert!(
            store.legacy_dir_is_on_disk(),
            "the node retired while an outsider held the volume"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Released: now it retires. Without this half the test would pass against a node that
    // never retires at all, which is the failure the whole migration exists to avoid.
    drop(held);
    let mut retired = false;
    for _ in 0..600 {
        if !store.legacy_dir_is_on_disk() && !store.has_legacy() {
            retired = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    shutdown.cancel();
    let _ = driver.await;
    assert!(
        retired,
        "the node never retired once the volume was free, so it was not waiting for it"
    );

    // And it still holds everything it had. Retiring is deleting the old copy, not the
    // chunks.
    for (n, key) in keys.iter().enumerate() {
        let served = store
            .get(key)
            .await
            .expect("read")
            .expect("every chunk must survive retirement");
        assert_eq!(
            served,
            chunk_bytes(0, n),
            "chunk {n} is wrong after retiring"
        );
    }
}

/// Open a node whose only remaining migration work is to retire.
///
/// Copied and committed by hand rather than by waiting for the driver, because the driver
/// gets here by waiting out the shed hold, which is days. Those gates have their own
/// tests; what the caller is about to watch is the volume lock.
async fn ready_to_retire(volume: &Path, root: &Path, keys: &[[u8; 32]]) -> Arc<ChunkStore> {
    let mut config = ChunkStoreConfig {
        root_dir: root.to_path_buf(),
        disk_reserve: 0,
        ..ChunkStoreConfig::default()
    };
    config.migration.tick_secs = 1;
    config.migration.copier_throttle_mib_per_sec = 0;
    config.migration.copier_slack_mb = 0;
    config.migration.lock_dir = Some(volume.to_path_buf());
    let store = Arc::new(ChunkStore::new(config).await.expect("open a node"));

    store
        .copy_batch(keys, 0, 0, &CancellationToken::new())
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
        // Past the delay that buys the rollback window, so the only thing left between
        // this node and deleting its environment is the volume.
        state.committed_at_unix = Some(now.saturating_sub(MIN_RETIRE_DELAY_HOURS * 3600 + 60));
    });
    assert!(
        store.legacy_dir_is_on_disk(),
        "the environment should still be here before the driver runs"
    );
    store
}

/// Two nodes sharing a disk both finish, and neither loses a chunk to the other.
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
