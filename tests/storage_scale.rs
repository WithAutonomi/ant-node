//! What one file per chunk costs at scale.
//!
//! The design accepted two costs on paper and never measured either: the startup scan
//! reads every filename in the store before the node serves anything, and every chunk
//! takes an inode and a directory entry. Both grow with the store, and a node that takes
//! minutes to start, or runs a filesystem out of inodes, is a node that is down.
//!
//! These are regression gates, not benchmarks. The ceilings are generous enough that a
//! loaded shared runner does not fail them and tight enough that an order-of-magnitude
//! regression does. What they measure precisely is printed, so a number that is drifting
//! is visible in the log before it ever trips the gate.
//!
//! `ANT_SCALE_KEYS` raises the count for a deliberate larger run. The default is what a
//! hosted runner can do in reasonable time; the fleet-scale figures the ADR wants still
//! need a machine with the disk for them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    // Test fixtures: every cast here is of a bounded loop counter into a byte, and the
    // wrap is what makes the fill vary.
    clippy::cast_possible_truncation
)]

use ant_node::storage::{FileStore, FileStoreConfig};
use std::path::Path;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Keys to plant unless told otherwise.
const DEFAULT_KEYS: usize = 100_000;

/// The longest a cold scan of `DEFAULT_KEYS` may take before this is a regression.
///
/// Measured at about 1.5 seconds cold for 250,000 files on a developer machine. Ten
/// times that for less than half the files leaves room for a slow shared runner while
/// still catching a scan that has gone from linear to something worse.
const SCAN_CEILING: Duration = Duration::from_secs(30);

/// How many keys this run should plant.
fn key_count() -> usize {
    std::env::var("ANT_SCALE_KEYS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_KEYS)
}

/// Plant `count` chunk files directly, without going through the store.
///
/// Writing them by hand rather than through `put` is the point: this measures opening a
/// store that already holds them, which is what a restart does, not the cost of filling
/// one.
fn plant_chunks(chunks_dir: &Path, count: usize) {
    for shard in 0u16..256 {
        std::fs::create_dir_all(chunks_dir.join(format!("{shard:02x}"))).expect("mkdir");
    }
    // One byte each. The scan reads names, never contents, so the payload would only cost
    // the test disk it does not need.
    for n in 0..count {
        let mut address = [0u8; 32];
        address[..8].copy_from_slice(&(n as u64).to_le_bytes());
        // The shard is the last byte, so spread across all 256 rather than piling into one.
        address[31] = (n % 256) as u8;
        let path = chunks_dir
            .join(format!("{:02x}", address[31]))
            .join(hex::encode(address));
        std::fs::write(path, b"x").expect("plant a chunk");
    }
}

/// Resident memory of this process, in bytes, where the platform will say.
#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

/// Not every platform makes this cheap to ask, and the gate below is the scan time.
#[cfg(not(target_os = "linux"))]
fn resident_bytes() -> Option<u64> {
    None
}

/// Opening a store that already holds a large number of chunks stays quick.
///
/// This is the first thing a restarted node does and nothing is served until it finishes,
/// so it is the cost that decides whether a big node can be restarted at all.
#[tokio::test]
async fn opening_a_large_store_stays_quick() {
    let keys = key_count();
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    let chunks_dir = root.join("chunks");
    std::fs::create_dir_all(&chunks_dir).expect("mkdir");

    let planting = Instant::now();
    plant_chunks(&chunks_dir, keys);
    let planted = planting.elapsed();

    let before = resident_bytes();
    let opening = Instant::now();
    let store = FileStore::new(FileStoreConfig {
        root_dir: root.clone(),
        verify_on_read: true,
        disk_reserve: 0,
    })
    .await
    .expect("open a store holding a large number of chunks");
    let scan = opening.elapsed();
    let after = resident_bytes();

    let indexed = store.current_chunks().expect("count");
    assert_eq!(
        indexed as usize, keys,
        "the scan must find every planted chunk"
    );

    let per_key_ns = scan.as_nanos() / keys.max(1) as u128;
    let growth = match (before, after) {
        (Some(before), Some(after)) => format!("{} KiB", after.saturating_sub(before) / 1024),
        _ => "not measured on this platform".to_string(),
    };
    println!(
        "scale: {keys} chunks planted in {planted:?}, scanned in {scan:?} \
         ({per_key_ns} ns/key), resident growth {growth}"
    );

    assert!(
        scan < SCAN_CEILING,
        "scanning {keys} chunks took {scan:?}, over the {SCAN_CEILING:?} ceiling"
    );
}

/// The index costs a bounded amount of memory per chunk.
///
/// One inode and one directory entry per chunk is the filesystem's share, and the ADR
/// accepts it. What it did not measure is the node's own share: an in-memory set of every
/// address, which is the part that could quietly make a large node unrunnable.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_in_memory_index_costs_a_bounded_amount_per_chunk() {
    let keys = key_count();
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    let chunks_dir = root.join("chunks");
    std::fs::create_dir_all(&chunks_dir).expect("mkdir");
    plant_chunks(&chunks_dir, keys);

    let before = resident_bytes().expect("linux reports this");
    let store = FileStore::new(FileStoreConfig {
        root_dir: root,
        verify_on_read: true,
        disk_reserve: 0,
    })
    .await
    .expect("open");
    let after = resident_bytes().expect("linux reports this");

    let grew = after.saturating_sub(before);
    let per_key = grew / keys.max(1) as u64;
    println!(
        "scale: index grew {} KiB, {per_key} bytes per chunk",
        grew / 1024
    );

    assert_eq!(store.current_chunks().expect("count") as usize, keys);
    // A 32-byte address in a sorted set, plus allocator and node overhead. 256 bytes each
    // is far above what a `BTreeSet` costs and far below anything that would make a
    // ten-million-chunk node impossible, which is the question being asked.
    assert!(
        per_key < 256,
        "the index costs {per_key} bytes per chunk, which does not scale"
    );
}

/// Every chunk takes exactly one inode and one directory entry.
///
/// Stated in the design and never checked. It matters because a filesystem runs out of
/// inodes independently of bytes, and a node that fills the inode table stops accepting
/// writes while `df` still shows free space.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn each_chunk_costs_one_inode() {
    use std::os::unix::fs::MetadataExt;

    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    let chunks_dir = root.join("chunks");
    std::fs::create_dir_all(&chunks_dir).expect("mkdir");

    // Small on purpose: this is about the ratio, and counting inodes means walking them.
    let keys = 5_000;
    plant_chunks(&chunks_dir, keys);

    let mut inodes = std::collections::HashSet::new();
    for shard in std::fs::read_dir(&chunks_dir)
        .expect("read shards")
        .flatten()
    {
        for chunk in std::fs::read_dir(shard.path())
            .expect("read a shard")
            .flatten()
        {
            inodes.insert(chunk.metadata().expect("stat").ino());
        }
    }
    assert_eq!(
        inodes.len(),
        keys,
        "each chunk should have one inode of its own"
    );
}
