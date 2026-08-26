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

/// The longest a cold scan may take per chunk before this is a regression.
///
/// Measured at 1,019 ns per key for 100,000 keys on a hosted CI runner. Fifty times that
/// leaves a slow, loaded, shared runner room to be slow while still catching a scan that
/// has gone from linear to something worse: the whole 100,000-key budget is five seconds
/// against a hundred milliseconds measured.
///
/// Per key rather than a flat number, so that raising `ANT_SCALE_KEYS` for a larger run
/// raises the allowance with it instead of turning the gate into a coin toss.
const SCAN_CEILING_PER_KEY: Duration = Duration::from_micros(50);

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

    let ceiling = SCAN_CEILING_PER_KEY * u32::try_from(keys).unwrap_or(u32::MAX);
    assert!(
        scan < ceiling,
        "scanning {keys} chunks took {scan:?} ({per_key_ns} ns/key), over the {ceiling:?} \
         ceiling"
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

/// Every chunk the store writes takes exactly one directory entry.
///
/// Through `put`, not through the fixture. An earlier version planted the files itself
/// and then counted them, which proves the test can count and nothing about the store: a
/// store that wrote a sidecar beside every chunk would have passed it.
///
/// It matters because a filesystem runs out of inodes independently of bytes, and a node
/// that fills the inode table stops accepting writes while `df` still shows free space.
#[tokio::test]
async fn each_chunk_the_store_writes_costs_one_directory_entry() {
    let keys = 2_000;
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    std::fs::create_dir_all(&root).expect("mkdir");

    let store = FileStore::new(FileStoreConfig {
        root_dir: root.clone(),
        verify_on_read: true,
        disk_reserve: 0,
    })
    .await
    .expect("open");

    for n in 0..keys {
        // Real content through the real path, so anything `put` writes is counted.
        let mut content = vec![0u8; 512];
        content[..8].copy_from_slice(&(n as u64).to_le_bytes());
        let address = ant_node::client::compute_address(&content);
        store.put(&address, &content).await.expect("put");
    }
    store.wait_idle().await;

    let entries = count_entries(&root.join("chunks"));
    assert_eq!(
        entries.files, keys,
        "the store wrote {} files for {keys} chunks",
        entries.files
    );
    // 256 shards and the layout marker are the fixed overhead; nothing should be
    // proportional to the chunk count but the chunks themselves.
    assert!(
        entries.dirs <= 256,
        "the store made {} directories, which grows with the store",
        entries.dirs
    );
}

/// Files and directories under a path, counted rather than summed.
struct Entries {
    files: usize,
    dirs: usize,
}

fn count_entries(path: &Path) -> Entries {
    let mut counted = Entries { files: 0, dirs: 0 };
    let Ok(entries) = std::fs::read_dir(path) else {
        return counted;
    };
    for entry in entries.flatten() {
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                counted.dirs += 1;
                let nested = count_entries(&entry.path());
                counted.files += nested.files;
                counted.dirs += nested.dirs;
            }
            // The store's own two files sit beside the shards and are not chunks: the
            // layout marker, and the lock that keeps a second process out. Both are
            // fixed, so neither grows with the store.
            Ok(_)
                if entry.file_name() == ant_node::storage::file_store::LAYOUT_FILE_NAME
                    || entry.file_name() == ".lock" => {}
            Ok(_) => counted.files += 1,
            Err(_) => {}
        }
    }
    counted
}

/// The startup scan does not read chunk contents.
///
/// The claim the scan's cost rests on: a store of 4 MiB chunks would be unopenable if
/// starting meant reading them.
///
/// Measured in bytes read, not in elapsed time. Timing cannot settle this: the files were
/// written moments earlier, so reading them back comes from the page cache and costs
/// almost nothing. A version of this test that compared durations passed with a
/// deliberate `read` of every file added to the scan. `rchar` counts what the process
/// asked the kernel for whether or not the answer was cached, which is the question.
///
/// Linux only, for `/proc/self/io`. Nothing about the scan is platform-specific, and this
/// is the platform where the answer can be had exactly.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_startup_scan_does_not_read_chunk_contents() {
    let keys = 3_000;
    let chunk = 64 * 1024;
    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path().join("node");
    plant_sized(&root.join("chunks"), keys, chunk);

    let before = bytes_read().expect("linux reports this");
    let store = FileStore::new(FileStoreConfig {
        root_dir: root.clone(),
        verify_on_read: true,
        disk_reserve: 0,
    })
    .await
    .expect("open");
    let read = bytes_read()
        .expect("linux reports this")
        .saturating_sub(before);

    let payload = (keys * chunk) as u64;
    println!(
        "scale: opening a store of {keys} chunks read {read} bytes, against {payload} \
         bytes of chunk"
    );
    assert_eq!(store.current_chunks().expect("count") as usize, keys);

    // Fixed, deliberately, and not a fraction of the payload. A fraction grows with the
    // store, so it would keep permitting a per-chunk read as long as the chunks were big
    // enough: at these sizes a hundredth of the payload allowed 655 bytes per chunk, which
    // is a header read of every file in the store passing a test named for not doing that.
    //
    // A scan that reads names reads the same handful of bytes whatever the store holds.
    // Measured at 125 bytes for 3,000 chunks on a hosted runner, which is the layout marker
    // and nothing else. 64 KiB is five hundred times that and still under 22 bytes per
    // chunk here, so any read that is per-chunk at all fails, and fails harder the larger
    // the run.
    const SCAN_READ_CEILING: u64 = 64 * 1024;
    assert!(
        read < SCAN_READ_CEILING,
        "the scan read {read} bytes of a {payload} byte store, over the \
         {SCAN_READ_CEILING} byte ceiling, so it is reading contents"
    );
}

/// Bytes this process has asked the kernel to read, cached or not.
#[cfg(target_os = "linux")]
fn bytes_read() -> Option<u64> {
    let io = std::fs::read_to_string("/proc/self/io").ok()?;
    io.lines()
        .find_map(|line| line.strip_prefix("rchar:"))
        .and_then(|value| value.trim().parse().ok())
}

/// Plant `count` chunk files of `bytes` each.
#[cfg(target_os = "linux")]
fn plant_sized(chunks_dir: &Path, count: usize, bytes: usize) {
    for shard in 0u16..256 {
        std::fs::create_dir_all(chunks_dir.join(format!("{shard:02x}"))).expect("mkdir");
    }
    let payload = vec![7u8; bytes];
    for n in 0..count {
        let mut address = [0u8; 32];
        address[..8].copy_from_slice(&(n as u64).to_le_bytes());
        address[31] = (n % 256) as u8;
        let path = chunks_dir
            .join(format!("{:02x}", address[31]))
            .join(hex::encode(address));
        std::fs::write(path, &payload).expect("plant a chunk");
    }
}
