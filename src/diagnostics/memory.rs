//! Logging-only process memory diagnostics for production canaries.

use std::fs;
use std::path::Path;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::logging::{debug, enabled, info, warn};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;
const DEFAULT_INTERVAL_SECS: u64 = 60;
const DEFAULT_WARN_RSS_MB: u64 = 4 * 1024;
const DEFAULT_DUMP_RSS_MB: u64 = 8 * 1024;

/// Start the process memory diagnostics loop when explicitly enabled.
///
/// Enable with `ANT_MEMORY_DIAG_ENABLE=1`. The loop emits one low-cardinality
/// structured log every `ANT_MEMORY_DIAG_INTERVAL_SECS` seconds and adds a
/// threshold marker when RSS crosses `ANT_MEMORY_DIAG_RSS_WARN_MB` or
/// `ANT_MEMORY_DIAG_RSS_DUMP_MB`.
#[must_use]
pub fn start_process_memory_diagnostics(
    node_label: String,
    port: u16,
    shutdown: CancellationToken,
) -> Option<JoinHandle<()>> {
    if std::env::var("ANT_MEMORY_DIAG_ENABLE").ok().as_deref() != Some("1") {
        return None;
    }

    let interval_secs = env_u64("ANT_MEMORY_DIAG_INTERVAL_SECS", DEFAULT_INTERVAL_SECS).max(5);
    let warn_rss_bytes = env_u64("ANT_MEMORY_DIAG_RSS_WARN_MB", DEFAULT_WARN_RSS_MB) * MIB;
    let dump_rss_bytes = env_u64("ANT_MEMORY_DIAG_RSS_DUMP_MB", DEFAULT_DUMP_RSS_MB) * MIB;

    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            telemetry = "process_memory_diagnostics_started",
            node_label = %node_label,
            port,
            interval_secs,
            warn_rss_bytes,
            dump_rss_bytes,
            jemalloc_heap_profiling = cfg!(feature = "jemalloc-heap-profiling"),
            "process memory diagnostics started"
        );

        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    if !enabled!(crate::logging::Level::INFO) {
                        continue;
                    }
                    emit_process_memory_snapshot(&node_label, port, warn_rss_bytes, dump_rss_bytes);
                }
            }
        }

        debug!(
            telemetry = "process_memory_diagnostics_stopped",
            node_label = %node_label,
            port,
            "process memory diagnostics stopped"
        );
    }))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn emit_process_memory_snapshot(
    node_label: &str,
    port: u16,
    warn_rss_bytes: u64,
    dump_rss_bytes: u64,
) {
    let status = read_status_snapshot();
    let smaps = read_smaps_rollup_snapshot();
    let cgroup = read_cgroup_memory_snapshot();
    let fd_count = count_dir_entries("/proc/self/fd");
    let jemalloc = jemalloc_stats_snapshot();

    let rss_bytes = status.vm_rss_kib.map(|v| v * KIB).unwrap_or_default();
    let threshold = if rss_bytes >= dump_rss_bytes {
        "dump"
    } else if rss_bytes >= warn_rss_bytes {
        "warn"
    } else {
        "ok"
    };

    info!(
        telemetry = "process_memory_snapshot",
        node_label = %node_label,
        port,
        threshold,
        rss_bytes,
        vm_size_bytes = status.vm_size_kib.map(|v| v * KIB),
        vm_hwm_bytes = status.vm_hwm_kib.map(|v| v * KIB),
        rss_anon_bytes = status.rss_anon_kib.map(|v| v * KIB),
        rss_file_bytes = status.rss_file_kib.map(|v| v * KIB),
        rss_shmem_bytes = status.rss_shmem_kib.map(|v| v * KIB),
        threads = status.threads,
        fd_count,
        smaps_rss_bytes = smaps.rss_kib.map(|v| v * KIB),
        smaps_pss_bytes = smaps.pss_kib.map(|v| v * KIB),
        smaps_private_clean_bytes = smaps.private_clean_kib.map(|v| v * KIB),
        smaps_private_dirty_bytes = smaps.private_dirty_kib.map(|v| v * KIB),
        smaps_anonymous_bytes = smaps.anonymous_kib.map(|v| v * KIB),
        smaps_file_bytes = smaps.file_kib.map(|v| v * KIB),
        smaps_swap_bytes = smaps.swap_kib.map(|v| v * KIB),
        cgroup_memory_current_bytes = cgroup.current_bytes,
        cgroup_memory_peak_bytes = cgroup.peak_bytes,
        cgroup_memory_max_bytes = cgroup.max_bytes,
        jemalloc_allocated_bytes = jemalloc.allocated,
        jemalloc_active_bytes = jemalloc.active,
        jemalloc_resident_bytes = jemalloc.resident,
        jemalloc_mapped_bytes = jemalloc.mapped,
        jemalloc_retained_bytes = jemalloc.retained,
        "process memory telemetry snapshot"
    );

    if threshold == "dump" {
        warn!(
            telemetry = "process_memory_dump_threshold",
            node_label = %node_label,
            port,
            rss_bytes,
            dump_rss_bytes,
            jemalloc_heap_profiling = cfg!(feature = "jemalloc-heap-profiling"),
            "process RSS crossed dump threshold; rely on jemalloc MALLOC_CONF prof dumps if enabled"
        );
    }
}

#[derive(Default)]
struct StatusSnapshot {
    vm_rss_kib: Option<u64>,
    vm_size_kib: Option<u64>,
    vm_hwm_kib: Option<u64>,
    rss_anon_kib: Option<u64>,
    rss_file_kib: Option<u64>,
    rss_shmem_kib: Option<u64>,
    threads: Option<u64>,
}

fn read_status_snapshot() -> StatusSnapshot {
    let Ok(text) = fs::read_to_string("/proc/self/status") else {
        return StatusSnapshot::default();
    };
    let mut out = StatusSnapshot::default();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key {
                "VmRSS" => out.vm_rss_kib = parse_kib(value),
                "VmSize" => out.vm_size_kib = parse_kib(value),
                "VmHWM" => out.vm_hwm_kib = parse_kib(value),
                "RssAnon" => out.rss_anon_kib = parse_kib(value),
                "RssFile" => out.rss_file_kib = parse_kib(value),
                "RssShmem" => out.rss_shmem_kib = parse_kib(value),
                "Threads" => out.threads = parse_first_u64(value),
                _ => {}
            }
        }
    }
    out
}

#[derive(Default)]
struct SmapsRollupSnapshot {
    rss_kib: Option<u64>,
    pss_kib: Option<u64>,
    private_clean_kib: Option<u64>,
    private_dirty_kib: Option<u64>,
    anonymous_kib: Option<u64>,
    file_kib: Option<u64>,
    swap_kib: Option<u64>,
}

fn read_smaps_rollup_snapshot() -> SmapsRollupSnapshot {
    let Ok(text) = fs::read_to_string("/proc/self/smaps_rollup") else {
        return SmapsRollupSnapshot::default();
    };
    let mut out = SmapsRollupSnapshot::default();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key {
                "Rss" => out.rss_kib = parse_kib(value),
                "Pss" => out.pss_kib = parse_kib(value),
                "Private_Clean" => out.private_clean_kib = parse_kib(value),
                "Private_Dirty" => out.private_dirty_kib = parse_kib(value),
                "Anonymous" => out.anonymous_kib = parse_kib(value),
                "File" => out.file_kib = parse_kib(value),
                "Swap" => out.swap_kib = parse_kib(value),
                _ => {}
            }
        }
    }
    out
}

#[derive(Default)]
#[allow(dead_code)]
struct CgroupMemorySnapshot {
    current_bytes: Option<u64>,
    peak_bytes: Option<u64>,
    max_bytes: Option<u64>,
}

fn read_cgroup_memory_snapshot() -> CgroupMemorySnapshot {
    CgroupMemorySnapshot {
        current_bytes: read_u64_file("/sys/fs/cgroup/memory.current"),
        peak_bytes: read_u64_file("/sys/fs/cgroup/memory.peak"),
        max_bytes: read_cgroup_max("/sys/fs/cgroup/memory.max"),
    }
}

fn read_u64_file(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

fn read_cgroup_max(path: &str) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;
    let value = text.trim();
    if value == "max" {
        None
    } else {
        value.parse::<u64>().ok()
    }
}

fn count_dir_entries(path: &str) -> Option<usize> {
    Some(
        fs::read_dir(Path::new(path))
            .ok()?
            .filter_map(Result::ok)
            .count(),
    )
}

fn parse_kib(value: &str) -> Option<u64> {
    parse_first_u64(value)
}

fn parse_first_u64(value: &str) -> Option<u64> {
    value.split_whitespace().next()?.parse::<u64>().ok()
}

#[derive(Default)]
#[allow(dead_code)]
struct JemallocStatsSnapshot {
    allocated: Option<usize>,
    active: Option<usize>,
    resident: Option<usize>,
    mapped: Option<usize>,
    retained: Option<usize>,
}

#[cfg(feature = "jemalloc-heap-profiling")]
fn jemalloc_stats_snapshot() -> JemallocStatsSnapshot {
    use tikv_jemalloc_ctl::{epoch, stats};

    let _ = epoch::advance();
    JemallocStatsSnapshot {
        allocated: stats::allocated::read().ok(),
        active: stats::active::read().ok(),
        resident: stats::resident::read().ok(),
        mapped: stats::mapped::read().ok(),
        retained: stats::retained::read().ok(),
    }
}

#[cfg(not(feature = "jemalloc-heap-profiling"))]
fn jemalloc_stats_snapshot() -> JemallocStatsSnapshot {
    JemallocStatsSnapshot::default()
}
