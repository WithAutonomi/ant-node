# ADR-0007: Cap the Windows LMDB map head-room

- **Status:** Proposed
- **Date:** 2026-07-28
- **Decision owners:** @jacderida
- **Reviewers:** @dirvine
- **Supersedes:** none
- **Superseded by:** none
- **Related:** PR #187, Linear V2-620

## Context

The LMDB chunk store auto-sizes its memory map to the whole storage partition:
`map = current_db_bytes + max(0, available_disk − reserve)` (`compute_map_size`).
On Linux the mapping stays sparse and this is effectively free.

On Windows, a node's committed / private memory scales with the *mapped* size
rather than with the data actually stored. Field reports of excessive
`ant-node.exe` memory were traced to this: a live single node showed ~7.4 GB of
extra commit for a ~3.7 TiB map, and a user running three nodes on a 64 GiB
machine reported ~60 GB "in use" that did not correspond to any per-process
working set. The overhead is size-proportional at roughly 0.2% of the mapped
size (measured: ~7.4 GB at ~3.7 TiB, ~181 MB at ~55 GiB). The exact kernel
structure — page tables / section metadata for the reserved file view — was
inferred from that scaling, not measured directly; the size-proportional effect
is what matters here. Because the map is sized to *free disk*, a larger disk
and/or multiple co-located nodes multiply the cost until it can exhaust a host's
commit limit or RAM.

Per-process working set stays small (~250–750 MB), so the problem is invisible
in Task Manager's default column and appears only in commit / virtual /
system-total views — which is why it was historically hard to pin down.

## Decision Drivers

- Windows nodes (especially multi-node, large-disk hosts) must not consume
  memory proportional to disk *capacity*.
- Nodes must retain existing data and still be able to grow to fill the disk.
- Linux behaviour, already correct and free, must not regress.
- The fix must be low-risk: no change to the wire protocol, stored-data format,
  payments, or the upgrade mechanism.

## Considered Options

1. **Cap the map head-room on Windows and grow on demand.** Size the initial map
   to `current_db_bytes + min(free − reserve, HEADROOM)` on Windows; rely on the
   existing `try_resize()` (already used for operator disk-expansion) to extend
   the map as data accumulates.
2. **Cap on all platforms.** Simpler cfg, but needlessly penalises Linux (more
   frequent exclusive-lock resizes) for a problem it does not have.
3. **Expose only a manual `db_size_gb` cap.** Already exists but is off by
   default; leaves every default Windows deployment broken and pushes the burden
   onto operators.
4. **Change the LMDB mapping strategy / write mode on Windows.** Larger blast
   radius, touches storage-engine internals and durability behaviour;
   disproportionate to the problem.

## Decision

We will adopt Option 1: on Windows, cap the disk-headroom term at
`WINDOWS_MAP_HEADROOM = 32 GiB` (`map_target_bytes`, `#[cfg(windows)]`), always
covering `current_db_bytes` so a resize can never truncate the database, and
rely on `try_resize()` to extend the map on demand (~once per 32 GiB written).
Non-Windows platforms keep the disk-sized map unchanged.

## Consequences

### Positive

- Windows commit/private overhead drops from ~0.2% of *disk capacity* to ~0.2%
  of *stored data + 32 GiB* — e.g. ~7.4 GB → ~181 MB on the validated node; the
  3-node / 64 GiB report projects to well under 1 GB.
- Existing databases open unchanged (verified against a live 22.6 GiB store); no
  migration.
- Linux is untouched.

### Negative / Trade-offs

- Resize becomes a routine Windows lifecycle event (~per 32 GiB) rather than a
  rare partition-expansion path. `try_resize()` takes the exclusive `env_lock`
  and calls the unsafe `Env::resize()`, so it briefly stalls that node's storage
  transactions during the remap. Mitigated by the 32 GiB granularity (infrequent)
  and by requiring *every* read/write transaction to hold the shared `env_lock`
  for its full duration — this PR fixes `all_keys`/`get_raw`, which previously
  did not, closing an unmap-during-read race.
- The head-room constant is a heuristic; a workload writing >32 GiB between
  resizes would see back-to-back resizes. 32 GiB keeps the map-proportional
  overhead ~100 MB while making resizes rare.

### Neutral / Operational

- Operators can still set an explicit `db_size_gb` cap to override the default.
- The exact Windows kernel accounting was inferred, not directly measured; a
  follow-up can confirm via RAMMap's Page Table row if a definitive attribution
  is wanted.

## Validation

- Unit tests: `map_target_bytes` cap binds on Windows and is a no-op elsewhere;
  existing data is always covered even when the head-room term saturates to zero.
- Resize-safety regression test `read_paths_block_while_env_is_being_resized`:
  proves `all_keys`/`get_raw` hold the shared lock and cannot run concurrently
  with a resize.
- Live before/after on a Windows production node (22.6 GiB stored): map
  3,719 GiB → 54.58 GiB; commit 7,537 MB → 181 MB; virtual 3,719 GB → 60 GB; DB
  reopened without data loss.
- Review trigger: revisit `WINDOWS_MAP_HEADROOM` if Windows resize-stall latency
  is observed under concurrent replication/audit load, or if a direct
  kernel-attribution measurement changes the cost model.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
