# ADR-0028: Pressure-gated retention of out-of-range records

- **Status:** Proposed
- **Date:** 2026-11-03
- **Decision owners:** Mick
- **Reviewers:** <pending>
- **Supersedes:** none. Amends ADR-0005 decision 11 and ADR-0016's pointer pruning.
- **Superseded by:** none
- **Related:**
  - ADR-0003: full-node detection.
  - ADR-0004: pricing from the pinned commitment.
  - ADR-0005 decision 11: prune-confirmation audits.
  - ADR-0016: pointer pruning.
  - `docs/REPLICATION_DESIGN.md` §11 and "Capacity-managed mode".
  - PR #266, folded into this change.
  - Linear V2-1833.

## Context

### How pruning works today

A node deletes a record once two things are true:
- it has been continuously outside the record's storage-retention width (9 nodes) for
  `PRUNE_HYSTERESIS_DURATION` (72 h);
- all but one of the current strict close group (6 of 7) prove possession.

A node removes a paid-list entry once two things are true:
- it has been continuously outside the entry's closest 20 for the same hysteresis;
- three quarters of the current 20 (15) confirm they track the key.

Pruning runs on a schedule. Whether the disk needs the room plays no part.

### Why the disk should decide

A close group's proof shows that the closest peers hold the bytes now. It says nothing
about how long they will keep them, and a node can't take back a copy it has erased.

An out-of-range copy costs a node nothing until its disk needs the room. Until then it is
one more copy that repair can draw on. So there is no reason to erase it any earlier.

The same goes for a paid-list entry: a retained record needs its entry for repair to
authorise it, and removing an entry frees no disk.

### Status

- **PR #266 removed the paths that deleted without any proof.** Every deletion needs the
  close group's proofs.
- **The spec already describes eviction at full disk.** `REPLICATION_DESIGN.md` has long
  said "if full … evict farthest out-of-range key". No code implemented it.

## Decision Drivers

- A node erases a record it is no longer responsible for only when its disk needs the
  room.
- A retained record stays repairable, so it keeps its paid-list entry.
- Disk must still be reclaimed: no node may fill up with records it is no longer
  responsible for.
- No wire, record-format or pricing change. The change is node-local and can ship in
  any release.
- A restart must not leave a node with nothing it can erase.
- Keep the existing guards (6-of-7 proofs, retained-commitment veto, bootstrap gate) as
  additional checks, not the only one.

## Considered Options

1. **Keep scheduled pruning with proofs** (the state after PR #266). Copies are erased
   while disks have room, for no gain.
2. **Never delete out-of-range records.** Disk grows without bound.
3. **Delete only under disk pressure, farthest first, still with proofs.** Chosen.
4. **Confirm deletions with randomly sampled auditors from the whole network.** It costs
   bandwidth on every prune, and gains nothing while disks have room.
5. **Also keep a distance floor that lowers as the disk fills.** Deferred: it adds
   mechanism we can add later if telemetry shows records near a node being erased under
   pressure.
6. **Keep confirming paid-list removals with 15 of the current 20 near capacity.** Each
   far entry needs about 19 peers and a pass may ask 32, so a pass removes about one entry
   and a full list can't recover. Local eviction chosen.

## Decision

### When a record becomes eligible

Unchanged:
- continuously outside width 9 for `PRUNE_HYSTERESIS_DURATION`;
- not held by a retained commitment;
- bootstrap drained.

Being eligible makes a record *erasable*, never due.

The clock now survives restarts. Disks run full of retained records by design, so a clock
that restarted with the process would leave a node with nothing to erase for 72 h after
every upgrade.

- **Wall-clock times:** chunk and pointer clocks are kept as wall-clock times, and saved
  in `record_out_of_range.bin` and `pointer_out_of_range.bin` after a prune pass that
  changed them.
- **Time offline counts:** a clock keeps its start across a restart, including the time
  the node was down.
- **Cleared only once bootstrap has drained:** a restarted node knows few peers at first,
  so it looks in range for everything. Clearing then would undo the restore.
- **Fallback:** a wall clock set back only delays an erasure, and an unreadable file only
  starts the clocks again.

### When eligible records are erased

Only while the partition holding the record store is **under pressure**. The pointer
store shares that partition.

| | Free share of the partition | and/or | Free bytes |
|---|---|---|---|
| Pressure starts | below 10% | or | below 2× the store's reserve |
| Pressure ends | at least 15% | and | at least 3× the reserve |

- **Hysteresis:** a node erases in spells, not one record per write.
- **Small partitions:** the reserve bounds start a spell while there is still room above
  the reserve, where the store starts refusing writes.
- **Free share:** measured against the partition's size less its root-reserved blocks, so
  it reads as `df` reads it.
- **Cadence:** the prune passes run after every completed neighbour-sync cycle and, while
  the disk is under pressure, on other sync rounds too, once the minimum sync interval (10
  minutes) has passed since the last pass finished. A cycle spans several rounds, so a
  node under pressure doesn't wait for one to end. Rounds run back to back while newly
  close peers are synced, and each pass scans every stored record, so the spacing keeps
  that repair from waiting behind passes.
- **Measurement:** free space is measured when a pass starts and again before each
  deletion. A pass stops as soon as pressure ends.
- **Late frees:** some filesystems show freed space only after a later commit, so a pass
  may erase a little past the exit line. That is bounded by one pass's budget, and costs
  only out-of-range records the group has proven.
- **Failed measurement:** a measurement that fails erases nothing, and logs a warning.

### Without pressure

- No prune-confirmation audit is sent, since none could lead to a deletion.
- Candidates are counted as retained: `retained=` in the prune log line, and
  `PruneResult::records_retained`.

### Under pressure

- **Order:** candidates are tried farthest from this node first, by XOR distance.
- **Failed proofs go last, oldest failure first:** a record whose proof failed comes after
  every record not yet tried, and failed records are retried in the order they last
  failed. So records the group can't prove yet never keep the rest from a turn, and a
  record that failed once for a passing reason is tried again within the spell, however
  many new candidates arrive. Demotions are forgotten when the spell ends.
- **Per-deletion checks:** each deletion still needs 6 of 7 proofs from the current
  strict close group, plus the existing re-check before deleting. A pointer candidate is
  also checked for pressure before its group is asked: once earlier deletions have ended
  the spell, a proof could not lead to a deletion.
- **Batch sizes:** the keys per prune challenge are sized from the records this node is
  in range for, not all it holds. Peers size what they accept from their own stores, so
  sizing from a store full of retained records would send batches a newer peer rejects,
  and the rejection would count against that peer.
- **Request budget:** raised from 256 to 1,024 audit requests per pass. With no fast
  path, every erasure needs proofs, and far candidates rarely share a close group, so
  each costs about seven requests. That allows about 146 candidates per pass, roughly
  600 MiB at the largest chunk size, instead of about 36. Audits are only sent under
  pressure.
- **Unchanged:** the per-pass candidate budget.

### Scope

- **Pointers:** the same rules, with one pressure state per node shared by the chunk and
  pointer passes. This replaces PR #266's address-order cursor; retrying the oldest
  failure first keeps its fairness. A pointer candidate asks its whole group at once, each
  request waiting at most 5 s for a slot and again for its answer, and awaits every
  answer, so its requests never outlive it.
- **Storage audits:** the responsible-chunk audit samples only records this node is in
  range for. Retained records are mostly far from the neighbours it audits, so sampling
  them would leave fewer keys audited per tick.
- **PR #266:** included. No record or pointer is ever deleted without the close group's
  proofs.
- **Paid-list entries:** kept, instead of being pruned by rank and confirmations.
  - **Below `paid_list_evict_start_entries`** (15 million, about 85% of the store): every
    entry stays, whatever the disk.
  - **Above it:** each prune pass evicts down to the threshold, at most 100,000 entries,
    farthest from this node first. Eviction is local, with no confirmations.
  - **What stays even then:** entries near this node, and entries of records it still
    stores. Near means within four to eight times the distance to its farthest paid-group
    peer, where it or a neighbour may still have a vote. While it knows too few peers to
    say, every entry counts as near.
  - **Sync hints:** read only the entries near this node, so their cost doesn't grow with
    the list.
  - **Store size:** the LMDB map grows from 256 MiB to 1 GiB, which holds about 17.6
    million entries, measured at about 61 bytes each with single-key commits. The file
    grows as entries do, on every platform. A full store logs one error, since new paid
    keys can't be recorded from then on.
- **Clocks and entries are independent:** removing a paid-list entry no longer clears its
  record's out-of-range clock.

### Implementation

- `src/replication/retention.rs`: the pressure state, thresholds and erase order.
- `src/replication/out_of_range_clocks.rs`: saving and restoring the clocks.
- `ChunkStore::disk_space`: the measurement.

### Why this holds

- **Only a node's own disk triggers erasure.** A node erases a record only when its disk
  needs the room.
- **Records near the node go last.** Even under pressure, a record close to the node is
  among the last to go.
- **Retained copies stay usable.** They keep feeding repair, with the paid entries that
  authorise it. Reading from retained copies is a separate client change.

## Consequences

### Positive

- A node no longer erases a copy while its disk has room, for chunks and pointers, and no
  record is deleted without its close group's proofs.
- Paid-list entries stay until the list nears its store's capacity.
- No prune-audit traffic while disks have room.
- Retained records keep feeding neighbour-sync repair, which offers them to their close
  groups.
- No wire, record-format or pricing change. Quotes price on the pinned commitment's key
  count (ADR-0004), which covers only keys inside the strict close group, so retained
  records don't raise prices. Older binaries ignore the two new clock files.
- A restart doesn't stop a node erasing.

### Negative / Trade-offs

- **Fuller disks, deliberately.** Disks fill to 85–90% before anything is erased, so
  operators see higher disk use than today.
- **More CPU per pass.** Prune scans and replica-hint construction walk every retained
  key, so per-pass CPU grows with the retained set.
- **Paid lists stop shrinking** until the threshold: up to about 915 MB of store per node.
- **Clock files add writes.** One is rewritten after a pass that changed it, at about 40
  bytes per retained record.
- **Erasure has a rate.** About 146 far candidates per pass, at most one pass per 10
  minutes. A large node in a fast-growing network may still fall behind and reach its
  reserve. A pass under pressure holds up its sync round while its audits run.
- **Nothing eligible yet means filling up.** A node under pressure with no record past the
  hysteresis keeps filling to its reserve and then refuses in-range writes, as a full node
  does today.
- **Under sustained pressure, a node keeps erasing** its farthest records on their groups'
  proofs. Records near it go last.
- **Above the paid threshold, a node forgets far entries without asking anyone.** It has
  no vote on those keys, and it keeps the entries of records it still stores.
- **Records that can't be proven can't be erased.** If out-of-range records can't be
  proven, a node can reach its reserve and refuse in-range writes, and ADR-0003's
  penalties then apply.
- **Erasure is not tied to writes.** Erasure starts within one sync round of pressure
  starting, not at write time. On a small partition, a burst of in-range uploads can
  cross from twice the reserve to the reserve before the next round, and writes are
  refused until a pass has erased. On larger disks the 10% line leaves far more room
  than a round's writes. Evicting at write time is possible follow-up work.
- **A long outage can leave records immediately eligible.** Time offline counts towards
  the hysteresis, so a node that returns after days can erase under pressure once
  bootstrap has drained, still only on the current group's proofs.

### Neutral / Operational

- **The prune log line gains `disk_pressure=` and `retained=`.**
- **Public Rust API breaks:**
  - `PrunePassContext` gains `disk_pressure`.
  - `ReplicationConfig` gains `paid_list_evict_start_entries`.
  - `PruneResult`'s paid counters become `paid_entries_evicted`, and the prune log line's
    paid part becomes `paid total= evicted=`.
  - `PaidList` loses its paid timers, its prune cursor and `all_keys`, and gains `keys_near`
    and `evict_far`. Its record timestamps are `SystemTime`s.
  - `PointerReplication::prune_pass` takes the pressure state.
  - `NeighborSyncState::prune_cursor` is removed.
  - PR #266's removals are included.

## Validation

- **Unit tests** (`retention.rs`):
  - thresholds and their hysteresis;
  - the reserve-based bounds;
  - a failed measurement;
  - farthest-first order with demotions last, and a limit taking the first of it;
  - no candidate waiting more than a round for its next turn, over many passes;
  - new candidates arriving not stopping failed ones being retried;
  - passes under pressure spaced, and a completed cycle always running one;
  - demotions ending with the spell.
- **Unit tests** (`out_of_range_clocks.rs`, `paid_list.rs`, `pruning.rs`, `pointer.rs`):
  - a saved clock keeping its age and counting time offline;
  - a wall clock gone backwards, and a missing or corrupt file;
  - record clocks surviving a reopen of the paid list;
  - a clock surviving "in range" during bootstrap;
  - paid-list eviction: farthest first, up to its limit, never what it keeps, never near;
  - near ranges, and reading only the keys in one;
  - the store's file not taking the whole map up front;
  - removing a paid entry leaving its record's clock;
  - a pointer needing all but one of its group to prove it.
- **End-to-end tests:**
  - `out_of_range_records_stay_until_the_disk_needs_the_room`: with room, a record the
    whole group holds is kept and its group never asked; under pressure it goes.
  - `paid_entries_stay_below_the_threshold_and_near_this_node`: disk pressure evicts no
    paid entry, and an entry near this node stays over the threshold.
  - The existing chunk prune tests run under a simulated nearly full disk.
  - The pointer prune test keeps a provable record while the disk has room.
  - The audit e2e tests pass with in-range sampling.
- **Dev testnet:** fill a node past 90% and check that:
  - `disk_pressure=true` appears;
  - it erases farthest first;
  - it stops at 15% free;
  - below the threshold, `paid ... evicted=0` holds on every node;
  - with a test build's low threshold, only far entries without a stored record go;
  - hint-build times stay flat as `paid total=` grows;
  - how fast a node under pressure erases, against how fast it receives in-range data;
  - after restarting a node under pressure, `candidates=` doesn't fall to 0 once bootstrap
    has drained;
  - whether far records can be proven, from `audit_below_threshold`;
  - how long passes hold up sync rounds under pressure.
- **Revisit if:**
  - nodes reach their reserve while holding retained records (the proof gate is
    blocking);
  - sync hint building slows noticeably as paid lists grow;
  - operators push back on disk use;
  - telemetry shows records near a node erased under pressure (then consider option 5).

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
