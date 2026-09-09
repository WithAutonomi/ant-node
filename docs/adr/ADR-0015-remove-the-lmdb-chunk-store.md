# ADR-0015: Remove the LMDB Chunk Store and Restore the Close-Group Penalty

- **Status:** Proposed
- **Date:** 2026-08-28
- **Decision owners:** Anselme Gaeremynck
- **Reviewers:** David Irvine, Chris O'Neil, Mick van der Most van Spijk
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0014 (one file per chunk, and retiring LMDB), which this completes

## Context

Moving chunks off LMDB shipped as three releases, because the penalty for not holding a
close-group chunk is the *auditor's* decision: a node that has to give chunks up cannot stop
its peers punishing it for that. So the peers stopped first.

1. **First:** suspend that one penalty.
2. **Second:** copy every chunk into a file of its own, then delete `chunks.mdb`. ADR-0014.
3. **Third:** this one.

ADR-0014 describes the third release as flipping the switch back and nothing more. What
actually has to happen is larger, and two parts of it are decisions rather than clean-up.

## Decision

**Restore the penalty, and keep its switch.** The constant goes back to `false`. The
process-wide atomic, the `ANT_SUSPEND_UNHELD_CHUNK_PENALTY` override and the startup
announcement all stay. They are not migration machinery: they are one release-level policy
that several audit paths have to obey identically, and the release that restores a penalty
is exactly the one most likely to need it undone in a hurry. Removing them would discard the
cheapest lever at the moment it is most useful. A test now pins the shipped value, because
the existing tests set the switch both ways on purpose and so could never notice which way
it was compiled.

**Delete the LMDB chunk store and the migration, and keep the name `ChunkStore`.** There is
one store. It is one file per chunk, it lives in `src/storage/chunk_store.rs`, and it is
called `ChunkStore` because that is what it is and what every caller already called it. The
type that used to present two stores as one is gone with the second store.

`heed` stays in the dependency list. The paid-key list has its own LMDB environment, which
this decision does not touch.

**A node that still has an unretired `chunks.mdb` starts anyway, and clears up what it can
prove is finished with.** This is the part worth arguing, and two earlier drafts of this
decision got it wrong in opposite directions.

That draft refused to start, and the reasoning was not silly. The chunks in that environment
are unreachable to this build, but the commitment the node published before the upgrade
*claimed* them, and a commitment stays answerable to its neighbours for three hours
(`GOSSIP_ANSWERABILITY_TTL`, which is `(RETAINED_GOSSIPED_COMMITMENTS + 1)` rotations). The
accusation the first release suspended was "you did not have a chunk you were supposed to
hold"; the commitment-bound subtree audit was never suspended in any release, precisely
because it rests on a signed claim. So a node that starts half-migrated does spend hours
failing audits, at the full weight, on the one lane that always counted.

Three things make refusing the worse answer anyway.

**A node that refuses serves nothing.** Not the chunks it cannot read, and not the far larger
number it migrated perfectly well. The bounded harm being avoided is a few hours of trust
penalty; the harm being accepted is the entire node, and not for a few hours.

**There is no recovery.** The obvious instruction, "put the previous build back and let it
finish", cannot be carried out. `Node::build_upgrade_monitor` is called unconditionally and
`UpgradeConfig` has no field that switches it off, so a node put back on the previous release
polls, finds this one, and takes it. There is nothing to set, in a config file or on the
command line, that stops it. On the deployed unit (`Restart=always`, `RestartSec=10`) a
refusing node is a ten-second restart loop with no health check and no automatic rollback, and
it stays in it until a person intervenes. An instruction nobody can follow is not a
mitigation.

(How quickly it is taken depends on the deployment. The unit in `deploy/terraform` runs the
node as `ant` under `ProtectSystem=strict` with write access only to its own directory, and
the binary lives in `/usr/local/bin`, so the in-process replacement cannot complete there at
all. That is a separate problem with that unit, not a way to hold a node on an old release:
nothing in the node consents to staying.)

**The population that reaches here is not the one refusing would protect.** A node that has
been offline long enough to miss the previous release entirely has no retained root at any
peer — the answerability window is three hours and its close group has long since re-placed
what it held — so it takes no *commitment-bound* penalty, which is the lane refusing was
protecting it from. The node that is exposed on that lane is one that was running and
unmigrated when this release landed, and that is exactly the population the previous release's
fleet signal exists to count and wait out.

It is not penalty-free, and it is worth being exact about what remains rather than rounding it
to nothing. This release restores the close-group unheld-chunk penalty, and that is a separate
lane from the commitment-bound audit. A node carrying an old store it cannot read is a node
with that much less disk, and a node short of disk fails to take on the chunks it is
responsible for and is penalised on that lane like any other full node. That is not a penalty
for having migrated badly; it is the ordinary consequence of a full disk, arriving through a
directory that is full of nothing useful. The node is told exactly that, once, by name, and
the remedy is the operator's: add disk, or delete the directory once its contents are known to
be elsewhere.

Refusing to start would not have spared it either. It would have had the same disk and none of
the service.

So this build starts, and it clears up **only what is provably finished with**.

Deleting whatever it finds was the second draft, and it was also wrong. The upgrade monitor
picks the newest eligible release rather than the next one, so a node that was offline
through the previous release arrives here with every chunk it owns in that environment and
nothing at all in the file store. Deleting that is destroying data that may have no other
copy, in order to reclaim disk.

The evidence that separates the two is the mark the previous release wrote *inside* the
directory before it deleted anything. A directory carrying `RETIRED` has already had its
contents copied out and is pure cost. So is an empty one, which is what a cleanup interrupted
between emptying a tombstone and removing it leaves. Those go, and their disk comes back.

| what is on disk | what happens |
|---|---|
| nothing, or a root that does not exist yet | start |
| a leftover carrying its `RETIRED` mark | start, remove it in the background, report the space once it is back |
| a leftover with nothing in it | start, remove it |
| a leftover with chunks in it and no mark | start, **keep it**, name it once |
| a leftover whose contents or mark cannot be established | start, keep it, name it once |
| a link at either name | start, keep it, name it once |
| a name retirement never created | start, ignore it entirely |

The rows that keep something are the point. A node in one of those states runs, serves its
file store, keeps its old one, and tells its operator exactly what it is and what to do about
it. It does not get its disk back, which is the honest cost of not being able to prove that
directory is safe to delete.

Two things are never done, both because a name is not evidence of what is behind it.

A **link is neither followed nor unlinked**. What is behind it is on storage this node does
not own: following it would delete somebody else's data, and unlinking it would throw away
the only record of where that data went.

Only the **exact names** the previous release created are considered: `chunks.mdb`,
`chunks.mdb.retired`, and `chunks.mdb.retired.<n>` for `n` in `1..=64` written without a
leading zero. An earlier draft matched by prefix and by "all digits", which would have claimed
a `chunks.mdb.retired-keep-this` an operator put there, and `.007` and `.999999`, which
retirement cannot have produced. The suffix is parsed and written back out so it has to match
itself, and there is a test that plants every near miss.

The deletion runs on its own thread and nothing waits for it. `remove_dir_all` over a store
with millions of files runs for minutes and must not be on the startup path. It deletes in
place: there is nothing to get out of the way, because the directory holds no chunks and this
build has no code that would read it if it did. An earlier draft renamed first and could run
out of names to rename to, at which point it stopped removing anything at all, permanently.
The space is only reported as returned once the deletion has actually finished, because a
number that is wrong for the next several minutes is worse than no number.

**The mark has to be the file the previous release wrote**, not merely something at that
name. It is written with `create_new`, so it is always an ordinary file; a directory, a link
or a FIFO wearing the name proves nothing, and this is the answer that authorises deleting
every chunk underneath it. Testing existence alone would let anything at that path clear an
unmigrated store for deletion.

**The mark is removed last.** `remove_dir_all` gives no promise about the order it unlinks
things in, and if the mark went before the chunks did and the process stopped there, the next
start would find an unmarked directory with data in it, decide it might be an unmigrated
store, and keep it for good. It is not one, but nothing on disk would say so any more, and
the node would report itself unfinished to the whole network for as long as it lived. So the
contents go, then the mark, then the directory: at every point either the mark is still there
and the next start resumes, or the directory is empty, which is also finished with.

**None of it happens until the file store has actually opened.** "Finished with" means the
chunks are in the file store, and that is only true if the file store is there to hold them.
An earlier draft ran this as soon as the root was known, which put the deletion in front of a
constructor that can still fail on an unreadable layout, a directory it cannot create, or a
lock another process has not let go of — and a node that lost both stores that way had
nothing to go back to. Waiting costs nothing in what this node reports: its user agent is
fixed when the transport is built, a moment earlier, but everything removed here is a leftover
the signal already reads as finished with — carrying the mark or being empty is both what
makes it removable and what makes it harmless — so the node announces `files` whether the
deletion has finished, is still running, or has not started.

Nothing here can fail. `clean_up` returns `()`. Every way a filesystem can disappoint it ends
in a node that runs, a warning that names the directory, and disk that has not come back —
which is a worse place than success and a far better one than a restart loop.

Nothing here can leave a node with no store: the deletion runs only after the store that
replaced it has opened, and only over directories that provably hold no chunks. A node that
never opens one, because storage is switched off, deletes nothing at all — it has established
nothing about where those chunks went, and it has no use for the disk either.

**One accepted risk, stated rather than half-fixed.** The checks name a path and the unlinking
names it again, so anything that can replace that directory between the two wins the race and
is deleted through. Closing it needs a directory handle held across the whole operation and
`unlinkat` against it, which Rust's standard library does not offer portably. It is accepted
because whoever can win that race already has write access to this node's data directory and
does not need the race to delete anything in it.

### What this release does NOT delete

The cleanup matches exactly `chunks.mdb`, `chunks.mdb.retired` and `chunks.mdb.retired.<n>`
for `n` in `1..=64`, and nothing else. Two things under the node root are deliberately
outside that set and must stay outside it:

- **The migration marker.** Small, harmless, and useful evidence if a node's history is ever
  in question.
- **Anything else an operator put there.** A prefix match would claim a
  `chunks.mdb.retired-keep-this`, which is why names are matched exactly rather than by
  prefix.

That the cleanup does not touch these today is a property of the exact-name match, not an
accident, and it is stated here because a future widening of that match would be a silent
data loss rather than an obvious one.

## Consequences

### Positive

- One store, one name, and about 5,600 lines of bridge and driver gone.
- The penalty means what it always meant again.
- No node is ever left unable to start by anything this release does.
- The per-volume migration lock and its deployment settings go with the migration.

### Negative / Trade-offs

- **A node that never finished migrating keeps its old store and does not get that disk
  back.** That population is the short-of-disk nodes, and how large it is remains the open
  fleet question ADR-0014 records — which is why that release now reports it on the wire, and
  why this one is not published until the count is clean. Such a node runs and serves what it
  migrated; what it does not do is reclaim the space, which it could not do safely under any
  of the three answers considered here.
- Restoring the penalty and deleting the bridge in one release means the emergency lever for
  the first is a switch, while the second can only be undone by rolling back the binary.
  Shipping them as separate releases was considered and is a legitimate call for whoever
  cuts the train; the two are separate commits so that remains possible.
- `ChunkStore` and its module were renamed from `FileStore` and `file_store.rs`. Callers did
  not change, because they already used the facade's name.

### Neutral / Operational

- `ANT_SUSPEND_UNHELD_CHUNK_PENALTY` still works and still logs loudly when it disagrees
  with the build.
- `storage.migration` and `storage.db_size_gb` are gone from the configuration. The second
  capped a memory map that no longer exists, and a setting that silently does nothing is
  worse than one that is absent. Nothing declares `deny_unknown_fields`, so a config file
  written by the previous release still loads with both keys in it, which is what stops
  every node on the fleet failing to start at once on upgrade. There is a test for that,
  because adding that attribute later would look harmless.
- There is no supported way to make this build read an old chunk store, and no way to stop
  it clearing one up. A leftover it declines to touch — a link, an unmarked store with chunks
  in it, or one whose state cannot be established — is named in a warning carrying
  `migration_event = "legacy_store_left"`, and is the operator's to remove.

## Validation

**Proved here.** A marked environment is removed and its disk comes back; so is a marked
tombstone, and so is an empty one. An **unmarked** environment with chunks in it is still
there afterwards, and so is an unmarked tombstone — those two are the data-loss tests, and
they are the ones that would have gone red against the draft that deleted everything. A node
whose root does not exist yet is fine. Four directories that only *look* like leftovers
(`chunks.mdb.retired-keep-this`, `chunks.mdb.backup`, `.65`, `.007`) are all still there, and
the name matcher is asserted directly on both sides. A linked environment is untouched: the
link is still there and what it points at still has its data, which is the pair of mistakes
prefix matching and link following would each have made.

A directory called `RETIRED` sitting where the mark would be does not authorise anything, and
the store it is in is still there afterwards. The deletion's order is asserted directly: with
a subdirectory made unremovable, the attempt fails and the mark has to still be there, because
that is what lets the next start recognise the directory rather than treat it as unmigrated
forever.

Through `NodeBuilder::build()`: a node with an unmigrated store starts under both
`storage.enabled = true` and `false` and still has its chunks afterwards; a node with a marked
one starts and the leftover goes; and a node whose file store cannot open — staged with a file
where the chunk directory has to be — fails to build with its old store still intact, which is
what pins the deletion behind the replacement. Restoring the penalty is pinned by a test that
fails if the constant is flipped back.

**Deleted, and what replaced it.** ADR-0014's validation section describes four harnesses.
Most of three of them existed to prove the bridge worked: that the disk came back when the
old store was deleted, that a node killed mid-copy lost nothing, and that several nodes on
one disk took turns. There is no bridge left for those to test. The fourth, which measures
what one file per chunk costs at scale, stays.

Not all of it went, and saying it did was wrong. Two tests inside the crash harness were
never about the bridge: that a process killed mid-publish leaves no chunk the store cannot
serve, and that what an interrupted write leaves behind is swept. Those are about the store's
own publish path, which is now the only one there is, so they matter more after this release
rather than less. They are back as `tests/chunk_store_crash_safety.rs` and run in CI. A third
property, that engine shutdown waits for a detached store write, is named under the gaps
below.

That leaves the loopback filesystem job with nothing to run, and deleting it would quietly
drop ext4, XFS and btrfs coverage of the store itself. It now runs the storage unit tests
against each mounted filesystem instead, which is what still has something to say there:
publishing through a temporary and a rename, flushing, deleting, and rebuilding an index
from the names.

**Not proved here, and inherited from ADR-0014.** Forced power loss on the five filesystems.
Scale at one and ten million keys. How many short-of-disk nodes can clear the possession
gate. Under ADR-0014 such a node keeps serving from both stores; under this one it starts,
serves what it migrated, keeps what it did not, and never gets that disk back.

**Coverage this release drops, named rather than lost.** A harness proved that
`ReplicationEngine::shutdown()` waits for a store write whose awaiter was dropped before it
returns. It was written against the old store and went with it. The property is still
current and still claimed by that method's own documentation, and nothing tests it now. It
needs a live P2P node to stage, which is why it is called out here rather than quietly
rewritten in the same change that deleted it.

**A fleet gate this decision adds.** Before this ships, the fleet has to show that nodes are
actually on the file store, because this is the release that stops any of them going back.
ADR-0014 puts the answer on the wire: every node announces `migration/legacy`,
`migration/files` or `migration/unknown` in the user agent it already sends with every signed
message, and each node counts what it sees around it. The gate is that nothing reports
`legacy` or `unknown` for itself, and that no observed peer reports `legacy`, `unknown`, or
nothing at all, over several consecutive days, against a roster of nodes we expect to hear
from. A peer that reports nothing is running a build from before the signal existed, which is
not evidence of anything having finished; the tally counts it as outstanding for that reason. Silence is not readiness:
a zero from a collector that scraped nothing looks exactly like a zero from a clean fleet,
which is why the count needs a denominator and not just a numerator.

That gate cannot be made airtight, and it is worth being honest about which part is soft.
Nodes that are offline for the whole window are in nobody's count and come back afterwards;
that is the population this decision knowingly cleans up rather than the one it waits for.

## What this release does not fix

Named rather than implied. None is a regression; each is the state before this change.

- **A node that kept an unreadable store does not get that disk back**, and a node short of
  disk is penalised on the unheld-chunk lane like any other full node. The remedy is the
  operator's, and the warning names the directory.
- **The path check and the unlink are not one operation** in either release's deleter. Closing
  that needs a directory handle held across the whole operation and `unlinkat` against it,
  which `std` does not offer portably. Accepted because whoever can win that race already has
  write access to the node's data directory.
- **`deploy/terraform/cloud-init/worker.yml` still cannot start a node**: it passes no rewards
  address, which production mode requires. The binary also sits in `/usr/local/bin` while the
  unit runs under `ProtectSystem=strict`, so an in-process upgrade cannot replace it. Both
  predate this work and belong to whoever owns that deployment. That path is not evidence for
  the fleet gate until they are fixed.
- **Off Unix a chunk is published under its final name**, so a power loss can leave a real
  chunk name over partial bytes, and a commitment built before anything reads it claims a
  chunk the node cannot produce. ADR-0014 states this; the forced power-loss run is still an
  open gate.

## Notes for AI-assisted work

Drafted with AI assistance. Not to be marked Accepted without human review.
