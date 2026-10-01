# ADR-0022: Remove the LMDB Chunk Store

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

**Restore the penalty here, and remove the switch with it.** An earlier version of this record
held the penalty off for one more release, on the ground that a node away while the migration
ran arrives here holding a store this build cannot read, and accusing it in the release that
stranded it would penalise it for a state it had no chance to leave. The decision owner reversed
that on 2026-10-01: the release is held back two more weeks so that the nodes still finishing
can finish, and a node that has still not migrated when it lands is penalised like any other
node that cannot serve the chunks it is responsible for. The reasoning is in *The penalty is
restored in this release* below.

So the switch goes too: the build constant, the process-wide atomic, the
`ANT_SUSPEND_UNHELD_CHUNK_PENALTY` override, the startup announcement, the helper every accusing
lane went through, and the two splits (`SingletonHintFault`, `FetchFault`) that existed only so
that sub-cases of one accusation could be charged differently. The lanes report trust exactly as
they did before the suspension, at the same weights, including the responsible-chunk audit's
charge for a timeout.

**Remove the migration signal.** The user agent is now `node/<version>`, this build's version
without the `migration/<state>` token, still under the `node/` prefix `saorsa-core` admits DHT
participants on.
The reporter that logged a tally of the peers' announcements every fifteen minutes is gone, and
so is the record of which peers had received the current commitment root, which only the
migration's shedding gate read. Their job was to tell when this release could ship.

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
unmigrated when this release landed, and that is exactly the population this release is held
back for.

It is not penalty-free, and since the penalty is restored it is not close to it. A node
carrying an old store it cannot read is charged on every lane that asks it for one of those
chunks, on top of the commitment-bound audit that every release enforces. It is also a node
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
directory before it deleted anything. A directory carrying `RETIRED` is one whose retirement
gates were all satisfied, and it is pure cost. So is an empty one, which is what a cleanup
interrupted between emptying a tombstone and removing it leaves. Those go, and their disk comes
back.

**Be exact about what those gates were, because "its contents were copied out" is not it** and
an earlier draft of this record said so four times. Retirement cleared a directory on two
different grounds, and only the first is a local copy:

- every chunk the node was **keeping** was copied into the file store and re-hashed there, byte
  for byte, before the mark went down; and
- every chunk the node was **shedding** was proven to be held by its close group — all but one
  of them answering a possession challenge with a cryptographic proof, after the reduced
  commitment had been delivered — and was then deliberately *not* copied. The pre-retirement
  verification pass skips exactly these keys, because re-hashing a chunk the node is giving up
  into a file store that is not going to keep it would defeat the point of shedding it.

So a marked directory can, entirely legitimately, contain bytes that are in no file store on
this node and never will be. The previous release was about to delete those bytes itself; this
one finishes that. The safety argument for them is the close group's proofs, not a local copy,
and it is the network that holds them afterwards.

| what is on disk | what the cleanup does | what the node then serves | disk back |
|---|---|---|---|
| nothing, or a root that does not exist yet | nothing | whatever it stores from here | n/a |
| a leftover carrying its `RETIRED` mark | remove it in the background, report the space once it is back | its file store — everything it kept, and nothing it shed | yes |
| a leftover with nothing in it | remove it | its file store | yes |
| a leftover with chunks in it and no mark | **keep it**, name it once | its file store only — **not** what is in that directory | no |
| a leftover whose contents or mark cannot be established | keep it, name it once | its file store only | no |
| a link at either name | keep it, name it once | its file store only | no |
| a name retirement never created | ignore it entirely | its file store | no |

The rows that keep something are the point, and the third column is the part it would be easy
to round off. **Kept is not the same as available.** There is no LMDB reader in this build, so
a node that keeps a directory keeps its bytes on disk and cannot serve one of them. For a node
that was part-way through the migration that is the tail it had not copied yet; for a node that
skipped the previous release altogether it is everything it holds, and such a node serves only
what it refetches from here on, exactly as a new node would, while its old bytes sit there
costing disk.

That is worth being plain about because it is the whole price of the decision: the data is
kept so that it is still there to be recovered by hand or by a future build, not because this
release can do anything with it. What the node gets is its own service back; what it does not
get is that disk, which is the honest cost of not being able to prove the directory is safe to
delete.

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

The deletion runs on **one** background thread and nothing waits for it. `remove_dir_all` over
a store with millions of files runs for minutes and must not be on the startup path. One
thread rather than one per directory, and they are deleted in turn: the names this release
recognises are the live directory, the unnumbered tombstone and sixty-four numbered ones, so a
root that has been through enough restore cycles can present sixty-six at once, and a thread
each would put sixty-six concurrent recursive deletions on the disk that is also serving
chunks, at the moment a node is starting. Nothing is waiting on them, so doing them in turn
costs nothing that matters. It deletes in place: there is nothing to get out of the way, because the directory holds nothing this node is answerable for and this
build has no code that would read it if it did. An earlier draft renamed first and could run
out of names to rename to, at which point it stopped removing anything at all, permanently.
The space is only reported as returned once the deletion has actually finished, because a
number that is wrong for the next several minutes is worse than no number.

**The mark has to be the file the previous release wrote**, not merely something at that
name. It is written with `create_new`, so it is always an ordinary file; a directory, a link
or a FIFO wearing the name proves nothing, and this is the answer that authorises deleting
every chunk underneath it. Testing existence alone would let anything at that path clear an
unmigrated store for deletion.

**The mark is believed, and not re-checked against anything.** It is worth stating as an
assumption rather than leaving it to be inferred, because it is the one that authorises every
deletion here. `RETIRED` records that the *previous release* satisfied both gates above — the
copy-and-re-hash for what it kept, the close-group possession proofs for what it shed. This
build cannot confirm either independently: it cannot re-run a possession challenge for keys it
cannot enumerate, and it has no LMDB reader, so it cannot compare what is in the directory against
what is in the file store, and no cheaper check is available — a file store that opens is not
evidence that it holds any particular key, and counting keys proves nothing about which ones.

So the mark is taken as final. For every state the previous release can actually produce, that
is correct: it wrote the mark after the copy and the re-hash, and a marked directory in this
release is one whose deletion was interrupted. The state it is wrong for is one no release
produces — an operator restoring an old marked directory alongside a file store that is not the
one it was retired against, or putting a file called `RETIRED` inside an environment by hand.
This release will delete such a directory. That is accepted: the alternative is to keep every
marked leftover for ever, which returns no disk on any node and defeats the release, and the
states that would be protected are ones a person constructed. **An operator restoring a backup
of `chunks.mdb` must not leave the `RETIRED` file in it.**

**The mark is removed last.** `remove_dir_all` gives no promise about the order it unlinks
things in, and if the mark went before the chunks did and the process stopped there, the next
start would find an unmarked directory with data in it, decide it might be an unmigrated
store, and keep it for good. It is not one, but nothing on disk would say so any more, and the
node would never get that disk back. So the
contents go, then the mark, then the directory: at every point either the mark is still there
and the next start resumes, or the directory is empty, which is also finished with.

**None of it happens until the file store has actually opened.** "Finished with" means
retirement's gates were met, and for everything the node kept that means the chunks are in the
file store, which is only true if the file store is there to hold them.
An earlier draft ran this as soon as the root was known, which put the deletion in front of a
constructor that can still fail on an unreadable layout, a directory it cannot create, or a
lock another process has not let go of — and a node that lost both stores that way had
nothing to go back to.

Nothing here can fail. `clean_up` returns `()`. Every way a filesystem can disappoint it ends
in a node that runs, a warning that names the directory, and disk that has not come back —
which is a worse place than success and a far better one than a restart loop.

Nothing here can leave a node with no store: the deletion runs only after the store that
replaced it has opened, and only over directories retirement had already cleared — everything
kept copied and re-hashed, everything shed proven held by the close group — or that are empty.
A node that
never opens one, because storage is switched off, deletes nothing at all — it has established
nothing about where those chunks went, and it has no use for the disk either.

Said precisely, because the looser version of it is not true: **nothing here vetoes a start**.
That is not the same as "every node starts". The file store is built before this runs, and a
store that cannot open — an unreadable layout, a directory it cannot create, a lock another
process holds — still stops the node, exactly as it did in the release before this one. What
this release removes is the *other* reason a node could fail to start, the one its first draft
introduced: being refused for what it was found carrying.

**What may be deleted is decided in two steps.** The function the previous release used to
report a node as finished now lives beside the cleanup and picks the candidates: a leftover
carrying the mark, or an empty one. The deleting thread then re-checks each candidate on a
directory handle and refuses anything a retired environment never contains — a subdirectory,
more entries than one ever holds, a mark that is not a regular file — which it keeps and names.
So nothing is removed that the classifier did not call harmless. A test stages every
classification over ordinary shapes and checks both directions, so a deleter that drifts from
the classifier fails there rather than on a fleet; the refusals are pinned by tests of their
own.

**The deletion is made against a directory handle, not against a path.** An earlier draft of
this decision named a path for the checks and named it again for the unlinking, and accepted the
window between them on the ground that whoever could win it already had write access to the data
directory. That reasoning was wrong, and independent review caught it: it covers deleting things
*inside* the data directory and says nothing about the variant that reaches outside. `read_dir`
follows a link. Point that name at a target elsewhere on the disk in the window, and the node
empties the target instead — and the node reaches far more of the filesystem than the actor who
moved the name does, and on many installations runs as root. That is privilege escalation, not
one more way to lose a chunk.

So on Unix the directory is opened once, `O_NOFOLLOW | O_DIRECTORY`, and every unlink is made
against that handle with `unlinkat` — the mark's included, so the handle is not dropped and the
path re-opened for the last step, which was a second window and is gone. A link cannot produce a
handle, so no unlink can be redirected through one. The pattern and the reasoning are already in
this codebase: `open_regular` refuses a link and a FIFO on the handle rather than on the path,
for the same class of reason.

**A subdirectory is refused, never entered**, and that is a second decision rather than a detail
of the first. `O_NOFOLLOW` declines a trailing symlink and says nothing about a mount point,
which `openat` walks into without complaint; a bind mount can also make a cycle. A retired chunk
environment is flat — two files and a mark — so a directory inside one is already something this
build does not understand, and descending into it risks emptying a filesystem that has nothing
to do with this node. Refusing keeps that shut, and it also leaves no recursion to bound and no
descriptor chain to exhaust. For the same reason a directory holding more entries than any
leftover ever has is refused rather than read into memory: a corrupt or hostile one should not
be able to take the node down through the cleanup that was meant to return it some disk.

**And the mark is not removed on the strength of a stale listing.** The names are read once and
unlinked one by one, and a listing is not a snapshot: anything created while that loop runs is
not in it and is still there at the end. So the handle is asked once more, immediately before
the one irreversible step, and the mark stays if the answer is no. Without that the ordering
protects nothing in exactly the case it exists for — the mark goes, something is left, and every
later start reads an unmigrated store.

**The type test on the mark masks with `S_IFMT`.** `S_IFLNK` and `S_IFSOCK` each contain every
bit of `S_IFREG`, so testing `st_mode & S_IFREG` accepts a symlink or a socket wearing the
mark's name — and that answer is what authorises deleting a store nothing migrated. This was
written wrongly first and caught by review; there is a test for both types now.

The directory itself still goes by path, and that is safe on its own terms: `rmdir` refuses a
symlink, so a swapped name fails the call rather than following it.

What is pinned by test is the primitive, not the interleaving, and the difference is worth being
exact about. The race cannot be staged without instrumenting the deleter. What the tests assert
is that a link never yields a handle, and that a *marked* target behind a link is untouched —
marked deliberately, because an unmarked one is refused by the gates even by a deleter that
follows links, so testing against one would pass while proving nothing. Both fail if `O_NOFOLLOW`
is dropped.

**Two things this still does not close, both stated rather than half-fixed.** Off Unix there is
no `unlinkat`, so that build keeps the path-based deleter and its window; its exposure is what
the previous release's deleter already had. And on either build the empty-directory case cuts
both ways within the data directory: an entry created inside a directory this found empty is
deleted with it, and an entry created after the mark has gone leaves an unmarked directory with
something in it, which every later start then keeps for good.

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

### Values over the size ceiling are not chunks, and none is preserved

This was argued both ways across the three releases, and one of the earlier answers — preserve
them to a sidecar rather than destroy them — was wrong. It is settled here so that a later
reader does not reopen it from the sidecar's remains.

**A chunk is at most 4 MB.** `MAX_CHUNK_SIZE` has been `4 * 1024 * 1024` since ant-protocol's
first commit, and every released path by which data enters a node from the network enforces it
before anything is stored: the protocol handler on a paid store, and replication on both the
receive and the fetch path. **So no value over the ceiling has ever entered this network as a
chunk through released node code.** Something planted on a disk by hand is a separate matter and
is refused on read rather than served. It does not follow that none can exist on a disk — one can, and the next paragraph says
how — only that anything which does is not a chunk: not data with a copy elsewhere, not data
whose owner is waiting for it, and nothing any peer would accept or serve.

**The one way such a value could reach a disk was ours.** Not the network's. The bridge's
public `ChunkStore::put` wrote to the legacy environment *first* — `LmdbStorage::put` has no
size ceiling, deliberately, because the store it wrote to was being abandoned and its verdict
was not allowed to refuse chunks the file store had room for — and only then offered the same
bytes to the file store, which refused them for size. The bridge then recorded the key as
legacy-only so the copier would retry it, and the copier's own size arm deleted it. Every
oversized value that can exist on any node came through a local caller of that method during
the bridge period, and through nothing else.

**This release removes the bridge, so it removes the hole.** There is one store; its `put`
refuses anything over the ceiling, and refuses *before* it writes, so there is no partial state
for a later pass to find and no key recorded anywhere. There is no `LmdbStorage::put` left to
take an unbounded value in the first place. The read path and the repair path refuse over the
ceiling too, so a file planted by hand is refused rather than served.

**Nothing is preserved and no sidecar is built.** An earlier draft added one, on the reasoning
that no peer can hold a copy of an over-ceiling value and no repair can fetch one, so deleting
it destroys the only copy. Both halves of that are true and the conclusion still does not
follow: there is no valid chunk there to be the only copy *of*. Building somewhere to keep
invalid values would be building for a case this release makes unreachable, and the cost of
doing it was measured — the sidecar was written, and adversarial review found two real defects
inside it, in code that existed only to serve a case that cannot arise. It was cut before it
shipped, and it is not coming back here.

A legacy directory that happens to contain such a value is kept if it is unmarked and removed if
it carries the mark, exactly like every other directory, and for exactly the same reasons. This
release never looks inside one, so its contents are not a factor in either verdict.

### The penalty is restored in this release

The original plan had this release delete the old store and restore the close-group storage
penalty together. An earlier version of this record separated them; the decision owner put
them back together on 2026-10-01.

The argument for separating them still describes what happens. The upgrade monitor picks the
newest eligible release rather than the next one, so a node that was offline while the
migration ran arrives here having never migrated, holding a store this build cannot read. This
release keeps that store rather than deleting it, which is right for its data, but the node
cannot serve those chunks and its close group notices. With the penalty restored it is charged
for each one, its trust at its neighbours falls below the swap threshold, and it loses routing
slots to peers that can serve what it cannot.

That is accepted, and the release is held back instead. Two more weeks gives the nodes still
moving their chunks time to finish, and a node that is still unmigrated after that is treated
like any other node that cannot serve what it is responsible for. Holding the penalty off for
another release would have kept a switch, an override and a split in every accusing lane alive
for nodes that have had the whole migration to move, and left the network another release
without the accusation that keeps a node honest about what it stores.

It does not cost data. The store such a node keeps is left on its disk, unread and undeleted,
and the replicas its close group holds are not touched by any of this. Losing the routing slots
hands responsibility for those chunks to peers that can serve them, which is what the penalty
is for.

## Consequences

### Positive

- One store, one name, and about 5,600 lines of bridge and driver gone.
- The unheld-chunk penalty is restored on every lane, and nothing of the suspension is left in
  the tree.
- No node logs a per-peer tally every fifteen minutes any more.
- **The cleanup never vetoes a start.** Not the same as "every node starts": the file store
  is built first and one that cannot open still stops the node, exactly as before. What is
  gone is the other reason, the refusal this release's first draft introduced.
- The per-volume migration lock and its deployment settings go with the migration.

### Negative / Trade-offs

- **A node that never finished migrating keeps its old store and does not get that disk
  back.** That population is the short-of-disk nodes, and how large it is remains the open
  fleet question ADR-0014 records, which is why this release is held back. Such a node runs and
  serves what it migrated, is penalised for what it did not, and does not reclaim the space,
  which it could not do safely under any of the three answers considered here.
- **Neither half has a fast lever any more.** The override that could have suspended the
  penalty from the fleet side is gone with the switch, so turning the accusation off again
  takes a release, as undoing the deletion of the bridge always did — and not even rolling the
  binary back undoes that, since the upgrade monitor takes the node forward again.
- `ChunkStore` and its module were renamed from `FileStore` and `file_store.rs`. Callers of
  the facade did not change, because they already used that name — but **`FileStore`,
  `FileStoreConfig`, `StoreLayout`, `VerifyReport` and `LEGACY_ENV_DIR` were exported too**,
  and all five are gone from the public API along with the LMDB and migration types. A
  downstream crate importing any of them stops compiling, so they belong in the release
  notes and not only in this list. Two caveats on how far that narrowing goes. Under the
  `test-utils` feature `chunk_store` is a public module, so everything `pub` inside it —
  `StoreLayout`, `CapacityVerdict`, every inherent method — is still importable; the narrowing
  above is the default build's surface. And `ChunkStore` keeps its public inherent methods,
  which is a wider surface than the re-export list suggests on its own.

### Neutral / Operational

- `ANT_SUSPEND_UNHELD_CHUNK_PENALTY` has no effect.
- The user agent no longer carries a `migration/` token, and `migration_event = "signal"` and
  `peer_state` lines are no longer logged. Peers on earlier releases read the shorter agent as
  a node that does not report, which changes only their own log lines.
- `storage.migration` and `storage.db_size_gb` are gone from the configuration. The second
  capped a memory map that no longer exists, and a setting that silently does nothing is
  worse than one that is absent. Nothing declares `deny_unknown_fields`, so a config file
  written by the previous release still loads with both keys in it, which is what stops
  every node on the fleet failing to start at once on upgrade. There is a test for that,
  because adding that attribute later would look harmless. Worth knowing what that test is: a
  hand-written fragment carrying the two removed keys, not a complete file emitted by the
  previous release. It proves those two keys are tolerated; it does not prove a whole persisted
  config round-trips, and an incompatibility in a field it omits would not be caught by it.
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

A value over the ceiling is refused by `put`, and refused *before* anything is written: the
store does not claim it, no file is left under its name, and a restart onto the same directory
finds nothing to index. Addressed to its own bytes on purpose, so the refusal is the size arm
and not the content-address arm — checking the wrong arm would pass while the ceiling was gone.
Mutation-checked: with the size branch deleted the test fails, which is what says it is testing
the ceiling rather than testing that something went wrong.

Three further properties are pinned that the earlier draft had no test for, because it had no
code for them either.

**The correspondence with the classifier.** A root is staged carrying at least one shape for
every verdict the classifier can return — harmless three ways (a marked live environment, a
marked tombstone, an empty one), holding two (an unmarked tombstone with chunks in it, a link
wearing a tombstone's name), unreadable two (something that is not the mark using the mark's
name, and a plain file wearing a tombstone's name) — plus the near misses that are not in the
name set at all. Each is classified before anything is removed, and afterwards each is asserted
gone exactly when it was called harmless and still there exactly when it was not. Both
directions, for these ordinary shapes, so a classifier that drifts either way fails here;
mutation-checked by making a link classify harmless, which the test catches. A marked directory
the deleter refuses — one with a subdirectory in it, or more entries than a retired environment
holds — is classified harmless and still kept, and those refusals have their own tests.

**A marked directory is removed even when nothing was copied into this node's file store**,
staged with no file store at all. That is a shedding node's ordinary state, and pinning it is
what stops somebody later adding a local-copy check that would strand every such directory for
ever.

**Sixty-six leftovers**, the whole namespace this release accepts, are removed by one start. And
**a root that cannot be listed** has nothing removed from it, which is the case that used to
return silently and left this record promising a warning nothing emitted.

**What these do NOT prove, said rather than implied.** The sixty-six-leftover test asserts that
all of them go; it does not observe how many threads did it, so it would still pass if the one
sequential worker went back to one per directory. The deletion ORDER — mark last — has its
failure half asserted only on Unix, because staging a part-way failure needs a permission bit
there and an open handle on Windows; off Unix that test proves only that a successful deletion
leaves nothing behind. And the entry-level unreadable case is not staged: the test that makes a
root unlistable exercises `read_dir` itself failing, not one `DirEntry` failing inside a
readable root, so turning that arm from a refusal into a skip would restore the false-green and
stay green here.

Through `NodeBuilder::build()`: a node with an unmigrated store starts under both
`storage.enabled = true` and `false` and still has its chunks afterwards; a node with a marked
one starts and the leftover goes; and a node whose file store cannot open — staged with a file
where the chunk directory has to be — fails to build with its old store still intact, which is
what pins the deletion behind the replacement. The restored penalty is pinned by the
possession-check tests, which assert the charge with no switch left to set.

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

**The hardening release's two tests, one deleted and one that must keep passing.** The release
that hardened the migration added exactly two, and this release does something different with
each, so both are named rather than left to be noticed in a diff.
`a_store_left_midway_by_the_previous_release_keeps_its_place` proved that an upgrade picks a
half-finished migration up where it left off instead of restarting its clock — it drives
`copy_batch`, `migration_phase`, `legacy_only_keys` and `migration_state`, all of which this
release deletes. It goes with its subject: there is no migration left for an upgrade to
continue, and a test of one cannot be rewritten against a release that has none.
`retiring_keeps_a_pinned_root_answerable_and_clearing_does_not` is the opposite case. It is why
the commitment rotation has no emptiness branch, it touches nothing this release removes, and it
still passes here. **It must go on passing**, because the branch it rules out is exactly the one
an earlier draft of this release was going to reinstate.

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

**The fleet gate, and how it was answered.** The previous releases put each node's migration
state in its user agent so that this release could wait for the fleet to finish, and that gate
could never be made airtight: a node sees only the peers it connects to, each answering as of
its own last start, and a node offline for the whole window is in nobody's count. It was
answered by a decision rather than by a count reaching zero: the release is held back two more
weeks after the nodes the project runs had all finished, and whatever has not finished by then
is penalised as described above. The signal is removed in this release because it has no further
use; an unmigrated node is now visible the way any node is that cannot serve its chunks, through
the audits.

## What this release does not fix

Named rather than implied. None is a regression; each is the state before this change.

- **A node that kept an unreadable store does not get that disk back**, and being short of disk
  is how that costs it: it fails to take on chunks it is responsible for, and with the
  unheld-chunk accusation restored it is charged for the ones it cannot read as well. The
  remedy is the operator's, and the warning names the directory.
- **Neither build re-marks or retries the way retirement did.** That release would retry a
  failed final removal many times and write the mark back if it could not finish. This one makes
  one attempt per start and leaves the rest to the next start, which is a longer wait on a host
  where something holds the directory open — antivirus on Windows is the realistic case. What it
  leaves behind is an empty unmarked directory, which the next start reads as harmless and
  removes, so the cost is delay rather than a stuck node.
- **Off Unix the path check and the unlink are not one operation.** They are on Unix, where the
  deletion is made against a handle opened `O_NOFOLLOW`; `std` offers no portable `unlinkat`, so
  the other platforms keep the path-based deleter and the window the previous release's deleter
  also had.
- **On a case-folding filesystem a leftover can be kept that should have gone.** Tombstone names
  are matched exactly, as strings, against what `read_dir` reports, while NTFS and a
  default-configured APFS compare names case-insensitively. A directory stored as
  `CHUNKS.MDB.RETIRED` is the same file to the filesystem and a different string to the matcher,
  so it is not recognised and is kept for ever. That is the safe direction — the failure is disk
  not returned, never data removed — and it takes an operator having renamed something, since
  retirement only ever writes lower case. The live name is unaffected: it is looked up by name
  rather than matched from a listing, so the filesystem's own comparison finds it.
- **`deploy/terraform/cloud-init/worker.yml` still cannot start a node**: it passes no rewards
  address, which production mode requires. The binary also sits in `/usr/local/bin` while the
  unit runs under `ProtectSystem=strict`, so an in-process upgrade cannot replace it. Both
  predate this work and belong to whoever owns that deployment. That path is not evidence of
  fleet behaviour until they are fixed.
- **Off Unix a chunk is published under its final name**, so a power loss can leave a real
  chunk name over partial bytes, and a commitment built before anything reads it claims a
  chunk the node cannot produce. ADR-0014 states this; the forced power-loss run is still an
  open gate. Nor can a directory be flushed off Unix through the standard library, so a power
  loss soon after a shard directory is created can lose it with the chunks just published into
  it, after the puts had succeeded. This node gets those back only if a peer offers them while
  it is still responsible for them; other replicas are untouched. Both predate this release,
  which neither widens nor narrows them.
- **There is no supported way to hold a node on an earlier release.** This is named here
  because it is why this release had to wait for the fleet rather than let nodes catch up
  afterwards. The on-disk format
  rolls back cleanly — the previous release reads the same one-file-per-chunk layout, and a
  legacy directory this release kept is one it can still pick up and finish — but the
  *operation* does not: `build_upgrade_monitor` is called unconditionally, `UpgradeConfig` has
  no field that disables it, and the monitor takes the newest eligible release, so a node put
  back on the previous binary is dragged forward again within the hour. Rolling back to
  v0.18.1 is worse than unsupported, because chunks this release accepted exist only in the
  file store that build does not have.

  The fix is an upgrade-subsystem one — a persisted disable, or a version ceiling — and it is
  deliberately not in this release: it changes the mechanism every node uses to take every
  release, which is not a change to make in the release that also deletes a store. It belongs
  in its own change, with its own evidence.

  What must not be said here, and an earlier draft of this record did say it, is that no state
  this release creates would ever have wanted a rollback. A marked directory can hold shed
  chunks, which are bytes the previous release proved the close group holds and deliberately did
  not copy locally. Deleting them is right and is what that release was about to do — but it is
  irreversible on this node, and rolling back would not bring them back either, because the
  previous release would have deleted them too. The remedy for those keys was never local: it is
  replication fetching them from the peers that proved they hold them.

## Notes for AI-assisted work

Drafted with AI assistance. Not to be marked Accepted without human review.
