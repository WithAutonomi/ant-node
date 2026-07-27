# ADR-0005: Replication repair hardening under churn, load, and shutdown

- **Status:** Proposed
- **Date:** 2026-07-16
- **Decision owners:** Mick
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0003 (full-node detection and eviction — shares `storage_admission_width` / `paid_list_close_group_size` and the delayed-possession-check trust path); ADR-0002 (gossip-triggered storage-commitment audit — shares the audit/trust/eviction path). PR #165 is the implementing change.

## Context

The replication subsystem (`src/replication/`) keeps paid chunks stored on the
nodes responsible for them. It has three interacting pipelines:

- **Neighbor sync** propagates paid-list hints to close-group members after
  topology change, so a joining or repairing node learns which keys it is now
  responsible for (`neighbor_sync.rs`, `bootstrap.rs`).
- **Verification and fetch** takes admitted hints, confirms the close group
  agrees a key is paid for, and downloads the chunk from a holder into local
  storage (`admission.rs`, `types.rs`, `mod.rs`).
- **Fresh offers, audit, and pruning** handle newly-written chunks, probe peers
  for possession, and evict keys the node is no longer responsible for
  (`fresh.rs`, `audit*.rs`, `pruning.rs`).

The subsystem was correct on the happy path but had accumulated a family of
defects that only surface under **churn** (correlated join/leave), **load**
(saturated workers, deep queues), **event-stream degradation** (broadcast lag or
closure), and **shutdown**. The original bug — neighbor sync stalling for tens
of minutes after a partition heal or mass join — turned out to be one instance
of a recurring shape: a decision made once against a snapshot, then acted on much
later against a world that had moved, or an unbounded/untracked unit of work that
could be griefed, leaked, or spun. Investigation surfaced roughly a dozen
distinct failure modes, several of them **remotely reachable** by a peer (forcing
out-of-range nodes to store arbitrary keys, wedging a victim in permanent
bootstrap, backing up the inbound queue until replication messages drop).

Verified pre-change behaviour that motivated the work:

- Replica hints skipped the `is_responsible(storage_admission_width)` gate that
  paid hints had to pass, and the `pipeline` tag was **stored**, so a second
  message could escalate a queued `PaidOnly` entry to `Replica` through the
  `already_pending` fast path and force a download the node was not responsible
  for (`admission.rs`; `types.rs`).
- Fresh-offer dispatch, once all worker permits were held, ran the next offer —
  on-chain payment verification plus a multi-MiB LMDB write — **inline on the
  serial message loop**, and per-key shard locks keyed on `key[0] % 64` collapsed
  the close-prefix accepted-key set onto one shard, making the inline path the
  steady state (`mod.rs`, `handle_fresh_offer`).
- `ReplicationEngine::shutdown()` promised no background work still held the LMDB
  environment when it returned, but dropping a `select!` loser does not cancel a
  `spawn_blocking` LMDB transaction — the closure kept running with a cloned
  `Env`, and reopening the same environment afterward was undefined behaviour
  (`storage/lmdb.rs`, `paid_list.rs`, `mod.rs`).
- Storage responsibility was decided once, at verification-completion time, then
  never rechecked before download, even though the fetch queue holds up to
  131,072 entries and dequeues nearest-first, so a far candidate can wait
  unboundedly long (`mod.rs`; the contract that responsibility is decided at
  download time is documented in `types.rs` and `admission.rs`).
- A bootstrap capacity-rejection record for a source was cleared only by that
  source's next clean admission cycle or its `PeerRemoved` cleanup; the note and
  removal paths run on different tokio tasks, so a removal inside the TOCTOU
  window orphaned a record no future event could retire — `check_bootstrap_drained`
  returned false forever, audits stayed disabled (Invariant 19), and the node
  advertised `bootstrapping: true` indefinitely (`bootstrap.rs`, `types.rs`).
- Closed Tokio broadcast receivers are immediately ready with `RecvError::Closed`
  forever; the replication loop continued selecting on them, spinning a core and
  flooding P2P warnings (`mod.rs`).

## Decision Drivers

Five cross-cutting principles emerged from the failure analysis and drive every
decision below:

- **Decide against live/authoritative state at the point of action, not at an
  earlier snapshot.** Responsibility, drain status, and close-peer membership are
  all live quantities; a cached answer acted on later is a bug waiting for churn.
- **Bound everything that an adversary or load can grow.** Verification cycles,
  network concurrency, admitted-offer memory, and stale-record lifetime must all
  have explicit ceilings; unbounded is a grief vector.
- **Track every detached unit of work through the engine lifecycle.** A spawned
  task or a `spawn_blocking` transaction that outlives `shutdown()` while holding
  storage or P2P state is a correctness hazard, not just untidy.
- **Fail terminally and cleanly rather than spin or stall.** A closed stream, an
  offer past the admission bound, and a key that lost responsibility mid-flight
  should each reach a clean terminal state, never a busy-loop or a permanent
  block.
- **Separate concerns the code had conflated.** Relevance vs. storage
  responsibility; a possession *claim* vs. storage *authorization*; heap
  *ordering* vs. candidate *payload*. Each conflation was the root of a distinct
  bug.

Constraints inherited from ADR-0002/ADR-0003 and the wider system:

- Wire compatibility: all changes are patch-level; no protocol message shape
  changes. Prune confirmation continues using the deployed multi-key
  `AuditChallenge` / `AuditResponse` variants. A rolling upgrade interoperates
  in both directions with 0.14.4 nodes at commit `571868a`: every message is
  understood on the wire. The only behavioural difference is that an oversized-
  batch `Rejected` is now treated as an attributable failure (see option 11)
  rather than recovered in-band, which under the store-spread assumption below
  does not occur for honestly-sized peers.
- Trust/eviction semantics (ADR-0002, ADR-0003) must not be widened: only
  directly-observed, attributable misbehaviour produces a penalty, and a peer
  that did nothing wrong (e.g. a source whose key we declined for our own churn)
  reports no trust event.
- The two responsibility widths are fixed knobs shared with ADR-0003:
  `storage_admission_width = close_group_size + STORAGE_ADMISSION_MARGIN` (7 + 2 =
  9) for retention/pruning, and `paid_list_close_group_size` (20) for
  payment-validity relevance and the widest legitimate client-PUT/fresh-offer
  storage-admission neighbourhood.

## Considered Options

At the whole-change level:

1. **Point-patch each failure in isolation** (e.g. shield each `select!` call
   site against blocking cancellation; add a membership check at each rejection
   note site). Rejected: several fixes only shrink a TOCTOU window rather than
   closing it, and the patches do not compose — the same root shape (stale
   snapshot, untracked work) would keep resurfacing.
2. **Rewrite the replication engine around a single event-sourced state machine.**
   Rejected for this cycle: far larger blast radius than the defects justify, and
   it would couple unrelated fixes into one un-shippable change. Out of scope; may
   be revisited if the pipeline count grows further.
3. **Apply the five principles above as a coordinated set of local, testable
   decisions, each shippable and independently covered (chosen).** Keeps the
   change patch-level and reviewable commit-by-commit while closing the root
   shapes, not just their symptoms.

Per-area alternatives that were weighed and rejected are recorded inline in each
decision below.

## Decision

### 1. Decide storage responsibility at the point of download, against live routing state

Admission and download answer **two different questions**, and the code had
merged them:

- **Relevance** ("should we learn this key exists and is paid for") is decided
  once, at hint admission, through a **single gate** at `paid_list_close_group_size`
  (20) for both replica and paid hints (`admission.rs`, `admit_hints`). The sender's
  label no longer chooses its own gate; mislabelling gains nothing because both
  labels reach the same gate, and the admissible key set is unchanged. This
  deletes the prior two-gate "rescue dance" (`rejected_replica` rescued by
  `admitted_paid`).
- **Storage responsibility** ("are we in the top-9 for this key *now*") is decided
  at the point of download, against live routing state, and **rechecked on every
  fetch attempt** inside `execute_single_fetch` (`mod.rs`): once at the top before
  spending bandwidth (per-source retries re-enter there, so they are covered) and
  once more before `storage.put`, so bytes that arrive after responsibility lapsed
  mid-round-trip are not written.

The `pipeline` (replica vs. paid) is **derived** from live `replica_hint_sources`
rather than stored (`types.rs`) — the tag *is* "did any peer claim to hold this",
so a stored copy could only drift from its own definition. Deriving it deletes the
paid→replica escalation and both demotion sites, closing the two-message conscription
attack.

A lapsed attempt resolves as the new `FetchResult::NoLongerResponsible`, which
deliberately shares `Stored`'s terminal path (`apply_fetch_result`, `mod.rs`):
`complete_fetch` releases the verification retry-slot reservation and the worker
shrinks the bootstrap pending set, so a declined key cannot stall bootstrap drain.
It reports **no trust event** — the source did nothing wrong. The
verification-time check is kept only as a cheap pre-filter that keeps
never-responsible keys out of the queue.

- **Rejected:** event-driven purging of the fetch queue on routing-change events —
  O(queue) scans per churn event, racy, and strictly more complex than the lazy
  per-attempt recheck. Edge flapping is instead dampened by the margin
  `storage_admission_width` already adds over `close_group_size`.

### 2. Keep fresh-offer verification and storage off the serial message loop

Fresh-offer dispatch now **only claims the key, takes an admission permit, and
spawns**; the worker permit is awaited *inside* the spawned task, so
`handle_fresh_offer` has a single caller and no inline verification/LMDB path
exists on the serial loop (`mod.rs`, `fresh.rs`).

- Outstanding admitted offers are bounded by a **16-permit admission semaphore**
  (a 64 MiB payload ceiling). Past the bound an offer is **refused** — not queued,
  not handled inline — and a refused offer is penalized as absent by the delayed
  possession check, identical to any other declined replica.
- The `key[0] % 64` shard locks are replaced by an **exact per-key in-flight set
  behind an RAII guard**, so unrelated keys never contend and concurrent duplicates
  collapse onto the first claimant instead of repeating its verification. The
  ordering the shard locks preserved has no meaning here: the key is the content
  address of the data, so same key implies same bytes.

- **Rejected:** keeping the inline fallback but enlarging the worker pool — does
  not remove the serial-loop stall, only raises the load needed to trigger it. The
  previous behaviour was not penalty-free either: a stalled loop drops offers
  through broadcast lag, with the same possession-penalty result and less
  predictability.

### 3. Track every detached async and LMDB blocking unit of work through the engine lifecycle

Cancellation of an async future does **not** cancel a `spawn_blocking` closure, so
tracking must live at the storage layer, not at each call site:

- `LmdbStorage` and `PaidList` route **every** `spawn_blocking` through a
  per-instance `TaskTracker` and expose `wait_idle()` (`storage/lmdb.rs`,
  `paid_list.rs`). Constructor-time opens stay untracked — they cannot outlive the
  constructor. `shutdown()` awaits `wait_idle()` on both environments after its
  detached-task drain, strengthening its contract: when it returns, no LMDB
  blocking operation is still running and no engine-spawned task holds
  `Arc<LmdbStorage>` / `Arc<PaidList>`, so the same files can be reopened safely.
- A **shared detached-task tracker** covers fresh-offer workers, digest/subtree/byte
  responders, delayed possession checks, first-audit launches, and gossip-triggered
  audits (`mod.rs`, `audit*.rs`). Started handlers are **waited for** rather than
  cancelled, so a dropped async waiter never detaches a live blocking transaction.
  All producer loops stop before the tracker is closed and drained, preventing
  late-registration races, and the best-effort timeout is removed so shutdown
  cannot claim LMDB-safe completion while blocking work remains.
- That unbounded drain is only safe if every detached task is **guaranteed to
  finish**, which fresh-offer workers were not: they neither checked the
  cancellation token nor shed stale work, and awaited a payment verification
  whose merkle path performs an iterative Kademlia lookup capped only by the
  verifier's `CLOSENESS_LOOKUP_TIMEOUT` (240s). Three changes close that, keeping
  the wait unbounded (a timeout could return with an `Arc<LmdbStorage>` still
  held, breaking the very contract above):
  1. `shutdown()` **closes the responder worker semaphores**, so tasks queued for
     a worker take the existing `Err` arm of `acquire_owned()` and exit at once
     rather than waiting behind the last in-flight batch. Those arms were
     previously unreachable — no semaphore was ever closed — and are now the
     prompt-exit path.
  2. Payment verification runs through `verify_payment_until_shutdown`, which
     races the shutdown token. The boundary is drawn at **network I/O only**:
     `storage.put` awaits `spawn_blocking` and is never cancelled, since dropping
     that awaiter detaches a live LMDB transaction.
  3. Fresh offers shed at dequeue once older than `possession_check_delay_min`.
     Unlike the sync/verification responders there is no requester deadline to
     honour — the send is fire-and-forget and a late store is still useful — so
     the threshold is the point at which the work becomes *redundant*: past it
     the sender's delayed possession check has already re-offered the key.
- Fresh offers and `PaidNotify` now use the **same bounded-responder admission**
  as the other classes (`admit_bounded_responder`), globally and per source.
  `PaidNotify` in particular was still verified **inline on the serial non-audit
  loop**: one message could park every other non-audit message behind that same
  240s-capped lookup while the bounded inbound queue behind it overflowed and
  dropped unrelated replication traffic wholesale. Fresh offers additionally
  apply their zero-cost structural checks (missing proof, oversized payload)
  *before* taking a permit, so malformed work cannot occupy one of sixteen slots
  for the length of a verification.
- **`PaidNotify` is bounded differently from the request/response responders,
  and deliberately so.** It is one-way: the protocol defines no response and the
  sender never retries, so refusing or shedding one does not push work back onto
  a requester — it discards durable paid-list evidence that this node then lacks
  until a later verification cycle happens to re-derive the key's paid status
  from a quorum. Sizing it like a request responder (8 outstanding / 2 per peer,
  shed at the 15s verification deadline) measurably broke replication: a joining
  node silently lost paid-list entries for a fraction of the keys it was
  responsible for and never fetched them inside a 90s window
  (`test_late_joiner_replicates_responsible_chunks`). The bounds are therefore
  set as a **memory ceiling** (64 outstanding, 16 per peer — 32 MiB at the
  512 KiB worst-case proof) and the staleness shed uses one slow-cadence
  neighbor-sync interval, the point at which the pull path would have learned
  the same fact. The class's real protection is `PAID_NOTIFY_WORKER_LIMIT` = 2,
  which bounds the concurrent EVM and DHT work that is actually expensive.
- Per-fetch tasks (initial and retry) are spawned on the detached tracker instead
  of bare `tokio::spawn`, so a dropped `in_flight` set can no longer leak
  `Arc<LmdbStorage>` past shutdown. Prompt network-I/O cancellation is unchanged —
  only the bounded in-flight transaction (milliseconds) is awaited.

- **Rejected:** shielding every individual `select!` call site against blocking
  cancellation — N fragile call sites vs. one storage-layer invariant, and it does
  not cover bare-spawned per-fetch tasks.

### 4. Treat closed event streams as terminal; keep lag recoverable

A closed Tokio broadcast receiver is immediately ready with `RecvError::Closed`
forever. `handle_replication_event_recv_error` now returns `ControlFlow` and both
the P2P and DHT branches **break** the loop on `Closed` (`mod.rs`); breaking drops
the replication sender and cascades a clean shutdown to the serial handler.
`RecvError::Lagged` stays **recoverable** (see decision 5) — the two are
deliberately distinguished.

### 5. Drain the priority neighbor-sync queue eagerly; recover from DHT lag by resnapshotting

- The neighbor-sync loop **parks only when the durable priority queue is empty**
  and otherwise runs rounds back-to-back, draining at round-trip speed instead of
  one batch per 10–20 minute periodic tick. `sync_trigger` is a coalescing
  `Notify`, so a churn burst that queued many priority peers previously drained
  only one batch; the drain now terminates because `select_next_sync_peer` pops
  each priority peer unconditionally and refills only under `is_cycle_complete()`
  (`neighbor_sync.rs`).
- On broadcast `Lagged`, recover from **ground truth**: resnapshot the current
  close-peer set, **prune queued peers that have departed** (matching the normal
  `KClosestPeersChanged` path via `retain_sync_peers`), queue current members for
  priority sync, and fire the trigger. Stale peers from missed departure events no
  longer sit ahead of genuine entrants burning a request timeout each.

### 6. Bound and self-heal bootstrap capacity-rejection accounting

The capacity-rejection record is now a `HashMap<PeerId, Instant>` (most-recent
rejection time) rather than a bare set (`types.rs`), and:

- Records expire after **`ReplicationConfig::capacity_rejected_max_age()`** —
  a full round-robin neighbor cycle including one request deadline per peer,
  plus the peer cooldown and one slow-cadence interval of slack (`config.rs`).
- The recorded time is **first-seen and never refreshed**. A repeat rejection
  re-asserts that the source still owes work but must not restart the clock:
  measuring from the most recent rejection meant a source that keeps overflowing
  the queue kept its own record permanently fresh, so `check_bootstrap_drained`
  never returned true, `bootstrapping: true` stood indefinitely, and **auditing
  stayed off for the entire duration of the pressure** (Invariant 19). That is a
  liveness wedge reachable by an ordinarily busy peer, with no attacker needed.
  First-seen semantics bound it at one TTL regardless of peer behaviour.
- Expiry forfeits the source's owed keys — whether it departed, abandoned
  re-delivery, or is simply overflowing us faster than it can re-deliver —
  consistent with `update_bootstrap_after_peer_removed`; post-bootstrap neighbor
  sync and audit/repair recover them.
- A **fairness displacement never stamps its victim.** Reclaiming a borrowed slot
  (decision 7) is this node's own fairness decision, not a failure by the peer
  that held it. Recording the displaced owner as capacity-rejected let a
  sustained flooder wedge our bootstrap drain open *through an unrelated honest
  peer* that had never overflowed us. Only the displaced key is forfeited, to the
  same recovery path as an expired record.
- Expiry **plus a drain re-check** runs on **every verification worker tick**,
  ahead of the `pending_peer_requests` early-returns: pending requests legitimately
  block the drain check itself but must not block expiry. This also closes the
  adjacent liveness gap where every drain check was event-driven, so a
  clean-cycle clear on a quiet node could satisfy the drain condition with no event
  left to observe it.
- On `PeerRemoved`, a departed peer's outstanding rejection marker is cleared and
  bootstrap drain is **immediately** rechecked (`bootstrap.rs`).

- **Rejected:** a routing-table membership check at the note sites (only shrinks
  the TOCTOU window, does not close it) and a global bootstrap deadline (would
  change Invariant 19 semantics for genuinely busy bootstraps).

### 7. Source-aware, bounded verification

- Retain **live hint sources** per key (including the subset that explicitly
  claimed replica possession) instead of a single sender. Capacity ownership is
  tracked separately from evidence provenance: unique keys are charged to one
  authenticated source, while duplicate advertisements merge evidence without
  consuming another slot.
- Bound that retention at **`MAX_HINT_SOURCES_PER_KEY` (8)** sources per key.
  `MAX_PENDING_VERIFY` counts keys, not the peers remembered against each one,
  and the duplicate-advertisement path merges a source into two per-key sets plus
  the reverse index at no capacity cost — so without this cap, N routing-table
  peers re-advertising a full queue cost `N x 131,072` associations charged
  against nothing. Re-advertising an already-pending key is also the cheapest
  path through admission, since `is_relevant` short-circuits on it without a
  routing-table lookup. At the cap, replica claimants displace paid-only
  advertisers: only a claimant is usable as a fetch candidate, so a paid-only
  source forfeits its slot and the key loses one unit of corroboration weight —
  never a fetch candidate and never the key itself. The capacity owner is never
  displaced, since `insert_pending_owned_unchecked` requires it to remain a live
  hint source.
- Enforce **elastic max-min sender accounting** under the 131,072-entry global
  bound. A sole sender may borrow unused capacity for a large bootstrap snapshot;
  once another sender has work, its fair allocation is restored by reclaiming
  low-corroboration borrowed entries from an over-represented owner. Reclaimed
  bootstrap work is forfeited to post-bootstrap recovery (decision 6), not
  charged against its former owner's standing.
- **This removes `MAX_PENDING_VERIFY_PER_PEER` (8,192)**, the base branch's hard
  per-source cap and — by its own doc comment — the primary flood defence. The
  trade is explicit and worth stating in adversarial terms: a single sender's
  worst-case resident footprint rises **8,192 -> 131,072 entries, a 16x jump**.
  What replaces the hard cap is a convergence property rather than a ceiling: the
  moment a second sender has work, max-min reclaim moves borrowed slots to it,
  one slot per admission, until both hold an even share. Max-min is preferred
  because a hard cap wastes capacity exactly when it is most useful — a
  single-peer bootstrap snapshot against an otherwise-idle queue — while still
  failing to bound N colluding senders, which the global cap has to catch
  regardless. The convergence claim is pinned by
  `borrowed_capacity_converges_to_fair_share_for_a_late_sender`, which fills the
  pool from one sender and asserts a late sender reclaims an even share; it also
  covers `fair_rejection_cache` and the stale-candidate skip loop in
  `pop_reclaimable_victim`, where a convergence failure would otherwise hide.
- Charge **retry reservations to their capacity owner**. A key promoted to the
  fetch pipeline leaves `pending_keys_by_owner` but keeps a reservation against
  the global pool; billing that to nobody let an owner with many in-flight
  retries read as under-loaded and win more than its share, a skew growing with
  exactly how much work it already held. `reclaim_borrowed_slot` now allocates
  the full pool against `resident + reserved` per owner, matching
  `pending_capacity_used`.
- Select each bounded verification cycle round-robin across capacity owners,
  redistributing unused service immediately. Protected fetch retries and
  corroborating-source count retain priority within an owner's share. Thus a
  continuously refilling sender cannot monopolise either resident queue slots
  or the 8,192-key verification budget.
- Bound one verification cycle to **8,192 keys** (`MAX_VERIFICATION_KEYS_PER_CYCLE`)
  and cap simultaneous verification exchanges at **32**
  (`MAX_CONCURRENT_VERIFICATION_REQUESTS`). Aggregate each peer's keys into **one
  request per cycle**; accept one full-cycle incoming request and reject oversized
  requests with a bounded, wire-compatible **empty** response (`config.rs`).
- Bootstrap neighbor batches are published **atomically**: sync requests run
  concurrently, the completed batch is admitted under one queue lock, and it stays
  outstanding until hints and drain accounting are fully published, so verification
  cannot select a partially-published batch and miss the source picture. This
  removes the prior timing-based singleton aggregation delay.
- A **sole** replica advertiser is penalized (bounded per peer and cycle) only when
  the close group **definitively rejects** the key or that advertiser **explicitly
  reports it absent**; inconclusive, paid-only, and corroborated hints remain
  neutral — closing the free-replication offload path without widening trust
  penalties (consistent with ADR-0003).

### 8. Reserve verification retry capacity; tolerate paid-list edge churn

- Retry metadata is carried through `pending_verify`, the fetch queue, and
  in-flight fetch state, and global/per-sender pending capacity is **reserved** for
  retryable verified work until completion, discard, or restoration to verification
  (`types.rs`, `mod.rs`). Dequeue uses **by-value APIs** so retry reservations
  cannot be orphaned, and promoted verified keys keep counting against capacity so
  unrelated hints cannot steal the slot needed to requeue them.
- Paid-list majority repair gains a **flexible edge** for full-width close
  groups: negative/missing edge votes do not enlarge the denominator, positive
  edge votes count and expand it, undersized groups stay on strict-majority rules,
  and inconclusive outcomes are preserved while unresolved votes could still change
  the result (`quorum.rs`, `paid_list.rs`).
- The edge is **scaled to the group** (`paid_group_size / 5`, capped at
  `PAID_LIST_FLEX_EDGE_COUNT = 4`) rather than a fixed four peers. At the
  production width of 20 this is exactly 4, so shipped behaviour is unchanged;
  at smaller *configured* widths a fixed four was disproportionate. The guard was
  `configured_group_size > PAID_LIST_FLEX_EDGE_COUNT`, so a configured group of
  five discounted four of its members, left a voting core of **one**, and
  authorized on a **single `Confirmed` vote** — and `validate()` accepts any width
  down to 1. Since `PaidListVerified` writes the paid list and enables repair
  fetches, that is the gate deciding what a node fetches and keeps.
- A **`PAID_LIST_ABSOLUTE_CONFIRM_FLOOR` of 3** confirmations applies on top of
  the discounted majority, bounded by the true group size so it can never demand
  more votes than there are peers to give them. The edge discount shrinks the
  denominator and with it the threshold; the floor keeps a lone voter from ever
  being decisive, whatever the discount does.
- **Not addressed here:** an edge peer that answers `NotFound` is still
  discounted identically to one that stays silent, so real negative evidence
  vanishes at the boundary while the same vote from a core peer counts against
  the key. Churn justifies discounting silence, not a peer that answered. The
  behaviour is deliberate and pinned by
  `paid_list_edge_notfound_votes_shrink_denominator_to_inner_group`; revisiting
  it is left to a follow-up, as is the width-20 relaxation from 11/20 to 9/16
  that the flexible edge introduces in the first place.

### 9. Merge duplicate hints in O(1) by separating ordering from payload

`FetchCandidate` is split into **`FetchOrder`** (key + distance — the only fields
the `Ord` impl reads) held in the heap, and **`FetchPayload`** (sources + retry
metadata) held in a key-indexed map that also serves as the membership index
(`types.rs`). Merging a re-advertised key's advertiser is now an O(1) map lookup
that never touches the heap; the departed-peer path edits payloads in place and
rebuilds the heap **only** when a peer actually orphans a candidate. This removes
the prior O(n)-per-duplicate / O(m·n)-per-batch heap rebuild under the global queue
write lock — a neighbor could trigger it by re-hinting queued keys. Measured
per-key merge cost drops from 302µs at a 50k-deep queue to a flat ~400ns
independent of depth.

### 10. Shared, bounded audit-challenge coordination

A shared per-target `AuditChallengeCoordinator` spans responsible, prune-confirmation,
and possession audits (`audit_coordinator.rs`, `pruning.rs`). Local concurrency is
limited to the deployed responder admission capacity and response deadlines start
**only after local admission**, so a local burst of independent audit issuers can no
longer exceed the responder's per-source limit and misread the resulting drops as
remote timeout. Coordinator reference accounting is cancellation-safe (RAII), and
timeout / unreachable / send-failure are separated in observability while retaining
wire-compatible evidence semantics; responder admission drops and digest dispatch
latency are recorded with logging-feature-safe metric labels.

### 11. Drain mature prune backlogs with a wide fast path and request-bounded batching

Prune classification remains attached to `NeighborSyncCycleComplete`: each pass
scans the local store against a fresh routing-table view and maintains the
process-local three-day out-of-range hysteresis. Audit execution is not moved to a
new background worker.

For each stored key, the pass derives three self-inclusive local groups:

- the storage-retention group (`storage_admission_width`, 9);
- the widest legitimate admission group (`paid_list_close_group_size`, 20); and
- the strict replica group (`close_group_size`, 7).

A key inside width 9 remains in range and clears its out-of-range timestamp. A key
continuously outside width 9 for less than `PRUNE_HYSTERESIS_DURATION` remains
hysteresis-pending. Once mature:

- if a **complete** width-20 lookup contains 20 peers and excludes self, the key is
  a fast-delete candidate and requires no remote possession audit;
- otherwise it remains an audited candidate and deletion requires all-but-one
  positive proofs from the current strict close group (6 of 7 at reference
  parameters).

The fast path deliberately accepts the durability risk that twenty locally-closer
peers do not prove any of them actually hold the bytes. Hysteresis protects against
short-lived responsibility churn, not under-replication. This trade-off is accepted
to make the widest admission boundary an eventual hard storage boundary instead of
retaining far-out copies indefinitely.

Both paths require bootstrap to be drained and preserve the retained-commitment
veto. Immediately before a fast deletion, the node rechecks the full width-20
lookup, width-9 exclusion, hysteresis, bootstrap state, and commitment state.
Immediately before an audited deletion, it rechecks width-9 exclusion, hysteresis,
bootstrap and commitment state, and that the positive proofs still satisfy the
current strict group. A key that moves outside width 20 during an audit may take the
fast path after the fast-path revalidation; a key that moves back inside width 9 is
retained and clears hysteresis.

Remote work is bounded by **actual batched requests and candidates**, not by
candidate-to-peer edges. A pass selects a rotating, bounded candidate window,
inverts `candidate -> peers` into `peer -> keys`, deduplicates keys, and chunks each
peer's list at the existing dynamic sender limit
`responsible_audit_key_limit(local_stored_keys) =
max(floor(sqrt(local_stored_keys)), 1)`. Requests retain the deployed key-count
scaled timeout, global concurrency, and per-peer coordinator limits. A candidate is
selected only when every request required for its complete proof set fits in the
pass request budget; partial evidence is not carried across passes.

A responder rejects a batch when its independently calculated
`max_incoming_audit_keys(stored_chunks) = 2 * responsible_audit_key_limit(stored_chunks)`
is below the batch size. Because that limit already carries a 2x margin over the
challenger's own `sqrt`-scaled sender size, an honestly-sized peer only rejects
once the close-group store spread exceeds **4x** (`sqrt(cc) > 2*sqrt(rc)`). We
assume close-group store spread stays within ~2x — half the rejection threshold —
so a size rejection is treated as attributable misbehaviour (a mis-sized or lying
responder), not accommodated with in-band renegotiation. This deliberately drops
the earlier split-and-retry that parsed the responder's rejection wording: a
`Rejected` response is never a possession signal (a peer that lacks a key answers
`Digests` with `ABSENT_KEY_DIGEST`), so it flows through the normal failure path
under a distinct `size_reject` metric label, subject to the same
fresh-responsibility-confirmation gate and per-peer-per-pass dedup as any other
prune-audit failure. The `size_reject` label is the re-open trigger: if it fires
in the field, the store-spread assumption is being violated and the accommodation
should be reconsidered. No protocol identifier, enum discriminant, message field,
digest, nonce, or challenge-ID rule changes; the wire representation is untouched.

## Consequences

### Positive

- Partition heals and mass joins drain priority neighbor-sync work in seconds-scale
  rounds instead of waiting through periodic ticks or stale-peer timeouts.
- A peer cannot conscript out-of-range nodes into fetching and storing arbitrary
  keys by labelling hints as replicas, and topology churn between fetch promotion
  and download no longer costs a download, a disk write, and a prune cycle.
- Bootstrap cannot be held indefinitely by partial batch publication or by a
  departed capacity-rejected peer — including one whose removal races the rejection
  record — so audits cannot be disabled permanently nor the node trust-penalized for
  a perpetual bootstrap claim.
- Fresh-offer verification and storage never run inline on the serial loop, so
  worker saturation no longer backs up the inbound queue or drops replication
  messages through broadcast lag; duplicate-hint bursts no longer scale the queue
  write-lock hold time with depth.
- When `shutdown()` returns, no LMDB blocking operation is still running on either
  environment and no engine-spawned task holds the storage, so the same LMDB files
  can be reopened safely; closed replication event streams terminate cleanly without
  CPU spin or repeated warnings.
- Sole peers cannot advertise unacknowledged replicas to offload storage for free
  without incurring bounded trust penalties; local audit concurrency no longer
  manufactures false remote-timeout verdicts.
- Mature records outside a complete width-20 local view are removed in bounded
  local batches without generating remote audit traffic, while ranks 10-20 gain
  substantially denser peer-batched audits per request.

### Negative / Trade-offs

- **Narrower replica repair.** A node with a transiently skewed routing table now
  declines to repair a key it ranks outside the top-9 (`storage_admission_width`).
  This matches pruning, which already evicts at the same width, but it does move
  repair from the sender's view to the receiver's own.
- **New refusal behaviour.** Past the 16-permit fresh-offer admission bound an offer
  is refused rather than queued; a refused offer is penalized as absent by the
  delayed possession check.
- **A capacity refusal still costs the refuser trust — known gap.** The sender
  transmits fresh offers with `send_message` and never reads the `Rejected`
  response, so a refusal is indistinguishable from absence at the later possession
  check and lands as `AUDIT_FAILURE_TRUST_WEIGHT` (5.0) on the *refuser*. This
  fires under ordinary load bursts, not just attacks: any node reaching its
  fresh-offer ceiling accumulates unearned trust damage from peers doing nothing
  wrong, and that feeds the eviction path. The per-source share (decision 2) bounds
  how much of the pool one peer can occupy, and so how *large* the effect can be
  made deliberately, but does not remove it. Closing it properly needs the sender
  to read the response — the receiver already returns a precise reason, it is
  simply discarded — and to grade the possession outcome accordingly. Deferred.
- **Forfeited owed keys on expiry.** When a capacity-rejection record expires, the
  source's owed keys are forfeited and recovered later via post-bootstrap neighbor
  sync and audit/repair, rather than held indefinitely. This now also covers a
  live source that keeps overflowing us, not only a departed one (decision 6):
  bounding the wedge is worth more than holding the debt.
- **Larger single-sender footprint.** Removing `MAX_PENDING_VERIFY_PER_PEER`
  raises one sender's worst-case resident share 8,192 -> 131,072 entries. Traded
  for max-min convergence and useful borrowing; see decision 7.
- **Bounded per-key corroboration.** Capping hint sources at 8 per key means a
  ninth advertiser of an already-well-corroborated key is not recorded. It costs
  a unit of corroboration weight, never a fetch candidate or the key itself.
- **More moving parts.** Task trackers, RAII in-flight guards, reservation
  bookkeeping, and the split heap add mechanism that must be kept correct; several
  new tunables now exist (see below).
- **Accepted far-copy durability risk.** A complete local width-20 view is a
  distance statement, not a possession proof. Fast deletion can remove the last
  surviving copy after hysteresis if replication failed across all closer peers.

### Neutral / Operational

- New/changed tunables, in `src/replication/config.rs` unless noted:
  `ReplicationConfig::capacity_rejected_max_age()` (derived, not a constant),
  `MAX_VERIFICATION_KEYS_PER_CYCLE` (8,192),
  `MAX_CONCURRENT_VERIFICATION_REQUESTS` (32), the fresh-offer admission bound
  (16 permits / 64 MiB) and its new per-source share
  (`FRESH_OFFER_MAX_OUTSTANDING_PER_PEER` = 2, `mod.rs`), the paid-notify
  responder bounds (`PAID_NOTIFY_WORKER_LIMIT` = 2,
  `PAID_NOTIFY_MAX_OUTSTANDING` = 8, `PAID_NOTIFY_MAX_OUTSTANDING_PER_PEER` = 2,
  `mod.rs`), `MAX_HINT_SOURCES_PER_KEY` (8, `scheduling.rs`), the paid-list edge
  ceiling `PAID_LIST_FLEX_EDGE_COUNT` (4) with its
  `PAID_LIST_FLEX_EDGE_DIVISOR` (5) scaling, and
  `PAID_LIST_ABSOLUTE_CONFIRM_FLOOR` (3). The two responsibility
  widths (`storage_admission_width` = 9, `paid_list_close_group_size` = 20) are
  unchanged and shared with ADR-0003.
- Prune passes use bounded candidate, request, and local fast-delete counts. The
  per-request key count remains dynamic (`floor(sqrt(local_stored_keys))`), and
  timeouts continue to scale with the actual number of challenged keys.
- **SemVer: patch.** No wire-format or public-API change; oversized verification
  requests retain their deployed response and prune audits retain the deployed
  multi-key challenge/response representation.
- Runs alongside ADR-0002's gossip-triggered audit and ADR-0003's full-node
  detection, sharing the same trust/eviction path; the sole-source replica penalty
  is another attributable-misbehaviour source feeding it.

## Validation

How we will know this decision remains correct (coverage added in PR #165):

- **Responsibility at download:** unit coverage of `apply_fetch_result` — worker
  disposition of `NoLongerResponsible` (terminal exit, retry-slot release, no
  verification requeue), terminal-path parity with `Stored`, and preserved
  source-failure retry/requeue transitions. A live 12-node **e2e** enqueues a fetch
  candidate for a key the target is not responsible for (via a test-only seam,
  since live topology cannot be shifted deterministically inside the
  promotion→dequeue window) and asserts the chunk is never stored and the key exits
  terminally, with an in-responsibility positive control; the e2e **fails when the
  rechecks are disabled**, confirming it discriminates.
- **Single-gate admission** parity across replica and paid labels for the unchanged
  admissible key set; replica-download responsibility gating at both fetch sites,
  including rejection of out-of-range keys and the removed paid→replica escalation.
- **Fresh-offer dispatch:** admission bounding, per-key in-flight collapse of
  concurrent duplicates, and the refusal-past-bound possession penalty.
- **Shutdown drain:** storage- and paid-list-level `wait_idle` tests (a write parked
  inside its blocking closure with a dropped awaiter keeps `wait_idle` blocked,
  commits after release, and leaves the store usable), and an engine-level
  `poc_shutdown_lmdb_drain` proving `shutdown()` blocks until a detached write
  commits and both environments reopen cleanly.
- **Bootstrap self-heal:** the peer-removal race ordering (removal cleanup first as
  a no-op, rejection recorded after for the departed peer, drain blocked, then TTL
  expiry drains it); per-source TTL semantics (within-TTL still blocks; a stale
  source's expiry does not forfeit a fresh source's owed re-delivery; a repeat
  rejection refreshes the timestamp); and the verification-tick self-heal helper.
- **Neighbor sync:** priority drain/termination contract and lag recovery (resnapshot
  + departed-peer prune); closed vs. lagged P2P event handling (terminal control flow
  vs. continuation with metric accounting).
- **Verification and repair:** source aggregation, elastic max-min admission in
  both arrival orders, a 50,000-key uncontended single-source bootstrap, and
  sender-fair bounded-cycle selection; displacement-aware bootstrap accounting;
  singleton replica-hint penalties for definitive rejection and explicit denial,
  with neutral inconclusive/paid-only/corroborated cases; atomic bootstrap batch
  publication and full-cycle request bounds; retry reservation transfer, discard,
  exhaustion, and per-sender capacity; paid-list edge votes; e2e paid-list majority
  repair below storage quorum.
- **Performance:** O(1) duplicate-source merge and heap rebuild only on genuine
  candidate orphaning.
- **Audit:** coordinator per-target serialization, cross-peer parallelism, and
  cancellation cleanup.
- **Pruning:** width-9 hysteresis classification; complete-width-20 fast deletion
  and incomplete-width-20 audited fallback; bootstrap and commitment deferrals;
  fast-path and audited TOCTOU revalidation; dynamic square-root peer batches;
  request-budget admission of complete candidate proof sets; every `Rejected`
  reason grading to the non-recovering `Rejected` status without parsing its
  wording; and rotating fairness.
- **Re-open triggers:** revisit the fresh-offer admission bound if legitimate offers
  are refused under normal load; revisit `CAPACITY_REJECTED_MAX_AGE` if bootstrap
  drains too slowly under real neighbor-sync cadence; revisit the narrowed replica
  repair width if routing skew causes measurable coverage loss the repair path does
  not heal; disable or narrow the width-20 fast path if data-availability telemetry
  shows that the accepted far-copy deletion risk is material; reconsider the
  size-rejection-as-misbehaviour treatment if the `size_reject` audit-failure label
  fires under normal load (the close-group store spread is exceeding the assumed
  ~2x and honest peers are being penalised).

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing this one. Several decisions here (the responsibility widths, the trust /
eviction path, the delayed possession check) are shared with ADR-0002 and ADR-0003
— changes to those knobs must be reconciled across all three records.
