# Replication Logic Specification (Codebase-Agnostic)

> Status: Design-level specification for pre-implementation validation.

## 1. Purpose

This document specifies replication behavior as a pure system design, independent of any language, framework, transport, or existing codebase.
It is designed for Kademlia-style decentralized networks, and assumes Kademlia nearest-peer routing semantics.

Primary goal: validate correctness, safety, and liveness of replication logic before implementation.

## 2. Scope

### In scope

- Permanent record replication in a decentralized key-addressed network.
- Churn-aware maintenance and proactive repair.
- Admission control, quorum verification, and storage audits.

### Out of scope

- Concrete wire formats and RPC APIs.
- Disk layout, serialization details, and database choices.
- Cryptographic algorithm selection beyond required properties.

## 3. System Model

- `Node`: participant with routing view, local store, and replication worker.
- `LocalRT(N)`: node `N`'s current authenticated local routing-table peer set (does not include `N` itself).
- `SelfInclusiveRT(N)`: derived local view `LocalRT(N) ∪ {N}` used for responsibility-range and local membership evaluations that must treat `N` as a candidate.
- `NeighborSyncOrder(N)`: deterministic ordering of peers, snapshotted from `LocalRT(N)` at the start of each round-robin cycle. Peers joining `LocalRT(N)` mid-cycle are not added (they enter the next cycle's snapshot). Peers may be removed from the snapshot mid-cycle if they are on per-peer cooldown or unreachable during sync.
- `NeighborSyncCursor(N)`: index into the current `NeighborSyncOrder(N)` snapshot indicating the next peer position to schedule. Valid for the lifetime of the snapshot.
- `NeighborSyncSet(N)`: current round's up-to-`NEIGHBOR_SYNC_PEER_COUNT` peers selected from `NeighborSyncOrder(N)` starting at `NeighborSyncCursor(N)`; periodic repair sync partners for `N`.
- `NeighborSyncCycleComplete(N)`: event that fires when node `N`'s cursor reaches or exceeds the end of the current `NeighborSyncOrder(N)` snapshot (all remaining peers synced, on cooldown, or unreachable). Triggers post-cycle pruning (Section 11) and a fresh snapshot from current `LocalRT(N)` for the next cycle.
- `Record`: immutable, content-addressed data unit with key `K`.
- `Distance(K, N)`: deterministic distance metric between key and node identity.
- `CloseGroup(K)`: the `CLOSE_GROUP_SIZE` nearest nodes to key `K`.
- `IsResponsible(N, K)`: true if `N` is among the `CLOSE_GROUP_SIZE` nearest nodes to `K` in `SelfInclusiveRT(N)`.
- `Holder`: node that stores a valid copy of a record.
- `OutOfRangeFirstSeen(N, K)`: per-key timestamp recording when key `K` was first continuously observed as out of range on node `N`. Cleared (set to `None`) when `K` is back in range.
- `PoP`: verifiable proof that a record was authorized for initial storage/payment policy.
- `PaidNotify(K)`: fresh-replication paid-list notification carrying key `K` plus PoP/payment proof material needed for receiver-side verification and whitelisting.
- `PaidForList(N)`: persistent set of keys node `N` currently believes are paid-authorized; MUST survive node restarts.
- `PaidCloseGroup(K)`: `PAID_LIST_CLOSE_GROUP_SIZE` nearest nodes to key `K` that participate in paid-list consensus, evaluated from the querying node's local view using `SelfInclusiveRT(querying_node)`.
- `PaidGroupSize(K)`: effective paid-list consensus set size for key `K`, defined as `|PaidCloseGroup(K)|`.
- `ConfirmNeeded(K)`: dynamic paid-list confirmation count for key `K`, defined as `floor(PaidGroupSize(K)/2)+1`.
- `QuorumNeeded(K)`: effective presence confirmation count for key `K`, defined as `min(QUORUM_THRESHOLD, floor(|QuorumTargets(K)|/2)+1)`.
- `BootstrapDrained(N)`: bootstrap-completion gate for node `N`; true only when peer discovery closest to `N`'s own address has populated `LocalRT(N)`, bootstrap peer requests are finished (response or timeout), and bootstrap work queues are empty (`PendingVerify`, `FetchQueue`, `InFlightFetch` for bootstrap-discovered keys).
- `RepairOpportunity(P, KSet)`: evidence that peer `P` has previously received replication hints/offers for keys in `KSet` and had at least one subsequent neighbor-sync cycle to repair before audit evaluation.
- `BootstrapClaimFirstSeen(N, P)`: timestamp when node `N` first observed peer `P` responding with a bootstrapping claim to a sync or audit request. Reset when `P` stops claiming bootstrap status.
- `EigenTrust`: trust subsystem that consumes replication evidence events, updates peer trust scores, and applies peer-eviction policy.

## 4. Tunable Parameters

All parameters are configurable. Values below are a reference profile used for logic validation.

| Parameter | Meaning | Reference                           |
|---|---|-------------------------------------|
| `CLOSE_GROUP_SIZE` | Close-group width and target holder count per key | `7`                                 |
| `QUORUM_THRESHOLD` | Full-network target for required positive presence votes (effective per-key threshold is `QuorumNeeded(K)`) | `floor(CLOSE_GROUP_SIZE/2)+1` (`4`) |
| `PAID_LIST_CLOSE_GROUP_SIZE` | Maximum number of closest nodes tracking paid status for a key | `20`                                |
| `NEIGHBOR_SYNC_PEER_COUNT` | Number of local-RT peers synced concurrently per round-robin repair round | `4`                                 |
| `NEIGHBOR_SYNC_INTERVAL` | Neighbor sync cadence | random in `[10 min, 20 min]`        |
| `NEIGHBOR_SYNC_COOLDOWN` | Per-peer min spacing between successive syncs with the same peer | `1h`                                |
| `MAX_PARALLEL_FETCH_BOOTSTRAP` | Bootstrap concurrent fetches | `20`                                |
| `AUDIT_TICK_INTERVAL` | Audit scheduler cadence | random in `[30 min, 1 hour]`        |
| `AUDIT_BATCH_SIZE` | Max local keys sampled per audit round (also max challenge items) | `8`                                 |
| `AUDIT_RESPONSE_TIMEOUT` | Audit response deadline | `12s`                               |
| `BOOTSTRAP_CLAIM_GRACE_PERIOD` | Max duration a peer may claim bootstrap status before penalties apply | `24h`                               |
| `PRUNE_HYSTERESIS_DURATION` | Minimum continuous out-of-range duration before pruning a key | `6h`                                |

Parameter safety constraints (MUST hold):

1. `1 <= QUORUM_THRESHOLD <= CLOSE_GROUP_SIZE`.
2. Effective paid-list authorization threshold is per-key dynamic: `ConfirmNeeded(K) = floor(PaidGroupSize(K)/2)+1`.
3. If constraints are violated at runtime reconfiguration, node MUST reject the config and keep the previous valid config.

## 5. Core Invariants (Must Hold)

1. A record is accepted only if it passes integrity and responsibility checks.
2. Neighbor-sync repair traffic passes verification only if any condition holds: paid confirmations `>= ConfirmNeeded(K)` across `PaidCloseGroup(K)`, presence positives `>= QuorumNeeded(K)`, or close-group replica majority (which also derives paid-list authorization).
3. Fresh replication bypasses presence quorum only when PoP is valid.
4. Neighbor-sync hints are accepted only from authenticated peers currently in `LocalRT(self)`; hints from peers outside `LocalRT(self)` are dropped.
5. Presence probes return only binary key-presence evidence (`Present` or `Absent`).
6. `CLOSE_GROUP_SIZE` is both the close-group width and the target holder count, not guaranteed send fanout.
7. Receiver stores only records in its current responsible range.
8. Queue dedup prevents duplicate pending/fetch work for same key.
9. Replication emits trust evidence/penalty signals to `EigenTrust`; trust-score thresholds and eviction decisions are outside replication logic.
10. Security policy is explicit: anti-injection may sacrifice recovery of data that is simultaneously below presence quorum AND has lost paid-list authorization (including derived authorization from close-group replica majority).
11. Neighbor-sync scheduling is deterministic and round-robin, and every neighbor-sync hint exchange reaches a deterministic terminal state.
12. Presence no-response/timeout is unresolved (neutral), not an explicit negative vote.
13. A failed fetch retries from alternate verified sources before abandoning. Verification evidence is preserved across fetch retries.
14. Paid-list authorization is key-scoped and majority-based across `PaidCloseGroup(K)`, not node-global.
15. `PaidForList(N)` MUST be persisted to stable storage and is bounded: node `N` tracks only keys for which `N` is in `PaidCloseGroup(K)` (plus short-lived transition slack).
16. Fresh-replication paid-list propagation is mandatory: sender MUST attempt `PaidNotify(K)` delivery to every peer in `PaidCloseGroup(K)` (reference profile: up to 20 peers when available), not a subset.
17. A `PaidNotify(K)` only whitelists key `K` after receiver-side proof verification succeeds; sender assertions never whitelist by themselves.
18. Neighbor-sync paid hints are non-authoritative and carry no PoP; receivers MUST only whitelist by paid-list majority verification (`>= ConfirmNeeded(K)`), never by hint claims alone.
19. Storage-proof audits start only after `BootstrapDrained(self)` becomes true.
20. Storage-proof audits target only peers derived from closest-peer lookups for sampled local keys and filtered through local authenticated routing state (`LocalRT(self)`); random global peers are never audited.
21. Verification-request batching is mandatory for unknown-key neighbor-sync verification and preserves per-key quorum semantics: each key receives explicit per-key evidence, and missing/timeout evidence is unresolved per key.
22. On every `NeighborSyncCycleComplete(self)`, node MUST run a prune pass using current `SelfInclusiveRT(self)`: for keys where `IsResponsible(self, K)` is false or `self ∉ PaidCloseGroup(K)`, record `OutOfRangeFirstSeen` if not already set, and delete only when `now - OutOfRangeFirstSeen >= PRUNE_HYSTERESIS_DURATION`. Clear `OutOfRangeFirstSeen` for keys that are back in range.
23. Peers claiming bootstrap status are skipped for sync and audit without penalty for up to `BOOTSTRAP_CLAIM_GRACE_PERIOD` from first observation. After the grace period, each continued bootstrap claim emits `BootstrapClaimAbuse` evidence to `EigenTrust`.

## 6. Replication

### 6.1 Fresh Replication

Trigger: node accepts a newly written record with valid PoP.

Rules:

1. Store locally after normal validation.
2. Compute holder target set for the key with size `CLOSE_GROUP_SIZE`.
3. Send fresh offers to remote target members only.
4. Fresh offer MUST include PoP.
5. Receiver MUST reject fresh path if PoP is missing or invalid.
6. A node that validates PoP for key `K` MUST add `K` to `PaidForList(self)`.
7. In parallel with record propagation, sender MUST send `PaidNotify(K)` to every member of `PaidCloseGroup(K)` and include the PoP for receiver verification.
8. Sender sends `PaidNotify(K)` with PoP to each peer in `PaidCloseGroup(K)` once (fire-and-forget, no ack tracking or retry).

### 6.2 Neighbor Replication Sync

Triggers:

- Periodic randomized timer (`NEIGHBOR_SYNC_INTERVAL`).

Rules:

1. At the start of each round-robin cycle, node snapshots `NeighborSyncOrder(self)` as a deterministic ordering of authenticated peers from `LocalRT(self)` and resets `NeighborSyncCursor(self)` to `0`. The snapshot is fixed for the entire cycle; peers joining `LocalRT(self)` mid-cycle are not added to the current snapshot (they enter the next cycle's snapshot).
2. Node selects `NeighborSyncSet(self)` by scanning `NeighborSyncOrder(self)` forward from `NeighborSyncCursor(self)`:
   a. If a candidate peer is on per-peer cooldown (`NEIGHBOR_SYNC_COOLDOWN` not elapsed since last successful sync with that peer), remove the peer from `NeighborSyncOrder(self)` and continue scanning.
   b. Otherwise, add the peer to `NeighborSyncSet(self)`.
   c. Stop when `|NeighborSyncSet(self)| = NEIGHBOR_SYNC_PEER_COUNT` or no unscanned peers remain in the snapshot.
3. Node initiates sync with each peer in `NeighborSyncSet(self)`. If a peer cannot be synced, remove it from `NeighborSyncOrder(self)` and attempt to fill the vacated slot by resuming the scan from where rule 2 left off. A peer cannot be synced if:
   a. Unreachable (connection failure/timeout).
   b. Peer responds with a bootstrapping claim. On first observation, record `BootstrapClaimFirstSeen(self, peer)`. If `now - BootstrapClaimFirstSeen(self, peer) <= BOOTSTRAP_CLAIM_GRACE_PERIOD`, accept the claim and skip without penalty. If the grace period has elapsed, emit `BootstrapClaimAbuse` evidence to `EigenTrust` and skip.
4. On any sync session open (outbound or inbound), receiver validates peer authentication and checks current local route membership (`peer ∈ LocalRT(self)`).
5. If `peer ∈ LocalRT(self)`, sync is bidirectional: both sides send and receive peer-targeted hint sets.
6. If `peer ∉ LocalRT(self)`, sync is outbound-only from receiver perspective: receiver MAY send hints to that peer, but MUST NOT accept replica or paid-list hints from that peer.
7. In each session, sender-side hint construction uses peer-targeted sets:
   - `ReplicaHintsForPeer`: keys the sender believes the receiver should hold (`receiver ∈ CloseGroup(K)` in sender view).
   - `PaidHintsForPeer`: keys the sender believes the receiver should track in `PaidForList` (`receiver ∈ PaidCloseGroup(K)` in sender view).
8. Transport-level chunking/fragmentation is implementation detail and out of scope for replication logic.
9. Receiver treats hint sets as unordered collections and deduplicates repeated keys.
10. Receiver diffs replica hints against local store and pending sets, then runs per-key admission rules before quorum logic.
11. Receiver launches quorum checks exactly once per admitted unknown replica key.
12. Replica keys passing presence quorum or paid-list authorization are queued for fetch.
13. Receiver processes unknown paid hints via Section 7.2 majority checks; paid hints never directly whitelist keys.
14. Sync payloads MUST NOT include PoP material; PoP remains fresh-replication-only.
15. Nodes SHOULD use ongoing neighbor sync rounds to re-announce paid hints for locally paid keys to improve paid-list convergence.
16. After each round, node sets `NeighborSyncCursor(self)` to the position after the last scanned peer in the (possibly shrunk) snapshot. Peers removed during scanning (cooldown or unreachable) do not occupy cursor positions — the cursor reflects the snapshot's state after removals.
17. When `NeighborSyncCursor(self) >= |NeighborSyncOrder(self)|`, the cycle is complete (`NeighborSyncCycleComplete(self)`). Node MUST execute post-cycle responsibility pruning (Section 11), then take a fresh snapshot from current `LocalRT(self)` and reset the cursor to `0` to begin the next cycle.

Rate control:

- `NEIGHBOR_SYNC_INTERVAL` governs the global sync timer cadence (how often batch selection runs).
- `NEIGHBOR_SYNC_COOLDOWN` is per-peer: a peer is skipped and removed from the snapshot if it was last successfully synced within `NEIGHBOR_SYNC_COOLDOWN`.

## 7. Authorization and Admission Rules

### 7.1 Neighbor-Sync Hint Admission (Per Key)

For each hinted key `K`, receiver accepts the hint into verification only if both conditions hold:

1. Sender is authenticated and currently in `LocalRT(self)`.
2. Key is relevant to the receiver:
   - Replica hint: receiver is currently responsible (`IsResponsible(self, K)`) or key already exists in local store/pending pipeline.
   - Paid hint: receiver is currently in `PaidCloseGroup(K)` (or key is already in local `PaidForList` pending cleanup).

Notes:

- Authorization decision is local-route-state only.
- Hints from peers outside current `LocalRT(self)` are dropped immediately.
- For inbound sync sessions from peers outside `LocalRT(self)`, receiver may send outbound hints but does not accept inbound hints.
- Mixed hint sets are valid: process admitted keys, drop non-admitted keys.
- Receiver MAY return rejected-key metadata to help sender avoid repeating obviously invalid hints in immediate subsequent sync attempts.

### 7.2 Paid-List Authorization (Per Key)

When handling an admitted unknown key `K` from neighbor sync:

1. If `K` is already in local `PaidForList`, paid-list authorization succeeds immediately.
2. Otherwise run the single verification round defined in Section 9 and collect paid-list responses from peers in `PaidCloseGroup(K)` (same round as presence evidence; no separate paid-list-only round).
3. If paid confirmations from `PaidCloseGroup(K)` are `>= ConfirmNeeded(K)`, add `K` to local `PaidForList`, treat `K` as paid-authorized, and record any peers that also report current presence as fetch candidates.
4. If presence positives from `CloseGroup(K)` during the same verification round reach `>= QuorumNeeded(K)` (close-group replica majority), add `K` to local `PaidForList` and treat `K` as paid-authorized. Close-group replica majority constitutes derived evidence of prior authorization and serves as a paid-list recovery path after cold starts or persistence failures.
5. If neither paid-list confirmations (rule 3) nor close-group replica majority (rule 4) nor presence quorum are met, paid-list authorization fails for this verification round.
6. Nodes answering paid-list queries MUST answer from local `PaidForList` state only; they MUST NOT infer paid status from record presence alone. (Derived paid-list entries from rule 4 are added to `PaidForList` and are thereafter indistinguishable from PoP-derived entries when answering queries.)
7. If a node learns `K` is paid-authorized by majority or close-group replica majority, it SHOULD include `K` in outbound `PaidHintsForPeer` for relevant neighbors so peers can re-check and converge.
8. Unknown paid hints that fail majority confirmation are dropped for this lifecycle and require a new hint/session to re-enter.

### 7.3 Fresh-Replication Paid-List Notification (Per Key)

When fresh replication accepts a new key `K` with valid PoP:

1. Sender constructs `PaidNotify(K)` containing key `K` and PoP.
2. Sender sends `PaidNotify(K)` to every peer in `PaidCloseGroup(K)` (fire-and-forget, no ack tracking or retry).
3. Receiver MUST validate PoP before adding `K` to local `PaidForList`; invalid PoP is silently dropped.

### 7.4 Paid-List Convergence Maintenance (Ongoing)

Nodes that already treat key `K` as paid-authorized SHOULD help convergence by advertising paid hints during neighbor sync:

1. Trigger on neighbor-sync cadence, topology changes affecting `PaidCloseGroup(K)`, and any observation that a `PaidCloseGroup(K)` peer reports unknown for paid key `K`.
2. Compute current `PaidCloseGroup(K)` membership.
3. During sync with peer `P`, if sender believes `P` is in `PaidCloseGroup(K)` and may be missing `K`, include `K` in `PaidHintsForPeer`.
4. Receiver treats paid hints as claims only and adds `K` to `PaidForList` only after local majority confirmation (`>= ConfirmNeeded(K)`).
5. On topology churn, recompute membership and continue on the new `PaidCloseGroup(K)` set.

### 7.5 Presence Probe Handling (Per Key)

For a presence probe on key `K`:

1. Receiver checks local store for key `K`.
2. Receiver returns `Present` if key `K` exists, else `Absent`.
3. If receiver cannot respond before deadline (overload/network delay), the requester observes timeout/no-response rather than a special protocol error code.

### 7.6 Presence Response Semantics

- `Present`: key exists locally.
- `Absent`: key not found locally.

Quorum counting:

- `Present` counts positive.
- `Absent` counts non-positive.
- Timeout/no-response is unresolved (neutral, not a negative vote).

## 8. Receiver Verification State Machine

```text
Idle
  -> OfferReceived
OfferReceived
  -> FilterRejected
  -> PendingVerify
PendingVerify
  -> QuorumVerified
  -> PaidListVerified
  -> QuorumInconclusive
  -> QuorumFailed
QuorumVerified
  -> QueuedForFetch
PaidListVerified
  -> QueuedForFetch
QueuedForFetch
  -> Fetching
Fetching
  -> Stored
  -> FetchRetryable     (timeout/error, transport marks retryable, and alternate sources remain)
  -> FetchAbandoned     (transport marks terminal failure or no alternate sources)
FetchRetryable
  -> QueuedForFetch     (select next alternate source from verified source set)
FetchAbandoned
  -> Idle               (key forgotten; requires new offer to re-enter pipeline)
QuorumFailed
  -> QuorumAbandoned    (quorum failed in this verification pass)
QuorumInconclusive
  -> QuorumAbandoned    (verification pass timed out undecidable)
QuorumAbandoned
  -> Idle               (key forgotten; stops wasting probe resources)
```

Transition requirements:

- `OfferReceived -> PendingVerify` only for unknown, admitted, in-range keys.
- `PendingVerify -> QuorumVerified` only if presence positives from the current verification round reach `>= QuorumNeeded(K)`. On success, record the set of positive responders as verified fetch sources and add `K` to local `PaidForList(self)` (close-group replica majority derives paid-list authorization).
- `PendingVerify -> PaidListVerified` only if paid confirmations from the same verification round reach `>= ConfirmNeeded(K)`. On success, mark key as paid-authorized locally and record fetch candidates from positive presence hints and/or hint sender.
- `PendingVerify -> QuorumInconclusive` when neither quorum nor paid-list success is reached and unresolved outcomes (timeout/no-response) keep both outcomes undecidable in this round.
- `Fetching -> Stored` only after all storage validation checks pass.
- `Fetching -> FetchRetryable` when fetch fails (timeout, corrupt response, connection error), the transport classifies the attempt as retryable, and at least one untried verified source remains. Mark the failed source as tried so it is not selected again.
- `Fetching -> FetchAbandoned` when fetch fails and either the transport classifies failure as terminal or all verified sources have been tried. Emit `ReplicationFailure` evidence for the failed source(s).
- `FetchRetryable -> QueuedForFetch` selects the next untried verified source and re-enters the fetch queue without repeating quorum verification.
- `QuorumFailed -> QuorumAbandoned` is immediate and terminal for this offer lifecycle. Key is forgotten and stops consuming probe resources. Requires a new offer to re-enter the pipeline.
- `QuorumInconclusive -> QuorumAbandoned` is immediate and terminal for this offer lifecycle. Requires a new offer to re-enter the pipeline.

## 9. Quorum Verification Logic

For each unknown key:

1. Deduplicate key in pending-verification table.
2. If `K` is already in local `PaidForList`, mark `PaidListVerified` and queue for fetch immediately (no network verification round required).
3. Otherwise compute `PaidTargets = PaidCloseGroup(K)`.
4. Compute `QuorumTargets` as up to `CLOSE_GROUP_SIZE` nearest known peers for `K` (excluding self).
5. Compute `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
6. Compute `VerifyTargets = PaidTargets ∪ QuorumTargets`.
7. Send verification requests to peers in `VerifyTargets` and continue the round until either success/fail-fast is reached or a local adaptive verification deadline for this round expires. Responses carry binary presence semantics (Section 7.6); peers in `PaidTargets` also return paid-list presence for `K`.
8. Mark `PaidListVerified` and queue for fetch as soon as paid confirmations from `PaidTargets` reach `>= ConfirmNeeded(K)`.
9. Mark `QuorumVerified`, add `K` to local `PaidForList(self)`, and queue for fetch as soon as presence positives from `QuorumTargets` reach `>= QuorumNeeded(K)`. Close-group replica majority constitutes derived paid-list evidence (Section 7.2 rule 4).
10. Verification succeeds as soon as either step 8 or step 9 condition is met (logical OR).
11. Fail fast and mark `QuorumFailed` only when both conditions are impossible in this round: `(paid_yes + paid_unresolved < ConfirmNeeded(K))` AND `(quorum_positive + quorum_unresolved < QuorumNeeded(K))`.
12. If the verification-round deadline expires with neither success nor fail-fast, mark `QuorumInconclusive`.
13. On `QuorumFailed` or `QuorumInconclusive`, transition immediately to `QuorumAbandoned` (no automatic quorum retry/backoff).

Undersized verification-set behavior:

- Presence threshold remains dynamic per key via `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.

Single-round requirement:

- Unknown-key verification MUST NOT run a second sequential network round for presence after a paid-list miss; both evidence types are collected in the same request round.

Verification request batching requirement:

- Implementation MUST coalesce concurrent unknown-key verification into one request per peer carrying many keys.
- Each peer response MUST include explicit per-key results: presence (`Present`/`Absent`) for each requested key, plus paid-list presence for keys where that peer is in `PaidTargets`.
- If a peer response omits key `K`, or the peer times out/no-responds, that peer contributes unresolved evidence for key `K` (never a negative vote).

Security-liveness policy:

- Neighbor-sync repair never stores without either presence quorum or paid-list authorization.
- Fresh replication can store with valid PoP alone.
- Therefore, below-quorum data is recoverable only if paid-list authorization can still be established.

## 10. Record Storage Validation

A fetched record is written only if all checks pass:

1. Type/schema validity.
2. Content-address integrity (`hash(content) == key`).
3. Authorization validity:
   - Fresh replication: valid PoP, or
   - Neighbor-sync repair: prior quorum-verified key or paid-list-authorized key.
4. Responsibility check: `IsResponsible(self, K)` at write time.

## 11. Responsibility Check

A node `N` is responsible for key `K` if `IsResponsible(N, K)` holds — that is, `N` is among the `CLOSE_GROUP_SIZE` nearest nodes to `K` in `SelfInclusiveRT(N)`.

This check is evaluated per-key at decision points:

1. Accept/reject incoming replication writes.
2. Post-cycle pruning eligibility (prune stored records where node is no longer responsible).
3. Post-cycle paid-list retention eligibility (drop `PaidForList` entries for keys where node is no longer in `PaidCloseGroup(K)`).

Post-cycle responsibility pruning (triggered by `NeighborSyncCycleComplete(self)`):

1. For each locally stored key `K`, recompute `IsResponsible(self, K)` using current `SelfInclusiveRT(self)`:
   a. If in range: clear `OutOfRangeFirstSeen(self, K)` (set to `None`).
   b. If out of range: if `OutOfRangeFirstSeen(self, K)` is `None`, set it to `now`. Delete the record only when `now - OutOfRangeFirstSeen(self, K) >= PRUNE_HYSTERESIS_DURATION`.
2. For each key `K` in `PaidForList(self)`, recompute `PaidCloseGroup(K)` membership using current `SelfInclusiveRT(self)`:
   a. If `self ∈ PaidCloseGroup(K)`: clear the key's `OutOfRangeFirstSeen` (set to `None`).
   b. If `self ∉ PaidCloseGroup(K)`: if `OutOfRangeFirstSeen` is `None`, set it to `now`. Delete the entry only when `now - OutOfRangeFirstSeen >= PRUNE_HYSTERESIS_DURATION`.
3. This prune pass is local-state-only and MUST NOT require remote confirmations.

Effect:

- Small network: each node is responsible for more keys.
- Large network: each node is responsible for fewer keys.

## 12. Scheduling and Capacity Rules

Queue model:

- `PendingVerify`: keys awaiting quorum result.
- `FetchQueue`: presence-quorum-passed or paid-list-authorized keys waiting for fetch slot.
- `InFlightFetch`: active downloads.

Rules:

1. Drive quorum checks with an adaptive worker budget that scales with backlog and observed network latency while respecting local CPU/memory/network guardrails.
2. During bootstrap, enforce `MAX_PARALLEL_FETCH_BOOTSTRAP` as fetch concurrency cap; outside bootstrap, fetch concurrency is controlled by the adaptive budget from rule 1.
3. Sort fetch candidates by relevance (e.g., nearest-first) before dequeue.
4. Evict stale queued entries using implementation-defined queue-lifecycle policy.
5. On fetch failure, mark source as tried and transition per `FetchRetryable`/`FetchAbandoned` rules (Section 8). Retry decisions are transport-owned. Retry fetches reuse the verified source set from the original verification pass and do not consume additional verification slots.
6. Storage-audit scheduling and target selection MUST follow Section 15 trigger rules.
7. Responsibility/paid-list prune passes MUST run on `NeighborSyncCycleComplete(self)` per Section 11.

Capacity-managed mode (finite store):

1. If full and new in-range key arrives, evict farthest out-of-range key if available.
2. If no out-of-range key exists, reject new key.
3. On each `NeighborSyncCycleComplete(self)`, prune keys that have been continuously out of range for `>= PRUNE_HYSTERESIS_DURATION` per Section 11.
4. `PaidForList` MUST be persisted to stable storage and SHOULD be bounded with paging/eviction policies; on each `NeighborSyncCycleComplete(self)`, keys outside `PaidCloseGroup(K)` that have been continuously out of range for `>= PRUNE_HYSTERESIS_DURATION` are first candidates for removal.

## 13. Churn and Topology Change Handling

Maintain tracker for neighbor-sync eligibility/order and classify topology events:

- `Trigger`: genuine change, run neighbor sync.
- `Skip`: probable restart churn, suppress.
- `Ignore`: far peers, no action.

Goal: avoid replication storms from restart noise while still reacting to real topology shifts.

## 14. Failure Evidence and EigenTrust Integration

Failure evidence types include:

- `ReplicationFailure`: failed fetch attempt from a source peer.
- `AuditFailure`: timeout, missing items, malformed response, or `AuditDigest` mismatch.
- `BootstrapClaimAbuse`: peer continues claiming bootstrap status after `BOOTSTRAP_CLAIM_GRACE_PERIOD` has elapsed since `BootstrapClaimFirstSeen`.

Rules:

1. Replication MUST emit failure evidence to the local `EigenTrust` subsystem; trust-score computation is out of scope for replication.
2. Replication MUST NOT apply threshold-based peer eviction; eviction/quarantine decisions are owned by `EigenTrust` policy.
3. A `ReplicationFailure` is emitted per peer per failed fetch attempt, not per key. If a key requires two retries from two different peers before succeeding on the third, each of the two failed peers emits one failure event.
4. Replication SHOULD mark fetch-failure evidence as stale/low-confidence if the key later succeeds via an alternate verified source.
5. On audit failure, replication MUST emit `AuditFailure` evidence with `challenge_id`, `challenged_peer_id`, and failure reason.
6. Replication MUST emit a trust-penalty signal to `EigenTrust` for audit failure when `RepairOpportunity(challenged_peer_id, PeerKeySet(challenged_peer_id))` is true.
7. On bootstrap claim past grace period, replication MUST emit `BootstrapClaimAbuse` evidence with `peer_id` and `BootstrapClaimFirstSeen` timestamp. Evidence is emitted on each sync or audit attempt where the peer claims bootstrapping after `BOOTSTRAP_CLAIM_GRACE_PERIOD`.
8. When a peer that previously claimed bootstrap status stops claiming it (responds normally to sync or audit), node MUST clear `BootstrapClaimFirstSeen(self, peer)`.
9. Final trust-score updates and any eventual peer eviction are determined by `EigenTrust`, not by replication logic.

## 15. Storage Audit Protocol (Anti-Outsourcing)

Challenge-response for claimed holders:

1. Challenger creates unique challenge id + nonce.
2. Challenger samples `SeedKeys` uniformly at random from locally stored record keys, with `|SeedKeys| = min(AUDIT_BATCH_SIZE, local_store_key_count)`. If local store is empty, the audit tick is idle.
3. For each `K` in `SeedKeys`, challenger performs one network closest-peer lookup and records the returned closest-peer set for `K`.
4. Challenger builds `CandidatePeers` as the union of returned peers across all sampled keys, then filters to `CandidatePeersRT = CandidatePeers ∩ LocalRT(self)`.
5. Challenger builds `PeerKeySet(P)` for each `P` in `CandidatePeersRT` as the subset of `SeedKeys` whose lookup result included `P`. This derivation MUST use only lookup results from step 3 (no additional lookup requests).
6. Challenger removes peers with empty `PeerKeySet(P)`. If no peers remain, the audit tick is idle.
7. Challenger selects one peer uniformly at random from remaining peers as `challenged_peer_id`.
8. Challenger sends that peer an ordered challenge key set equal to `PeerKeySet(challenged_peer_id)`.
9. Target responds with either an `AuditDigest` or a bootstrapping claim:
   a. `AuditDigest`: `H(nonce || challenged_peer_id || record_bytes_1 || ... || record_bytes_n)`, where `record_bytes_i` is the full raw bytes of challenged record `i` in challenge order.
   b. Bootstrapping claim: target asserts it is still bootstrapping. Challenger applies the bootstrap-claim grace logic (Section 6.2 rule 3b): record `BootstrapClaimFirstSeen` if first observation, accept without penalty within `BOOTSTRAP_CLAIM_GRACE_PERIOD`, emit `BootstrapClaimAbuse` evidence if past grace period. Audit tick ends (no `AuditDigest` verification).
10. On `AuditDigest` response, challenger recomputes expected `AuditDigest` from local copies and verifies equality before deadline.

Audit-proof requirements:

1. Challenger MUST hold a local copy of each challenged record to recompute `AuditDigest`. Audit selection is therefore limited to records the challenger stores.
2. Records are opaque bytes for replication; audit digest construction MUST operate over raw record bytes (no schema dependency) and be deterministic.
3. `AuditDigest` input MUST be exactly ordered concatenation: `nonce`, then challenged node public peer id (`challenged_peer_id`), then full bytes of each challenged record in challenge order.
4. `AuditDigest` MUST include full record bytes for every challenged record; key-only digests are invalid.
5. Nodes that advertise audit support MUST produce valid responses within `AUDIT_RESPONSE_TIMEOUT`.
6. Responses are invalid if the receiver cannot recompute `AuditDigest` from `nonce`, `challenged_peer_id`, and the challenged records' full bytes.

Audit challenge bound:

- Challenge size is dynamic per selected peer: `1 <= |PeerKeySet(challenged_peer_id)| <= AUDIT_BATCH_SIZE` when a challenge is issued.
- Worst-case challenge bytes are bounded because each record is max `4 MiB` (`<= AUDIT_BATCH_SIZE * 4 MiB`).

Failure conditions:

- Timeout, missing items, malformed response, or `AuditDigest` mismatch.
- Bootstrapping claim past `BOOTSTRAP_CLAIM_GRACE_PERIOD` (emits `BootstrapClaimAbuse`, not `AuditFailure`).

Audit trigger and target selection:

1. Node MUST NOT schedule storage-proof audits until `BootstrapDrained(self)` is true.
2. On the transition where `BootstrapDrained(self)` becomes true, node MUST execute one audit tick immediately.
3. After the immediate start tick, audit scheduler runs periodically at randomized `AUDIT_TICK_INTERVAL`.
4. Per tick, node MUST run the round-construction flow in steps 2-8 above (sample local keys, lookup closest peers, filter by `LocalRT(self)`, build per-peer key sets, then choose one random peer).
5. Node MUST NOT issue storage-proof audits to peers outside the round-construction output set for that tick.
6. If round construction yields no eligible peer, node records an idle audit tick and waits for the next tick (no forced random target).

## 16. New Node Bootstrap Logic

A joining node performs active sync:

1. Node MUST initiate peer discovery closest to its own address and wait until `LocalRT(self)` is at least partially populated before proceeding. Without a sufficiently populated routing table, the node cannot accurately evaluate `IsResponsible(self, K)`, `CloseGroup(K)`, or `PaidCloseGroup(K)`, which would cause incorrect admission decisions and quorum target selection during bootstrap.
2. Snapshot deterministic `NeighborSyncOrder(self)` from the populated `LocalRT(self)` for the bootstrap cycle.
3. Request replica hints (keys peers think self should hold) and paid hints (keys peers think self should track) in round-robin batches of up to `NEIGHBOR_SYNC_PEER_COUNT` peers at a time.
4. For each discovered key `K`, compute `QuorumTargets` as up to `CLOSE_GROUP_SIZE` nearest known peers for `K` (excluding self), and compute `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
5. Aggregate paid-list reports and add key `K` to local `PaidForList` only if paid reports are `>= ConfirmNeeded(K)`.
6. Aggregate key-presence reports and accept keys observed from `>= QuorumNeeded(K)` peers, or keys that are now paid-authorized locally. When a key meets presence quorum, also add `K` to local `PaidForList(self)` (close-group replica majority derives paid-list authorization per Section 7.2 rule 4).
7. Fetch accepted keys with bootstrap concurrency.
8. Fall back to normal concurrency after `BootstrapDrained(self)` is true.
9. Set `BootstrapDrained(self)=true` only when both conditions hold:
   - bootstrap peer requests from step 3 have all completed (response or timeout), and
   - bootstrap work queues are empty (`PendingVerify`, `FetchQueue`, `InFlightFetch` for bootstrap-discovered keys).
10. Transition `BootstrapDrained(self): false -> true` opens the audit start gate in Section 15.

This compresses quorum formation into one bootstrap round instead of waiting for multiple periodic cycles.

## 17. Logic-Risk Checklist (Pre-Implementation)

Use this list to find design flaws before coding:

1. Quorum deadlock risk:
   - Can strict admission + strict quorum prevent legitimate repair in sparse/partitioned states?
2. Bootstrap incompleteness:
   - If enough neighbor-sync peers are unavailable, is there a deterministic retry strategy?
3. Range oscillation (mitigated):
   - Pruning requires a key to be continuously out of range for `PRUNE_HYSTERESIS_DURATION` before deletion. This is time-based, not cycle-based, so pruning behavior is consistent regardless of routing-table size or cycle cadence. A single partition-and-heal event clears the timestamp and resets the clock.
4. Restart suppression false negatives:
   - Could real topology loss be suppressed too long?
5. Hint-set integrity:
   - How are duplicate keys, partial deliveries, and retries handled deterministically?
6. Neighbor-sync coverage:
   - Under sustained backlog/churn, do neighbor sync rounds still revisit all relevant keys within an acceptable bound?
7. Admission asymmetry:
   - Can temporary disagreement about `LocalRT` membership between honest nodes delay propagation?
8. Capacity fairness:
   - Can nearest-first plus finite capacity starve less-near but still responsible keys?
9. Audit bias:
   - Are audit targets selected fairly, or can adversaries avoid frequent challenge?
10. Failure attribution:
   - Could transient network issues create unfair `EigenTrust` penalties without sufficient dampening/evidence quality?
11. Paid-list poisoning:
   - Can colluding nodes in `PaidCloseGroup(K)` falsely mark unpaid keys as paid?
12. Paid-list cold-start (mitigated):
   - `PaidForList` is now persisted, surviving normal restarts. Close-group replica majority (Section 7.2 rule 4) provides a recovery path when persistence is corrupted or unavailable. Residual risk: keys below both presence quorum AND lost paid-list remain unrecoverable — accepted as explicit security-over-liveness tradeoff.

## 18. Pre-Implementation Test Matrix

Each scenario should assert exact expected outcomes and state transitions.

1. Fresh write happy path:
   - Valid PoP propagates to target holders without quorum check.
2. Fresh write invalid PoP:
   - Receiver rejects and does not enqueue fetch.
3. Neighbor-sync unknown key quorum pass:
   - Key transitions to stored through full state machine.
4. Neighbor-sync unknown key quorum fail:
   - Key transitions to `QuorumAbandoned` (then `Idle`) and is not fetched.
5. Unauthorized sync peer:
   - Hints from peers not in `LocalRT(self)` are dropped and do not enter verification.
6. Presence probe response shape:
   - Presence responses are only `Present` or `Absent`; there are no `RejectedUnauthorized`/`RejectedBusy` presence codes.
7. Out-of-range key hint:
   - Key rejected regardless of quorum.
8. Duplicate and retry safety:
   - Duplicate keys and repeated hints do not create invalid acceptance or duplicate queue/fetch work.
9. Fetch timeout with alternate source retry:
   - First source times out, key transitions to `FetchRetryable`, re-enters `QueuedForFetch` with next verified source, and succeeds. Verification is not re-run. Failed source receives one `ReplicationFailure`; successful alternate source clears stale failure attribution (rule 14.4).
10. Fetch retry exhaustion:
   - All verified sources fail or transport classifies failure as terminal. Key transitions to `FetchAbandoned`. Each failed source receives one `ReplicationFailure`.
11. Repeated confirmed failures:
   - Replication emits failure evidence and trust-penalty signals to `EigenTrust`; eviction decisions are made by `EigenTrust` policy rather than replication thresholds.
12. Bootstrap quorum aggregation:
   - Node accepts only keys meeting multi-peer threshold.
13. Responsible range shrink:
   - Out-of-range records have `OutOfRangeFirstSeen` recorded; they are pruned only after being continuously out of range for `>= PRUNE_HYSTERESIS_DURATION`. New in-range keys still accepted per capacity policy.
14. Neighbor-sync coverage under backlog:
   - Under load, each local key is eventually re-hinted within expected neighbor-sync timing bounds as round-robin peer batches rotate through `LocalRT(self)`.
15. Partition and heal:
   - Confirm below-quorum recovery succeeds when paid-list authorization survives, and fails when it cannot be re-established.
16. Quorum responder timeout handling:
   - No-response/timeouts are unresolved and can yield `QuorumInconclusive`, which is terminal for that offer lifecycle (`QuorumAbandoned` -> `Idle`).
17. Neighbor-sync admission asymmetry:
   - When two honest nodes temporarily disagree on `LocalRT` membership, hints are accepted only once sender is present in receiver `LocalRT`; before that, inbound sync is outbound-only at the receiver.
18. Invalid runtime config:
   - Node rejects configs violating parameter safety constraints.
19. Audit digest mismatch:
   - Challenge fails when `AuditDigest` mismatches, even if response format is syntactically valid; replication emits `AuditFailure` evidence and emits a trust-penalty signal to `EigenTrust` only when `RepairOpportunity(...)` is true.
20. Paid-list local hit:
   - Unknown key with local paid-list entry bypasses presence quorum and enters fetch pipeline.
21. Paid-list majority confirmation:
   - Unknown key not in local paid list is accepted only after `>= ConfirmNeeded(K)` confirmations from `PaidCloseGroup(K)`.
22. Paid-list rejection:
   - Unknown key is rejected when paid confirmations are below threshold and presence quorum also fails.
23. Paid-list cleanup after churn:
   - Node drops paid-list entries for keys where it is no longer in `PaidCloseGroup(K)`.
24. Fresh-replication paid-list propagation:
   - Freshly accepted key sends `PaidNotify` with PoP to all peers in current `PaidCloseGroup(K)` (fire-and-forget).
25. Paid-list convergence repair:
   - For a known paid key with incomplete `PaidCloseGroup(K)` coverage, nodes include `K` in `PaidHintsForPeer` during neighbor sync; receiver whitelists only after `>= ConfirmNeeded(K)` confirmations (no PoP in sync payloads).
26. Dynamic paid-list threshold in undersized consensus set:
   - With `PaidGroupSize(K)=8`, paid-list authorization requires `ConfirmNeeded(K)=5` confirmations (not 11).
27. Single-round dual-evidence verification:
   - For unknown key verification, implementation sends one request round to `VerifyTargets`; no second sequential quorum-probe round is issued after paid-list miss.
28. Dynamic quorum threshold in undersized verification set:
   - With `|QuorumTargets|=3`, unknown-key presence quorum requires `QuorumNeeded(K)=2` confirmations (not 4).
29. Audit start gate:
   - Node does not schedule audits before `BootstrapDrained(self)`; first audit tick fires immediately when `BootstrapDrained(self)` transitions to true.
30. Audit peer selection from sampled keys:
   - Scheduler samples up to `AUDIT_BATCH_SIZE` local keys, performs closest-peer lookups, filters peers by `LocalRT(self)`, builds `PeerKeySet` from those lookup results only, and selects one random peer to audit.
31. Audit periodic cadence with jitter:
   - Consecutive audit ticks occur on randomized intervals bounded by configured `AUDIT_TICK_INTERVAL` window.
32. Dynamic challenge size:
   - Challenged key count equals `|PeerKeySet(challenged_peer_id)|` and is dynamic per round; if no eligible peer remains after `LocalRT` filtering, the tick is idle and no audit is sent.
33. Batched unknown-key verification:
   - When multiple unknown keys share a target peer, implementation MUST send one batched verification request (not separate per-key requests); responses must still be keyed per key with binary presence semantics (and paid-list presence where applicable).
34. Batched partial response semantics:
   - If a batched response omits key `K` or a peer times out, evidence for that peer/key pair is unresolved for `K` and does not count as an explicit negative vote.
35. Neighbor-sync round-robin batch selection with cooldown skip:
   - With more than `NEIGHBOR_SYNC_PEER_COUNT` eligible peers, consecutive rounds scan forward from cursor, skip and remove cooldown peers, and sync the next batch of up to `NEIGHBOR_SYNC_PEER_COUNT` non-cooldown peers. Cycle completes when all snapshot peers have been synced, skipped (cooldown), or removed (unreachable).
36. Post-cycle responsibility pruning with time-based hysteresis:
   - When a full neighbor-sync round-robin cycle completes, node runs one prune pass using current `SelfInclusiveRT(self)` (`LocalRT(self) ∪ {self}`): stored keys with `IsResponsible(self, K)=false` have `OutOfRangeFirstSeen` recorded (if not already set) but are deleted only when `now - OutOfRangeFirstSeen >= PRUNE_HYSTERESIS_DURATION`. Keys that are in range have their `OutOfRangeFirstSeen` cleared. Same logic applies to `PaidForList` entries where `self ∉ PaidCloseGroup(K)`.
37. Non-`LocalRT` inbound sync behavior:
   - If a peer opens sync while not in receiver `LocalRT(self)`, receiver may still send hints to that peer, but receiver drops all inbound replica/paid hints from that peer.
38. Neighbor-sync snapshot stability under peer join:
   - Peer `P` joins `LocalRT(self)` mid-cycle. `P` does not appear in the current `NeighborSyncOrder(self)` snapshot. After cycle completes and a new snapshot is taken, `P` is included in the next cycle's ordering.
39. Neighbor-sync unreachable peer removal and slot fill:
   - Peer `P` is in the snapshot. Sync attempt with `P` fails (unreachable). `P` is removed from `NeighborSyncOrder(self)`. Node resumes scanning from where batch selection left off and picks the next available peer `Q` to fill the slot. `P` is not in the next cycle's snapshot (unless it has rejoined `LocalRT`).
40. Neighbor-sync per-peer cooldown skip:
   - Peer `P` was successfully synced in a prior round and is still within `NEIGHBOR_SYNC_COOLDOWN`. When batch selection reaches `P`, it is removed from `NeighborSyncOrder(self)` and scanning continues to the next peer. `P` does not consume a batch slot.
41. Neighbor-sync cycle completion is guaranteed:
   - Under arbitrary churn, cooldowns, and unreachable peers, the cycle always terminates because the snapshot can only shrink (removals) and the cursor advances monotonically. Cycle completes when `NeighborSyncCursor >= |NeighborSyncOrder|`.
42. Quorum-derived paid-list authorization:
   - Unknown key `K` passes presence quorum (`>= QuorumNeeded(K)` positives from `CloseGroup(K)`). Key is stored AND added to local `PaidForList(self)`. Node subsequently answers paid-list queries for `K` as "paid."
43. Paid-list persistence across restart:
   - Node stores key `K` in `PaidForList`, restarts. After restart, `PaidForList` is loaded from stable storage and node correctly answers paid-list queries for `K` without re-verification.
44. Paid-list cold-start recovery via replica majority:
   - Multiple nodes restart simultaneously and lose `PaidForList` (persistence corrupted). Key `K` has `>= QuorumNeeded(K)` replicas in the close group. During neighbor-sync verification, presence quorum passes and all verifying nodes re-derive `K` into their `PaidForList` via close-group replica majority.
45. Paid-list unrecoverable below quorum:
   - Key `K` has only 1 replica (below quorum) and `PaidForList` is lost across all `PaidCloseGroup(K)` members. Key cannot be recovered via either presence quorum or paid-list majority — accepted as explicit security-over-liveness tradeoff.
46. Bootstrap claim within grace period (sync):
   - Peer `P` responds with bootstrapping claim during sync. Node records `BootstrapClaimFirstSeen(self, P)`. `P` is removed from `NeighborSyncOrder(self)` and slot is filled from next peer. No penalty emitted.
47. Bootstrap claim within grace period (audit):
   - Challenged peer responds with bootstrapping claim during audit. Node records `BootstrapClaimFirstSeen`. Audit tick ends without `AuditFailure`. No penalty emitted.
48. Bootstrap claim abuse after grace period:
   - Peer `P` first claimed bootstrapping 25 hours ago (`> BOOTSTRAP_CLAIM_GRACE_PERIOD`). On next sync or audit attempt where `P` still claims bootstrapping, node emits `BootstrapClaimAbuse` evidence to `EigenTrust` with `peer_id` and `BootstrapClaimFirstSeen` timestamp.
49. Bootstrap claim cleared on normal response:
   - Peer `P` previously claimed bootstrapping. `P` later responds normally to a sync or audit request. Node clears `BootstrapClaimFirstSeen(self, P)`. No residual penalty tracking.
50. Prune hysteresis prevents premature deletion:
   - Key `K` goes out of range at time `T`. `OutOfRangeFirstSeen(self, K)` is set to `T`. Key is NOT deleted. At `T + 3h` (less than `PRUNE_HYSTERESIS_DURATION`), key is still retained. At `T + 6h` (`>= PRUNE_HYSTERESIS_DURATION`), key is deleted on the next prune pass.
51. Prune hysteresis timestamp reset on partition heal:
   - Key `K` goes out of range at time `T`. `OutOfRangeFirstSeen` is set to `T`. At `T + 4h`, partition heals, peers return, `K` is back in range. `OutOfRangeFirstSeen` is cleared. Key is retained. If `K` later goes out of range again, the clock restarts from zero.
52. Prune hysteresis applies to paid-list entries:
   - `PaidForList` entry for key `K` where `self ∉ PaidCloseGroup(K)` follows the same time-based hysteresis: `OutOfRangeFirstSeen` is recorded, entry deleted only when `now - OutOfRangeFirstSeen >= PRUNE_HYSTERESIS_DURATION`, timestamp cleared if `self` re-enters `PaidCloseGroup(K)`.

## 19. Acceptance Criteria for This Design

The design is logically acceptable for implementation when:

1. All invariants in Section 5 can be expressed as executable assertions.
2. Every scenario in Section 18 has deterministic pass/fail expectations.
3. Security-over-liveness tradeoffs are explicitly accepted by stakeholders.
4. Parameter sensitivity (especially, quorum, `PAID_LIST_*`, and suppression windows) has been reviewed with failure simulations.
5. Audit-proof digest requirements are implemented and test-validated.
