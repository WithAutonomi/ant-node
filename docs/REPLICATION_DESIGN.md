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
- `LocalRT(N)`: node `N`'s current authenticated local routing-table peer set.
- `NeighborSyncSet(N)`: up to `NEIGHBOR_SYNC_PEER_COUNT` peers nearest to node `N` in `LocalRT(N)`; periodic repair sync partners for `N`.
- `Record`: immutable, content-addressed data unit with key `K`.
- `Distance(K, N)`: deterministic distance metric between key and node identity.
- `CloseGroup(K)`: the `CLOSE_GROUP_SIZE` nearest nodes to key `K`.
- `IsResponsible(N, K)`: true if `N` is among the `CLOSE_GROUP_SIZE` nearest nodes to `K` in `LocalRT(N) ∪ {N}`.
- `Holder`: node that stores a valid copy of a record.
- `PoP`: verifiable proof that a record was authorized for initial storage/payment policy.
- `PaidNotify(K)`: fresh-replication paid-list notification carrying key `K` plus PoP/payment proof material needed for receiver-side verification and whitelisting.
- `PaidForList(N)`: in-memory set of keys node `N` currently believes are paid-authorized.
- `PaidCloseGroup(K)`: `PAID_LIST_CLOSE_GROUP_SIZE` nearest nodes to key `K` that participate in paid-list consensus.
- `PaidGroupSize(K)`: effective paid-list consensus set size for key `K`, defined as `|PaidCloseGroup(K)|`.
- `ConfirmNeeded(K)`: dynamic paid-list confirmation count for key `K`, defined as `floor(PaidGroupSize(K)/2)+1`.
- `QuorumNeeded(K)`: effective presence confirmation count for key `K`, defined as `min(QUORUM_THRESHOLD, floor(|QuorumTargets(K)|/2)+1)`.

## 4. Tunable Parameters

All parameters are configurable. Values below are a reference profile used for logic validation.

| Parameter | Meaning | Reference                           |
|---|---|-------------------------------------|
| `CLOSE_GROUP_SIZE` | Close-group width and target holder count per key | `7`                                 |
| `QUORUM_THRESHOLD` | Full-network target for required positive presence votes (effective per-key threshold is `QuorumNeeded(K)`) | `floor(CLOSE_GROUP_SIZE/2)+1` (`4`) |
| `PAID_LIST_CLOSE_GROUP_SIZE` | Maximum number of closest nodes tracking paid status for a key | `20`                                |
| `NEIGHBOR_SYNC_PEER_COUNT` | Number of closest local-RT peers synced per repair round | `20`                                |
| `NEIGHBOR_SYNC_INTERVAL` | Neighbor sync cadence | random in `[10m, 20m]`              |
| `NEIGHBOR_SYNC_COOLDOWN` | Min spacing between neighbor sync rounds | `1h`                                |
| `QUORUM_RETRY_BACKOFF` | Retry delay before repeating a previously rejected/failed hint path | `60s`                               |
| `MAX_PARALLEL_FETCH_BOOTSTRAP` | Bootstrap concurrent fetches | `20`                                |
| `AUDIT_STARTUP_GRACE` | Delay after bootstrap completion before audit scheduling can start | `5 min`                             |
| `AUDIT_TICK_INTERVAL` | Audit scheduler cadence | random in `[5 min, 10 min]`         |
| `AUDIT_BATCH_SIZE` | Max local keys sampled per audit round (also max challenge items) | `8`                                 |
| `AUDIT_RESPONSE_TIMEOUT` | Audit response deadline | `5s`                                |
| `BAD_NODE_WINDOW` | Window for failure counting | `5 min`                             |
| `BAD_NODE_THRESHOLD` | Failures needed for eviction | `3`                                 |

Parameter safety constraints (MUST hold):

1. `1 <= QUORUM_THRESHOLD <= CLOSE_GROUP_SIZE`.
2. Effective paid-list authorization threshold is per-key dynamic: `ConfirmNeeded(K) = floor(PaidGroupSize(K)/2)+1`.
3. If constraints are violated at runtime reconfiguration, node MUST reject the config and keep the previous valid config.

## 5. Core Invariants (Must Hold)

1. A record is accepted only if it passes integrity and responsibility checks.
2. Neighbor-sync repair traffic passes verification only if either condition holds: paid confirmations `>= ConfirmNeeded(K)` across `PaidCloseGroup(K)`, or presence positives `>= QuorumNeeded(K)`.
3. Fresh replication bypasses presence quorum only when PoP is valid.
4. Neighbor-sync hints from non-`NeighborSyncSet(self)` peers are dropped.
5. Presence probes return only binary key-presence evidence (`Present` or `Absent`).
6. `CLOSE_GROUP_SIZE` is both the close-group width and the target holder count, not guaranteed send fanout.
7. Receiver stores only records in its current responsible range.
8. Queue dedup prevents duplicate pending/fetch work for same key.
9. Bad-node decisions are local-only (no gossip reputation).
10. Security policy is explicit: anti-injection may sacrifice recovery of below-quorum non-PoP data.
11. Every neighbor-sync hint exchange reaches a deterministic terminal state.
12. Presence no-response/timeout is unresolved (neutral), not an explicit negative vote.
13. A failed fetch retries from alternate verified sources before abandoning. Verification evidence is preserved across fetch retries.
14. Paid-list authorization is key-scoped and majority-based across `PaidCloseGroup(K)`, not node-global.
15. `PaidForList(N)` is memory-bounded: node `N` tracks only keys for which `N` is in `PaidCloseGroup(K)` (plus short-lived transition slack).
16. Fresh-replication paid-list propagation is mandatory: sender MUST attempt `PaidNotify(K)` delivery to every peer in `PaidCloseGroup(K)` (reference profile: up to 20 peers when available), not a subset.
17. A `PaidNotify(K)` only whitelists key `K` after receiver-side proof verification succeeds; sender assertions never whitelist by themselves.
18. Neighbor-sync paid hints are non-authoritative and carry no PoP; receivers MUST only whitelist by paid-list majority verification (`>= ConfirmNeeded(K)`), never by hint claims alone.
19. Storage-proof audits start only after bootstrap completion plus `AUDIT_STARTUP_GRACE`.
20. Storage-proof audits target only peers derived from closest-peer lookups for sampled local keys and filtered through local authenticated routing state (`LocalRT(self)`); random global peers are never audited.
21. Verification-request batching is mandatory for unknown-key neighbor-sync verification and preserves per-key quorum semantics: each key receives explicit per-key evidence, and missing/timeout evidence is unresolved per key.

## 6. Replication Modes

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

1. Node computes `NeighborSyncSet(self)` as the up to `NEIGHBOR_SYNC_PEER_COUNT` closest peers to self from `LocalRT(self)`.
2. Node initiates a bidirectional sync session with each peer in `NeighborSyncSet(self)` (or responds if peer initiated first).
3. In each session, both sides send peer-targeted hint sets:
   - `ReplicaHintsForPeer`: keys the sender believes the receiver should hold (`receiver ∈ CloseGroup(K)` in sender view).
   - `PaidHintsForPeer`: keys the sender believes the receiver should track in `PaidForList` (`receiver ∈ PaidCloseGroup(K)` in sender view).
4. Transport-level chunking/fragmentation is implementation detail and out of scope for replication logic.
5. Receiver treats hint sets as unordered collections and deduplicates repeated keys.
6. Receiver diffs replica hints against local store and pending sets, then runs per-key admission rules before quorum logic.
7. Receiver launches quorum checks exactly once per admitted unknown replica key.
8. Replica keys passing presence quorum or paid-list authorization are queued for fetch.
9. Receiver processes unknown paid hints via Section 7.2 majority checks; paid hints never directly whitelist keys.
10. Sync payloads MUST NOT include PoP material; PoP remains fresh-replication-only.
11. Nodes SHOULD use ongoing neighbor sync rounds to re-announce paid hints for locally paid keys to improve paid-list convergence.

Rate control:

- Skip neighbor sync if `NEIGHBOR_SYNC_COOLDOWN` not elapsed.

## 7. Authorization and Admission Rules

### 7.1 Neighbor-Sync Hint Admission (Per Key)

For each hinted key `K`, receiver accepts the hint into verification only if both conditions hold:

1. Sender is authenticated and currently in `NeighborSyncSet(self)`.
2. Key is relevant to the receiver:
   - Replica hint: receiver is currently responsible (`IsResponsible(self, K)`) or key already exists in local store/pending pipeline.
   - Paid hint: receiver is currently in `PaidCloseGroup(K)` (or key is already in local `PaidForList` pending cleanup).

Notes:

- Authorization decision is local-route-state only.
- Hints from non-neighbor-sync peers are dropped immediately.
- Mixed hint sets are valid: process admitted keys, drop non-admitted keys.
- Receiver MAY return rejected-key metadata to help sender avoid repeating obviously invalid hints; sender SHOULD apply `QUORUM_RETRY_BACKOFF` before repeating the same rejected path.

### 7.2 Paid-List Authorization (Per Key)

When handling an admitted unknown key `K` from neighbor sync:

1. If `K` is already in local `PaidForList`, paid-list authorization succeeds immediately.
2. Otherwise run the single verification round defined in Section 9 and collect paid-list responses from peers in `PaidCloseGroup(K)` (same round as presence evidence; no separate paid-list-only round).
3. If paid confirmations from `PaidCloseGroup(K)` are `>= ConfirmNeeded(K)`, add `K` to local `PaidForList`, treat `K` as paid-authorized, and record any peers that also report current presence as fetch candidates.
4. If confirmations are below threshold, paid-list authorization fails for this verification round.
5. Nodes answering paid-list queries MUST answer from local paid-list state only; they MUST NOT infer paid status from record presence alone.
6. If a node learns `K` is paid-authorized by majority, it SHOULD include `K` in outbound `PaidHintsForPeer` for relevant neighbors so peers can re-check and converge.
7. Unknown paid hints that fail majority confirmation are dropped for this lifecycle and require a new hint/session to re-enter.

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
- `PendingVerify -> QuorumVerified` only if presence positives from the current verification round reach `>= QuorumNeeded(K)`. On success, record the set of positive responders as verified fetch sources.
- `PendingVerify -> PaidListVerified` only if paid confirmations from the same verification round reach `>= ConfirmNeeded(K)`. On success, mark key as paid-authorized locally and record fetch candidates from positive presence hints and/or hint sender.
- `PendingVerify -> QuorumInconclusive` when neither quorum nor paid-list success is reached and unresolved outcomes (timeout/no-response) keep both outcomes undecidable in this round.
- `Fetching -> Stored` only after all storage validation checks pass.
- `Fetching -> FetchRetryable` when fetch fails (timeout, corrupt response, connection error), the transport classifies the attempt as retryable, and at least one untried verified source remains. Mark the failed source as tried so it is not selected again.
- `Fetching -> FetchAbandoned` when fetch fails and either the transport classifies failure as terminal or all verified sources have been tried. Record a `ReplicationFailure` against the failed source(s).
- `FetchRetryable -> QueuedForFetch` selects the next untried verified source and re-enters the fetch queue without repeating quorum verification.
- `QuorumFailed -> QuorumAbandoned` is immediate and terminal for this offer lifecycle. Key is forgotten and stops consuming probe resources. Requires a new offer to re-enter the pipeline.
- `QuorumInconclusive -> QuorumAbandoned` is immediate and terminal for this offer lifecycle. Requires a new offer to re-enter the pipeline.

## 9. Quorum Verification Logic

For each unknown key:

1. Deduplicate key in pending-verification table.
2. If `K` is already in local `PaidForList`, mark `PaidListVerified` and queue for fetch immediately (no network verification round required).
3. Otherwise compute `PaidTargets = PaidCloseGroup(K)`.
4. Compute `QuorumTargets` as up to `CLOSE_GROUP_SIZE` nearest known peers for `K` (including self).
5. Compute `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
6. Compute `VerifyTargets = PaidTargets ∪ QuorumTargets`.
7. Send verification requests to peers in `VerifyTargets` and continue the round until either success/fail-fast is reached or a local adaptive verification deadline for this round expires. Responses carry binary presence semantics (Section 7.6); peers in `PaidTargets` also return paid-list presence for `K`.
8. Mark `PaidListVerified` and queue for fetch as soon as paid confirmations from `PaidTargets` reach `>= ConfirmNeeded(K)`.
9. Mark `QuorumVerified` and queue for fetch as soon as presence positives from `QuorumTargets` reach `>= QuorumNeeded(K)`.
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

A node `N` is responsible for key `K` if `IsResponsible(N, K)` holds — that is, `N` is among the `CLOSE_GROUP_SIZE` nearest nodes to `K` in `LocalRT(N) ∪ {N}`.

This check is evaluated per-key at decision points:

1. Accept/reject incoming replication writes.
2. Background pruning eligibility (prune stored records where node is no longer responsible).
3. Paid-list retention eligibility (drop `PaidForList` entries for keys where node is no longer in `PaidCloseGroup(K)`).

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

Capacity-managed mode (finite store):

1. If full and new in-range key arrives, evict farthest out-of-range key if available.
2. If no out-of-range key exists, reject new key.
3. Periodically prune keys that moved out of responsibility.
4. `PaidForList` is in-memory only and SHOULD be bounded with paging/eviction policies; keys outside `PaidCloseGroup(K)` are first candidates for removal.

## 13. Churn and Topology Change Handling

Maintain tracker for closest peers and classify topology events:

- `Trigger`: genuine change, run neighbor sync.
- `Skip`: probable restart churn, suppress.
- `Ignore`: far peers, no action.

Goal: avoid replication storms from restart noise while still reacting to real topology shifts.

## 14. Bad Node Detection and Eviction

Failure events include:

- Fetch timeout failures.
- Audit failures (timeout, missing items, malformed response, or `AuditDigest` mismatch).

Rules:

1. Track failures per peer over rolling `BAD_NODE_WINDOW`.
2. Evict peer at `BAD_NODE_THRESHOLD` failures.
3. Purge pending work assigned to evicted peer.
4. Do not penalize stale failures if key already succeeded via another source (including via fetch retry from an alternate holder).
5. Never gossip reputation; eviction is local.
6. A `ReplicationFailure` is recorded per peer per failed fetch attempt, not per key. If a key requires two retries from two different peers before succeeding on the third, each of the two failed peers receives one failure event.

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
9. Target computes and returns one `AuditDigest` as `H(nonce || challenged_peer_id || record_bytes_1 || ... || record_bytes_n)`, where `record_bytes_i` is the full raw bytes of challenged record `i` in challenge order.
10. Challenger recomputes expected `AuditDigest` from local copies and verifies equality before deadline.

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

Audit trigger and target selection:

1. Node MUST NOT schedule storage-proof audits until bootstrap is complete and `AUDIT_STARTUP_GRACE` has elapsed since bootstrap completion.
2. Audit scheduler runs periodically at randomized `AUDIT_TICK_INTERVAL` (reference profile: jittered in `[5 min, 10 min]`).
3. Per tick, node MUST run the round-construction flow in steps 2-8 above (sample local keys, lookup closest peers, filter by `LocalRT(self)`, build per-peer key sets, then choose one random peer).
4. Node MUST NOT issue storage-proof audits to peers outside the round-construction output set for that tick.
5. If round construction yields no eligible peer, node records an idle audit tick and waits for the next tick (no forced random target).

## 16. New Node Bootstrap Logic

A joining node performs active sync:

1. Discover up to `NEIGHBOR_SYNC_PEER_COUNT` closest peers to self from `LocalRT(self)`.
2. Request replica hints (keys peers think self should hold) and paid hints (keys peers think self should track) from those peers.
3. For each discovered key `K`, compute `QuorumTargets` as up to `CLOSE_GROUP_SIZE` nearest known peers for `K` (excluding self), and compute `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
4. Aggregate paid-list reports and add key `K` to local `PaidForList` only if paid reports are `>= ConfirmNeeded(K)`.
5. Aggregate key-presence reports and accept keys observed from `>= QuorumNeeded(K)` peers, or keys that are now paid-authorized locally.
6. Fetch accepted keys with bootstrap concurrency.
7. Fall back to normal concurrency after bootstrap drains.

This compresses quorum formation into one bootstrap round instead of waiting for multiple periodic cycles.

## 17. Logic-Risk Checklist (Pre-Implementation)

Use this list to find design flaws before coding:

1. Quorum deadlock risk:
   - Can strict admission + strict quorum prevent legitimate repair in sparse/partitioned states?
2. Bootstrap incompleteness:
   - If enough neighbor-sync peers are unavailable, is there a deterministic retry strategy?
3. Range oscillation:
   - Can rapid responsible-range shifts cause thrash (store/prune/store loops)?
4. Restart suppression false negatives:
   - Could real topology loss be suppressed too long?
5. Hint-set integrity:
   - How are duplicate keys, partial deliveries, and retries handled deterministically?
6. Neighbor-sync coverage:
   - Under sustained backlog/churn, do neighbor sync rounds still revisit all relevant keys within an acceptable bound?
7. Admission asymmetry:
   - Can two honest nodes disagree on neighbor-sync membership enough to delay propagation?
8. Capacity fairness:
   - Can nearest-first plus finite capacity starve less-near but still responsible keys?
9. Audit bias:
   - Are audit targets selected fairly, or can adversaries avoid frequent challenge?
10. Failure attribution:
   - Could transient network issues misclassify healthy peers as bad without dampening?
11. Paid-list poisoning:
   - Can colluding nodes in `PaidCloseGroup(K)` falsely mark unpaid keys as paid?
12. Paid-list cold-start:
   - After broad restart, can paid-list snapshots be rebuilt deterministically before churn repair starts?

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
   - Hints from non-`NeighborSyncSet(self)` peer are dropped and do not enter verification.
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
11. Repeated true source failures:
   - Peer evicted exactly at threshold behavior.
12. Bootstrap quorum aggregation:
   - Node accepts only keys meeting multi-peer threshold.
13. Responsible range shrink:
   - Out-of-range records become prune candidates; new in-range keys still accepted per capacity policy.
14. Neighbor-sync coverage under backlog:
   - Under load, each local key is eventually re-hinted within expected neighbor-sync timing bounds.
15. Partition and heal:
   - Confirm below-quorum recovery succeeds when paid-list authorization survives, and fails when it cannot be re-established.
16. Quorum responder timeout handling:
   - No-response/timeouts are unresolved and can yield `QuorumInconclusive`, which is terminal for that offer lifecycle (`QuorumAbandoned` -> `Idle`).
17. Neighbor-sync admission asymmetry:
   - When two honest nodes temporarily disagree on `NeighborSyncSet` membership, propagation resumes after topology refresh without relaxing admission policy.
18. Invalid runtime config:
   - Node rejects configs violating parameter safety constraints.
19. Audit digest mismatch:
   - Challenge fails when `AuditDigest` mismatches, even if response format is syntactically valid.
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
   - Node does not schedule audits before `bootstrap_complete + AUDIT_STARTUP_GRACE`.
30. Audit peer selection from sampled keys:
   - Scheduler samples up to `AUDIT_BATCH_SIZE` local keys, performs closest-peer lookups, filters peers by `LocalRT(self)`, builds `PeerKeySet` from those lookup results only, and selects one random peer to audit.
31. Audit periodic cadence with jitter:
   - Consecutive audit ticks occur on randomized intervals bounded by configured `AUDIT_TICK_INTERVAL` window (`5-10 min` in reference profile).
32. Dynamic challenge size:
   - Challenged key count equals `|PeerKeySet(challenged_peer_id)|` and is dynamic per round; if no eligible peer remains after `LocalRT` filtering, the tick is idle and no audit is sent.
33. Batched unknown-key verification:
   - When multiple unknown keys share a target peer, implementation MUST send one batched verification request (not separate per-key requests); responses must still be keyed per key with binary presence semantics (and paid-list presence where applicable).
34. Batched partial response semantics:
   - If a batched response omits key `K` or a peer times out, evidence for that peer/key pair is unresolved for `K` and does not count as an explicit negative vote.

## 19. Acceptance Criteria for This Design

The design is logically acceptable for implementation when:

1. All invariants in Section 5 can be expressed as executable assertions.
2. Every scenario in Section 18 has deterministic pass/fail expectations.
3. Security-over-liveness tradeoffs are explicitly accepted by stakeholders.
4. Parameter sensitivity (especially, quorum, `PAID_LIST_*`, and suppression windows) has been reviewed with failure simulations.
5. Audit-proof digest requirements are implemented and test-validated.
