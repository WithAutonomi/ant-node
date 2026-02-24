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
- `Record`: immutable, content-addressed data unit with key `K`.
- `Distance(K, N)`: deterministic distance metric between key and node identity.
- `CloseGroup(K)`: the `CLOSE_GROUP_SIZE` nearest nodes to key `K`.
- `Holder`: node that stores a valid copy of a record.
- `PoP`: verifiable proof that a record was authorized for initial storage/payment policy.
- `PaidNotify(K)`: Tier 1 paid-list notification carrying key `K` plus PoP/payment proof material needed for receiver-side verification and whitelisting.
- `PaidForList(N)`: in-memory set of keys node `N` currently believes are paid-authorized.
- `ClosestX(K)`: `PAID_LIST_CLOSEST_X` nearest nodes to key `K` that participate in paid-list consensus.
- `X_eff(K)`: effective paid-list consensus set size for key `K`, defined as `|ClosestX(K)|`.
- `ConfirmNeeded(K)`: dynamic paid-list confirmation count for key `K`, defined as `floor(X_eff(K)/2)+1`.
- `QuorumNeeded(K)`: effective presence confirmation count for key `K`, defined as `min(QUORUM_THRESHOLD, floor(|QuorumTargets(K)|/2)+1)`.

## 4. Tunable Parameters

All parameters are configurable. Values below are a reference profile used for logic validation.

| Parameter | Meaning | Reference |
|---|---|---|
| `CLOSE_GROUP_SIZE` | Close-group width | `7` |
| `REPLICATION_FACTOR` | Target holder count per key | `7` |
| `QUORUM_THRESHOLD` | Full-network target for required positive presence votes (effective per-key threshold is `QuorumNeeded(K)`) | `floor(REPLICATION_FACTOR/2)+1` (`4`) |
| `PAID_LIST_CLOSEST_X` | Maximum number of closest nodes tracking paid status for a key | `20` |
| `PAID_LIST_CONFIRM_THRESHOLD` | Legacy reference value for full-size paid-list set; effective per-key threshold is `ConfirmNeeded(K)` | `11` (when `X_eff(K)=20`) |
| `K_AUTH_OFFER` | Offer auth window (per key) | `12` |
| `QUORUM_PROBE_FANOUT` | Peers queried per key during unknown-key verification round | `12` |
| `TIER2_INTERVAL` | Neighbor sync cadence | random in `[90s, 180s]` |
| `TIER3_INTERVAL` | Global verification cadence | `15 min` |
| `GLOBAL_REPL_COOLDOWN` | Min spacing between Tier 2 runs | `30s` |
| `PER_TARGET_DEDUP` | Min spacing for same sender->target replication | `45s` |
| `RESTART_SUPPRESSION` | Rejoin suppression window | `90s` |
| `MAX_FETCH_RETRIES` | Max alternate-source fetch attempts per quorum pass | `2` |
| `FETCH_TIMEOUT` | Per-record fetch timeout | `20s` |
| `PENDING_TIMEOUT` | Max queue residency | `15 min` |
| `QUORUM_RESPONSE_TIMEOUT` | Presence probe wait budget | `3s` |
| `QUORUM_RETRY_BACKOFF` | Retry delay for non-quorum sender retry paths (e.g., `AuthHint`) | `60s` |
| `MAX_PARALLEL_FETCH` | Normal concurrent fetches | `5` |
| `MAX_PARALLEL_FETCH_BOOTSTRAP` | Bootstrap concurrent fetches | `20` |
| `MAX_PARALLEL_QUORUM_CHECKS` | Concurrent quorum checks | `16` |
| `NETWORK_CYCLE_DEADLINE` | Max time to re-check all records | `4 days` |
| `AUDIT_STARTUP_GRACE` | Delay after bootstrap completion before audit scheduling can start | `5 min` |
| `AUDIT_TICK_INTERVAL` | Audit scheduler cadence | random in `[5 min, 10 min]` |
| `AUDIT_BATCH_SIZE` | Max local keys sampled per audit round (also max challenge items) | `8` |
| `AUDIT_RESPONSE_TIMEOUT` | Audit response deadline | `5s` |
| `BAD_NODE_WINDOW` | Window for failure counting | `5 min` |
| `BAD_NODE_THRESHOLD` | Failures needed for eviction | `3` |

Parameter safety constraints (MUST hold):

1. `1 <= QUORUM_THRESHOLD <= REPLICATION_FACTOR`.
2. `QUORUM_THRESHOLD <= QUORUM_PROBE_FANOUT`.
3. `QUORUM_PROBE_FANOUT >= CLOSE_GROUP_SIZE`.
5. Effective paid-list authorization threshold is per-key dynamic: `ConfirmNeeded(K) = floor(X_eff(K)/2)+1`.
6. If constraints are violated at runtime reconfiguration, node MUST reject the config and keep the previous valid config.

## 5. Core Invariants (Must Hold)

1. A record is accepted only if it passes integrity and responsibility checks.
2. Tier 2 and Tier 3 repair traffic requires either receiver-side presence quorum success or paid-list authorization success before fetch.
3. Tier 1 bypasses presence quorum only when PoP is valid.
4. Unauthorized offer keys are dropped per key (not per message).
5. Presence probes return only binary key-presence evidence (`Present` or `Absent`).
6. `REPLICATION_FACTOR` is a target holder count, not guaranteed send fanout.
7. Receiver stores only records in its current responsible range.
8. Queue dedup prevents duplicate pending/fetch work for same key.
9. Bad-node decisions are local-only (no gossip reputation).
10. Global replication prioritizes low-observed-replica records first.
11. Security policy is explicit: anti-injection may sacrifice recovery of below-quorum non-PoP data.
12. Every Tier 2 offer exchange reaches a deterministic terminal state.
13. Presence no-response/timeout is unresolved (neutral), not an explicit negative vote.
14. A failed fetch retries from alternate verified sources before abandoning. Verification evidence is preserved across fetch retries.
15. Paid-list authorization is key-scoped and majority-based across `ClosestX(K)`, not node-global.
16. `PaidForList(N)` is memory-bounded: node `N` tracks only keys for which `N` is in `ClosestX(K)` (plus short-lived transition slack).
17. Tier 1 paid-list propagation is mandatory: sender MUST attempt `PaidNotify(K)` delivery to every peer in `ClosestX(K)` (reference profile: up to 20 peers when available), not a subset.
18. A `PaidNotify(K)` only whitelists key `K` after receiver-side proof verification succeeds; sender assertions never whitelist by themselves.
19. Paid-list convergence is maintained continuously: nodes that know key `K` is paid MUST help repair missing `PaidForList` entries across all peers in `ClosestX(K)` until full coverage is restored or the key leaves maintenance scope.
20. Storage-proof audits start only after bootstrap completion plus `AUDIT_STARTUP_GRACE`, and only after at least one responsible-range computation has completed.
21. Storage-proof audits target only peers derived from closest-peer lookups for sampled local keys and filtered through local authenticated routing state (`LocalRT(self)`); random global peers are never audited.

## 6. Replication Tiers

### Tier 1: Fresh Propagation (Immediate)

Trigger: node accepts a newly written record with valid PoP.

Rules:

1. Store locally after normal validation.
2. Compute holder target set for the key with size `REPLICATION_FACTOR`.
3. Send fresh offers to remote target members only.
4. Fresh offer MUST include PoP.
5. Receiver MUST reject fresh path if PoP is missing or invalid.
6. Fresh path MAY bypass normal fetch queue limits for low-latency propagation.
7. A node that validates PoP for key `K` MUST add `K` to `PaidForList(self)`.
8. In parallel with chunk propagation, sender MUST send `PaidNotify(K)` to every member of `ClosestX(K)` and include proof material sufficient for independent receiver verification.
9. Sender MUST track per-peer `PaidNotify(K)` acknowledgment state for the current propagation pass and attempt each peer in `ClosestX(K)` once per pass (no immediate retry loop).
10. Completion of paid-list propagation for a pass is defined per key as `acked_count == X_eff(K)`.

### Tier 2: Neighbor Anti-Entropy (Periodic + Topology Events)

Triggers:

- Periodic randomized timer.
- Topology changes that are not suppressed as restart noise.

Rules:

1. Sender enumerates local keys.
2. For each key, sender computes holder target set and selects remote members.
3. Sender transmits one logical offer set of keys to each target for the sync run.
4. Transport-level chunking/fragmentation is implementation detail and out of scope for replication logic.
5. Receiver treats the offer set as an unordered key collection and deduplicates repeated keys.
6. Receiver diffs offered keys against local store and pending sets.
7. Receiver runs per-key admission rules before quorum logic.
8. Receiver launches quorum checks exactly once per admitted unknown key in the offer set.
9. Keys passing presence quorum or paid-list authorization are queued for fetch.
10. During Tier 2 runs, nodes SHOULD also execute paid-list convergence maintenance for locally known paid keys by repairing missing `PaidForList` entries in `ClosestX(K)`.

Rate control:

- Skip Tier 2 if `GLOBAL_REPL_COOLDOWN` not elapsed.
- Do not send to same target within `PER_TARGET_DEDUP`.
- Suppress triggers from remove+quick-readd patterns within `RESTART_SUPPRESSION`.

### Tier 3: Global Verification and Repair (Proactive)

Trigger: periodic timer (`TIER3_INTERVAL`).

Rules:

1. Select batch size paced to complete full local-key coverage within `NETWORK_CYCLE_DEADLINE`.
2. Prioritize keys by last observed replica count (ascending).
3. For each key, query close-group members for presence.
4. Offer repair to members that report missing.
5. Mark severe shortfall when observed holders `< QUORUM_THRESHOLD`.
6. Severe shortfall raises priority only; it does not bypass admission, presence quorum, or paid-list safeguards.

## 7. Authorization and Admission Rules

### 7.1 Offer Key Admission (Per Key)

For each offered key `K`, accept if either condition holds:

1. Sender is in receiver-local top `K_AUTH_OFFER` nodes nearest `K`.
2. Key is PoP-authorized (fresh path), or key is already in receiver-local `PaidForList`.

Notes:

- Authorization decision is local-route-state only.
- Unauthorized keys are dropped immediately.
- Mixed offers are valid: accept authorized keys, drop unauthorized keys.
- On unauthorized drop, receiver SHOULD return `RejectedUnauthorized` plus optional `AuthHint` (small list of currently authorized peers for `K`) so sender can retry through those peers instead of blind retries.
- Senders SHOULD apply `QUORUM_RETRY_BACKOFF` before retrying an `AuthHint` path and MUST respect `PER_TARGET_DEDUP` for repeat attempts.

### 7.2 Paid-List Authorization (Per Key)

When handling an admitted unknown key `K` for Tier 2/3 repair:

1. If `K` is already in local `PaidForList`, paid-list authorization succeeds immediately.
2. Otherwise run the single verification round defined in Section 9 and collect paid-list responses from peers in `ClosestX(K)` (same round as presence evidence; no separate paid-list-only round).
3. If paid confirmations from `ClosestX(K)` are `>= ConfirmNeeded(K)`, add `K` to local `PaidForList`, treat `K` as paid-authorized, and record any peers that also report current presence as fetch candidates.
4. If confirmations are below threshold, paid-list authorization fails for this verification round.
5. Nodes answering paid-list queries MUST answer from local paid-list state only; they MUST NOT infer paid status from chunk presence alone.
6. If a node learns `K` is paid-authorized by majority, it MUST notify queried peers that answered unknown so they can re-check and converge.
7. If paid-list checks show missing `PaidForList` entries among `ClosestX(K)`, node MUST enqueue `PaidNotify(K)` repair for missing peers in the next maintenance pass.

### 7.3 Tier 1 Paid-List Notification (Per Key)

When Tier 1 accepts a fresh key `K` with valid PoP:

1. Sender MUST construct `PaidNotify(K)` containing key `K` and proof material required for receiver-side verification.
2. Sender MUST target every identity in `ClosestX(K)` and attempt each target once for that notification pass (no immediate retry loop).
3. Receiver MUST validate proof material before adding `K` to local `PaidForList`.
4. Receiver MUST return one of: `NotifyAckVerified`, `NotifyRejectInvalidProof`, or `RejectedUnauthorized`.
5. Sender counts completion for a target only on `NotifyAckVerified`.
6. `NotifyRejectInvalidProof` is terminal for that attempt and MUST raise operator-visible error telemetry.
7. Any non-ack outcome is terminal for that pass and MUST be emitted as operator-visible telemetry.

### 7.4 Paid-List Convergence Maintenance (Ongoing)

Nodes that already treat key `K` as paid-authorized MUST help keep `ClosestX(K)` fully populated with `K` in `PaidForList`:

1. Trigger on Tier 2 cadence, topology changes affecting `ClosestX(K)`, and any observation that a `ClosestX(K)` peer reports unknown for paid key `K`.
2. Compute current `ClosestX(K)` membership and probe paid-list presence.
3. For each member missing `K`, send `PaidNotify(K)` repair with proof material and record per-peer ack state.
4. Convergence completion for a maintenance pass is `acked_count == X_eff(K)`.
5. If incomplete, keep key `K` in the convergence set and evaluate again on the next Tier 2 or topology trigger (no dedicated retry loop/backoff).
6. On topology churn, recompute membership and continue convergence on the new `ClosestX(K)` set.

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
  -> FetchRetryable     (timeout/error and retry count < MAX_FETCH_RETRIES and alternate sources remain)
  -> FetchAbandoned     (retry count >= MAX_FETCH_RETRIES or no alternate sources)
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
- `PendingVerify -> PaidListVerified` only if paid confirmations from the same verification round reach `>= ConfirmNeeded(K)`. On success, mark key as paid-authorized locally and record fetch candidates from positive presence hints and/or offer sender.
- `PendingVerify -> QuorumInconclusive` when neither quorum nor paid-list success is reached and unresolved outcomes (timeout/no-response) keep both outcomes undecidable in this round.
- `Fetching -> Stored` only after all storage validation checks pass.
- `Fetching -> FetchRetryable` when fetch fails (timeout, corrupt response, connection error), retry count has not reached `MAX_FETCH_RETRIES`, and at least one untried verified source remains. Mark the failed source as tried so it is not selected again.
- `Fetching -> FetchAbandoned` when fetch fails and either retry count `>= MAX_FETCH_RETRIES` or all verified sources have been tried. Record a `ReplicationFailure` against the failed source(s).
- `FetchRetryable -> QueuedForFetch` selects the next untried verified source and re-enters the fetch queue without repeating quorum verification.
- `QuorumFailed -> QuorumAbandoned` is immediate and terminal for this offer lifecycle. Key is forgotten and stops consuming probe resources. Requires a new offer to re-enter the pipeline.
- `QuorumInconclusive -> QuorumAbandoned` is immediate and terminal for this offer lifecycle. Requires a new offer to re-enter the pipeline.

## 9. Quorum Verification Logic

For each unknown key:

1. Deduplicate key in pending-verification table.
2. If `K` is already in local `PaidForList`, mark `PaidListVerified` and queue for fetch immediately (no network verification round required).
3. Otherwise compute `PaidTargets = ClosestX(K)`.
4. Compute `QuorumTargets` as up to `QUORUM_PROBE_FANOUT` nearest known peers for `K` (excluding self).
5. Compute `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
6. Compute `VerifyTargets = PaidTargets ∪ QuorumTargets`.
7. Send one verification request per peer in `VerifyTargets` and wait up to `QUORUM_RESPONSE_TIMEOUT`. Responses carry binary presence semantics (Section 7.6); peers in `PaidTargets` also return paid-list presence for `K`.
8. Mark `PaidListVerified` and queue for fetch as soon as paid confirmations from `PaidTargets` reach `>= ConfirmNeeded(K)`.
9. Mark `QuorumVerified` and queue for fetch as soon as presence positives from `QuorumTargets` reach `>= QuorumNeeded(K)`.
10. Fail fast and mark `QuorumFailed` only when both conditions are impossible in this round: `(paid_yes + paid_unresolved < ConfirmNeeded(K))` AND `(quorum_positive + quorum_unresolved < QuorumNeeded(K))`.
11. If timeout occurs with neither success nor fail-fast, mark `QuorumInconclusive`.
12. On `QuorumFailed` or `QuorumInconclusive`, transition immediately to `QuorumAbandoned` (no automatic quorum retry/backoff).

Single-round requirement:

- Unknown-key verification MUST NOT run a second sequential network round for presence after a paid-list miss; both evidence types are collected in the same request round.

Security-liveness policy:

- Tier 2/3 never store without either presence quorum or paid-list authorization.
- Tier 1 can store with valid PoP alone.
- Therefore, below-quorum data is recoverable only if paid-list authorization can still be established.

## 10. Record Storage Validation

A fetched record is written only if all checks pass:

1. Type/schema validity.
2. Content-address integrity (`hash(content) == key`).
3. Authorization validity:
   - Tier 1: valid PoP, or
   - Tier 2/3: prior quorum-verified key or paid-list-authorized key.
4. Responsible-range inclusion at write time.

## 11. Responsible Range Logic

Periodic recalculation (example cadence: 15s):

1. Estimate network size from routing-table density.
2. Derive density-based distance budget.
3. Compute responsible cutoff from density and close-group parameters.
4. Lower-bound cutoff using distance to a nearby rank (for stability).
5. Apply cutoff to:
   - Accept/reject future replication writes.
   - Background pruning eligibility.
   - Paid-list retention eligibility (drop paid-list entries when node is no longer in `ClosestX(K)`, after transition slack).

Effect:

- Small network: larger per-node responsibility.
- Large network: narrower per-node responsibility.

## 12. Scheduling and Capacity Rules

Queue model:

- `PendingVerify`: keys awaiting quorum result.
- `FetchQueue`: presence-quorum-passed or paid-list-authorized keys waiting for fetch slot.
- `InFlightFetch`: active downloads.
- `PendingPaidNotify`: per-key map of `ClosestX(K)` notification ack state for Tier 1 propagation and ongoing paid-list convergence repair.

Rules:

1. Enforce `MAX_PARALLEL_QUORUM_CHECKS`.
2. Enforce `MAX_PARALLEL_FETCH` (or bootstrap override).
3. Sort fetch candidates by relevance (e.g., nearest-first) before dequeue.
4. Evict stale queued entries after `PENDING_TIMEOUT`.
5. On fetch failure, mark source as tried and transition per `FetchRetryable`/`FetchAbandoned` rules (Section 8). Retry fetches reuse the verified source set from the original verification pass and do not consume additional verification slots.
6. `PENDING_TIMEOUT` applies to total time since verification success (`QuorumVerified` or `PaidListVerified`), including retry cycles. A key that exhausts `PENDING_TIMEOUT` across retries transitions to `FetchAbandoned`.
7. `PendingPaidNotify` tracks a single pass outcome per key; pass completion is `acked_count == X_eff(K)`. Missing peers are evaluated again only on the next Tier 2 or topology trigger.
8. Storage-audit scheduling and target selection MUST follow Section 15 trigger rules.

Capacity-managed mode (finite store):

1. If full and new in-range key arrives, evict farthest out-of-range key if available.
2. If no out-of-range key exists, reject new key.
3. Periodically prune keys that moved out of responsibility.
4. `PaidForList` is in-memory only and SHOULD be bounded with paging/eviction policies; keys outside `ClosestX(K)` are first candidates for removal.

## 13. Churn and Topology Change Handling

Maintain tracker for closest peers and classify topology events:

- `Trigger`: genuine change, run Tier 2.
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

1. Node MUST NOT schedule storage-proof audits until both conditions hold: bootstrap is complete and `AUDIT_STARTUP_GRACE` has elapsed since bootstrap completion.
2. Node MUST also wait for at least one responsible-range computation before the first audit scheduling tick; if unavailable, skip the tick.
3. Audit scheduler runs periodically at randomized `AUDIT_TICK_INTERVAL` (reference profile: jittered in `[5 min, 10 min]`).
4. Per tick, node MUST run the round-construction flow in steps 2-8 above (sample local keys, lookup closest peers, filter by `LocalRT(self)`, build per-peer key sets, then choose one random peer).
5. Node MUST NOT issue storage-proof audits to peers outside the round-construction output set for that tick.
6. If round construction yields no eligible peer, node records an idle audit tick and waits for the next tick (no forced random target).

## 16. New Node Bootstrap Logic

A joining node performs active sync:

1. Discover close-group peers.
2. Request key lists and paid-list snapshots for its responsible range from those peers.
3. For each discovered key `K`, compute `QuorumTargets` as up to `QUORUM_PROBE_FANOUT` nearest known peers for `K` (excluding self), and compute `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
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
   - If close-group peers are partially unavailable, is there a deterministic retry strategy?
3. Range oscillation:
   - Can rapid responsible-range shifts cause thrash (store/prune/store loops)?
4. Restart suppression false negatives:
   - Could real topology loss be suppressed too long?
5. Offer-set integrity:
   - How are duplicate keys, partial deliveries, and retries handled deterministically?
6. Severe shortfall behavior:
   - Is priority escalation enough, or are additional safeguards needed when holders fall below quorum?
7. Admission asymmetry:
   - Can two honest nodes disagree on `top K` enough to block propagation?
8. Capacity fairness:
   - Can nearest-first plus finite capacity starve less-near but still responsible keys?
9. Audit bias:
   - Are audit targets selected fairly, or can adversaries avoid frequent challenge?
10. Failure attribution:
   - Could transient network issues misclassify healthy peers as bad without dampening?
11. Paid-list poisoning:
   - Can colluding nodes in `ClosestX(K)` falsely mark unpaid keys as paid?
12. Paid-list cold-start:
   - After broad restart, can paid-list snapshots be rebuilt deterministically before churn repair starts?

## 18. Pre-Implementation Test Matrix

Each scenario should assert exact expected outcomes and state transitions.

1. Fresh write happy path:
   - Valid PoP propagates to target holders without quorum check.
2. Fresh write invalid PoP:
   - Receiver rejects and does not enqueue fetch.
3. Tier 2 unknown key quorum pass:
   - Key transitions to stored through full state machine.
4. Tier 2 unknown key quorum fail:
   - Key transitions to `QuorumAbandoned` (then `Idle`) and is not fetched.
5. Unauthorized offer sender:
   - Unauthorized keys dropped, authorized keys in same offer still processed.
6. Presence probe response shape:
   - Presence responses are only `Present` or `Absent`; there are no `RejectedUnauthorized`/`RejectedBusy` presence codes.
7. Out-of-range key offer:
   - Key rejected regardless of quorum.
8. Duplicate and retry safety:
   - Duplicate keys and repeated offers do not create invalid acceptance or duplicate queue/fetch work.
9. Fetch timeout with alternate source retry:
   - First source times out, key transitions to `FetchRetryable`, re-enters `QueuedForFetch` with next verified source, and succeeds. Verification is not re-run. Failed source receives one `ReplicationFailure`; successful alternate source clears stale failure attribution (rule 14.4).
10. Fetch retry exhaustion:
   - All verified sources fail or `MAX_FETCH_RETRIES` reached. Key transitions to `FetchAbandoned`. Each failed source receives one `ReplicationFailure`.
11. Repeated true source failures:
   - Peer evicted exactly at threshold behavior.
12. Bootstrap quorum aggregation:
   - Node accepts only keys meeting multi-peer threshold.
13. Responsible range shrink:
   - Out-of-range records become prune candidates; new in-range keys still accepted per capacity policy.
14. Severe under-replication:
   - Key is prioritized immediately in next Tier 3 selection.
15. Partition and heal:
   - Confirm below-quorum recovery succeeds when paid-list authorization survives, and fails when it cannot be re-established.
16. Quorum responder timeout handling:
   - No-response/timeouts are unresolved and can yield `QuorumInconclusive`, which is terminal for that offer lifecycle (`QuorumAbandoned` -> `Idle`).
17. Offer admission asymmetry:
   - `AuthHint`-guided retry via authorized peer succeeds without relaxing admission policy.
18. Invalid runtime config:
   - Node rejects configs violating parameter safety constraints.
19. Audit digest mismatch:
   - Challenge fails when `AuditDigest` mismatches, even if response format is syntactically valid.
20. Paid-list local hit:
   - Unknown key with local paid-list entry bypasses presence quorum and enters fetch pipeline.
21. Paid-list majority confirmation:
   - Unknown key not in local paid list is accepted only after `>= ConfirmNeeded(K)` confirmations from `ClosestX(K)`.
22. Paid-list rejection:
   - Unknown key is rejected when paid confirmations are below threshold and presence quorum also fails.
23. Paid-list cleanup after churn:
   - Node drops paid-list entries for keys where it is no longer in `ClosestX(K)`.
24. Tier 1 paid-list full propagation:
   - Freshly accepted key sends `PaidNotify` to all peers in current `ClosestX(K)`; pass is propagation-complete only when all `X_eff(K)` peers acknowledge verified proof.
25. Tier 1 paid-list non-ack handling:
   - Any non-ack outcome in a pass is terminal for that pass and raises operator-visible telemetry; no immediate retry loop is performed.
26. Paid-list convergence repair:
   - For a known paid key with incomplete `ClosestX(K)` coverage, nodes detect missing peers and attempt repair on each Tier 2/topology convergence pass; per-pass completion uses `acked_count == X_eff(K)`.
27. Dynamic paid-list threshold in undersized consensus set:
   - With `X_eff(K)=8`, paid-list authorization requires `ConfirmNeeded(K)=5` confirmations (not 11).
28. Single-round dual-evidence verification:
   - For unknown key verification, implementation sends one request round to `VerifyTargets`; no second sequential quorum-probe round is issued after paid-list miss.
29. Dynamic quorum threshold in undersized verification set:
   - With `|QuorumTargets|=3`, unknown-key presence quorum requires `QuorumNeeded(K)=2` confirmations (not 4).
30. Audit start gate:
   - Node does not schedule audits before `bootstrap_complete + AUDIT_STARTUP_GRACE` and before at least one responsible-range computation.
31. Audit peer selection from sampled keys:
   - Scheduler samples up to `AUDIT_BATCH_SIZE` local keys, performs closest-peer lookups, filters peers by `LocalRT(self)`, builds `PeerKeySet` from those lookup results only, and selects one random peer to audit.
32. Audit periodic cadence with jitter:
   - Consecutive audit ticks occur on randomized intervals bounded by configured `AUDIT_TICK_INTERVAL` window (`5-10 min` in reference profile).
33. Dynamic challenge size:
   - Challenged key count equals `|PeerKeySet(challenged_peer_id)|` and is dynamic per round; if no eligible peer remains after `LocalRT` filtering, the tick is idle and no audit is sent.

## 19. Acceptance Criteria for This Design

The design is logically acceptable for implementation when:

1. All invariants in Section 5 can be expressed as executable assertions.
2. Every scenario in Section 18 has deterministic pass/fail expectations.
3. Security-over-liveness tradeoffs are explicitly accepted by stakeholders.
4. Parameter sensitivity (especially `K_AUTH_OFFER`, quorum, `PAID_LIST_*`, and suppression windows) has been reviewed with failure simulations.
5. Audit-proof digest requirements are implemented and test-validated.
