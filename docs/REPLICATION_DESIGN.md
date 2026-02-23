# Replication Logic Specification (Codebase-Agnostic)

> Status: Design-level specification for pre-implementation validation.

## 1. Purpose

This document specifies replication behavior as a pure system design, independent of any language, framework, transport, or existing codebase.

Primary goal: validate correctness, safety, and liveness of replication logic before implementation.

## 2. Scope

### In scope

- Permanent record replication in a decentralized key-addressed network.
- Pull-based repair (key offers + receiver fetch).
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
- `ResponsibleRange(N)`: max distance from node `N` within which `N` is willing to store replicated records.
- `Holder`: node that stores a valid copy of a record.
- `PoP`: verifiable proof that a record was authorized for initial storage/payment policy.
- `PaidNotify(K)`: Tier 1 paid-list notification carrying key `K` plus PoP/payment proof material needed for receiver-side verification and whitelisting.
- `PaidForList(N)`: in-memory set of keys node `N` currently believes are paid-authorized.
- `ClosestX(K)`: `PAID_LIST_CLOSEST_X` nearest nodes to key `K` that participate in paid-list consensus.
- `ClosestY(K)`: `PAYMENT_ACCEPT_CLOSEST_Y` nearest nodes to key `K` allowed to accept initial paid writes (`Y <= X`).

## 4. Tunable Parameters

All parameters are configurable. Values below are a reference profile used for logic validation.

| Parameter | Meaning | Reference |
|---|---|---|
| `CLOSE_GROUP_SIZE` | Close-group width | `7` |
| `REPLICATION_FACTOR` | Target holder count per key | `7` |
| `QUORUM_THRESHOLD` | Required positive presence votes | `floor(REPLICATION_FACTOR/2)+1` (`4`) |
| `PAID_LIST_CLOSEST_X` | Number of closest nodes tracking paid status for a key | `20` |
| `PAYMENT_ACCEPT_CLOSEST_Y` | Number of closest nodes allowed to accept initial paid write | `7` |
| `PAID_LIST_CONFIRM_THRESHOLD` | Paid-list confirmations needed to treat key as paid | `floor(PAID_LIST_CLOSEST_X/2)+1` (`11`) |
| `K_AUTH` | Probe auth window (per key) | `12` |
| `K_AUTH_OFFER` | Offer auth window (per key) | `12` |
| `QUORUM_PROBE_FANOUT` | Peers probed per key during quorum check | `max(CLOSE_GROUP_SIZE, K_AUTH)` (`12`) |
| `TIER2_INTERVAL` | Neighbor sync cadence | random in `[90s, 180s]` |
| `TIER3_INTERVAL` | Global verification cadence | `15 min` |
| `GLOBAL_REPL_COOLDOWN` | Min spacing between Tier 2 runs | `30s` |
| `PER_TARGET_DEDUP` | Min spacing for same sender->target replication | `45s` |
| `RESTART_SUPPRESSION` | Rejoin suppression window | `90s` |
| `MAX_FETCH_RETRIES` | Max alternate-source fetch attempts per quorum pass | `2` |
| `FETCH_TIMEOUT` | Per-record fetch timeout | `20s` |
| `PENDING_TIMEOUT` | Max queue residency | `15 min` |
| `QUORUM_RESPONSE_TIMEOUT` | Presence probe wait budget | `3s` |
| `QUORUM_RETRY_BACKOFF` | Retry delay for non-quorum sender retry paths (e.g., `AuthHint`, `PaidNotify`) | `60s` |
| `MAX_PARALLEL_FETCH` | Normal concurrent fetches | `5` |
| `MAX_PARALLEL_FETCH_BOOTSTRAP` | Bootstrap concurrent fetches | `20` |
| `MAX_PARALLEL_QUORUM_CHECKS` | Concurrent quorum checks | `16` |
| `NETWORK_CYCLE_DEADLINE` | Max time to re-check all records | `4 days` |
| `AUDIT_RANGE_BYTES` | Bytes proven per challenged record | `4096` |
| `AUDIT_BATCH_SIZE` | Normal audit items | `8` |
| `AUDIT_BURST_BATCH_SIZE` | Escalated audit items | `32` |
| `AUDIT_RESPONSE_TIMEOUT` | Audit response deadline | `5s` |
| `AUDIT_ESCALATION_THRESHOLD` | Normal audit failures before burst | `3 in 10 min` |
| `BAD_NODE_WINDOW` | Window for failure counting | `5 min` |
| `BAD_NODE_THRESHOLD` | Failures needed for eviction | `3` |

Parameter safety constraints (MUST hold):

1. `1 <= QUORUM_THRESHOLD <= REPLICATION_FACTOR`.
2. `QUORUM_THRESHOLD <= QUORUM_PROBE_FANOUT`.
3. `QUORUM_PROBE_FANOUT >= CLOSE_GROUP_SIZE`.
4. `QUORUM_PROBE_FANOUT >= K_AUTH`.
5. `1 <= PAYMENT_ACCEPT_CLOSEST_Y <= PAID_LIST_CLOSEST_X`.
6. `1 <= PAID_LIST_CONFIRM_THRESHOLD <= PAID_LIST_CLOSEST_X`.
7. If constraints are violated at runtime reconfiguration, node MUST reject the config and keep the previous valid config.

## 5. Core Invariants (Must Hold)

1. A record is accepted only if it passes integrity and responsibility checks.
2. Tier 2 and Tier 3 repair traffic requires either receiver-side presence quorum success or paid-list authorization success before fetch.
3. Tier 1 bypasses presence quorum only when PoP is valid.
4. Unauthorized offer keys are dropped per key (not per message).
5. Presence probes are key-scoped authorized; no neighbor-only bypass is allowed.
6. `REPLICATION_FACTOR` is a target holder count, not guaranteed send fanout.
7. Receiver stores only records in its current responsible range.
8. Queue dedup prevents duplicate pending/fetch work for same key.
9. No unbounded key-list transfer; each offer exchange MUST be resource-bounded.
10. Bad-node decisions are local-only (no gossip reputation).
11. Global replication prioritizes low-observed-replica records first.
12. Security policy is explicit: anti-injection may sacrifice recovery of below-quorum non-PoP data.
13. Every Tier 2 offer exchange reaches a deterministic terminal state.
14. `RejectedBusy` is retryable and does not count as an explicit negative vote.
15. A failed fetch retries from alternate verified sources before abandoning. Verification evidence is preserved across fetch retries.
16. Paid-list authorization is key-scoped and majority-based across `ClosestX(K)`, not node-global.
17. `PaidForList(N)` is memory-bounded: node `N` tracks only keys for which `N` is in `ClosestX(K)` (plus short-lived transition slack).
18. Tier 1 paid-list propagation is mandatory: sender MUST attempt `PaidNotify(K)` delivery to every peer in `ClosestX(K)` (reference profile: all 20 peers), not a subset.
19. A `PaidNotify(K)` only whitelists key `K` after receiver-side proof verification succeeds; sender assertions never whitelist by themselves.
20. Paid-list convergence is maintained continuously: nodes that know key `K` is paid MUST help repair missing `PaidForList` entries across all peers in `ClosestX(K)` until full coverage is restored or the key leaves maintenance scope.

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
9. Sender MUST track per-peer `PaidNotify(K)` acknowledgment state and retry non-acknowledged peers with backoff until all peers in `ClosestX(K)` have acknowledged verification, or the key is no longer sender-responsible.
10. Completion of paid-list propagation is defined per key as `acked_count == PAID_LIST_CLOSEST_X` (reference profile: 20/20).

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
2. Otherwise query all peers in `ClosestX(K)` (reference profile: 20 peers) for paid-list presence of `K` and optional current holder presence for source selection.
3. If paid confirmations `>= PAID_LIST_CONFIRM_THRESHOLD`, add `K` to local `PaidForList`, treat `K` as paid-authorized, and record any peers that also report current presence as fetch candidates.
4. If confirmations are below threshold, paid-list authorization fails for this attempt.
5. Nodes answering paid-list queries MUST answer from local paid-list state only; they MUST NOT infer paid status from chunk presence alone.
6. If a node learns `K` is paid-authorized by majority, it MUST notify queried peers that answered unknown so they can re-check and converge.
7. If paid-list checks show missing `PaidForList` entries among `ClosestX(K)`, node MUST enqueue `PaidNotify(K)` repair for missing peers and retry until all peers in `ClosestX(K)` acknowledge verified proof, or key `K` leaves node maintenance scope.

### 7.3 Tier 1 Paid-List Notification (Per Key)

When Tier 1 accepts a fresh key `K` with valid PoP:

1. Sender MUST construct `PaidNotify(K)` containing key `K` and proof material required for receiver-side verification.
2. Sender MUST target every identity in `ClosestX(K)` and MUST keep retrying non-acknowledged targets with backoff while key `K` remains sender-responsible.
3. Receiver MUST validate proof material before adding `K` to local `PaidForList`.
4. Receiver MUST return one of: `NotifyAckVerified`, `NotifyRejectInvalidProof`, `RejectedUnauthorized`, or `RejectedBusy`.
5. Sender counts completion for a target only on `NotifyAckVerified`.
6. `NotifyRejectInvalidProof` is terminal for that attempt and MUST raise operator-visible error telemetry.
7. `RejectedBusy` is retryable and does not count as negative evidence about paid validity.

### 7.4 Paid-List Convergence Maintenance (Ongoing)

Nodes that already treat key `K` as paid-authorized MUST help keep `ClosestX(K)` fully populated with `K` in `PaidForList`:

1. Trigger on Tier 2 cadence, topology changes affecting `ClosestX(K)`, and any observation that a `ClosestX(K)` peer reports unknown for paid key `K`.
2. Compute current `ClosestX(K)` membership and probe paid-list presence.
3. For each member missing `K`, send `PaidNotify(K)` repair with proof material and record per-peer ack state.
4. Retry missing peers with backoff until `acked_count == PAID_LIST_CLOSEST_X` (reference profile: 20/20), or key exits maintenance scope.
5. On topology churn, recompute membership and continue convergence on the new `ClosestX(K)` set.

### 7.5 Presence Probe Admission (Per Key)

Presence probe for key `K` is accepted only if:

1. Requester is in receiver-local top `K_AUTH` for key `K`.

If unauthorized, return `RejectedUnauthorized` and skip expensive lookup work when possible.

### 7.6 Presence Response Semantics

- `Present`: key exists locally.
- `Absent`: requester authorized; key not found locally.
- `RejectedUnauthorized`: requester not authorized for key.
- `RejectedBusy`: requester authorized but temporarily rate-limited/overloaded.

Quorum counting:

- `Present` counts positive.
- `Absent` and `RejectedUnauthorized` count non-positive.
- `RejectedBusy` is neutral (retryable, not a negative vote).

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
- `PendingVerify -> QuorumVerified` only if positives `>= QUORUM_THRESHOLD`. On success, record the set of positive responders as verified fetch sources.
- `PendingVerify -> PaidListVerified` only if paid confirmations `>= PAID_LIST_CONFIRM_THRESHOLD`. On success, mark key as paid-authorized locally and record fetch candidates from positive presence hints and/or offer sender.
- `PendingVerify -> QuorumInconclusive` when positives are insufficient but neutral outcomes (`RejectedBusy`/timeout) keep quorum undecidable in this round.
- `Fetching -> Stored` only after all storage validation checks pass.
- `Fetching -> FetchRetryable` when fetch fails (timeout, corrupt response, connection error), retry count has not reached `MAX_FETCH_RETRIES`, and at least one untried verified source remains. Mark the failed source as tried so it is not selected again.
- `Fetching -> FetchAbandoned` when fetch fails and either retry count `>= MAX_FETCH_RETRIES` or all verified sources have been tried. Record a `ReplicationFailure` against the failed source(s).
- `FetchRetryable -> QueuedForFetch` selects the next untried verified source and re-enters the fetch queue without repeating quorum verification.
- `QuorumFailed -> QuorumAbandoned` is immediate and terminal for this offer lifecycle. Key is forgotten and stops consuming probe resources. Requires a new offer to re-enter the pipeline.
- `QuorumInconclusive -> QuorumAbandoned` is immediate and terminal for this offer lifecycle. Requires a new offer to re-enter the pipeline.

## 9. Quorum Verification Logic

For each unknown key:

1. Deduplicate key in pending-verification table.
2. Run paid-list authorization check (Section 7.2). If it succeeds, mark `PaidListVerified` and queue for fetch.
3. If paid-list authorization fails, select up to `QUORUM_PROBE_FANOUT` nearest known peers for `K` (excluding self) and send presence probes.
4. Wait up to `QUORUM_RESPONSE_TIMEOUT`.
5. Pass if positive responses `>= QUORUM_THRESHOLD`.
6. Fail fast if `positives + unresolved_remaining < QUORUM_THRESHOLD`, where `unresolved_remaining` excludes explicit negatives (`Absent`, `RejectedUnauthorized`) but includes `RejectedBusy` and no-response peers.
7. If timeout occurs with undecidable outcome (not pass, not fail-fast), mark `QuorumInconclusive`.
8. On `QuorumFailed` or `QuorumInconclusive`, transition immediately to `QuorumAbandoned` (no automatic quorum retry/backoff).

Security-liveness policy:

- Tier 2/3 never store without either presence quorum or paid-list authorization.
- Tier 1 can store with valid PoP alone.
- Therefore, below-quorum data is recoverable only if paid-list authorization can still be established.

## 10. Record Storage Validation

A fetched record is written only if all checks pass:

1. Type/schema validity.
2. Content-address integrity (`hash(content) == key`).
3. Auditable commitment validity (when audits are enabled): record can produce deterministic range proofs bound to key.
4. Authorization validity:
   - Tier 1: valid PoP, or
   - Tier 2/3: prior quorum-verified key or paid-list-authorized key.
5. Responsible-range inclusion at write time.

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
7. `PendingPaidNotify` retries SHOULD use `QUORUM_RETRY_BACKOFF` as minimum spacing per target and MUST continue until `acked_count == PAID_LIST_CLOSEST_X` (or key leaves maintenance scope).

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
- Escalated audit failures.

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
2. Selects random records the target should hold.
3. Requests random byte ranges per selected record.
4. Target returns bytes plus range proofs bound to challenge id, nonce, target id, key, offset, and length.
5. Challenger verifies returned bytes against the record's auditable commitment before deadline.

Audit-proof requirements:

1. Challenger MUST hold a local copy of each challenged record to verify range proofs. Audit selection is therefore limited to records the challenger stores.
2. Commitment MUST be deterministically derived from record content and cryptographically bound to key `K`.
3. Responses lacking valid commitment linkage are invalid even if bytes are well-formed.

Audit modes:

- Normal: `AUDIT_BATCH_SIZE`.
- Burst: `AUDIT_BURST_BATCH_SIZE` after repeated normal failures.

Failure conditions:

- Timeout, missing items, invalid proofs, malformed response, or commitment mismatch.

## 16. New Node Bootstrap Logic

A joining node performs active sync:

1. Discover close-group peers.
2. Request key lists and paid-list snapshots for its responsible range from those peers.
3. Aggregate paid-list reports and add key `K` to local `PaidForList` only if paid reports are `>= PAID_LIST_CONFIRM_THRESHOLD`.
4. Aggregate key-presence reports and accept keys observed from `>= QUORUM_THRESHOLD` peers, or keys that are now paid-authorized locally.
5. Fetch accepted keys with bootstrap concurrency.
6. Fall back to normal concurrency after bootstrap drains.

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
6. Unauthorized probe requester:
   - Response is `RejectedUnauthorized`; no positive quorum credit.
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
16. Authorized but overloaded quorum responder:
   - `RejectedBusy` can yield `QuorumInconclusive`, which is terminal for that offer lifecycle (`QuorumAbandoned` -> `Idle`).
17. Offer admission asymmetry:
   - `AuthHint`-guided retry via authorized peer succeeds without relaxing admission policy.
18. Invalid runtime config:
   - Node rejects configs violating parameter safety constraints.
19. Audit commitment mismatch:
   - Challenge fails even if response bytes are syntactically valid.
20. Paid-list local hit:
   - Unknown key with local paid-list entry bypasses presence quorum and enters fetch pipeline.
21. Paid-list majority confirmation:
   - Unknown key not in local paid list is accepted only after `>= PAID_LIST_CONFIRM_THRESHOLD` confirmations from `ClosestX(K)`.
22. Paid-list rejection:
   - Unknown key is rejected when paid confirmations are below threshold and presence quorum also fails.
23. Paid-list cleanup after churn:
   - Node drops paid-list entries for keys where it is no longer in `ClosestX(K)`.
24. Tier 1 paid-list full propagation:
   - Freshly accepted key sends `PaidNotify` to all `PAID_LIST_CLOSEST_X` peers; key is considered propagation-complete only when all 20 peers acknowledge verified proof.
25. Tier 1 paid-list retry behavior:
   - Busy/unreachable paid-list targets are retried with backoff; invalid-proof responses do not whitelist and trigger error telemetry.
26. Paid-list convergence repair:
   - For a known paid key with incomplete `ClosestX(K)` coverage, nodes detect missing peers and continue `PaidNotify` repair until all 20 closest peers confirm `PaidForList` membership.

## 19. Acceptance Criteria for This Design

The design is logically acceptable for implementation when:

1. All invariants in Section 5 can be expressed as executable assertions.
2. Every scenario in Section 18 has deterministic pass/fail expectations.
3. Security-over-liveness tradeoffs are explicitly accepted by stakeholders.
4. Parameter sensitivity (especially `K_AUTH*`, quorum, `PAID_LIST_*`, and suppression windows) has been reviewed with failure simulations.
5. Audit-proof commitment requirements are implemented and test-validated.
