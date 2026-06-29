# ADR-0003: Full-node detection, penalisation, and eviction

- **Status:** Proposed
- **Date:** 2026-06-25
- **Decision owners:** Mick
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ant-client ADR-0002 (client-side fallback and diagnostics); ADR-0002 (gossip-triggered storage-commitment audit — shares the trust/eviction path); saorsa-core trust-score eviction (the enforcement layer — already implemented, no change required)

## Context

A network design axiom frames this whole ADR: **a full node and a dishonest node are
treated identically.** A node that cannot accept puts is an unhealthy close-group
member and must be evicted from routing; the close group must always be healthy and
accept puts. This holds **only while fullness is a minority within any
neighbourhood** — there must always be healthy peers holding the data when a full one
is shed. A globally near-capacity network is the explicit failure boundary, where both
eviction (nothing healthy to shift to) and client fallback (no willing acceptor)
degrade together. Every mechanism below is designed for the minority-full regime and
must degrade gracefully — not cascade-evict — when that assumption breaks.

Verified current behaviour:

- A node rejects a put when its disk is full with a **distinct**
  `ProtocolError::StorageFailed`, *before* payment verification
  (`src/storage/handler.rs:274-281`; `src/storage/lmdb.rs:599-621`).
- A direct client PUT does **not** reject on the node's own storage-responsibility
  view (`src/storage/handler.rs:283-285`). Acceptance is bounded only *indirectly* by
  the issuer-in-local-20-closest test (`src/payment/verifier.rs:942-1003`;
  `PAID_QUOTE_ISSUER_CLOSENESS_WIDTH = K_BUCKET_SIZE = 20`).
- Fresh replication requires a proof of payment **and** enforces closeness via
  `admission::is_responsible(... storage_admission_width = close_group + margin)`,
  reusing the same `ClientPut` verification path
  (`src/replication/mod.rs:1902-1916, 1987-2007, 2035-2048`).
- ADR-0002 established the principle that misbehaviour must be **attributable** before
  eviction is enabled.

The gap: nothing currently turns "a close peer is full" into an attributable penalty,
and nothing stops a non-close node from accepting a client put and then
mis-attributing the resulting replication failures to honest nodes.

## Decision Drivers

- Detect full close peers from **direct, locally-observed, verifiable** signals —
  never client hearsay, which is an eclipse/grief vector.
- Never wrongly penalise an honest-but-slow node — mirror ADR-0002's
  deterministic-vs-transient split and adaptive grace.
- Every close-group peer is responsible for holding the chunk; this node's failure to
  deliver its push does not excuse a peer that lacks the data — all are tested and
  penalised alike.
- Keep the close group healthy as full nodes are shed, without losing readability of
  data already stored (safe while fullness stays a minority).
- Do not strangle the client fallback (ant-client ADR-0002): the self-closeness gate
  width and the fallback ceiling are the same knob viewed from two sides.
- Degrade gracefully at the near-capacity boundary instead of cascade-evicting.

## Considered Options

1. **Penalise on client-reported full rejections.** Rejected: unverifiable; lets a
   client grief honest nodes into eviction.
2. **Detect fullness only through the existing periodic responsible-chunk audit.**
   Rejected as insufficient: too slow to react to a peer that is full at put time, and
   it does not observe the fresh-replication path where the failure actually shows up.
3. **Detect during fresh replication, verify possession after a 5–15 minute delay, feed
   an attributable penalty into the trust score, evict via saorsa-core's existing
   eviction, and gate client-put acceptance on self-closeness (chosen).**

## Decision

### Detection

- When a node fresh-replicates a chunk to its close group, it records **every** close
  peer responsible for the chunk and schedules a **delayed possession check** for each
  one. The push outcome — accepted, refused with `StorageFailed`, or undelivered — does
  not change *who* is checked: the delayed check below is the single, authoritative test
  and it runs against the **whole** close group. All events are **locally observed** by
  the replicating node itself.
- **Best-effort delivery, but no delivery-based exemption.** The node still tries to
  deliver each fresh-replication request and retries that peer **up to 2 times** on a
  delivery/transport failure. But delivery success is **not** a precondition for
  judgement: a close peer is responsible for holding the chunk regardless of whether
  *this* node's push got through (the chunk also reaches it via the client's own puts,
  other replicators, and neighbour sync). A peer the push never reached after the
  retries is therefore **still tested and still penalised** if it lacks the data — the
  same as every other close peer.
- **Delayed verification — 5 to 15 minutes after fresh replication.** The node waits a
  randomised interval in `[5 min, 15 min]`, then queries each close peer (a PaidForList
  possession query) for whether it actually holds the chunk. The delay (a) gives fresh
  replication time to settle, so an honest peer still mid-store is never judged
  prematurely, and (b) makes the check a surprise the peer cannot anticipate.
- **Asymmetric, unrewarding scoring.** A peer confirmed to hold the chunk receives
  **no positive trust** — storing what it was paid to store is the baseline
  expectation, not meritorious. A peer that does **not** hold the chunk receives a
  penalty **as severe as a normal AuditChallenge failure** (the same magnitude as the
  responsible-chunk / storage-commitment audit penalty).
- Only the observing node's **own direct interaction** produces a penalty. No
  third-party report and no client claim ever does.

### Accounting (reusing the ADR-0002 philosophy)

- A confirmed **not-present** result after the delayed window is a **deterministic
  failure** — re-asking cannot turn a genuine absence into possession — and is
  penalised at **AuditChallenge severity on its first occurrence**, exactly as ADR-0002
  acts on deterministic audit failures the first time. The push outcome (accepted,
  `StorageFailed`, or undelivered) does not change this — the verdict comes solely from
  the possession check, applied identically to every close peer.
- A peer unreachable **when the possession check itself is run** has not yet *yielded*
  a verdict — distinct from a peer the replication push failed to reach. The check keeps
  the same grace allowance as ADR-0002's audit deadline misses (resets on success,
  scales with the network-wide timeout level, never with deterministic failures) and is
  **re-attempted until it returns present or absent**. This grace buys time to obtain the
  answer, not a way to skip the test: every close peer is ultimately judged on whether it
  holds the chunk.
- The score moves in one direction only: storing earns nothing, and only a confirmed
  absence moves it — downward.

### Eviction (provided by saorsa-core — already implemented)

- The trust-score eviction this plan needs **already exists in saorsa-core**: full-peer
  penalties feed the peer's trust score, and a peer below the threshold is immediately
  evicted from routing. **No saorsa-core change is required by this ADR** — the
  node-side work here only emits the full-peer penalty, at AuditChallenge severity, into
  that existing trust system.
- This ADR therefore **depends on, rather than defines,** saorsa-core's existing
  threshold/eviction policy, its recovery path (a node that frees capacity can
  re-enter), and any near-capacity protection that avoids cascade-evicting a
  uniformly-full neighbourhood. These are confirmed here as integration behaviour
  (see Validation), not implemented as part of this work.

### Self-closeness gate on client puts

- Add a gate so a node accepts a client put only when it considers **itself** within
  its local K closest to the address. This makes an accepting node's subsequent
  fresh-replication participation legitimate, so it cannot mis-penalise honest nodes —
  the concern behind the original "only accept a client put if within the local K
  closest" requirement. It replaces today's *indirect* issuer-in-20 bound with an
  explicit self-closeness check.
- **Coupling (must design as one knob):** the gate width MUST be **≥ the client
  fallback ceiling** (ant-client ADR-0002, bounded by the 20-wide window), or the gate
  strangles the fallback it is meant to coexist with. Express both against the same
  width and choose them together.

### Fresh-replication admission during convergence

A healthy node that *should* hold a chunk can transiently fail to recognise its own
responsibility: while full nodes closer to the key still sit in its routing table
(not yet detected and evicted), they push it past the narrow
`storage_admission_width` (close group + small margin) in its *own* view. With that
narrow window it would then **reject** a fresh-replication offer it ought to accept —
so the replication path that is meant to heal coverage instead refuses it, stalling
convergence. This is also inconsistent: the same node already accepts a **client
PUT** for that key within the wider `K_BUCKET_SIZE` window (both the payment
issuer-closeness check and the self-closeness gate above use it), so a key could land
on the node directly from a client but not via replication.

**Decision:** widen the **fresh-replication accept** admission to the K-wide
paid-close-group neighbourhood (`paid_list_close_group_size`, equal to
`K_BUCKET_SIZE` = 20) — the same window client PUTs use — so transient view-skew
from un-evicted full nodes no longer causes spurious rejection. A node accepts a
fresh offer when it is within its own local `paid_list_close_group_size`-closest to
the key. Two properties keep this safe:

- **No extra storage from the accept side.** The sender still fans out only to its
  `close_group_size` targets, so widening the *receiver's* accept window adds no
  stores — it only stops those targets from rejecting due to view-skew.
- **Retention stays narrow.** Long-term retention/pruning keeps using
  `storage_admission_width`, so steady-state replication is still ≈ K. Any transient
  over-coverage is reclaimed once the close group converges (full nodes evicted → the
  node's view tightens → it sits correctly inside or outside the narrow window), and
  the multi-day prune hysteresis comfortably spans the minutes-long eviction window,
  so a legitimate replica is never pruned mid-convergence.

**Sender side (deliberately not widened).** The mirror case — the *sender's* own
close group being mostly full, so its `close_group_size` offers never reach the
healthy nodes ranked beyond the full ones — is left to the existing convergence loop:
the possession check evicts the full nodes, the close group tightens to healthy
members, and the responsible-chunk repair (neighbour sync) fetches the chunk to the
nodes that become responsible. Widening the sender fan-out to `K_BUCKET_SIZE` was
considered and rejected — it would triple fresh-replication fan-out on *every* write
and hold large transient over-replication for the full prune-hysteresis window, for a
case the repair path already heals.

## Consequences

### Positive

- Full peers become attributable and are shed, so the close group self-heals toward
  peers that can keep storing.
- Honest nodes are protected three ways: the 5–15 minute settle delay before any check,
  the deterministic-vs-transient split, and saorsa-core's adaptive grace — so a peer
  still mid-store or briefly slow is never penalised.
- Client fallback acceptance and node-side acceptance stay aligned because the gate and
  the fallback ceiling are a single tuned width.

### Negative / Trade-offs

- Detection adds replication-time verification cost (an extra possession check per
  fresh-replication wave).
- **Enabling eviction is a coordinated, breaking change**: the network must run
  detection before eviction can be relied on, consistent with ADR-0002's rollout
  gating.
- The near-capacity boundary is a real limitation — mitigated by saorsa-core's existing
  safety valve and recovery path, not eliminated.
- The self-closeness gate changes today's permissive client-put acceptance and must be
  rolled out in step with the client fallback.

### Neutral / Operational

- New node-side tunables: the fresh-replication delivery retry budget (up to 2 per
  peer), the post-put verification envelope (the 5–15 minute delay window plus per-check
  timeout and re-attempt budget), and the self-closeness gate width. The penalty
  magnitude is not new — it reuses the existing AuditChallenge severity.
- Trust score, eviction threshold, recovery, and near-capacity protection are
  **already implemented in saorsa-core**; this node only emits penalties into them —
  **no saorsa-core change in this work**.
- Runs **alongside** ADR-0002's gossip-triggered storage-commitment audit and the
  periodic responsible-chunk audit, sharing the same trust/eviction path; full-node
  detection is simply another attributable-misbehaviour source feeding it.

## Validation

How we will know this decision remains correct:

- **Minority-full testnet:** full close peers accrue penalties from direct observation
  only, cross the threshold, are evicted, and the close group recomputes to healthy
  peers — with stored data still readable throughout (the surviving majority held the
  replicas).
- **Honest-node safety:** under induced churn, honest-but-slow nodes are not evicted
  (grace plus adaptive timeout scaling hold; no eviction death spiral), and a client
  cannot induce eviction of an honest node by claiming it is full.
- **Self-closeness gate:** non-close nodes no longer accept client puts, and the chosen
  gate width still leaves at least quorum-many acceptors available for the client
  fallback set (cross-checked against ant-client ADR-0002).
- **Near-capacity:** when a neighbourhood is uniformly full, the node degrades to
  best-effort storage rather than cascade-evicting.
- **Tests required before Accepted:** the possession check fires only within the 5–15
  minute window and never before it, and runs for **every** close-group peer; a peer
  confirmed holding the chunk receives **no** trust change, while a confirmed not-present
  peer records exactly one penalty at **AuditChallenge severity** against the right
  peer — identically whether the push was accepted, refused with `StorageFailed`, or
  never delivered; a peer the push never reached after 2 retries is still tested and
  still penalised if it lacks the chunk; client/third-party claims record none; a peer
  unreachable *at check time* is re-attempted under the grace allowance until it yields
  present/absent; the adaptive timeout grace tracks widespread timeouts but never
  deterministic failures; the node emits into saorsa-core such that an
  evicted-for-fullness node can re-enter after it frees capacity (integration); the
  self-closeness gate width is ≥ the fallback ceiling; a healthy node with un-evicted
  full nodes ahead of it in its routing table (so it ranks outside
  `storage_admission_width` but within `K_BUCKET_SIZE`) still **accepts** a
  fresh-replication offer for the key, while retention/pruning stays scoped to
  `storage_admission_width`.
- **Re-open triggers:** revisit thresholds if false positives appear; revisit the
  near-capacity degradation if the network approaches global capacity.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing this one.
