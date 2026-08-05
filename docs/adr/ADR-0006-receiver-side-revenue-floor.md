# ADR-0006: Close-group pricing for the receiver-side revenue floor

- **Status:** Proposed
- **Date:** 2026-07-14 (amended 2026-08-05 after canary measurement)
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none (amends the economic scope of ADR-0004; see Decision)
- **Superseded by:** none
- **Related:** ADR-0004 (commitment-bound quote pricing), ant-node #136
  (flexible 1..=7 proof bundles), ant-node #176 (first implementation, the
  approach withdrawn below), ant-node #193 (close-group pricing),
  ant-client #150 (one-quote uploads)

## Context

ADR-0004 made a quote's price an exact function of the issuer's signed
storage commitment. That is a **price ceiling**: a node cannot charge more
than the storage it can prove. ADR-0004 explicitly noted that "a ceiling is
not a revenue floor" and left the floor to a follow-up policy. Its
implementation also retired the old receiver-side floor
(`validate_paid_quote_price_floor`), which compared quote prices against the
receiver's raw on-disk record count — a count that legitimately diverges from
committed responsible counts (out-of-responsibility records, data awaiting
pruning), so the old floor false-rejected honest quotes.

Separately, ant-node #136 made the payment verifier accept flexible
single-node proof bundles of 1..=7 quotes, verifying only the median-priced
candidate in full. Each change was sound alone; combined they leave no floor
at all. The verifier cannot see which quotes a client *omitted*, so a
modified client can fetch quotes from the whole neighbourhood, pay only the
cheapest valid K-close issuer 3x its (commitment-bound, possibly baseline)
price, submit a one-quote proof, and every receiver accepts. The effective
network price collapses to "cheapest valid quote in the close group" —
typically the newest, emptiest node's baseline. One-quote clients
(ant-client #150, a liveness fix this ADR deliberately does not block) make
that proof shape routine rather than adversarial-only.

Quote-count minimums cannot close this: omission is unprovable, and any
count requirement recreates the availability failure #150 exists to fix.

## Attempted and failed: a plain price floor against the receiver's own price

**This is the substantive amendment. The original decision below was
implemented, deployed in shadow mode, measured in production, and withdrawn.
A plain price floor does not work, and the reason is structural rather than a
matter of calibration.**

The original rule was `settled >= 3 x tolerance% x calculate_price(receiver's
own committed responsible key count)`. It shipped in ant-node #176 in shadow
mode and ran on ant-prod-01 from 2026-07-29 to 2026-08-04: **70,078
evaluations across 912 of 913 node instances**, `enforce` never set.

**Records observed during canary testing:**

- **264 honest stores fell below the floor (0.377%)**, against **zero** across
  ~350k staging evaluations. Staging simply never exercised the rejection path.
- The rejections were **systematic, not noise**. They landed on the fullest
  nodes: rejecting nodes had a median committed count of **5,365** against a
  fleet median of **3,091**, and they missed narrowly — median
  `settled/required` of **0.909**.
- Only **16 of 937 node instances** ever rejected anything, but within those
  the rate was high (median 9.8%, worst 63 of 66 evaluations).
- Had enforcement been on at the shipped 50% tolerance, **229 of 18,258 chunks
  (1.25%)** would have lost at least one replica, and **16 chunks would have
  been refused by every node that evaluated them** — upload failures after the
  client had already paid, with no refund path.
- Meanwhile the underpayment the floor exists to stop was **still admitted by
  62.9% of receivers**.
- The rate was rising as the network filled: 0.21% at 08:00 to 1.01% at 16:00
  on the busiest day.

**Root cause: node size difference.** Committed key counts across the fleet
span roughly **1,700 to 6,300**, which is a **~4x spread in price**. A client
pays `3x` the **median** of the quotes it collected, so the original rule
compared a median against a single draw from a 4x-wide distribution. The
fullest nodes therefore rejected honest payments while the emptiest admitted
deep underpayment. Both failures are the same defect.

**No tolerance setting rescues it.** The underpayment underpays by only
**1.69x** while receiver prices vary **4.1x** — the signal is smaller than the
noise:

| tolerance | honest rejected | underpayment admitted |
|-----------|-----------------|-----------------------|
| 50% (as shipped) | 264 (0.377%) | 62.9% of receivers |
| 40% | 43 (0.061%) | 74.4% |
| 30% | 7 (0.010%) | 89.8% |
| 25% | 0 (0.000%) | 94.6% |

Replaying the floor formula over all 70,078 records reproduced the nodes' own
264 `below_floor=true` decisions exactly, so the honest-rejection column is
measured rather than modelled. The admitted column assumes the cheapest of ~20
quotes sits near the 5th percentile of the fleet price spread.

Caveat on the evidence: 67,892 of the 70,078 evaluations (97%) come from
2026-08-03 alone; the rest of the week was near idle. This is one day of
representative traffic, not a week.

Also worth recording: **no client was price shopping during the canary.** Paid
quotes tracked the fleet distribution exactly (median paid issuer 3,126 keys
against a fleet median of 3,117), so the risk this policy addresses is
prospective rather than observed.

## Decision Drivers

- Storers must be able to refuse payments priced below a defensible cost
  basis; otherwise network revenue is set by the cheapest neighbour rather
  than by the market the median-of-7 intended.
- The floor must not resurrect the old apples-to-oranges comparison that
  false-rejected honest quotes, nor invent a new one.
- A wrongly calibrated floor rejects payments that are already settled and
  irrecoverable, so a false rejection outranks a missed detection, and rollout
  must produce evidence before it produces rejections.
- Historical receipts must never be repriced against later, higher floors.

## Considered Options

1. Require a minimum quote count in the proof — rejected: omission is
   unprovable, and any count requirement recreates the liveness failure #150
   exists to fix.
2. Carry witness/completeness evidence in the proof — rejected: witnessing is
   deliberately client-side selection, not proof material.
3. Floor from the receiver's **own** committed key count — implemented in
   ant-node #176 and **withdrawn after production measurement**; see
   "Attempted and failed" above.
4. Floor from the **close group's median** committed key count — chosen.

## Decision

On single-node store admissions (direct client PUT and immediate fresh
replication), the receiver additionally requires, alongside the existing
`settled >= 3 x median` check:

```text
settled_amount >= 3 x tolerance% x calculate_price(median committed key count
                                                   over the receiver's close group)
```

Compare a median to a median. That is the whole correction.

- **Sample.** This node's own live commitment (via the non-mutating
  `CommitmentSource::current_binding_snapshot`) plus the TTL-fresh gossiped
  commitments of the K peers closest to the chunk in its own routing table.
  Never the on-disk record count; never the answerability-refreshing quote
  path. Nothing in the payment bundle contributes, so a client cannot pad,
  prune or reorder quotes to move the floor. Counts above
  `MAX_COMMITMENT_KEY_COUNT` are dropped: gossip ingest authenticates a
  commitment's sender without bounding its count, while quote validation does.
- **Lower median on even samples.** The upper median rounds the reference up,
  and up is the direction that rejects honest settled payments.
- **Minimum 15 neighbour commitments**, counted separately from this node's
  own. Below about 11 a median over this distribution is unstable enough to be
  *worse* than the withdrawn rule (at 3 neighbours it rejects 2.0% of honest
  stores). The K-closest scan returns at most 20 entries including self and the
  cache never holds self, so the ceiling is 19: the gate tolerates 4 unknown or
  stale neighbours.
- **Below the gate, or no own commitment, or no cache, or no routing view:
  SKIP.** Never fall back to a guess. This replaces the withdrawn rule's
  "price at `calculate_price(0)`" fallback.
- **Default tolerance 65%.** At the minimum permitted view this rejects 0.140%
  of honest payments while catching ~90% of underpayment, against the withdrawn
  rule's measured 0.377% and 37.1%. Both axes improve, by roughly 2.7x on
  rejections. 60% is the conservative alternative: 5x safer on honest traffic
  at 66% detection.
- **Settled amount, not quote price.** An honest client may overpay a cheap
  quote to clear stricter receivers.
- **Scope.** Applies to `ClientPut` and `FreshReplication` (a below-floor
  proof must not fan out through one cheap accepting node). Never applies to
  paid-list admission, later repair, cache hits, or merkle-batch proofs: no
  historical receipt is repriced. This makes the floor an *ingress* rule by
  design.
- **Economic decision only.** A floor rejection is a payment decline. It
  never feeds trust or misbehaviour scoring: honest heterogeneity and churn
  can look like underpricing (ADR-0004's own warning).
- **Rollout.** Shadow mode by default: the floor is computed and logged
  (target `ant_node::payment::price_floor`) on every evaluated admission,
  never enforced. Enforcement is a per-node opt-in via
  `ANT_PRICE_FLOOR_ENFORCE=1`, tolerance via
  `ANT_PRICE_FLOOR_TOLERANCE_PERCENT` (default 65%). Unsetting the variable and
  restarting is the kill switch.

This amends ADR-0004's stated contract "a node may always charge less" to:
a quote may always charge less, but a receiver may refuse the resulting
payment when it settles below its close group's median-priced floor.

## Consequences

### Positive

- Removes both failure modes of the withdrawn rule at once: honest payments
  land near the reference by construction, and the cheapest-of-K underpayment
  lands well below it.
- No protocol change. Quotes, wire format and the ADR-0004 binding rule are
  untouched; this is receiver-side admission logic over state the node already
  holds.
- Telemetry quantifies the honest settled/floor ratio, and the skip rate by
  reason, before a single payment is rejected.

### Negative / Trade-offs

- **The manipulation bound is about a quarter of the sample, not a majority.**
  The floor does not need the median to reach a liar's value, only to move past
  the tolerance headroom, and each liar shifts the order statistic by one rank.
  Measured on the implementation's own fixture, **4 of 15** neighbours suffice
  in either direction: overstating rejects an honest at-median payment
  (griefing — the attacker spends nothing and destroys already settled money),
  understating admits the underpayment the floor exists to reject. Both are
  pinned by tests that deliberately assert the weakness. **This is why
  enforcement stays off.**
- **One-quote liveness is in tension with any floor.** An honest client that
  could reach only one cheap quoter pays `3x` that quote, and the proof carries
  no evidence separating that from "I chose the cheapest of twenty". A
  populated receiver rejects both. Shadow mode does not have this problem;
  enforcement does. The Decision Driver "one-quote liveness must be preserved"
  therefore holds under shadow mode only, and is the second enforcement
  blocker.
- **Availability of the reference is unmeasured.** The gate assumes a settled
  node normally knows most of its neighbours' commitments. That follows from
  the gossip TTL being hours against a much shorter sweep, but no telemetry
  confirms it, and the sample is drawn from peers close to the *chunk* while
  the cache is filled from peers close to *this node*, so edge-of-range chunks
  will skip more often.
- As an ingress-only rule, a below-floor chunk accepted elsewhere can still
  reach an enforcing node later via repair. Accepted: repair replays no
  fresh economic decision. The merkle-batch lane never reaches this floor at
  all, so canary results must not be read as "underpayment stopped".
- Enforcement is per-node, so mixed fleets decide differently by design;
  clients already tolerate per-receiver acceptance divergence.
- The tolerance and sample tables are simulations over the measured price
  distribution, not measurements.

### Neutral / Operational

- `VerificationContext::FreshReplication` exists, verified identically to
  `ClientPut` everywhere; it labels floor telemetry and keeps fan-out policy
  independently tunable.
- Client proof reuse (PUT fallback across the target set, partial-upload
  recovery) is evaluated against the receiver's *current* reference; the
  tolerance must absorb honest quote-to-PUT drift, which telemetry measures.

## Validation

- Unit gates: the reference equals the group median and is unmoved by this
  node's own extreme count; a receiver far above that median admits an honest
  at-median payment (the production false-rejection shape); a cheapest-of-group
  settlement is rejected; a bundle padded with cheap quotes does not move the
  reference; thin, fully stale, no-own-commitment and over-cap views skip; a
  mixed cache prices against the fresh entries only; three understated or three
  overstated neighbours do not break the floor and four of either do, pinned
  deliberately as known limits.
- Shadow telemetry before any canary enforces: the distribution of
  `settled / (3 x tolerance% x reference_price)` on honest traffic, and the
  `skipped=true` rate broken down by `skip_reason` — `no_commitment_cache` and
  `no_routing_view` are wiring bugs, `thin_sample` is the signal that the gate
  exceeds what the network supplies.
- Review trigger: enabling enforcement anywhere requires a fix or an accepted
  bound for the ~25% manipulation result above and for one-quote liveness, and
  revisiting this ADR. Changing the default tolerance or extending the floor to
  any currently exempt path also requires revisiting it.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
