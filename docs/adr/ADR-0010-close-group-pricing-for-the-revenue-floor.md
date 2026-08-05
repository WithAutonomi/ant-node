# ADR-0010: Close-group pricing for the receiver-side revenue floor

- **Status:** Proposed
- **Date:** 2026-08-05
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** ADR-0006 (its pricing basis only; scope, rollout discipline
  and "economic decision only" carry over unchanged)
- **Superseded by:** none
- **Related:** ADR-0004 (commitment-bound quote pricing), ant-node #176
  (ADR-0006 implementation), ant-node #193 (this change)

## Context

ADR-0006 priced the receiver-side floor against **the receiving node's own**
commitment-bound price. Production shadow telemetry says that reference does not
work, and that no tolerance setting rescues it.

Measured on ant-prod-01, 2026-07-29..08-04, 70,078 evaluations across 912 of 913
node instances, all shadow:

- **0.377% of honest stores were below the floor.** Not noise: they landed on
  the fullest nodes (rejecter median committed count 5,365 against a fleet
  median of 3,091) and missed by a median of 9%. Enforcing at the then-default
  50% would have cost 229 of 18,258 chunks a replica and refused 16 chunks at
  *every* node that evaluated them — upload failures after the client had
  already paid, with no refund path.
- **The underpayment it targets was still admitted by 62.9% of receivers.**

Both failures share one cause. A client pays `3x` the **median** of the quotes
it collected, and ADR-0006 compared that median to a single draw from a
distribution spanning ~4x, because committed key counts across the fleet run
roughly 1,700 to 6,300. The reference was a sample; the payment was a median.

Replaying the floor formula over all 70,078 records reproduced the nodes' own
264 `below_floor=true` decisions exactly, so those figures are measured rather
than modelled.

## Decision Drivers

- A wrongly rejected payment is already settled on-chain and cannot be refunded,
  so false rejections cost real user money and outrank missed detections.
- The reference must not be movable by anything the paying client supplies.
- Node prices legitimately diverge; the reference has to absorb that rather than
  treat it as evidence.

## Decision

Price the floor against the **median committed key count of the receiver's close
group**, not the receiver's own:

```text
settled_amount >= 3 x tolerance% x calculate_price(median committed key count
                                                   over the receiver's close group)
```

- **Sample.** This node's own live commitment plus the TTL-fresh gossiped
  commitments of the K peers closest to the chunk in its own routing table.
  Nothing from the payment bundle contributes, so a client cannot pad, prune or
  reorder quotes to move the floor. Counts above `MAX_COMMITMENT_KEY_COUNT` are
  dropped: gossip ingest authenticates a commitment's sender without bounding
  its count, while quote validation does bound it.
- **Lower median on even samples.** The upper median rounds the reference up,
  and up is the direction that rejects honest settled payments.
- **Minimum 15 neighbour commitments**, counted separately from this node's own.
  Below about 11 a median over this distribution is unstable enough to be
  *worse* than the ADR-0006 reference it replaces (at 3 neighbours it rejects
  2.0% of honest stores). The K-closest scan returns at most 20 entries
  including self and the cache never holds self, so the ceiling is 19: the gate
  tolerates 4 unknown or stale neighbours.
- **Below the gate, or with no own commitment, or no cache, or no routing view:
  SKIP.** Never fall back to a guess. This replaces ADR-0006's "price at
  baseline" rule.
- **Default tolerance 65%.** At the minimum permitted view this rejects 0.140%
  of honest payments while catching ~90% of underpayment, against ADR-0006's
  measured 0.377% and 37.1%. Both axes improve, by roughly 2.7x on rejections.
  60% is the conservative alternative: 5x safer on honest traffic at 66%
  detection.

Unchanged from ADR-0006: scope (`ClientPut` and `FreshReplication` only, never
paid-list admission, repair, cache hits or merkle-batch proofs), shadow-by-
default rollout with `ANT_PRICE_FLOOR_ENFORCE=1` as the per-node opt-in and the
restart-based kill switch, and that a floor rejection is an economic decline
that never feeds trust or misbehaviour scoring.

## Consequences

### Positive

- Removes both ADR-0006 failure modes at once: honest payments land near the
  reference by construction, and the cheapest-of-K underpayment lands well below
  it.
- No protocol change. Quotes, wire format and the ADR-0004 binding rule are
  untouched; this is receiver-side admission logic over state the node already
  holds.

### Negative / Trade-offs

- **The manipulation bound is about a quarter of the sample, not a majority.**
  The floor does not need the median to reach a liar's value, only to move past
  the tolerance headroom, and each liar shifts the order statistic by one rank.
  Measured on the implementation's own fixture, **4 of 15** neighbours suffice
  in either direction: overstating rejects an honest at-median payment (griefing
  — the attacker spends nothing and destroys settled money), understating admits
  the underpayment the floor exists to reject. Both are pinned by tests that
  deliberately assert the weakness. **This is why enforcement stays off.**
- **One-quote liveness is in tension with any floor.** An honest client that
  could reach only one cheap quoter pays `3x` that quote, and the proof carries
  no evidence separating that from "I chose the cheapest of twenty". A populated
  receiver rejects both. Shadow mode does not have this problem; enforcement
  does.
- **Availability of the reference is unmeasured.** The gate assumes a settled
  node normally knows most of its neighbours' commitments. That follows from the
  gossip TTL being hours against a much shorter sweep, but no telemetry confirms
  it, and the sample is drawn from peers close to the *chunk* while the cache is
  filled from peers close to *this node*, so edge-of-range chunks will skip more
  often.
- Simulation caveats: 97% of the production evaluations come from a single busy
  day, and the tolerance and sample tables are simulations over the measured
  price distribution, not measurements.

## Validation

- Unit gates: the reference equals the group median and is unmoved by this
  node's own extreme count; a receiver far above that median admits an honest
  at-median payment (the production false-rejection shape); a cheapest-of-group
  settlement is rejected; a bundle padded with cheap quotes does not move the
  reference; thin, fully stale, no-own-commitment and over-cap views skip; a
  mixed cache prices against the fresh entries only; three understated or three
  overstated neighbours do not break the floor and four of either do, pinned
  deliberately.
- Shadow telemetry before any canary enforces: the distribution of
  `settled / (3 x tolerance% x reference_price)` on honest traffic, and the
  `skipped=true` rate broken down by `skip_reason` — `no_commitment_cache` and
  `no_routing_view` are wiring bugs, `thin_sample` is the signal that the gate
  exceeds what the network supplies.
- Review trigger: enabling enforcement anywhere requires a fix or an accepted
  bound for the ~25% manipulation result above, and revisiting this ADR.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
