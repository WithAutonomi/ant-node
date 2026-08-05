# ADR-0006: Receiver-side revenue floor for single-node store admissions

- **Status:** Proposed
- **Date:** 2026-07-14
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none (amends the economic scope of ADR-0004; see Decision)
- **Superseded by:** none
- **Related:** ADR-0004 (commitment-bound quote pricing), ant-node #136
  (flexible 1..=7 proof bundles), ant-node #176 (implementation),
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
The enforceable invariant is the receiver's own reservation price.

## Decision Drivers

- Storers must be able to refuse payments priced below their own proven
  storage cost basis; otherwise network revenue is set by the cheapest
  neighbour rather than by the market the median-of-7 intended.
- The floor must not resurrect the old apples-to-oranges comparison that
  false-rejected honest quotes.
- One-quote liveness must be preserved: uploads may proceed with a single
  valid quote.
- A wrongly calibrated floor rejects payments that are already settled and
  irrecoverable, so rollout must produce evidence before it produces
  rejections.
- Historical receipts must never be repriced against later, higher floors.

## Considered Options

1. Require a minimum quote count in the proof — rejected: cannot prove
   completeness, and recreates the liveness failure at higher counts.
2. Carry witness/completeness evidence in the proof — rejected: witnessing is
   deliberately client-side selection, not proof material.
3. Receiver-side floor from the receiver's committed responsible key count,
   shadow-first — chosen originally, **withdrawn after production measurement**
   (see "Amendment 1" below).
4. Receiver-side floor from the close group's MEDIAN committed key count —
   chosen.

## Decision

On single-node store admissions (direct client PUT and immediate fresh
replication), the receiver additionally requires, alongside the existing
`settled >= 3 x median` check:

```text
settled_amount >= 3 x tolerance% x calculate_price(median committed key count
                                                   over the receiver's close group)
```

- **Pricing basis.** The floor prices against the MEDIAN of the close group's
  committed key counts, not the receiver's own. The sample is this node's own
  live commitment (via the non-mutating
  `CommitmentSource::current_binding_snapshot`) plus the TTL-fresh gossiped
  commitments of the K peers closest to the chunk in this node's routing
  table. Never the on-disk record count; never the answerability-refreshing
  quote path.
- **Why the median.** A client pays `3x` the MEDIAN of the quotes it
  collected. Pricing the floor against a single node's own price compares a
  median to one draw from a distribution that spans ~4x across the fleet, so
  the fullest receivers reject honest payments while the emptiest admit deep
  underpayment. Both failures are the same defect. Comparing median to median
  removes it. See Amendment 1 for the production numbers.
- **Reference is local-only.** Nothing in the payment bundle feeds the
  reference: a client cannot pad, prune or reorder quotes to move it. The
  remaining lever is gossiping a false commitment, and a median only moves if
  a MAJORITY of the group does so, while commitments stay signed and audited.
- **Too thin a view SKIPS.** Below `PRICE_FLOOR_MIN_GROUP_SAMPLE` fresh
  commitments the floor does not evaluate. A settled payment cannot be
  refunded, so guessing a reference from one or two peers would burn user
  money during a startup or post-churn window. A node that can suppress its
  neighbours' gossip can therefore disable a receiver's floor, but cannot make
  it reject honest traffic; that asymmetry is deliberate.
- **Settled amount, not quote price.** An honest client may overpay a cheap
  quote to clear stricter receivers.
- **No group view = skip.** A fresh, retired, or restarting receiver, or one
  with no gossip cache wired, does not evaluate the floor at all. This
  replaces the original "price at `calculate_price(0)`" rule: the same
  availability outcome by a clearer route, and no longer dependent on the
  baseline happening to sit below every honest settlement.
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
  `ANT_PRICE_FLOOR_TOLERANCE_PERCENT` (default 65%, derived in Amendment 1).
  Canary nodes enforce first; clients need 4-of-20 successful stores, so
  sparse enforcement cannot fail honest uploads while telemetry calibrates the
  tolerance. Unsetting the variable is the kill switch.

This amends ADR-0004's stated contract "a node may always charge less" to:
a quote may always charge less, but a receiver may refuse the resulting
payment when it settles below the receiver's own commitment-priced floor.

## Consequences

### Positive

- Restores an economic floor without sacrificing one-quote liveness, and
  with the false-rejection cause of the old floor removed by construction.
- The cheapest-of-K omission strategy stops working against enforcing
  receivers: the sole quote no longer sets the whole price.
- Telemetry quantifies the honest settled/floor ratio distribution before a
  single payment is rejected.

### Negative / Trade-offs

- Committed counts still legitimately diverge across a close group
  (rotation windows, churned responsibility sets, baseline-priced fresh
  nodes), so the tolerance is a real dial: too tight rejects honest
  settlements that are already paid and irrecoverable. Hence shadow-first
  and the loose 50% starting point.
- As an ingress-only rule, a below-floor chunk accepted elsewhere can still
  reach an enforcing node later via repair. Accepted: repair replays no
  fresh economic decision.
- Enforcement is per-node, so mixed fleets decide differently by design;
  clients already tolerate per-receiver acceptance divergence.

### Neutral / Operational

- `VerificationContext::FreshReplication` now exists, verified identically
  to `ClientPut` everywhere; it labels floor telemetry and keeps fan-out
  policy independently tunable.
- Client proof reuse (PUT fallback across the 20-peer target set,
  partial-upload recovery) is evaluated against the receiver's *current*
  floor; the tolerance must absorb honest quote-to-PUT drift, which
  telemetry measures directly.

## Amendment 1 (2026-08-04): price against the group median, not your own price

The original decision priced the floor against the receiver's own commitment.
Shadow telemetry from ant-prod-01 (2026-07-29..08-04, 70,078 evaluations
across 912 of 913 node instances) showed that reference does not work, and
that no tolerance setting rescues it.

**Honest stores were rejected.** `below_floor=true` fired 264 times (0.377%),
against zero across ~350k staging evaluations. The rejections were systematic,
not noise: they landed on the fullest nodes (rejecter median committed count
5,365 against a fleet median of 3,091) and missed narrowly (median
`settled/required` 0.909). Enforcing at the then-default 50% over that window
would have cost 229 of 18,258 chunks at least one replica, and refused 16
chunks at every node that evaluated them — upload failures after the client
had already paid, with no refund path.

**And the attack still got through.** The underpayment the floor targets (pay
`3x` the cheapest of ~20 quotes rather than `3x` the median) underpays by only
1.69x, while receiver prices span 4.1x because committed counts span roughly
1,700 to 6,300. The signal is smaller than the noise:

| tolerance | honest rejected | underpayment admitted |
|-----------|-----------------|-----------------------|
| 50%       | 0.377%          | 62.9% of receivers    |
| 40%       | 0.061%          | 74.4%                 |
| 30%       | 0.010%          | 89.8%                 |
| 25%       | 0.000%          | 94.6%                 |

Replaying the floor formula over all 70,078 records reproduced the nodes' own
264 `below_floor=true` decisions exactly, so the honest-rejection column is
measured rather than modelled. The admission column is a model assuming the
cheapest of ~20 quotes sits near the 5th percentile of the fleet price spread.

**The fix is the reference, not the threshold.** Against the group median,
honest payments land near the reference and the underpayment well below it.
Replaying the fleet's real price distribution, with the client paying `3x` the
median of a `CLOSE_GROUP_SIZE`-quote bundle and the receiver holding the
minimum permitted view (15 neighbours plus its own commitment):

| tolerance | honest rejected | underpayment caught |
|-----------|-----------------|---------------------|
| 50%       | 0.000%          | 6.4%                |
| 65%       | 0.140%          | 89.8%               |
| 70%       | 0.338%          | 96.0%               |
| 75%       | 1.175%          | 98.1%               |

65% is the shipped default: it improves on the own-price floor's measured
0.377% honest-rejection rate while raising detection from 37.1% to ~90%.

**Both axes improve, but by roughly 2.7x on rejections, not the order of
magnitude an earlier draft of this amendment claimed.** That draft modelled the
client as paying the median of 20 quotes; the proof bundle actually carries at
most `CLOSE_GROUP_SIZE` (7), and a 7-sample median is far noisier than a
20-sample one. The correction does not change the direction of the decision,
only its size.

**Sample size is a safety parameter, not a detail.** The reference is a median,
and a median over a small sample of a distribution this wide is unstable. Below
about 11 known neighbours the group-median floor is *worse* than the own-price
reference it replaces:

| fresh neighbours | honest rejected | underpayment caught |
|------------------|-----------------|---------------------|
| 3                | 2.022%          | 70.9%               |
| 7                | 0.618%          | 84.0%               |
| 11               | 0.217%          | 88.6%               |
| 15               | 0.105%          | 89.9%               |

Hence the gate at 15 of the 20 closest, and hence the lower median rather than
the upper one on even samples: the upper median rounds the reference up, and at
the smallest permitted sample that alone moves honest rejections from 2.2% to
17.3%.

**Caveat on the evidence.** 67,892 of the 70,078 production evaluations (97%)
come from 2026-08-03 alone; the rest of the week was near idle. This is one day
of representative traffic, not a week. The tolerance and sample tables above are
simulations over the measured price distribution, not measurements. Both are
reasons the default stays shadow.

## Amendment 1 residual risks

Stated plainly, because two of them are new with this design.

**A false commitment cuts both ways, and the dangerous direction is up.**
Understating drags the reference down and weakens the floor, costing a missed
underpayment. **Overstating drags it up and makes a receiver reject settled,
honest payments** — the attacker spends nothing and destroys someone else's
money. Moving a median needs roughly half the sample, so the mitigations are the
sample gate, and dropping any gossiped count above `MAX_COMMITMENT_KEY_COUNT`
(gossip ingest authenticates the sender but does not bound the count, while
quote validation does). Neither is a proof: an attacker holding half a close
group defeats this, and address grinding into a close group is a known adjacent
problem. A signature establishes who said a number, never that it is true.

**One-quote liveness is in tension with any floor.** ADR-0006's context assumes
a client may legitimately pay against a single quote when only one peer
answered. Such a client pays `3x` a possibly-cheap quote, and the proof carries
no evidence distinguishing "only one node answered" from "I chose the cheapest
of twenty". A populated receiver will reject it exactly as it rejects the
attack. This is inherent to floors rather than to this reference, but the group
median makes it bite more often than the own-price version did on empty
receivers. The tolerance headroom is the only thing absorbing it, which is a
further reason to read shadow telemetry before enforcing.

**Availability of the reference is unmeasured.** The gate assumes a settled node
normally knows most of its neighbours' commitments, which follows from the
gossip TTL being hours against a much shorter sweep, but no production telemetry
confirms it. If the skip rate turns out high, the floor is safe but useless. The
`skipped=true` / `group_sample` fields exist to measure exactly this.

## Validation

- Unit gates (ant-node #176): a 3x-baseline settlement against a fuller
  receiver is rejected under enforcement on both admission contexts;
  exactly-at-floor passes; shadow mode never rejects; no-commitment
  receivers stay vacuous; paid-list admission is never repriced.
- Unit gates (Amendment 1): the reference equals the group median and is
  unmoved by this node's own extreme count; an honest median payment is
  admitted by a receiver far above that median (the production
  false-rejection shape); a cheapest-of-group settlement is rejected; a bundle
  padded with cheap quotes does not move the reference; a thin or fully stale
  group view skips rather than rejects; a minority of understated commitments
  does not disarm the floor.
- Shadow telemetry: distribution of `settled / (3 x tolerance% x
  reference_price)` on honest traffic, plus the `skipped=true` rate showing
  how often the group reference is unavailable; projected rejection rate must
  be ~0 at the chosen tolerance before any canary enforces.
- Canary enforcement: zero honest-upload failures at 4-of-20 store quorum
  while enforcing nodes reject synthetic cheapest-of-K proofs.
- Review trigger: enabling enforcement fleet-wide, changing the default
  tolerance, or extending the floor to any currently exempt path requires
  revisiting this ADR.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
