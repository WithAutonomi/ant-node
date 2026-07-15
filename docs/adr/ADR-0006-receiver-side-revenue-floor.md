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
   shadow-first — chosen.

## Decision

On single-node store admissions (direct client PUT and immediate fresh
replication), the receiver additionally requires, alongside the existing
`settled >= 3 x median` check:

```text
settled_amount >= 3 x tolerance% x calculate_price(receiver's current
                                                   committed responsible key count)
```

- **Pricing basis.** The floor reads the SAME live commitment the receiver's
  own `QuoteGenerator` prices from, via a non-mutating snapshot
  (`CommitmentSource::current_binding_snapshot`). Never the on-disk record
  count; never the answerability-refreshing quote path.
- **Settled amount, not quote price.** An honest client may overpay a cheap
  quote to clear stricter receivers.
- **No commitment = baseline.** A fresh, retired, or restarting receiver
  prices the floor at `calculate_price(0)`. Every on-curve honest quote clears
  a baseline floor at a 3x settlement, so this is not an availability
  regression. (Only an off-curve sub-baseline quote — which the ADR-0004
  arithmetic gate rejects once enforced — could fall below it, an economic
  decline rather than an outage.)
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
  `ANT_PRICE_FLOOR_TOLERANCE_PERCENT` (default 50%). Canary nodes enforce
  first; clients need 4-of-20 successful stores, so sparse enforcement
  cannot fail honest uploads while telemetry calibrates the tolerance.
  Unsetting the variable is the kill switch.

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

## Validation

- Unit gates (ant-node #176): a 3x-baseline settlement against a fuller
  receiver is rejected under enforcement on both admission contexts;
  exactly-at-floor passes; shadow mode never rejects; no-commitment
  receivers stay vacuous; paid-list admission is never repriced.
- Shadow telemetry: distribution of `settled / (3 x tolerance% x
  local_price)` on honest traffic; projected rejection rate must be ~0 at
  the chosen tolerance before any canary enforces.
- Canary enforcement: zero honest-upload failures at 4-of-20 store quorum
  while enforcing nodes reject synthetic cheapest-of-K proofs.
- Review trigger: enabling enforcement fleet-wide, changing the default
  tolerance, or extending the floor to any currently exempt path requires
  revisiting this ADR.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
