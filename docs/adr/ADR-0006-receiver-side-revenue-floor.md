# ADR-0006: Close-group pricing for the receiver-side revenue floor

- **Status:** Proposed
- **Date:** 2026-07-14 (amended 2026-08-05 after canary measurement; Amendment 2
  2026-10-20: enforced on every node)
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
span roughly **1,700 to 6,300**. On the pinned quadratic pricing curve that is
a **6.3x spread end to end**, and **4.1x between the 5th and 95th percentiles**
of what nodes actually charge, which is the range most payments meet. A client
pays `3x` the **median** of the quotes it collected, so the original rule
compared a median against a single draw from that spread. The
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

> **Amended.** [Amendment 2](#amendment-2-2026-10-20-enforced-on-every-node)
> changes four things below: the tolerance (65% → 30%), the reference (now
> capped at the receiver's own price), the scope (paid-list admission is
> floored too) and the rollout (enforced on every node, with nothing to
> configure). Where the two disagree, the amendment wins. The text here is kept
> as decided, so the reasons for each step stay readable.

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

## Amendment 2 (2026-10-20): enforced on every node

This amendment turns enforcement on for every node, with nothing to
configure. To make that safe it also adds a cap to the reference, lowers the
tolerance, floors paid-list admission, and keeps a refusal under the floor,
within a stated margin and once nodes run this release, from costing the
refuser trust. It answers the review
trigger in Validation above. The manipulation result now has a fix for the
dangerous direction and an accepted bound for the other. One-quote liveness
is accepted as a residual that could not be measured.

### What the shadow period and a review of the code found

Shadow telemetry from ant-prod-01, 2026-10-14T00:33Z to 2026-10-20T00:07Z, on
node 0.22.0 and 0.23.0: 2,117 floor lines from 699 node instances on 72 hosts.
54 of them (2.6%) skipped, all `thin_sample` with 14 known neighbours; across
all lines the median receiver knew 18. Replaying the logged formula
reproduced all 53 of the nodes' own `below_floor=true` lines (47 distinct
admissions) exactly. Taking each chunk and receiver once leaves 1,898
admissions over 536 chunks (944 first seen as a client PUT, 954 as fresh
replication), arriving in 48 upload bursts. Of those, 1,801 admissions over
521 chunks were matched to the receiver's own committed count, from the
`Storage commitment rotated` line written when `current()` changes.

- **65% was not safe.** Against the group median it would have refused 47 of
  the 1,898 admissions (2.5%), all among the 1,801 matched, and 2.1% of
  chunks would have been refused by every receiver that evaluated them. The
  window 2026-09-10 to 09-16 showed the same shape: 3.4% of admissions at
  65%.
- **Honest payments sit further below the group median than the simulation
  assumed.** The lowest observed ratio of the settled amount to `3 x` group
  median was 0.473, and 1% of admissions settled below 0.57x. Receivers of the
  same chunk also disagree about the median: by 1.08x at the median, 1.36x at
  p95 (1.37x among receivers matched to their own commitment) and 1.91x at
  worst. A node's own committed count swings hour to hour as neighbours come
  and go (3,132 to 5,921 keys within nine hours on one node), while the fleet
  median held between about 3,700 and 4,100 keys all week.
- **Griefing takes the whole chunk, not one replica.** Every receiver of a
  chunk prices against nearly the same median, so neighbours that push it up
  make every receiver refuse, after the money has settled. That was the first
  enforcement blocker above.
- **One accepting node was enough to replicate a below-floor write.** The node
  that stores a write announces it with `PaidNotify` to its paid close group
  before it sends fresh offers. `PaidNotify` was verified as
  `PaidListAdmission`, which the floor exempted, so peers recorded the key as
  paid and paid-list repair later copied the bytes from that one node. The
  floor refused the fresh offers and then let repair deliver the same data.
- **A refusal became a trust penalty.** Shadow mode never refused anything,
  so none of this has fired, but four existing checks judge a peer on data it
  does not hold:
  - the storing node probes every fresh-offer target 5 to 15 minutes later
    and penalises a peer that does not hold the data: at weight 5 for a chunk
    (about a 48% cut in trust) and weight 1 for a pointer (about 12%);
  - neighbour sync records a repair proof for every key a node hints to a
    peer as a replica, and from an hour later the responsible audit
    challenges that peer on the key, at weight 5;
  - a node that has held an out-of-range record for three days challenges
    the current close group before deleting it, and penalises an absent peer
    at weight 5;
  - a peer whose quorum check fails for a key only one node hinted penalises
    that node, at weight 1, up to three times per verification round.

  A peer that refused on price would be penalised by the first three for
  following policy, and the node that accepted the write by the last.

### Decision

1. **The reference is capped at the receiver's own price:**
   `reference = min(group median price, calculate_price(own committed count))`.
   A receiver never demands more than the tolerance of what it would itself
   quote right now. So `settled >= 3 x tolerance x own price` always clears
   it, however many neighbours lie. While gossip is honest, a receiver above
   the group median prices exactly as before. The withdrawn own-price rule's
   failure, honest rejections on the fullest nodes, therefore does not return.
2. **Tolerance 30%, a deliberate starting point.** 40% also refuses no
   measured admission, but the week measured is light and 40% leaves less
   margin (see below). Starting lower gives up some detection for that
   margin, and the trade is accepted on purpose. A follow-up reads enforced
   traffic, and only a later amendment raises the tolerance toward 40% (see
   Validation of this amendment).
3. **Paid-list admission is floored too.** `PaidNotify` is only sent when a
   node stores a client's write, and it carries the proof the client
   presented for it, within the same reuse window as the PUT itself. Repair
   and fetch never call the verifier, and an already verified key is answered
   from the cache. So this floors the one remaining fresh economic event and
   still reprices no historical receipt. (A client PUT that hits the payment
   cache forwards whatever proof the client attached, unverified, exactly as
   before this change; its receivers verify it.)
4. **No peer is judged on a contested write.** When a node's verifier first
   admits the payment for a write (as the node a client PUT it to, on a fresh
   offer, or on a `PaidNotify`), it prices the proof against its current
   view; a later admission of the same write from the payment cache reuses
   that decision. The write is *contested* in two cases:
   - the node cannot price it (no own commitment, or too thin a view);
   - its paid price is below 60% of the **uncapped** group median, twice the
     30% floor.

   An admitted contested write, one the node cannot price or one paid between
   the floor and that threshold, is still stored and its offers still sent,
   but the node does not judge its close-group peers on it:
   - a fan-out (chunk or pointer) schedules no possession check. This is
     decided from the proof as it stands, even one a cached PUT forwards
     unverified, since its peers verify that proof and may refuse it;
   - for a chunk, the key's paid-list entry carries a one-byte mark, which
     survives restarts. Releases before this one only test presence, so they
     read it as an ordinary paid key;
   - a marked key goes out in paid hints only, never as a replica hint. No
     repair proof is recorded for it, so no responsible audit challenges a
     peer on it, and no peer can penalise this node as its sole hinter. A
     paid hint is never punished, and repair still works wherever the group
     accepted the key. The node also keeps its marked keys in memory, so
     leaving them out of the hints it builds for a peer reads nothing on
     disk. Each paid-list write updates that copy in commit order, a new
     mark just before its commit, so the copy never lacks a committed mark,
     and a write that commits the key unmarked, a plain insert that adds it
     or a removal, drops any mark the copy holds for it. If the marks cannot be read when the node starts, it still starts, as
     before, and hints no key as a replica until a restart can read them;
   - the responsible audit never samples a marked key, which also covers one
     hinted in the moment before its mark was written;
   - a prune audit still needs its proofs before deleting a marked key, but
     scores no absent peer for it, and paid-list pruning keeps a marked entry
     while the record is held;
   - a mark that cannot be read counts as set: when in doubt, judge no one.
     While reads fail the node judges no peer on any key they hit, so it
     warns at the first failure of a run and, when a read succeeds again,
     logs how many failed.

   The mark follows the decision the node took when it verified the payment:
   the verifier remembers which admitted chunk payments the floor contested,
   in a memory of its own sized for 100,000 of them, so a small payment cache
   cannot make it forget one before the key is recorded. A write admitted
   later from the payment cache is recorded by that decision. The proof
   attached to it was never checked, and anyone can attach one to a
   `PaidNotify` or a fresh offer, so it can neither set the mark nor veto it.
   The first paid-list record of a key decides its mark, so a later payment
   can neither add nor remove it. A fan-out skips its possession check
   whenever the write is marked, by this node's verified decision or by the
   record of the key that won, read after the write records its own, as
   well as when the proof it forwards is contested. Pointers need no mark:
   the possession check is the only check that penalises a peer for a
   missing pointer.

   The paid quote's price stands in for a third of the settled amount;
   settlement is at least that, so an overpaid write is only ever judged more
   leniently. Deciding from the proof itself means a write stored after
   prices moved is judged like any other.

   The 2x margin covers the largest spread measured between receivers' views
   of the same chunk (1.91x; 1.37x at p95 among matched receivers). **It is a
   margin, not a guarantee**, because only the refusing peer knows its own
   view. Replayed over all 5,536 ordered pairs of measured receivers of the
   same chunk, at payment levels from 0.2x to 1x the median in 0.02x steps,
   no write one would judge was refused by the other. A 1.5x margin left 4
   such pairs, at payments near 0.3x the median. The cost is coverage: on the
   measured week these checks are given up for 1.4% of the 1,801 admissions
   matched to their receiver's own commitment, plus the 2.6% of evaluations
   the floor could not price. A mark stays while the node holds the key, so a
   node keeps unchecked every key it recorded while it could not price
   (its first hour before a commitment, or while its gossip view refills
   after a restart); the other holders of those keys still check them,
   unless the mark was front-run (see the consequences below).
   Penalising a peer for following the floor is the worse failure, so that
   coverage is given up. A real guarantee needs the
   refusing peer to tell the sender. A peer that can say "refused on price"
   can also dodge ADR-0003's full-node detection that way, so that is a
   separate decision.

   The threshold is its own constant, so a raise of the tolerance needs care.
   A node still at 30% judges every write paid above 0.6x of its median, and
   a peer already at 40% refuses below 0.4x of its own view. On the measured
   pairs that leaves 3 of 5,536 where a refusal would be judged. A raise
   therefore takes two releases: the first moves this threshold to 80%, and
   the tolerance moves only once nearly every node runs it. Nodes that never
   upgrade past the first stay a residual.

   The contest reads the **uncapped** median, which the cap does not
   protect. Neighbours that overstate their commitments raise it, more of
   their group's writes then count as contested, and the peers holding those
   writes go unchecked on them. A minority can lift the median only as far as
   the dearest honest members. Overstating also needs fake leaves, which fail
   the commitment byte spot-checks (ADR-0004). Neighbours that understate at
   the storer narrow the margin instead: on the test fixture, seven of
   fifteen pull its median down to the cheapest honest member, which takes
   the threshold to about 0.33x of the honest median, so a peer whose own
   view and price both sit at least 1.11x above the honest median may refuse
   a write the storer judges. That needs the same minority that disarms the
   floor (see Griefing below).
5. **Enforced on every node, with nothing to configure.** There is no
   per-node switch and no tolerance setting: `ANT_PRICE_FLOOR_ENFORCE` and
   `ANT_PRICE_FLOOR_TOLERANCE_PERCENT` are no longer read. A node whose floor
   sat above its peers' would refuse writes they store and then fail their
   possession checks for it, and one below would just admit underpayment, so
   the tolerance is the same everywhere. A node that still sets either
   variable gets no warning; the variable is ignored. Backing the floor out
   takes a release, so the release train's canary is where it is stopped. A
   node whose replication engine fails to start runs without one, as before,
   and its floor then has nothing to price from and skips every evaluation
   (`skip_reason=no_commitment_cache`). So does a local `ant-devnet`, which
   runs no replication engine.

The telemetry line keeps every earlier field. `enforce` is now always
`true`, which tells these nodes apart from shadow-mode releases while the
fleet upgrades (as does the presence of `target`). `reference_price` is
still the value `required` is computed from. It adds `target` (chunk or
pointer), `group_median_price`, `own_price`, `paid_quote_age_secs` and
`contested`.

### Why the cap, and why 30%

The measured admissions replayed through both rules, as admissions refused
out of 1,801:

| tolerance | median only | capped |
|---|---|---|
| 30% (chosen) | 0 | 0 |
| 40% | 0 | 0 |
| 45% | 0 | 0 |
| 50% | 1 | 0 |
| 55% | 11 | 1 |
| 60% | 26 | 5 |
| 65% (old default) | 47 | 11 |

- **Margin, not the zero count, picks the tolerance.** Zero refusals out of
  1,801 only bounds the true rate below 0.17% per admission, 0.58% per chunk,
  or 6.4% per upload burst at 95% confidence, because admissions in one burst
  are not independent. The tolerance therefore rests on how far the worst
  observed payment sits above it. With the cap, the lowest ratio is 0.534, so
  30% leaves 1.78x of headroom. 40% would leave 1.34x, 45% 1.19x and 50% only
  1.07x. The week measured is light traffic, 48 upload bursts, so the floor
  starts where the margin is widest and moves up as enforced traffic adds to
  it.
- **Proof reuse.** A client may present the same proof for up to about a
  day. A receiver's capped reference can rise with its own count (one node's
  price can double within a day) up to its group median, so a reused proof is
  safe only against the uncapped median. There, the worst measured admission
  sat at 0.473x, 1.58x above 30% (1.18x above 40%). Fleet-wide the median
  reference moved by up to about 1.2x in price from one day to the next,
  which 1.58x covers. Neither per-group drift over a day nor refusals of aged
  proofs were measured. The new `paid_quote_age_secs` field makes them
  measurable.
- **What it catches.** The realistic underpayment pays a near-empty, fresh
  or sybil quoter. A baseline quote is about a sixth of the group median.
  Share of measured receivers that refuse a 3x payment to a quoter, with the
  cap:

  | quoter's count, as a share of the group median | 30% (chosen) | 40% |
  |---|---|---|
  | 0 (a baseline quote) | 91.4% | 98.0% |
  | a quarter | 75.4% | 94.6% |
  | 40% | 27.9% | 75.2% |
  | half | 0% | 39.1% |

  Every receiver observed for a chunk refuses a baseline quote on 84.5% of
  chunks at 30%, and 95.2% at 40%. The median-only rule at 40% refuses the
  first three rows at 100%, 99.6% and 95.8%. That detection is what the cap
  and the lower tolerance give up.
- **What it does not catch.** A quoter 40% as full as its group is admitted
  by 72% of receivers, and one half as full by all of them. Shopping for the
  cheapest member of the close group is not caught either: members measured
  in August spanned about 1.4x in price, so the cheapest sits no lower than
  about 0.7x the median. No tolerance that is safe for honest traffic catches
  that, with or without the cap.
- **Griefing.** In the worst case, every neighbour gossips the protocol
  maximum. The median-only rule then refuses every honest payment. With the
  cap, all 1,801 measured admissions still clear at 30% (1,799 at 40%). On
  the test fixture, seven of fifteen overstating neighbours flip no verdict
  and eight do. Understating is where 30% costs something. Six neighbours
  claiming almost nothing leave the floor standing against a baseline quote,
  and seven disarm it, because the median then falls to the cheapest honest
  member (3,000 keys), and 30% of that member's price is below a baseline
  quote. At 40% it took eight. Disarming admits an underpayment and costs no
  one an honest payment, so this minority bound is an accepted residual of
  starting at 30%. For overstating, the close group's honest majority stays
  the trust boundary the rest of the protocol already rests on.

### Consequences of this amendment

- **Liveness is a quorum question.** A client needs 4 stores out of up to 20
  targets (a pointer needs 5 of 7). It moves to the next target, with the same
  proof, when one refuses. Under the cap, every receiver whose own price is at
  most `settled / (3 x 30%)` accepts unconditionally. That is nearly every
  receiver for a payment at the group median. The measurement could not
  observe the quorum itself: the median chunk shows only two receivers' client
  PUT lines.
- **One-quote liveness is an accepted, unmeasured residual.** An honest client
  whose only reachable quoter is a fresh node pays 3x baseline, and nearly
  every mature receiver refuses it. This cannot be told apart from the attack.
  None of the measured payments was at baseline, and the lowest paid issuer
  committed 2,147 keys, but that does not bound how often it happens. A client
  retries a refused proof
  for up to about a day, then re-quotes and pays again. A client-side change,
  such as not settling a lone baseline quote when a committed quote is
  available, is the remaining fix and belongs to the client.
- **A write below the floor stays where it was accepted.** A near-empty quoter
  accepts its own payment, because its cap is its own price. A node with no
  commitment or a thin view skips the floor. Mature peers now refuse both the
  fresh offer and the `PaidNotify`. Unless the accepting nodes make up a
  majority of the group, neither paid-list repair nor presence repair has the
  votes to authorise copying the data. The accepting node finds such a write
  contested and marks it (item 4), so it judges none of the peers that
  refused it while it holds the key. When the accepting nodes are a majority
  of the paid group, the refusers repair the key from those votes like any
  other, unmarked, since repair carries no proof to price; a refuser whose own
  quorum check fails while its neighbours' passes can then be judged on it.
- **Narrow gaps remain on nodes running this release.**
  - On the PUT path the record is stored a moment before its paid-list
    entry is written. A sync that scans the store in that moment can hint
    the key once; the audit filter keeps that from becoming an audit, but a
    refusing peer can charge the storer weight 1 once. A crash in that
    moment leaves the stored key unrecorded, so unmarked unless a later
    verified `PaidNotify` records it.
  - A PUT served from the payment cache with no proof attached stores the
    record without writing a paid-list entry at all, as before this change,
    so it is not marked either.
  - The verifier's memory of contested admissions is bounded: a decision is
    lost before its key is recorded only if 100,000 newer contested
    admissions reach the node in the moments between its verification and
    its record.
  - A paid-list insert that fails before its commit leaves the key out of
    the paid list, so unmarked. When a marked insert's commit is what
    failed, the in-memory copy keeps the mark, since the commit may still
    have reached the disk, so this node does not hint the key as a replica
    while the mark stays. A later plain insert that adds the key, or a
    removal of it, drops the mark once that write commits, and a restart
    rebuilds the copy from the database.
  - Paid-list pruning checks for the record before and after its network
    round, but a record admitted between that check and the delete would
    lose its mark. Both store paths require this node inside the same width
    the prune requires it outside, so that needs its routing view to change
    at that moment.
- **The first paid-list record decides a key's mark, which a quoter can
  front-run.** A quoter in the 20 closest to an honest key can pay itself
  for the key, for gas only, and announce it before the client's write
  lands. At a price between the floor and the contest threshold, or at any
  price on nodes that cannot price, the nodes it reaches first mark the key
  and leave it unchecked, though they still store and repair it; those among
  the client's storers skip their possession check too, while storers it did
  not reach first still run theirs. Paying above the
  threshold first does the opposite: those nodes record the key unmarked and
  can judge peers that later refuse the client's cheaper write, until those
  peers repair it from the votes the front-run created.
- **Rollout skew is the main rollout risk.** Until the fleet upgrades, a node
  on an older release admits every payment and still probes every
  fresh-offer target 5 to 15 minutes later. Each upgraded peer that refused a
  below-floor chunk it fanned out is penalised at weight 5. In that node's
  view the peer falls from a neutral 0.5 to about 0.26, below the 0.35 swap
  threshold, for about 9.5 hours (a pointer costs weight 1: 0.5 to 0.44). The
  score is local to that node (for peers in its persisted close group it
  survives a restart), and falling below 0.35 only lets a better candidate
  replace the peer in that node's routing
  table when its bucket is full; nothing is blocked. Honest writes are not
  refused, so this needs below-floor writes, which an attacker can buy for
  little more than gas by paying its own near-empty node within the 20
  closest to the key: one write stored by `s` older nodes yields up to `s`
  penalties on each upgraded member of the close group. Such a key also
  stays on the older node unmarked, before and after it upgrades: its replica
  hints and responsible and prune audits keep judging the refusers on it,
  repeatedly, while it holds the key, and the refusers penalise it (weight 1)
  as the sole hinter of a key their quorum rejects. On the v0.17.0 rollout the
  managed fleet went from 24 of 73 hosts in the first hour to 65 in six and
  71 within about 17; community nodes follow on their own schedule. Enabling
  enforcement one release after item 4 ships would remove this, at the cost
  of a release that does not enforce. That was not chosen.
- **Retry load is new.** A proof that was accepted before can now be refused.
  Refusals are not cached, so every peer a client tries re-verifies it, the
  on-chain read included: up to 20 targets over 4 rounds. The load falls on
  below-floor proofs, including the honest residuals above (a lone baseline
  quote, an aged proof).
- Floor refusals stay economic. The refusal itself feeds no trust or
  misbehaviour scoring, and on nodes running this release item 4 keeps the
  checks that judge peers on held data from turning it into a penalty, within
  the margin stated there and apart from the gaps above. Merkle batches still
  bypass the floor entirely.

### Validation of this amendment

- Unit tests pin each piece:
  - the cap binds below the median, and no number of overstating neighbours
    lifts a receiver above its own price;
  - seven of fifteen overstating neighbours leave the verdict unchanged and
    eight flip it, and six understating neighbours leave the floor standing
    while seven disarm it (pinned as known limits);
  - the cheapest member of a realistic group is admitted, and a near-empty
    quoter is refused;
  - paid-list admission and pointer payments are floored;
  - a write below the contest threshold, or one the node cannot price, is
    contested, and one at the median is not. The threshold is 60% of the
    uncapped median to the atto, it stays on the median when the cap binds,
    and a fan-out judges the proof it forwards against the view when it fans
    out, while a chunk's paid-list mark keeps the decision its verification
    made;
  - the tolerance is 30%: exactly `3 x 30%` of the group median clears it
    and one atto less does not;
  - a node with no floor wired contests nothing;
  - the verifier remembers a contested payment it admitted, in a memory a
    small payment cache cannot shrink, a later cache-hit admission reads that
    decision, and a refused payment is never remembered; the paid-list mark
    is written only with a new entry, survives a restart and a later plain
    insert, and goes with the entry;
  - a marked key is left out of replica hints and of responsible-audit
    sampling, and its paid entry outlives paid pruning while its record is
    held;
  - the in-memory copy of the marks is filled on opening and follows every
    write and removal, and a marked insert and a batch removal change it
    only in the order writes take; a mark held in memory alone, as a failed
    commit can leave it, goes with a later plain insert of the key and with
    its removal, single or batched; building
    replica hints works while the paid list cannot be read at all, and a
    paid list whose marks cannot be read on opening still opens and hints no
    replica;
  - a mark that cannot be read counts as set in the responsible audit, paid
    pruning and a write's fan-out, and a run of such reads logs one
    warning. The tests make the read fail by holding the thread's one LMDB
    reader slot;
  - a record reports the winning record's mark, or its own when that is
    set, so a plain decision that loses to a marked record still leaves the
    write unjudged.
- Four e2e tests run the real schedulers on a local testnet, each with a
  control. They settle nothing on chain, so where a test needs a verified
  contested admission it stands one in; unit tests pin that a real
  verification records it:
  - a chunk PUT through the handler schedules no possession check when the
    storer's verified decision was contested (the key is marked and hinted
    to a close peer as paid only), when only the proof it forwards is
    contested, or when a marked record of the key won before its own plain
    one, while the control write is penalised;
  - a fresh pointer state the storer cannot price is not used to judge its
    peers, while the control is;
  - a prune audit of a marked record keeps it but scores none of the absent
    peers, while the control scores them;
  - a PUT, a fresh offer and a `PaidNotify`, each admitted from the payment
    cache with a forged proof the floor would contest, mark the key exactly
    when the recording node's own verified decision was contested, and never
    from that proof.
- 54 mutations of the floor, the contest decision, the verifier's memory,
  the mark, its in-memory copy and every check that reads the mark were run
  against these unit and e2e tests on this amendment's code, and 53 fail at
  least one of them. The one that survives makes prune-audit scoring count
  a mark that cannot be read as unset. Only the e2e prune test reaches that
  check, and it cannot make a node's paid-list read fail; the same read
  counts as set, under test, in the audit, paid pruning and the fan-out.
- `tests/e2e/price_floor_ab.rs` drives the same honest and near-empty-quoter
  uploads through a production-wired local testnet. Nodes are seeded to
  production-sized commitments, payments are real (on Anvil), and possession
  checks are shortened. It reports who stores each write, whose paid list
  holds it, and whether any peer is penalised, so two builds can be compared.
  It asserts what the floor promises:
  - every honest upload reaches a quorum with no floor refusal;
  - no peer that refused a near-empty write, or that the quoter fanned it
    out to, loses penalty-sized trust in the quoter's view;
  - every near-empty write stays off a quorum, with every refusal the
    floor's. A mature storer whose own price is low enough may accept it, as
    the cap allows.

  It refuses to report when the floor could not evaluate at all. Its tail is
  minutes, too short for the responsible audit (an hour) or a prune audit
  (three days). The prune e2e test covers the prune audit; the responsible
  audit is covered by keeping marked keys out of replica hints, so no repair
  proof exists, and by the sampling filter's unit test. It returns at once
  unless `PRICE_FLOOR_AB=1`, so CI only compiles it.
- `tests/poc_price_floor_live.rs` runs the floor against a real Anvil vault
  and real signed neighbour commitments. It shows that a 3x-baseline
  settlement is refused, and that an at-floor overpayment clears while one
  atto less does not.
- After release, watch `ant_node::payment::price_floor` for `below_floor=true`
  with `enforce=true`, split by `context` and `target`, along with the
  `contested=true` and `skipped=true` rates. Any refusal of a payment whose
  paid issuer holds a mature commitment is a reason to revisit this amendment.
  So is a refusal rate above 0.1% of evaluations.
- **Raising to 40%.** Each evaluated line carries `settled` and
  `reference_price`, so it answers whether 40% would have refused it:
  `settled < 3 x 40% x reference_price`. The case for 40% is enforced traffic
  where that never happens, counted per upload burst: chunks less than 120 s
  apart, and one event if any admission in the burst would be refused. Zero
  events in 300 bursts bound the rate below 1% at 95% confidence, against
  6.4% from the 47 bursts measured so far that hold a matched admission.
  Bursts from one client are not independent, so that bound is the least the
  evidence must show, not proof. Production logs are kept for seven days, so
  each week's counts must be saved before they expire. Before any raise,
  aged proofs (`paid_quote_age_secs`) and
  payments to near-empty quoters are read the same way. The raise then
  follows the two steps in item 4.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
