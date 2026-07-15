# ADR-0004: Commitment-bound quote pricing

- **Status:** Proposed
- **Date:** 2026-06-12
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0002 (gossip-triggered contiguous-subtree storage audit)

## Context

Nodes are paid to store chunks, and the price a node may charge grows with how
much data it holds: the quoted price is a fixed public formula of the node's record
count, so the count *is* the price. Today that count is self-reported and
free: a quote is just a signed price, the client pays the median of the close
group's seven quotes, and nothing ties the price to anything checkable. A node
can claim any count it likes — the only existing check is a node refusing
*its own* stale underpriced quote; a neighbour's quote is explicitly
unjudgeable.

Meanwhile ADR-0002 already makes every node publish a signed **storage
commitment** — a Merkle root over the chunks it claims to hold plus the exact
**leaf count** — and makes neighbours audit it against real bytes. So the
network already maintains an audited, signed measure of how much data each
node holds.
Pricing just doesn't use it.

This ADR binds the two. The delivered guarantee is a **price ceiling**: to be
paid above the empty-node baseline, a node must surrender a signed commitment
that passes synchronous binding checks before payment and faces audit after
it. A node may always charge less; what dies is extraction — charging more
than the storage you can prove.

Terms used below: *commitment* = the signed `(root, key_count)` of ADR-0002.
*Pin* = the commitment's hash, identifying exactly one signed artifact.
*Forced price* = the price computed by the public formula from the pinned
commitment's `key_count`. *Baseline* = the formula at count zero.

## Decision Drivers

- Make it impossible to profit from overstating held data, alone or colluding,
  short of capturing a whole neighbourhood.
- Every check must be deterministic where possible: exact arithmetic or a
  contradiction between two artifacts signed by the same key — never a
  tolerance band, never a remote clock.
- A lie must be stopped **before payment** wherever possible; penalty lanes
  are backstops, not the ceiling itself.
- Never wrongly penalise an honest node — rotation races, gossip lag, crash
  restarts and missing state must be graced, exactly as in ADR-0002.
- Reuse what ADR-0002 ships (the commitment, its gossip, its retention rules,
  its audits, its grace lanes, its evidence path) without inventing new
  cryptography.

## Considered Options

1. **Client-side plausibility checks only** (compare the seven quoted prices,
   reject outliers). Rejected: honest heterogeneity (churn, new nodes) looks
   like lying, and a neighbourhood that inflates together passes together. A
   heuristic can deprioritise; it cannot convict.

2. **Neighbour-attested quotes** (a quote is valid only when co-signed by
   peers vouching for the count). Rejected: new signature plumbing, extra
   round-trips on the hot quoting path, and the vouchers are the same peers
   who profit from a rising neighbourhood median — collusion built in.

3. **On-chain enforcement** (post commitments to the contract; the vault
   checks price against count). Rejected: per-rotation gas for every node, and
   the chain still cannot know whether a count is *true* — that knowledge only
   exists off-chain, in the audits.

4. **Force the price from the pinned commitment (chosen).** The quote carries
   the claimed count and the pin of the commitment it priced against, and the
   commitment itself travels with the quote, so the binding is verified before
   any payment; ADR-0002's audits then check the artifact against the disk.

## Decision

We will make a quote's price a **deterministic function of the node's storage
commitment**, verifiable in full by whoever is about to pay, and auditable
afterwards by everyone else.

- **Forced price, provable on receipt.** A quote gains two fields, both
  covered by its signature and therefore by the quote hash the vault settles
  against: the claimed `key_count` and the pin of the commitment it prices
  against. The quote response carries that full signed commitment alongside —
  no extra round trip — so any receiver can verify the whole binding at once:
  the commitment's signature and peer binding, claimed count equals the
  commitment's `key_count`, and price equals the formula applied to that
  count, checked by exact recomputation (never by inverting the price, which
  rounds). A node with no commitment quotes the baseline with no pin; any
  count above zero requires the pin and its commitment. A quote may pin only
  the node's **live current commitment**, snapshotted atomically at issuance;
  retired commitments stay answerable under retention but can never be newly
  quoted, so quote traffic cannot keep a stale fat commitment alive forever.
  This applies to **both quote types** — the single-node quote and the
  merkle-batch candidate — which live in the shared payment library and need
  a versioned, breaking change to their signed payloads. Pricing thereby
  moves from "all records on disk" to the committed, *responsible* set, so
  data a node is about to prune no longer raises its price.

- **The client pays nothing it cannot resolve.** Before paying, the client
  runs the full binding check on every quote. The commitment arrived with the
  quote, so an unresolvable, withheld, or mismatched pin is never paid — this
  synchronous gate, not any later penalty lane, is the ceiling's load-bearing
  wall. A failing quote is treated exactly like an unresponsive quoter
  (today's retry/recovery path).

- **Storers re-check the arithmetic; nobody trusts the client to have.** A
  malicious client may pay a malformed bundle on purpose, so every storer
  re-runs the price-equals-formula-of-count check on every quote in the
  bundle (all seven single-node quotes; all sixteen merkle candidates) before
  reconstructing the median. This needs only the bundle itself, so every
  honest storer reaches the same verdict: an off-curve quote makes the bundle
  objectively malformed, rejected by all with no split-brain risk and no
  trust action — the rejection is the consequence.

- **Quoting is advertising: you stay answerable for what you monetize.**
  Issuing a quote refreshes the pinned (current) commitment's answerability
  retention exactly as gossiping it does — judged by the node's own clock,
  current commitment only. A new small request lets any neighbour fetch a
  commitment by its pin. Failing to answer for a quoted pin is **graced,
  never confirmed**: an unanswerable pin is indistinguishable from an honest
  crash-restart (retention is in-memory by design), so it lands in the
  existing timeout-strike lane, not the deterministic one. The funnel still
  closes because payment already forced the artifact into the open: a cheater
  must serve its commitment to be paid at all, and once seen it is audited.

- **Peers cross-check the original and route monetized commitments into
  audit.** The client forwards each quote's commitment sidecar with the
  single-node client-put bundle; storers ingest it exactly like a gossiped
  commitment (signature and binding checks) and then drop it from the receipt
  they persist — so the cross-check is synchronous and the audit never depends
  on a post-payment fetch from the accused. Merkle client-put bundles carry NO
  sidecars: sixteen per-candidate commitments (~13 KB each serialized) would
  exceed the payment-proof size budget — and did, rejecting every merkle PUT in
  production the moment nodes carried live commitments. The forced-disclosure
  invariant still holds on the merkle path because the client's
  resolve-before-pay gate makes every candidate serve its commitment BEFORE it
  can enter a paid pool; the storer-side cross-check resolves merkle pins from
  gossip or the rate-limited fetch instead, and an unanswerable pin remains
  timeout-class while the deterministic first-audit queue closes the funnel.
  On fresh client-put bundles only (a
  replication receipt's pin has legitimately aged out and is skipped), each
  storer compares every neighbour quote's claimed count to the pinned
  original — from the sidecar, from gossip if seen within the answerability
  TTL, or fetched as a fallback. A mismatch is two artifacts signed by the
  same key that contradict each other: reported on first occurrence as new
  evidence carrying both artifacts, portable and verifiable by anyone. A
  *rational* cheater is self-consistent and never trips this; for them the
  binding's job is to force the priced count into one auditable artifact,
  and the audit convicts: a commitment first seen through the quote channel
  enters a per-peer **deterministic first-audit queue** — deduped by pin,
  most recently monetized first, drained within the existing per-peer
  cooldown and concurrency caps; the lottery applies only to re-audits — so
  the latest commitment earning money for a peer always faces an audit soon,
  and minting fresh pins faster than the cooldown forfeits the older ones'
  coverage, never the newest's. Inflated counts need fake leaves; fake leaves
  fail the byte spot-check in proportion to the inflated fraction; one hit is
  a deterministic first-occurrence failure. Pin fetches are rate-limited,
  capped per bundle and per peer, negatively cached, and run off the payment
  hot path.

- **Freshness without remote clocks.** The client bounds quote age itself (it
  requested the quote moments ago and pays promptly — its own clock, its own
  risk). Node-side, no check ever gates on the quote's timestamp; staleness is
  bounded by pin answerability instead. The existing percentage-based
  staleness gate on a node's own quote is retired: the pin identifies the
  exact artifact the price came from, so the comparison is equality against a
  frozen value.

- **Rollout.** The quote format change is a **hard cutover**, not a
  mixed-fleet observe-only window. The two fields are part of the signed
  payload and therefore of the quote hash, so an old quote's signature fails
  on a new node (and vice versa) regardless of any flag — there is no version
  in which old and new nodes interoperate on the quote wire. The fleet **and**
  the clients upgrade together in one coordinated release of the shared
  payment library; no flag accepts an old-format signature or hash. What
  *is* a rollout dial is the **arithmetic/binding enforcement**: the
  `QUOTE_ARITHMETIC_RECHECK_ENABLED` gate ships observe-only first (recompute
  the forced-price/binding rule on every quote and log every would-be
  rejection, but reject nothing), then flips to reject once the fleet is on
  the new format. That gate is reject-only with no silence lane, so it is
  independent of timeout eviction. The **unanswerable-quoted-pin** path is the
  only part that couples to ADR-0002's timeout-eviction gate: until that gate
  is enabled a never-answering node's exposure is bounded but not zero. The
  own-quote price-staleness gate is retired for commitment-bound quotes (it
  compared against the on-disk count, which the committed responsible count
  legitimately differs from).

## Consequences

### Positive

- The ceiling holds before money moves: an off-curve quote dies at every
  checker, a withheld or unresolvable pin is never paid, a count that
  contradicts its pinned commitment is first-occurrence signed evidence, and
  a commitment that contradicts the disk fails its deterministic first audit.
  Each lie lands in an existing lane; no new cryptography.
- Overstating is self-defeating even before detection: an inflated forced
  price sits above the neighbourhood median, where it earns nothing on new
  uploads while the audit clock runs.
- Understating extracts nothing for the understater — it is a discount, and
  its commitment still has to be real to be quoted at all.
- The fuzzy staleness tolerance is replaced by exact equality against a
  pinned artifact — strictly fewer ways to be wrong, and no remote-clock
  false rejects.

### Negative / Trade-offs

- **The ceiling is "data held", not "data deserved".** A node that genuinely
  stores self-generated junk keyed into its range prices that storage
  honestly-by-the-letter: every check passes because the bytes are real. We
  accept this: the attack costs real disk for as long as the price is wanted,
  and audits keep it real. Junk can also be *spread* through the documented
  replication self-dealing hole at the cost of a settled on-chain payment
  plus gas per chunk — victims then hold (and rightfully price) real data, so
  the price signal stays truthful about disk even when demand was fake.
  Closing junk fully — proving sampled leaves were *paid for* by third
  parties — is deliberate future work, not this ADR.
- **A ceiling is not a revenue floor.** The median's economic meaning assumes
  the quote set is the true close group, but verification today checks seven
  unique quoters, not *which* seven; a malicious client can assemble cheap
  quorums, and coordinated undercutting (4 of 7) can suppress the median paid
  to honest peers. This ADR neither fixes nor worsens that pre-existing gap;
  quote-set closeness enforcement and payment policy are the follow-up that
  owns the floor.
- **Price freshness equals rotation cadence.** A quote prices the last
  commitment, up to one rotation old. Acceptable: a node's record count moves
  slowly relative to an hour. The lever, if ever needed, is rotating early on a
  large count change, not loosening the binding.
- **The quote format change is a hard cutover** — the signed payload changes,
  so the whole fleet and the clients move together in one coordinated release;
  there is no mixed-fleet window. Enforcement then has two *independent* dials:
  the arithmetic/binding gate (observe-only → reject, no silence lane, so
  independent of timeout eviction), and the unanswerable-quoted-pin silence
  lane (gated behind ADR-0002's timeout-eviction enable).

### Neutral / Operational

- A quote grows by roughly forty bytes; the quote *response* additionally
  carries the pinned signed commitment (a few kilobytes next to an
  already-kilobytes quote), with no extra round trip. Single-node client-put
  bundles forward the sidecars; merkle bundles omit them (the client already
  resolved every candidate's commitment before paying, and sixteen sidecars
  per chunk proof exceeded the payment-proof size budget in production);
  persisted and replicated receipts keep only the pin and count, so stored
  proofs do not grow.
- One new request type (fetch a commitment by pin), rate-limited and
  negatively cached like other replication requests.
- One new deterministic evidence variant carrying the two conflicting signed
  artifacts (quote and pinned commitment). An off-curve quote is reject-only:
  no evidence, no trust action. No repudiation variant: unanswerable pins are
  timeout-class by design.
- Quoted-pin answerability reuses the existing retention machinery and TTL;
  the only additions are the issuance-time refresh and the current-only rule.
- Median ties (e.g. several baseline quotes on a young network) are broken by
  peer id — canonical, not grindable per quote — so the paid slot is not
  client-steerable among equals. A baseline median on a mostly-empty
  neighbourhood is correct pricing, not a failure.

## Validation

How we will know this decision remains correct:

- **Tests required before this ADR is Accepted.** A quote whose pin cannot be
  resolved, whose commitment is withheld, or whose count mismatches its
  commitment is never paid by the client; an off-curve quote in a paid bundle
  is rejected identically by every storer (exact recomputation, not
  inversion); a count contradicting its pinned commitment produces the
  evidence variant on first occurrence, client-put context only; an honest
  node is never flagged across rotation races, gossip lag, and crash-restart
  (an unanswerable quoted pin is graced, never confirmed — a regression test,
  since this is the false-eviction hole); quote issuance refreshes
  answerability for the current commitment only, and a retired pin cannot be
  newly quoted; a sidecar in a client-put bundle is ingested and cross-checked
  with no fetch, and persisted receipts carry no sidecar; a commitment first
  seen via the quote channel is audited deterministically within the
  cooldown/concurrency budget with the most recently monetized pin
  prioritised, and a flood of fresh pins does not amplify into unbounded
  fetches or audits; a cached
  commitment older than the answerability TTL is treated as unknown; a node
  with no commitment quotes baseline with no pin and verifies; both quote
  types carry and verify the new fields; end-to-end, an inflating node is
  caught and earns nothing meanwhile.
- **Economic check in simulation.** With forced pricing, the expected profit
  of any *overstating* strategy — small or large, solo or colluding short of
  capturing a whole neighbourhood, including strategic count targeting of the
  median slot — is at or below honest earnings once the synchronous client
  gate, the deterministic first audit, and eviction are priced in; including
  during the window where timeout eviction is still gated.
- **Operational signals and re-open triggers.** Mismatch evidence and
  would-be rejections on an honest test network stay at zero; fetch traffic
  and deterministic-first-audit load stay within budget. Revisit if
  junk-minting or replication-seeded junk is observed at scale (escalate the
  paid-leaf proof to its own ADR); revisit when quote-set closeness
  enforcement lands (it may strengthen the median claims here); revisit the
  rotation cadence if record counts ever move fast enough that hour-stale
  prices misprice storage.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.

---

## Amendment 1 (2026-07-02): audit grace is removed — a responsive audit miss is always a confirmed failure

The original decision graces an unanswerable pin as "indistinguishable from an
honest crash-restart (retention is in-memory by design)". That grace — for every
`UnknownCommitment`, not just paid pins — is the quote-gaming loophole: a node can
be paid/credited for a commitment it cannot prove and escape by answering
`UnknownCommitment`/`Transient`. We remove grace entirely, made safe by
guaranteeing an honest node is always answerable for any pin it can be challenged
on: **(1) answerability survives restart** — the responder persists and reloads
its commitment retention (the signed commitments, their key sets, and gossip
deadlines), rebuilding each Merkle tree from the still-durable chunk bytes, so a
restart is no longer an excuse (ML-DSA signatures are randomized, so it is the
persisted *signed* commitment — never a re-signed rebuild — that preserves the
exact pin); and **(2) the auditor only challenges in-window pins** — the
gossip-lottery and downgrade paths pin the responder's own freshly-gossiped root
by construction, and the monetized first-audit path screens a client-forwarded
quote to the answerability window (assuming bounded clock skew).

With both, an honest responsive node can always answer a pin an auditor could
form, so a **responsive** rejection is graded with no grace: `UnknownCommitment`
(or missing / wrong bytes) is a **confirmed** failure; `Transient` (a local read
error, retried first by the responder) routes to the non-response/timeout lane —
no trust penalty, but the holder credit for the pin is revoked, so it gains no
standing. Only genuine **silence** stays ADR-0002's timeout lane; deterministically
attributing malicious silence/transient conditions network-wide is the
(out-of-scope) distributed non-response problem. This supersedes the "unanswerable
quoted pin is graced, never confirmed" rule and deletes `RejectKind::is_graced`;
the regression tests are updated accordingly.

---

## Amendment 2 (2026-07-14): first audits are bounded best-effort sampling — payments nominate, the clock launches

The original decision made the monetized first audit deterministic: every pinned
quote in every verified client-put proof entered the first-audit queue at every
verifying storer, gated only by the per-peer 30-minute cooldown. That per-peer
gate bounds one observer against one peer but places no bound on the aggregate:
fleet-wide launch pressure scaled as
`uploads x pinned-quotes-per-proof x verifying-storers`, with hourly commitment
rotation re-arming pin-level dedup every rotation. In the v0.14.3 production
rollout this amplification saturated the audit-responder admission pools;
overflow challenges were dropped and recorded by auditors as Timeout failures
(545k Timeout errors/24h fleet-wide, ~31% slower downloads). A matched staging
ablation attributed 97.7% of storage-commitment audit traffic and 99.955% of
one-key timeout failures to this path, and a per-service concurrency cap alone
(without a launch-rate budget) reproduced the storm. Amendment 1's answerability
guarantees are unaffected; this amendment changes only who is nominated and how
fast nominations launch.

**Nomination narrows to paid pins.** Only the candidate whose on-chain
settlement actually verified is nominated: the single-node path nominates the
settlement-verified median candidate (not the whole bundle), and the merkle
path nominates the contract-paid indices (not the whole pool). Unpaid quotes
earned nothing; their gossiped commitments remain under the ADR-0002 lottery.
The storer-side cross-check (arithmetic re-check and mismatch evidence) still
runs on every quote and candidate.

**Launches are budgeted, not deterministic.** Each node's first-audit drainer
runs a launch limiter: a token bucket (burst 2, one token per 5 minutes — a
sustained per-node rate of 12 launches/hour, plus at most the burst of 2 in
the first hour), an in-flight cap (2), and a uniform
0-30s launch jitter so the storers of one chunk, which all verify the same
payment at the same instant, do not challenge the paid peer simultaneously.
Fleet-wide first-audit pressure is therefore `nodes x refill-rate`, independent
of upload volume. Budget deferral is penalty-free: a deferred pin stays pending
(bounded, one entry per peer) and launches when tokens allow; only audits that
actually launch have consequences.

**Pending coalescing keeps the highest count per peer, not merely the newest.**
The per-peer pending slot retains the pin that most needs auditing — the
HIGHEST committed key count (newest on an equal-count tie). A strictly-lower-
count nomination for a peer never displaces a higher-count pending pin, and a
suppressed lower nomination does not disturb the retained pin's queue position.
Without this rule a peer could erase an inflated (audit-worthy) commitment for
the cost of one cheaper same-peer settlement, since the count-jump override
only compares against the last AUDITED count and a sidecar-only inflated pin
has no gossip-lottery backstop. The same rule governs the requeue of a
reservation that loses the shared-cooldown race. Accepted residual: if the
retained higher pin later ages out of the answerability window (un-auditable
once aged, grace removed), the single per-peer slot has already discarded the
lower fallback — a small coverage reduction versus keeping both, not a revival
of the lower-count-displacement bypass.

**Per-peer re-audit window survives pin rotation.** After a first audit
launches at a peer, further nominations for that peer are dropped for 2 hours
(inside the 3h answerability TTL) — unless the new pin's committed key count
exceeds the audited one by more than 1.5x, which re-nominates immediately. The
jump override preserves the anti-inflation property this queue exists for: an
inflated commitment delivered only as a quote sidecar is visible to payment
verifiers alone, so no gossip-lottery audit can ever select it; a peer that
passes an audit on an honest count and then mints a much larger sidecar-only
commitment is re-audited at once. Ordinary rotations with a stable count stop
re-arming the fleet.

**Coverage restated.** "The latest commitment earning money for a peer always
faces an audit soon" becomes: the FIRST commitment earning money for a peer,
and any later commitment whose claimed count materially jumps, faces an audit
soon (minutes, from multiple independent storers, each within its own budget);
commitments rotated without material count change rely on the ADR-0002 lottery
for re-audit. First-audit coverage is best-effort supplementary sampling under
an explicit load budget, not a per-payment guarantee. The scheduler's funnel
(received / queued / coalesced / duplicates / window_deduped / rate_deferred /
cooldown_deferred / launched / terminal outcomes, plus tokens and in-flight
gauges) is exported in the periodic scheduler summary so this coverage is
measurable in production.

**Every pipeline stage is bounded, and the invariants hold by construction.**
The verifier-to-drainer nomination channel is bounded (producers `try_send`
and drop on full — penalty-free), the pending set is a bounded
highest-count-per-peer LRU, and launches are token-bucketed. Durable
suppression (the first-audited pin dedup, the per-peer re-audit window, the
shared cooldown stamp, the lane flip, and the launch count) is committed ONLY
at promotion, after an authoritative answerability + cooldown check-and-stamp
taken immediately before the wire challenge; a reservation cancelled during
its jitter refunds its token, releases its in-flight slot, and leaves no
suppression behind. The answerability screen runs both as a schedule-time
prefilter (over the whole jitter horizon) and authoritatively at promotion, so
a pin can never be challenged outside its window regardless of how deferral
time, jitter, and the skew margin compose.

**Nomination scope and known coverage limits (measured in staging).** (a) On
the single-node path only the FIRST settlement-verified median candidate is
nominated; if a client settles several tied-median candidates, gossiped extras
retain the ADR-0002 lottery but sidecar-only extra settled pins do not and are
an accepted best-effort residual. The merkle path nominates every
contract-paid index. (b) The per-peer re-audit window is stamped at LAUNCH, not
at a passing outcome: a peer that answers with a `Transient`/silence reaches
the ADR-0002 timeout lane and is not automatically re-launched by this
scheduler (automatic retries would change the load bound and need their own
policy). Both effects reduce coverage without weakening the price ceiling and
are to be quantified against the terminal-outcome counters in the matched
staging run.

**Accepted residuals.** (1) *Budget-exhaustion starvation, mitigated by
alternating lanes:* an attacker can try to keep observers' launch budgets
saturated with newer settled decoy nominations so an older pending pin
expires un-first-audited. Stated precisely: suppressing one pin requires
outcompeting roughly 31 launch opportunities per observer over the 150-minute
eligibility window; a single decoy settlement consumes budget at every storer
of its chunk simultaneously (a cohort, not per-observer, cost), a merkle
settlement nominates every paid index, principal recycles through
sybil-controlled reward addresses (the real costs are gas, liquidity, and
close-group positioning, not the transferred amount), and a sidecar-only
target pin has NO lottery backstop. The scheduler therefore does not rely on
economics alone: consecutive LAUNCHES strictly alternate between a
newest-first and an oldest-first lane. The lane advances on every committed
launch — not per scheduling pass (most pass over an empty bucket, and a pass
is triggered by ingress, so per-pass parity would be attacker-steerable) and
not once per launching pass (a full burst spends two tokens in one pass, and
those two must alternate with each other). Fresh decoy nominations therefore
cannot capture the oldest lane, and an aging pin is served there.

Two suppression routes remain, both requiring real settled payments at scale.
An attacker holding pre-aged pending decoys at every observer can occupy the
oldest lane too — though that lane drains them, and the per-peer re-audit
window blocks the same issuers from refreshing them. And 4096 fresher
distinct-peer nominations at an observer evict the target from that
observer's pending LRU, which is permanent for that nomination: coverage then
depends on the peer's NEXT settled payment (or, for a gossiped commitment, on
the ADR-0002 lottery). We accept this: both routes cost per-observer sybil
positioning plus a stream of genuine on-chain settlements, and neither is
free or silent — the scheduler funnel exports capacity evictions and lane
outcomes. (2) *Settlement overwrite (pre-existing,
contract-level):* the vault's `payForQuotes` unconditionally overwrites
`completedPayments[quoteHash]`, so a third party who learns a quote hash can
overwrite the record (already breaking the long-standing amount check with a
1-wei payment, on all node versions) and now equivalently the
rewards-address binding. This griefing race predates this amendment and
needs a vault-side fix (reject or accumulate on existing entries); it is
tracked as follow-up work, not a property this ADR can enforce from the node
side.
