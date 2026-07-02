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
  client-put bundle; storers ingest it exactly like a gossiped commitment
  (signature and binding checks) and then drop it from the receipt they
  persist — so the cross-check is synchronous and the audit never depends on
  a post-payment fetch from the accused. On fresh client-put bundles only (a
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
  already-kilobytes quote), with no extra round trip. The client-put bundle
  forwards the sidecars; persisted and replicated receipts keep only the pin
  and count, so stored proofs do not grow.
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

## Amendment 1 (2026-07-02): a paid commitment must stay answerable until its quote can no longer be audited, and across restarts

The original decision graces an unanswerable quoted pin ("indistinguishable from
an honest crash-restart; retention is in-memory by design"). That grace is the
pay-then-shed hole: a node can be paid for a fat commitment, delete or rotate
past it, and have the deterministic first audit graced as `UnknownCommitment`. We
close it with two rules that make an unanswerable *paid* pin provable misbehaviour
rather than an honest accident: **(1) answerability ≥ quote validity** — a
commitment (its leaves and the bytes they commit) stays answerable for at least
as long as a quote priced against it can still be paid and first-audited
(`quote_ts + max-quote-age + max-first-audit-delay ≤ commitment answerability`,
asserted at startup; the node also refuses to accept payment on an above-baseline
quote older than that window); and **(2) retention survives restart** — retained
commitments are persisted and reloaded, so answerability is exactly as durable as
the stored data, and a restart is no longer an excuse.

With both, an honest holder can always answer an in-window paid pin, so a
**responsive** node that returns `UnknownCommitment` (or missing/wrong bytes) for
one is a **confirmed audit failure**, not graced. (Only definitive repudiation is
newly convicted; sustained *silence* remains ADR-0002's existing timeout lane, and
gossip-only, aged, or non-paid pins keep the existing grace.) This supersedes the
"unanswerable quoted pin is graced, never confirmed" rule for the paid-pin case;
its regression test is inverted accordingly.
