# ADR-0008: Storage economics and the quoting + payment protocol

- **Status:** Proposed
- **Date:** 2026-07-28
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0002 (storage audit, merged), ADR-0004 (commitment-bound
  quote pricing, merged), ADR-0006 (receiver-side revenue floor, merged).
  **Not merged at this head, referenced only as pending work:** ADR-0005
  (earned-reward eligibility, on `adr-0005-earned-reward-eligibility`),
  ADR-0007 (audit proof shape, on the verified-slice-audit branch),
  ant-client ADR-0003 (client-side eligibility gate).

## Context

Every ADR so far amends one corner of the economics — ADR-0004 puts a ceiling
on what a node may charge, ADR-0006 puts a floor under what it will accept, the
pending eligibility work decides who may be paid at all — but the model those
amendments modify was never written down. Anyone reading the ADR set today can
see the patches and not the machine.

This ADR is **mostly descriptive**: it records the pricing and payment design
as built, so that later ADRs can amend a stated baseline instead of an implied
one. Two things follow from that and are called out wherever they appear:

- **Shipped vs pending.** Sections below mark what is live at this head, what
  is behind a rollout flag, and what lives on an unmerged branch. Nothing here
  should be read as deployed unless it says so.
- **One normative decision.** Writing the model down surfaced a defect: the
  merkle batch path settled a third of what the single-node path settles for an
  identical chunk, because the 3× multiplier was never applied when pool
  commitments are built. This ADR **decides** to raise merkle to 3×, and the
  change ships **client-first**: a released ant-client pays 3× on every batch
  from the moment it is used, and nodes begin *requiring* 3× at a fixed instant
  set after that release, **2026-08-04 15:00 UTC** (Unix `1785855600`). There is
  no shadow mode and no flag to flip afterwards. Because it is a pricing
  decision and not just an arithmetic repair, it still needs the economic
  owner's sign-off before the client is published; the alternatives that were
  weighed are recorded below.

Terms: *record* (one stored chunk, the priced unit), *close group* (the 7 nodes
closest to an address, which hold the replicas), *quote* (a node's signed
offer), *commitment* (ADR-0002's signed Merkle root plus key count over what a
node holds), *ANT* (the ERC-20 payment token on Arbitrum), *atto* (10⁻¹⁸ ANT).

## Decision Drivers

- One payment, stored indefinitely — the client transacts once and never again
  for that data.
- The price must be a public function anyone can recompute. No negotiation, no
  oracle, no per-operator configuration.
- The price must rise as the network fills, so scarcity attracts new supply,
  and must be non-zero when empty, so storage is never free to spam.
- Every storer must be able to verify payment independently, from the chain,
  without trusting the client or the paying node.
- Gas must not dominate: a large upload cannot mean one transaction per chunk.
- Client and node must compute prices from the same code, so they can never
  disagree about what was owed.

## Considered Options

1. **Per-byte pricing.** Rejected: the network's unit of work is a record —
   replication, audit, and routing all cost the same per chunk regardless of
   how full it is. Per-byte pricing prices the wrong thing and invites padding
   games.
2. **Rent / recurring payment.** Rejected: it makes permanence conditional on
   a live payer, requires an eviction-for-non-payment path, and puts a
   recurring on-chain cost on every stored object.
3. **Pay every member of the close group.** Rejected on gas: seven settlements
   per chunk. The chosen design pays one node a multiple instead, so the
   network receives the same money for a seventh of the transactions.
4. **Fixed network price.** Rejected: it carries no supply signal, so a
   filling network cannot pay more to attract capacity.
5. **Quadratic per-record price, median-of-group selection, one on-chain
   settlement, re-verified by every storer (chosen).**

## Decision

We price and settle storage as follows.

### 1. What is sold

A **record** — one chunk of up to 4 MiB — is the unit of sale. The price is
per record and does not depend on how many bytes the chunk actually carries.
Payment is once; the data is then stored indefinitely. There is no rent, no
renewal, no retrieval fee, and no emission or inflation subsidy: **client
payments are the network's only revenue**.

### 2. The price curve

    price_per_record(n) = BASELINE + K × (n / D)²

with `BASELINE = 0.00390625 ANT`, `K = 0.03515625 ANT`, `D = 6000 records`,
computed in `u256` wei. `n` is the node's **committed** key count — the count
in its signed storage commitment (ADR-0004) — not its raw on-disk count. A
node with no live commitment can only quote the baseline.

The formula lives once, in `ant-protocol`, and both sides import it, so a
quote's price is recomputable by the client before paying and by every storer
after (see `ant-protocol/src/payment/pricing.rs`).

At $0.10/ANT and full 4 MiB chunks (256 chunks/GiB), the quoted price per GiB
is roughly:

| Committed records | ANT / chunk | Quoted $/GiB | Client pays (3×) |
|---|---|---|---|
| 0 (empty) | 0.0039 | $0.10 | $0.30 |
| 6 000 | 0.0391 | $1.00 | $3.00 |
| 12 000 | 0.1445 | $3.70 | $11.10 |

Chunks smaller than 4 MiB cost the same each, so the effective $/GiB rises for
small-chunk data.

### 3. Quoting

The client asks the **witnessed close group**: the 7 nodes closest to the
address, each recognised by a quorum of its neighbours' reported views, so the
client cannot be handed a fabricated group. The request carries the address,
data size, type, and a fresh 32-byte nonce.

The quorum is **not a fixed 5-of-7**. It starts at `ceil(7 × 2/3) = 5` and is
reduced by one for every close-group peer that returned no responder view,
floored at 1 (`witnessed_close_group_quorum_for_missing_views`). Under churn or
partial responses the bar therefore degrades, in the worst case to a single
witness. That is a deliberate liveness choice, but it means "witnessed" is a
best-effort check, not a 5-of-7 guarantee.

Each responder returns, signed with ML-DSA-65: the **quote** (content address,
timestamp, price, rewards address, committed key count, commitment pin) and the
**signed commitment** the price was derived from. A responder that already
holds the chunk says so, and the client skips payment for that address
entirely.

Before paying, the client drops any quote it cannot fully resolve: wrong
public-key-to-peer binding, bad signature, wrong content address, a price that
is not exactly `calculate_price(committed_key_count)`, or a commitment that
does not parse, does not belong to the quoter, or does not hash to the quote's
pin.

*Pending, not at this head:* the quote response also carries a nonce-bound
**audit report**, which feeds a payee-eligibility gate excluding quoters their
neighbours have not attested clean at the size they are monetizing. That is
ADR-0005 / ant-client ADR-0003 work on unmerged branches, observe-only even
there. It is described here because it shapes the model, not because it is
running.

### 4. Paying — two shapes

#### 4a. Shipped baseline

**Single-node (default below 64 chunks).** The quotes the client collected are
sorted by price; it pays the **upper-median** issuer **3× its quoted price** and
the others nothing, in one `payForQuotes` call. Cost per chunk is 3 × that
median. The multiplier keeps the network's revenue equal to paying three of the
group while costing one transaction's gas. The median is taken over *the set
the client chose to supply*, which a storer cannot audit for completeness —
ADR-0006's receiver-side floor exists for exactly that reason.

**Merkle batch (64 chunks and above).** The client builds a Merkle tree over up
to 256 addresses, derives `2^ceil(depth/2)` candidate pools from its midpoints,
and collects 16 quotes per pool — one `payForMerkleTree` call for the whole
batch. The contract selects a winner pool and pays `depth` of its 16
candidates: `total = median16(amount) × 2^depth`, split evenly. Today the
client submits the **bare quoted price** as the payable `amount`, so a batch
settles `1 × median16 × 2^depth`. The receipt is valid for one week; larger
uploads split into successive batches.

So the shipped baseline is asymmetric: **3× the close-group median per chunk on
the single-node path, 1× the winner pool's own 16-candidate median per padded
leaf on the merkle path.**

The client needs ANT and Arbitrum gas, and approves the vault once.

#### 4b. Decision: raise merkle to 3×, client-first, enforced from a fixed date

Apply the same 3× multiplier on the merkle path, to the on-chain payable
`amount` rather than to the signed quote, so a batch settles
`3 × median16 × 2^depth`. Signed candidate prices and the pool hash stay
untouched, so every existing proof still verifies against the quotes the nodes
actually signed.

Two PRs: ant-client#161 pays the multiplier, this one makes ant-node require it.
**The requirement is on by default** — no shadow mode, no follow-up flag — but
the two halves do not arrive at the same time, and the gap between them is what
makes the change safe.

##### Five events, not one

Most of the reasoning below is about ordering, so the events have to be kept
apart. Saying "the release" conflates all five:

| Event | What it is | Timing |
|---|---|---|
| **PR landing** | ant-client#161 and this PR merge | either order, no user-visible effect |
| **Client publication** | a released ant-client that pays 3× | **must precede the boundary** |
| **Client adoption** | users actually running that client | rolling, never complete |
| **Node deployment** | operators running a node that knows the boundary | rolling, before or after the boundary |
| **Enforcement** | upgraded nodes start requiring 3× | **2026-08-04 15:00 UTC** (`1785855600`) |

Only the last is a date in the code. The others are release and operations
events, and the boundary is chosen to sit after client publication with room
for adoption.

##### Why client-first works

The client's 3× is unconditional and immediate: from the first upload made with
the published client, batches settle at `3 × median16 × 2^depth`. It carries no
date and consults no flag.

Nodes that have not upgraded accept those payments anyway, because they require
1× as a *minimum* and 3× clears it. So the client can go out — and be adopted —
well ahead of any node change, paying the network the intended amount the whole
time. That is the whole reason this ordering was chosen: the money is corrected
from the moment the client ships, and the node-side requirement only closes the
door behind it.

##### The cutover, and the receipts it must not destroy

A merkle receipt stays spendable for one week. Refusing every 1× settlement the
moment a node upgrades would therefore reject uploads whose payment had already
been made, correctly, under the previous rule, with no way to refund it. So the
requirement keys off **the receipt's own timestamp**, against a compiled-in
boundary (`MERKLE_PARITY_ENFORCED_FROM_UNIX` = `1785855600`, 2026-08-04
15:00 UTC — after client publication, with room for adoption):

| Receipt stamped | Must settle |
|---|---|
| before the boundary | 1× (the rule it was bought under) |
| at or after the boundary | 3× |

Note what this keys off: not when the chunk was stored, not when the node
upgraded, but when the *receipt* was bought. A node deployed after the boundary
enforces immediately on fresh receipts and still honours the unexpired legacy
ones.

Two properties make that a bounded compatibility window rather than an open
loophole:

- **It self-retires.** Receipts older than one week are expired anyway, so once
  `boundary + 1 week` has passed, every still-valid receipt is necessarily
  stamped at or after the boundary and the 1× branch is unreachable. Nobody has
  to remember to remove it; the branch becomes dead code that can be deleted.
- **Evasion is possible, but bounded and self-closing.** The timestamp is
  client-chosen: it is passed to `payForMerkleTree`, and the contract only
  checks that it is not in the future and not more than a week old. Quoting
  nodes sign whatever stamp the request carries. So during the week after the
  boundary, a *modified* client can deliberately stamp a receipt just before the
  boundary, pay 1×, and be admitted — the same route the honest grace uses. What
  closes it is expiry, not detection: a stamp before the boundary is unusable
  once it is more than a week old, so the route disappears at
  `boundary + 1 week` and cannot be extended. Nothing prevents backdating
  *during* the window; it is accepted as the cost of not destroying legitimately
  bought receipts, and it is bounded at one week of underpayment by clients who
  went out of their way to underpay.

What this does **not** protect: a client still running the *old* code after the
boundary builds a genuinely fresh 1× receipt, and every upgraded node refuses
it. That is the deliberate cost of enforcing rather than shadowing. The boundary
is placed after client publication precisely so adoption can run ahead of it,
and the failure is loud — the store is refused with the required multiplier
named — rather than a silent underpayment. Nodes that never upgrade keep
accepting 1×; enforcement is per-node, so the old client degrades gradually as
the fleet upgrades rather than failing everywhere at once.

What that does and does not equalise, stated precisely, because "parity" is
easy to over-read:

- It equalises **aggregate client spend per padded tree leaf**, at 3× a median.
- The two medians are **different quantities**: the single-node median is over
  the close-group quotes the client supplied for that one chunk; the merkle
  median is over the winner pool's 16 candidates for a midpoint address. Equal
  multipliers do not make them equal prices.
- It does **not** equalise what any individual node earns. Merkle pays `depth`
  candidates drawn from the batch's winner pool, not the storer of each chunk;
  a node can store a merkle chunk and be paid nothing for it. Single-node pays
  one close-group issuer per chunk. Both are lotteries, with different draws.
- Per *chunk* rather than per leaf, it is exact only at power-of-two batch
  sizes. The tree pads to `2^ceil(log2(N))` and the contract charges for every
  leaf, so 65 chunks pay for 128. Cost per chunk is
  `3 × median16 × 2^depth / N`, from 3× up to just under 6× the median. This
  padding premium predates the proposal and is unchanged by it.

**Alternatives considered.** (1) Retain the differential and document it as a
volume discount. (2) Lower single-node to 1×, which cuts per-chunk revenue
network-wide by two thirds. (3) Raise merkle to 3× — **chosen**, and the
direction the multiplier was designed for. (4) Ship it in shadow mode first and
enforce later, which was the earlier plan and was rejected: it leaves the
network underpaid for as long as it takes someone to flip a flag, and the
timestamp boundary already provides the compatibility a shadow period was
meant to buy. Tripling the common large-upload path is a pricing decision
rather than an arithmetic repair, so (3) needs the economic owner's approval
before the client is published — the client, not the node, is what starts
charging 3×.

### 5. Storing and verifying

The PUT carries the payment proof. Every storer independently re-verifies,
before writing anything: the bundle's structure (**1 to 7 quotes** — a
single-quote bundle is valid, so "the median of seven" is the intended shape,
not an enforced one), the median selection, and then, **for the paid median
candidate only**: its content address, that its public key hashes to the peer
it claims, that the issuer is among the storer's own K closest peers for that
address, its ML-DSA-65 signature, and the on-chain settlement — which must be
at least 3× the median **and recorded for the quote's own rewards address**, so
a client cannot redirect the money to itself and still be admitted.

ADR-0004's `price == calculate_price(committed_key_count)` recheck **is
enforced**, over every quote in the bundle rather than the paid one alone. A
quote whose signed price is not exactly the curve value for its own signed
count is rejected, as is a quote whose binding shape is invalid. The gate is
reject-only: an off-curve quote produces no trust evidence and schedules no
audit.

Two limits of that check remain, both current behaviour:

- **Non-paid quotes are not fully re-verified.** They position the median but
  their signatures and content addresses are not checked, so a bad signature on
  an unpaid quote is accepted (`test_legacy_unpaid_quote_bad_signature_accepted`
  pins this). They still influence which quote gets paid.
- **The signed count is not resolved against the peer's own commitment.** The
  arithmetic gate forces the price to the count the quoter signed, but a quoter
  can still sign a count it does not store. Resolving the pin and reporting the
  contradiction is `QUOTE_COMMITMENT_MISMATCH_TRUST_ENABLED`, which is `false`;
  today such mismatches are only logged.

Merkle proofs are checked against the pool's on-chain record: every candidate's
signature, the pool's closeness to the midpoint, the tree proofs, and each paid
node's index, address and amount. The required per-node amount depends on the
receipt's own timestamp: **3× parity for receipts stamped from
`MERKLE_PARITY_ENFORCED_FROM_UNIX` onward, the historic 1× for receipts bought
before it** (see §4b). Since a receipt expires after a week, the 1× branch
becomes unreachable one lifetime past the boundary.

The chunk then replicates to the close group; peers admit the fan-out under
the same proof. Later repair between neighbours carries no proof and is
authorized from network evidence instead. Each node keeps an LRU of verified
addresses and a persistent paid list, so a chunk already paid for at a node is
free to store there again.

Payment verification cannot be turned off, and a node without a rewards
address does not start.

### 6. What payment does not buy

Payment is not proof of storage. Reads are free and unmetered. Whether a node
keeps what it was paid for is settled entirely by the audit and eviction path
(ADR-0002, ADR-0003, ADR-0007). The two layers meet in one place only: the
committed count that pricing binds to is the same artifact the audits check,
and a node that was actually paid is nominated for a first audit.

### 7. Enforcement state at the time of writing

| Gate | State at this head |
|---|---|
| Client resolve-before-pay quote binding | **enforced** |
| Node re-verification of the **paid median** quote (signature, content, K-closeness, settlement, payee address) | **enforced** |
| Node re-verification of **non-paid** quotes in the bundle | not done (bad signature on an unpaid quote is accepted) |
| Node rejection of off-curve quotes (`QUOTE_ARITHMETIC_RECHECK_ENABLED`) | **enforced**, on every quote in the bundle |
| Quote/commitment mismatch reported to trust | off (telemetry only) |
| Receiver-side price floor (ADR-0006) | shadow (`ANT_PRICE_FLOOR_ENFORCE`, 65% tolerance), priced against the **close group's median** committed count, not the receiver's own; the own-price basis was withdrawn after canary measurement |
| Payee eligibility gate (ADR-0005) | **not merged**; observe-only on its branch (`ADR5_ENFORCE`) |
| Client pays the 3× multiplier on the merkle path | **enforced** by the published client, immediately and unconditionally (no flag, no date) |
| Storer requires it (`MERKLE_PARITY_ENFORCED_FROM_UNIX`) | **enforced** by upgraded nodes, for receipts stamped from 2026-08-04 15:00 UTC onward |

So the guarantees once both halves are out are: the client pays only prices it
can recompute and resolve to a signed commitment; every **single-node** stored
chunk is settled on-chain at ≥3× the supplied-set median, to the quoting node's
own address; and every **merkle** chunk from an upgraded client is settled at
≥3× the winner pool's median per padded leaf. Upgraded nodes require that from
the boundary, except on receipts stamped before it, which keep the 1× rule until
they expire. Everything else in the table is still instrumented rather than
enforced.

The parity telemetry no longer gates a decision — the decision has been made.
It now answers one operational question: how much traffic is still arriving on
pre-boundary receipts, which is how we know the compatibility window has drained
and the 1× branch is dead code that can be deleted. Traffic on pre-boundary
receipts *after* the boundary is also the only visibility we have into
deliberate backdating, since honest and evasive use of that branch are
indistinguishable from a single receipt.

## Consequences

### Positive

- Anyone — client, storer, or observer — can recompute what a chunk should
  cost from public data. There is no price oracle to attack and no per-node
  price configuration to misconfigure.
- The curve carries a supply signal: as nodes fill, quotes rise and new
  capacity is worth adding; an empty node still charges a spam barrier rather
  than zero.
- Gas cost is one settlement per chunk, or one per 256-chunk batch, rather
  than one per replica.
- Payment is verified by every storer against the chain, so a forged,
  underpaid, or redirected payment is rejected everywhere it lands rather than
  at one gatekeeper.

### Negative / Trade-offs

- **Batch uploads get three times more expensive.** Raising the merkle path
  from 1× to 3× the median per padded leaf is a real price increase for every
  upload of 64 chunks or more — the common path for files. The alternative,
  lowering the single-node path to 1×, would instead cut per-chunk revenue
  across the whole network by two thirds; parity had to be restored in one
  direction or the other, and this is the one the 3× multiplier was designed
  for.
- **An un-upgraded client's batch uploads start failing at the boundary.** It
  pays 1× on a fresh receipt and upgraded storers refuse it. There is no way to
  both require 3× and accept a new 1× payment, so this is the unavoidable cost
  of enforcing by default rather than shadowing. The boundary sits after client
  publication to give adoption time, and the rejection names the required
  multiplier so the cause is obvious rather than looking like a random store
  failure. Anyone pinned to an old client past the boundary is affected and
  needs telling before it, not after.
- **The 1× branch is a one-week underpayment window for a determined client.**
  Because the receipt timestamp is client-chosen and quoting nodes sign what
  they are asked for, a modified client can keep paying 1× until
  `boundary + 1 week` by stamping receipts just before the boundary. The window
  is bounded and closes on its own, and the same branch is what protects honest
  in-flight receipts, so it is accepted rather than fixed. It cannot be
  narrowed without also refusing legitimately bought receipts.
- **The boundary is a compiled-in date.** It has to sit after the client is
  published and after operators have had time to deploy nodes carrying it. If
  the client release slips past it, upgraded nodes begin requiring 3× while
  clients are still paying 1×, and batch uploads fail for everyone. If node
  rollout slips, enforcement is simply thinner than intended for a while, which
  is far less harmful. So the constant must be moved forward if the **client**
  release slips, must never be set earlier than the client that pays it, and
  changing it is a fleet-wide recompile — a node built with the old value keeps
  the old behaviour.
- **Parity is exact only up to the contract's integer division.** The vault
  computes `amountPerNode = total / depth`, which discards a remainder when
  `depth` does not divide `median × 2^depth`. The loss is under one wei per
  paid node per batch — economically nil, but it means the invariant is
  "within rounding", not exact.
- **Batches still pay for padding leaves.** The tree rounds up to a power of
  two and the contract charges for every leaf, so a batch of 65 chunks pays
  for 128. Per chunk that is up to 2× the parity price, worst just above a
  power-of-two boundary. Pre-existing and untouched here; closing it needs a
  contract change, so it is recorded rather than fixed.
- **Node revenue is a lottery.** One of 7 quoters is paid per chunk, or
  `depth` of a 16-node pool per batch. Fair in expectation over many chunks,
  high variance for a small or new node — and a node earns nothing for merely
  being online and healthy.
- **Price tracks the committed count, not cost or demand.** It does not
  respond to bandwidth, hardware price, or how much clients actually want to
  store, and USD cost per GiB moves one-for-one with the ANT price.
- **One payment funds unbounded future cost.** A node's storage, replication,
  and audit costs continue indefinitely against a fixed past payment, with no
  mechanism to reprice.
- **Median-of-K is only as honest as the quote set the client presents.** A
  modified client can shop the neighbourhood and settle the cheapest valid
  quote; the receiver-side floor is the counterweight and is not yet enforcing.

### Neutral / Operational

- The economic constants — `BASELINE`, `K`, `D`, the 3× multiplier, close
  group 7, 16 candidates per pool, the 64-chunk merkle threshold, the one-week
  receipt life — are compile-time. The price constants live in `ant-protocol`,
  so client and node must move together; changing any of them is a coordinated
  fleet change.
- ANT is an ERC-20 on Arbitrum; vault and token addresses are per-network
  configuration. Clients need both ANT and gas.
- Cost per GiB is a function of chunk fill. Data that self-encrypts into small
  chunks pays more per byte than data that fills 4 MiB chunks.

## Validation

- **Price parity.** Client and node import one `calculate_price`; round-trip
  and monotonicity tests hold in `ant-protocol`. A second implementation of the
  formula anywhere is a defect.
- **End to end against a real chain.** Anvil-backed tests pay and verify both
  shapes, including the redirect-rejection and underpayment cases. **Still owed
  before the client is published:** a client → vault → node test proving 3×
  construction, settlement and acceptance against a real vault, plus the
  just-below-3× and redirected-payee cases. Unit tests cover the cutover matrix
  (1× refused after the boundary, 1× honoured before it, 3× accepted on both
  sides) but not against a live chain.
- **The cutover is exercised in both directions.** Tests pin the boundary
  explicitly rather than reading the production constant, because every merkle
  receipt is stamped within a week of now — a test left on the real boundary
  would silently change which regime it exercised once the wall clock crossed
  that date.
- **The parity arithmetic is pinned by unit tests.** They assert that a merkle
  **leaf** settles for the single-node 3× median at every tree depth; that the
  per-node expectation is the floor of the multiplied total, which is *not* the
  1× expectation scaled (they differ by up to `multiplier - 1` wei, so a
  refactor that divided before multiplying fails); and, client-side, that
  applying the multiplier leaves the signed candidate prices and the pool hash
  untouched. Any future change to either path must keep these passing; a
  per-path price difference is a defect unless an ADR says otherwise.
- **Rollout telemetry has to be trustworthy before it is trusted.** The parity
  line is emitted only after a proof's paid indices, addresses and amounts have
  all validated, and only for store admissions, so rejected proofs and
  paid-list replays cannot enter the signal. Cardinality is one line per
  settlement per storer, not one per chunk: the line carries the pool hash, and
  a bounded, pool-keyed first-emission cache — written only after that full
  validation, and deliberately separate from the on-chain pool cache, which is
  populated before it — drops the rest of the batch. Its check-and-insert is a
  single locked operation, so the concurrent admissions a batch upload actually
  produces still emit once. Regression tests pin all of it: zero events from an
  invalid paid index, a wrong reward address, an underpayment or a paid-list
  verification; one event from two chunks of one pool; one more from a second
  pool; one from eight concurrent admissions of one pool.
- **Re-open triggers.** The ANT price moving enough to put $/GiB outside its
  intended band; the **client** release slipping past the parity boundary date,
  which requires moving the constant forward; node rollout not reaching enough
  of the fleet before the boundary, which weakens enforcement without breaking
  anything; a rise in refused batch uploads after the boundary, indicating
  clients that never upgraded; parity telemetry still reporting pre-boundary
  receipts more than a week after the boundary, which would mean the expiry
  assumption is wrong; a volume of pre-boundary receipts during the window that
  looks like deliberate backdating rather than honest in-flight traffic;
  enabling any of the gates still listed as instrumented; any move to pay nodes
  for uptime rather than for stores, which would make client payments no longer
  the only revenue and invalidate this ADR's central assumption.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
