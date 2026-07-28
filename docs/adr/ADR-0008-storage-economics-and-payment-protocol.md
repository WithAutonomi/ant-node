# ADR-0008: Storage economics and the quoting + payment protocol

- **Status:** Proposed
- **Date:** 2026-07-28
- **Decision owners:** Anselme (@grumbach)
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0002 (storage audit), ADR-0004 (commitment-bound quote
  pricing), ADR-0006 (receiver-side revenue floor), ADR-0007 (audit proof
  shape), ant-client ADR-0003 (earned-reward eligibility gate)

## Context

Every ADR so far amends one corner of the economics — ADR-0004 puts a ceiling
on what a node may charge, ADR-0006 puts a floor under what it will accept,
ADR-0005/ant-client ADR-0003 decide who may be paid at all — but the model
those amendments modify was never written down. Anyone reading the ADR set
today can see the patches and not the machine.

This ADR is **descriptive**: it records the pricing and payment design as
built, so that later ADRs can amend a stated baseline instead of an implied
one. Where the code is behind a rollout flag, the ADR says so.

Writing it down immediately surfaced one defect, which this ADR also fixes:
the merkle batch path was paying a third of what the single-node path pays for
an identical chunk, because the 3× settlement multiplier was never applied
when pool commitments were built. Nobody had compared the two paths' arithmetic
side by side before, which is the argument for having written this down.

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

The client asks the **witnessed close group** — the 7 nodes closest to the
address, each confirmed by a 5-of-7 quorum of its neighbours' views, so the
client cannot be handed a fabricated group. The request carries the address,
data size, type, and a fresh 32-byte nonce.

Each responder returns, signed with ML-DSA-65: the **quote** (content address,
timestamp, price, rewards address, committed key count, commitment pin), the
**signed commitment** the price was derived from, and its **audit report** on
the peers it observes near that address, bound to the request nonce so it
cannot be replayed. A responder that already holds the chunk says so, and the
client skips payment for that address entirely.

Before paying, the client drops any quote it cannot fully resolve: wrong
public-key-to-peer binding, bad signature, wrong content address, a price that
is not exactly `calculate_price(committed_key_count)`, or a commitment that
does not parse, does not belong to the quoter, or does not hash to the quote's
pin. The audit reports feed the payee-eligibility gate, which excludes quoters
their neighbours have not attested clean at the size they are monetizing.

### 4. Paying — two shapes

**Single-node (default below 64 chunks).** The 7 quotes are sorted by price;
the client pays the **median-priced** issuer **3× its quoted price** and the
other six nothing, in one `payForQuotes` call. Cost per chunk is 3 × median.
The multiplier keeps the network's revenue equal to paying three of the group
while costing one transaction's gas.

**Merkle batch (64 chunks and above).** The client builds a Merkle tree over
up to 256 addresses, derives `2^ceil(depth/2)` candidate pools from its
midpoints, and collects 16 quotes per pool — one `payForMerkleTree` call for
the whole batch. The contract selects a winner pool and pays `depth` of its 16
candidates: `total = median16(amount) × 2^depth`, split evenly. The client
applies the same 3× multiplier here, to the on-chain payable `amount` rather
than to the signed quote, so a batch settles `3 × median16 × 2^depth`. The
receipt is valid for one week; larger uploads split into successive batches.

The two paths now price a **leaf** identically at 3 × median. **They did not
until this ADR**: the merkle path submitted the bare quoted price as the
payable amount, so a chunk stored through a batch earned its node one third of
what the same chunk earned through a single-node upload. Nothing detected it,
because the storer recomputed its expectation from the same un-multiplied
prices. The multiplier is now applied client-side when pool commitments are
built, and the storer computes both expectations and logs the difference until
the rollout gate below is flipped.

Per *chunk*, parity is exact only when the batch size is a power of two. The
tree pads to `2^ceil(log2(N))` leaves and the contract charges for all of
them, so a 65-chunk batch pays for 128 leaves. Cost per chunk is therefore
`3 × median16 × 2^depth / N`, between 3× and just under 6× the median. That
padding premium is a property of the contract formula, predates this ADR, and
is unchanged by it.

The client needs ANT and Arbitrum gas, and approves the vault once.

### 5. Storing and verifying

The PUT carries the payment proof. Every storer independently re-verifies,
before writing anything: the bundle's structure (1 to 7 quotes, no duplicate
peers), each quote's price against the curve, the median selection, that the
paid issuer is among its own K closest peers for that address, the ML-DSA-65
signature, and the on-chain settlement — which must be at least 3× the median
**and recorded for the quote's own rewards address**, so a client cannot
redirect the money to itself and still be admitted. Merkle proofs are checked
the same way against the pool's on-chain record.

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

| Gate | Default today |
|---|---|
| Client resolve-before-pay quote binding | **enforced** |
| Node rejection of off-curve quotes (`QUOTE_ARITHMETIC_RECHECK_ENABLED`) | off (telemetry only) |
| Quote/commitment mismatch reported to trust | off (telemetry only) |
| Receiver-side price floor (ADR-0006) | shadow (`ANT_PRICE_FLOOR_ENFORCE`, 50% tolerance) |
| Payee eligibility gate (ADR-0005) | observe-only (`ADR5_ENFORCE`) |
| Client applies the 3× multiplier on the merkle path | **enforced** |
| Storer requires it (`MERKLE_PAYMENT_MULTIPLIER_ENFORCED`) | off (telemetry only) |

So the guarantees live in production today are: the client pays only prices it
can recompute and resolve to a signed commitment, and every stored chunk is
settled on-chain at ≥3× the median quote, to the quoting node's own address.
The rest is instrumented and awaiting evidence before it rejects.

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

- **Batch uploads get three times more expensive.** Restoring parity raises
  the merkle path from 1× to 3× the median per chunk. That is a real price
  increase for every upload of 64 chunks or more — the common path for files —
  and it lands the moment clients upgrade. The alternative, lowering the
  single-node path to 1×, would instead cut per-chunk revenue across the whole
  network by two thirds; parity had to be restored in one direction or the
  other, and this is the one the 3× multiplier was designed for.
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
  shapes, including the redirect-rejection and underpayment cases.
- **Telemetry before enforcement.** Price-floor shadow lines, off-curve quote
  counts, and observe-only eligibility decisions must show honest nodes
  clearing each gate before that gate is flipped to reject; a wrongly
  calibrated gate rejects payments that are already settled and irrecoverable.
- **Payment parity holds across both paths.** Unit tests assert that a merkle
  chunk's settlement equals the single-node 3× median at every tree depth, up
  to the contract's division remainder, and that applying the multiplier
  leaves the signed candidate prices and the pool hash untouched. Any future
  change to either path must keep that test passing; a per-path price
  difference is a defect unless an ADR says otherwise.
- **Re-open triggers.** The ANT price moving enough to put $/GiB outside its
  intended band; merkle-parity telemetry showing uploads still settling at 1×
  after clients have upgraded; enabling any of the gates above; any proposal to
  pay nodes for uptime rather than for stores, which would make client payments
  no longer the only revenue and invalidate this ADR's central assumption.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
