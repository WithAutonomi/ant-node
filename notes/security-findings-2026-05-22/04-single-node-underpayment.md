# Finding 4: Single-node underpayment via missing price floor

**Severity:** HIGH
**Category:** Fund theft (free / near-free uploads)
**PoC:** `tests/poc_underpayment_no_price_floor.rs` (2 tests, all pass)

## Root cause

`PaymentVerifier::validate_completed_single_node_payment` (`src/payment/verifier.rs:865-897`)
checks:

```rust
if quote.price == Amount::ZERO { return Err(...) }   // line 870
let expected_amount = 3 * quote.price                // line 877
if on_chain_amount < expected_amount { return Err(...) }
if on_chain_rewards_prefix != ... { return Err(...) }
```

`quote.price` is **fully client-controlled**. The verifier never references
`calculate_price(records_stored)` from `src/payment/pricing.rs:52`. Grep:

```
$ grep -n calculate_price src/payment/verifier.rs
(no matches)
```

This is the gap. The reverted #101 had `(b) Q.price >= price_floor` wired via a
shared `Arc<QuotingMetricsTracker>`. PR #107 (which closed the
recipient-binding part of #101) did not carry over the price-floor part.

## Attack

Client constructs 7 quotes at `quote.price = 1` (1 wei). One quote has
`rewards_address = local node's address` (satisfies #107's identity check).
Client pays 3 wei on-chain to the local node's rewards address (satisfies
on-chain amount + recipient prefix checks).

Result: chunk stored. Total cost: 3 wei + gas. Honest minimum at an empty node:
`3 * calculate_price(0) ≈ 1.17 × 10^16 wei` (~0.0117 ANT).

## Quantified impact

- Per-chunk cost: **3 wei** (plus gas for the payment tx).
- Underpayment ratio: ~3.9 × 10^15× at an empty node (PoC asserts ≥ 1e15).
- Subsidy scales with node fullness: at ~18k records stored, `calculate_price`
  is ~85× the empty-node value (also asserted by the PoC). Bug gets worse over
  time.
- At 4 KiB chunks and $0.10/ANT, the savings are ~$305/GiB at floor, growing.

Sustainability: limited only by the attacker's ability to land a valid 7-peer
proof in some node's local close-group view. #107's close-group check bounds
*which* nodes accept the proof — it doesn't bound the *price*. The attacker
picks a target node whose close group includes 6 attacker-controlled peers (the
same Sybil capability that Findings 3 and 5 assume) plus the victim — and the
attack is unlimited.

## Fix space

One change: add the price floor.

```rust
let price_floor = self.quoting_metrics.calculate_price(self.records_stored()) / TOL;
if quote.price < price_floor {
    return Err(Error::Payment(format!(
        "Quote price {} below floor {} for quote {}",
        quote.price, price_floor, quote.quote_hash
    )));
}
```

Wire `quoting_metrics` via a shared `Arc<QuotingMetricsTracker>` (the same
tracker the quote generator uses), so the floor moves with the live network
state. `TOL` (tolerance divisor) accommodates legitimate sub-floor quotes from
slightly-less-loaded peers in the same close group. The reverted #101 used a
tolerance constant; reuse the same value.

This is structurally my reverted #101's check (b) rebuilt onto #107's base.
Small, isolated, ship-today.

## Post-fix test

The PoC tests deliberately call out the gap as a forward regression marker;
post-fix they should be inverted: same inputs should now return
`Err(Error::Payment(...))` from the verifier.
