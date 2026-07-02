# ADR-0004 implementation slicing

This file tracks the slicing strategy used to ship ADR-0004 incrementally inside
ant-node alone, while the multi-repo evmlib breaking change ripens. The ADR
itself (`ADR-0004-commitment-bound-quote-pricing.md`) describes the end state;
this document describes the order in which the end state lands.

The constraint that drives the slicing: `PaymentQuote`, `ProofOfPayment`,
`bytes_for_signing`, and `quote.hash()` live in evmlib (crates.io `0.8.1`) and
flow into the on-chain `payForQuotes` interface. Adding signed fields to
`PaymentQuote` is therefore a coordinated four-repo release
(`evmlib` → `ant-protocol` → `ant-client` → `ant-node`). Until that lands,
every part of ADR-0004 that does NOT require new signed quote fields can —
and should — ship behind the rollout const the ADR's "Rollout" section
already specifies.

## Slice 1 — arithmetic re-check (shipped)

**What:** every storer re-runs `price == calculate_price(n)` for some
non-negative integer `n`, by exact recomputation, on every quote in every
payment bundle (all 7 single-node quotes and all 16 merkle candidates), in
every `VerificationContext`. Reject-only when enforced; no trust evidence.
Rollout-gated by `QUOTE_ARITHMETIC_RECHECK_ENABLED` (defaults to `false` —
observe-only). Telemetry runs only after ML-DSA-65 signature verification has
passed, so unauthenticated peers cannot poison rollout logs.

**Why first:** needs no evmlib change, no new state, no new wire types, no
new gossip; it is the ADR's "every storer re-runs the
price-equals-formula-of-count check on every quote in the bundle" rule in
its purest form. The price already encodes the count, so canonicality testing
the price alone catches every off-curve lie (a strictly weaker attack than
on-curve count inflation, which Slice 2 addresses).

**Files touched:** `src/payment/verifier.rs` (new functions
`validate_quote_arithmetic`, `validate_merkle_candidate_arithmetic`,
`log_off_curve_single_node`, `log_off_curve_merkle`,
`price_off_curve_diagnostics`, `candidate_count_to_usize`,
`quote_price_is_on_curve`), `src/replication/config.rs` (new const
`QUOTE_ARITHMETIC_RECHECK_ENABLED`).

**Scope it does NOT cover:** an on-curve quote for a fake `n`. That requires
the signed `claimed_key_count` and `commitment_pin` fields that only Slice 3
can add.

## Slice 2 — commitment-binding sidecar (no evmlib change)

**What:** carry the issuing node's current signed `StorageCommitment` as a
sidecar inside the existing payment-proof envelope. Wire the storer-side
cross-check (claimed count from the quote vs. pinned commitment's
`key_count`) using the sidecar where present, the gossiped cache where the
sidecar pin matches, or a `GetCommitmentByPin` fetch otherwise. Adds the
`FailureEvidence::QuoteCommitmentMismatch` variant. Adds the
deterministic-first-audit queue keyed on monetized pins.

**Why second:** this is the ADR's "peers cross-check the original and route
monetized commitments into audit" paragraph. It lands the full audit funnel
end-to-end against real signed commitments without changing evmlib. The
sidecar's `claimed_count` is not yet covered by the on-chain quote hash, so
the binding is enforced at the gossip/audit layer rather than at the chain
layer — exactly the residual the ADR's rollout phase already names.

**Files touched (planned):** `src/payment/proof.rs` (sidecar serialization
envelope), `src/payment/verifier.rs` (cross-check rule),
`src/replication/protocol.rs` (`GetCommitmentByPin` request/response),
`src/replication/commitment_state.rs` (quote-issuance answerability refresh),
`src/replication/mod.rs` (first-audit queue alongside
`last_commitment_by_peer`), `src/replication/types.rs`
(`FailureEvidence::QuoteCommitmentMismatch`), `src/payment/quote.rs` (read
current pin from commitment state).

## Slice 3 — signed quote fields (multi-repo, breaking cutover) — LANDED

**What:** signed `committed_key_count: u32` and `commitment_pin:
Option<[u8; 32]>` added to `PaymentQuote` and `MerklePaymentCandidateNode`
in evmlib, included in `bytes_for_signing` (single-node) and `bytes_to_sign`
(merkle), with the quote types' fields placed at the struct **tail** so an
old-format value still rmp-decodes (as `(0, None)`). `ant-protocol` is
patched in lockstep to verify the 5-field merkle message, so the merkle
binding is genuine same-key-signed evidence too. Both `evmlib` and
`ant-protocol` are brought in via `[patch.crates-io]` against local
checkouts; the eventual upstream path is published `evmlib` →
`ant-protocol` → `ant-client` → `ant-node` releases.

**This is a HARD CUTOVER, not a mixed-fleet observe-only.** Appending the
fields to the signed payload changes every quote's signature and
`quote.hash()`, so an old quote fails signature verification on a new node
regardless of any flag — there is no version in which old and new nodes
interoperate on the quote wire. The whole fleet and the clients upgrade
together. The earlier "Slice 3 deferred behind observe-only" framing was
wrong on this point (a round-2 review finding): only the **arithmetic
enforcement** (`QUOTE_ARITHMETIC_RECHECK_ENABLED`, reject vs log) is a
rollout dial; the signed-fields format is a one-shot breaking change. With
the fields signed, Slice 1's arithmetic gate strengthens from curve
canonicality to the exact `price == calculate_price(committed_key_count)`
binding rule (`binding_violation`), and pricing moves off the on-disk count
entirely (no-commitment → baseline).

## Rollout coupling

The ADR's "Rollout" section says full enforcement requires the fleet
upgraded **and** the ADR-0002 timeout-eviction gate enabled.
`QUOTE_ARITHMETIC_RECHECK_ENABLED` (reject vs observe-only-log) is
independent of timeout eviction: the arithmetic/binding gate is reject-only
on a confirmed off-curve or mis-shaped quote, with no silence lane. The
own-quote price-staleness gate is retired for commitment-bound quotes (it
compared against the on-disk count, which the committed responsible count
legitimately differs from). The Slice-2 cross-check's silence lane (an
unanswerable quoted pin) is what couples to timeout eviction, exactly as the
ADR specifies.
